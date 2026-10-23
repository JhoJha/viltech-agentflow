#!/usr/bin/env python3
"""Seeded, budgeted stress campaign planning and execution."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any, Callable, Mapping

import os as _os
import subprocess as _subprocess

from tools.prod_readiness.common import (
    BudgetEngine,
    BudgetLimits,
    ErrorCode,
    RunnerError,
    SignalSentinel,
    budget_limits_from_plan,
    canonical_state,
    capture_resource_snapshot,
    freeze_run_plan,
    initialize_owned_run_root,
)
from tools.prod_readiness.verify_evidence import verify_evidence
from tests.prod_readiness_support import process_identity as _process_identity

CRITICAL_METRICS = (
    "false_human_gate",
    "unrelated_signal",
    "unexplained_internal_error",
    "ordering_violation",
    "evidence_corruption",
    "process_leak",
    "zombie_leak",
    "lease_leak",
    "worktree_leak",
)

PROFILES = {
    "test": {"queue_count": 2, "items_per_queue": 2, "seeds": [7, 8], "workers": 2},
    "smoke": {
        "queue_count": 20,
        "items_per_queue": 5,
        "seeds": list(range(20)),
        "workers": 1,
    },
    "release": {
        "queue_count": 200,
        "items_per_queue": 5,
        "seeds": list(range(100000, 100200)),
        "workers": 4,
    },
}

# Frozen stress worker-result contract (TEST and RELEASE alike): every
# executor result consumed by the scheduler must carry an explicit terminal
# status.  Empty results ({}) or FAIL/INTERNAL_ERROR must never PASS.
STRESS_SUCCESS_STATUS = "PASS"
STRESS_EXPECTED_LOCAL_FAILURE = "EXPECTED_LOCAL_FAILURE"


def _is_stress_local_scenario(scenario_id: str) -> bool:
    lowered = str(scenario_id).lower()
    return (
        lowered in {"local", "local-failure", "deterministic-local-failure"}
        or "local" in lowered
    )


def validate_stress_worker_result(
    actual: Any, scenario_id: str
) -> tuple[bool, str]:
    """Validate one stress worker result shape. Returns (ok, reason)."""
    if not isinstance(actual, dict):
        return False, "worker result is not an object"
    status = actual.get("status")
    if not isinstance(status, str):
        return False, "worker result status is missing or not a string"
    if _is_stress_local_scenario(scenario_id):
        if status not in (STRESS_SUCCESS_STATUS, STRESS_EXPECTED_LOCAL_FAILURE):
            return False, f"unexpected status {status!r} for local scenario"
        return True, ""
    if status != STRESS_SUCCESS_STATUS:
        return False, f"unexpected status {status!r}"
    return True, ""


def logical_plan(
    profile: Mapping[str, Any], scenarios: list[str]
) -> list[dict[str, Any]]:
    if not scenarios or any(
        not isinstance(item, str) or not item for item in scenarios
    ):
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST, "stress scenarios must be non-empty IDs"
        )
    count, width, seeds = (
        profile.get("queue_count"),
        profile.get("items_per_queue"),
        profile.get("seeds"),
    )
    if (
        not isinstance(count, int)
        or not isinstance(width, int)
        or not isinstance(seeds, list)
        or count != len(seeds)
    ):
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST, "stress profile dimensions are inconsistent"
        )
    plan = []
    for queue_index, seed in enumerate(seeds):
        rng = random.Random(seed)
        plan.append(
            {
                "queue_id": f"queue-{queue_index:04d}",
                "seed": seed,
                "scenarios": [
                    scenarios[rng.randrange(len(scenarios))] for _ in range(width)
                ],
            }
        )
    return plan


def _zero_metrics() -> dict[str, int]:
    return {key: 0 for key in CRITICAL_METRICS}


def _baseline_pid_snapshot() -> dict[int, tuple[Any, Any]]:
    snapshot: dict[int, tuple[Any, Any]] = {}
    proc_root = Path("/proc")
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return {}
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            identity = _process_identity(pid)
            snapshot[pid] = (identity.start_time, identity.boot_id)
        except Exception:
            continue
    return snapshot


def _is_descendant_of_pid(pid: int, ancestor: int, *, max_depth: int = 64) -> bool:
    current = pid
    for _ in range(max_depth):
        if current == ancestor:
            return True
        try:
            identity = _process_identity(current)
        except Exception:
            return False
        parent = identity.ppid
        if parent is None:
            return False
        if parent == ancestor:
            return True
        if parent <= 1:
            return False
        current = parent
    return False


def _real_owned_survivors(
    baseline: dict[int, tuple[Any, Any]], runner_pid: int
) -> tuple[list[int], list[int]]:
    """Detect real owned survivors independent of executor self-report.

    Returns (processes, zombies). Uses subreaper reparenting + ppid ancestry
    so setsid() descendants are still owned. Never claims foreign processes:
    only PIDs that are new (or reused with new start_time) and descend from
    the runner are reported; PID reuse/wrong start-time/boot mismatches and
    foreign parents are excluded.
    """
    processes: list[int] = []
    zombies: list[int] = []
    try:
        runner_identity = _process_identity(runner_pid)
        runner_boot = runner_identity.boot_id
    except Exception:
        return [], []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return [], []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == runner_pid:
            continue
        try:
            current = _process_identity(pid)
        except Exception:
            continue
        if runner_boot is not None and current.boot_id != runner_boot:
            continue
        old = baseline.get(pid)
        is_new = old is None or old[0] != current.start_time or old[1] != current.boot_id
        if not is_new:
            continue
        # Only claim descendants of the runner (direct child via subreaper
        # or transitive ppid chain). Foreign processes are never claimed.
        if not _is_descendant_of_pid(pid, runner_pid):
            # Subreaper direct-child fallback (already covered by ancestry,
            # but keep explicit for reparented daemons).
            if current.ppid != runner_pid:
                continue
        if current.state == "Z":
            zombies.append(pid)
        else:
            processes.append(pid)
    return sorted(processes), sorted(zombies)


def run_stress_campaign(
    *,
    canonical_repo: Path,
    run_root: Path,
    profile_name: str,
    scenarios: list[str],
    executor: Callable[[dict[str, Any], Path], Mapping[str, Any]],
    budget: BudgetEngine | None = None,
    run_plan: Mapping[str, Any] | None = None,
    _test_hook: Any = None,
) -> dict[str, Any]:
    import dataclasses as _dataclasses

    if profile_name not in PROFILES:
        raise RunnerError(ErrorCode.INVALID_MANIFEST, "unknown stress profile")
    profile = PROFILES[profile_name]
    policy, owned = initialize_owned_run_root(
        run_root,
        canonical_repo,
        source_directories=(Path(__file__).resolve().parent,),
        test_hook=_test_hook,
    )
    # ROOTBIND: after initialization the public pathname must still name
    # the held inode; otherwise no PASS may ever be committed.
    _binding_failure: dict[str, Any] | None = None
    try:
        owned.assert_public_binding()
    except RunnerError as exc:
        _binding_failure = exc.to_dict()
    _subreaper_acquired = False
    try:
        plan = logical_plan(profile, scenarios)
        total = profile["queue_count"] * profile["items_per_queue"]
        default_limits = BudgetLimits(
            wall_seconds=3600,
            scenarios=total,
            executions=total,
            evidence_bytes=500_000_000,
        )
        frozen_plan = freeze_run_plan(
            policy,
            run_plan,
            expected_campaign_kind="stress",
            default_limits=default_limits,
            seed=plan[0]["seed"],
            scenario_selection=scenarios,
            tool_paths=(Path(__file__).resolve(),),
            owned=owned,
        )
        before = canonical_state(canonical_repo)
        engine = budget or BudgetEngine(budget_limits_from_plan(frozen_plan))
        worker_roots: list[Path] = []
        for worker_id in range(profile["workers"]):
            owned.mkdir_rel(f"sandboxes/stress-worker-{worker_id}")
            for child in ("repos", "worktrees", "locks", "tmp"):
                owned.mkdir_rel(f"sandboxes/stress-worker-{worker_id}/{child}")
            worker_roots.append(
                policy.disposable_root / "sandboxes" / f"stress-worker-{worker_id}"
            )
        # Owned-execution boundary: baseline PIDs + subreaper so setsid
        # descendants remain attributable independent of executor reports.
        from tools.prod_readiness.common import _ensure_child_subreaper as _ens

        _subreaper_acquired = _ens()
        runner_pid = _os.getpid()
        baseline = _baseline_pid_snapshot()
        fixture_manifest = {"owned_roots": [str(policy.disposable_root)]}
        try:
            resources_before = capture_resource_snapshot(
                source_repo=canonical_repo, fixture_manifest=fixture_manifest
            )
        except Exception as exc:
            raise RunnerError(
                ErrorCode.INTERNAL_HARNESS_ERROR,
                "stress resource baseline failed",
            ) from exc
        metrics = _zero_metrics()
        results = []
        incomplete = False
        failure_code: str | None = None
        try:
            with SignalSentinel(policy, "stress-unrelated") as sentinel:
                sentinel_pid = sentinel.proc.pid
                for queue_index, queue in enumerate(plan):
                    worker_id = queue_index % profile["workers"]
                    for item_index, scenario_id in enumerate(queue["scenarios"]):
                        action_id = f"{queue['queue_id']}:{item_index}:{scenario_id}"
                        try:
                            engine.reserve("scenarios", action_id=action_id)
                            engine.reserve("executions", action_id=action_id)
                        except RunnerError as exc:
                            # Stable error model: budget exhaustion is explicit.
                            incomplete = True
                            failure_code = exc.code.value
                            results.append(
                                {"status": "INCOMPLETE", "error": exc.to_dict()}
                            )
                            raise
                        try:
                            actual = dict(
                                executor(
                                    {
                                        "scenario_id": scenario_id,
                                        "seed": queue["seed"],
                                        "queue_id": queue["queue_id"],
                                        "item_index": item_index,
                                        "worker_id": worker_id,
                                    },
                                    worker_roots[worker_id],
                                )
                            )
                        except (KeyboardInterrupt, SystemExit):
                            raise
                        except _subprocess.TimeoutExpired:
                            actual = {
                                "status": "INCOMPLETE",
                                "unexplained_internal_error": 1,
                                "error": "TimeoutExpired",
                            }
                            incomplete = True
                            failure_code = ErrorCode.STRESS_THRESHOLD_FAILED.value
                        except FileNotFoundError:
                            actual = {
                                "status": "INCOMPLETE",
                                "unexplained_internal_error": 1,
                                "error": "FileNotFoundError",
                            }
                            incomplete = True
                            failure_code = ErrorCode.STRESS_THRESHOLD_FAILED.value
                        except BaseException as exc:
                            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                                raise
                            actual = {
                                "status": "INCOMPLETE",
                                "unexplained_internal_error": 1,
                                "error": type(exc).__name__,
                            }
                            incomplete = True
                        # VERDICT: every worker result must carry a valid
                        # explicit terminal status even in TEST profile.
                        # Empty results or FAIL must never PASS.
                        _ok_shape, _shape_reason = validate_stress_worker_result(
                            actual, scenario_id
                        )
                        if not _ok_shape:
                            incomplete = True
                            failure_code = (
                                failure_code or ErrorCode.STRESS_THRESHOLD_FAILED.value
                            )
                            # Record the shape failure without hiding the
                            # original result.
                            try:
                                actual["status_validation_error"] = _shape_reason
                            except Exception:
                                pass
                            actual["unexplained_internal_error"] = max(
                                1,
                                actual.get("unexplained_internal_error", 0)
                                if isinstance(actual.get("unexplained_internal_error"), int)
                                and not isinstance(
                                    actual.get("unexplained_internal_error"), bool
                                )
                                else 0,
                            )
                        evidence_root = actual.get("evidence_root")
                        if isinstance(evidence_root, str):
                            candidate = Path(evidence_root).resolve(strict=False)
                            try:
                                if candidate.is_relative_to(
                                    worker_roots[worker_id].resolve()
                                ):
                                    verified = verify_evidence(
                                        candidate,
                                        expected_candidate_sha=frozen_plan.candidate_sha,
                                        require_sealed=True,
                                    )
                                    actual["evidence_verified"] = (
                                        verified["status"] == "PASS"
                                    )
                                else:
                                    actual["evidence_verified"] = False
                            except Exception:
                                actual["evidence_verified"] = False
                        elif profile_name != "test":
                            actual["evidence_verified"] = False
                        if actual.get("evidence_verified", True) is not True:
                            actual["evidence_corruption"] = max(
                                1, actual.get("evidence_corruption", 0)
                            )
                        for key in CRITICAL_METRICS:
                            value = actual.get(key, 0)
                            if (
                                isinstance(value, bool)
                                or not isinstance(value, int)
                                or value < 0
                            ):
                                value = 1
                            metrics[key] += value
                        results.append(
                            {
                                "action_id": action_id,
                                "worker_id": worker_id,
                                "actual": actual,
                            }
                        )
                try:
                    sentinel.assert_untouched()
                except AssertionError:
                    metrics["unrelated_signal"] += 1
                except Exception:
                    metrics["unrelated_signal"] += 1
        except (KeyboardInterrupt, SystemExit):
            raise
        except RunnerError as exc:
            incomplete = True
            if not any("error" in row for row in results[-1:]):
                results.append({"status": "INCOMPLETE", "error": exc.to_dict()})
            if failure_code is None:
                failure_code = exc.code.value
        except Exception as exc:
            incomplete = True
            failure_code = ErrorCode.INTERNAL_HARNESS_ERROR.value
            results.append(
                {
                    "status": "INCOMPLETE",
                    "error": RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "stress worker failed",
                        error=type(exc).__name__,
                    ).to_dict(),
                }
            )
        try:
            resources_after = capture_resource_snapshot(
                source_repo=canonical_repo, fixture_manifest=fixture_manifest
            )
        except Exception as exc:
            raise RunnerError(
                ErrorCode.INTERNAL_HARNESS_ERROR, "stress resource snapshot failed"
            ) from exc
        if resources_after.unexpected_leaks:
            for row in resources_after.unexpected_leaks:
                metric = {
                    "process": "process_leak",
                    "write_lease": "lease_leak",
                    "worktree": "worktree_leak",
                }.get(row.kind, "process_leak")
                metrics[metric] += 1
        # Real owned-survivor guard: do NOT depend solely on
        # executor_result["process_leak"]. Metric may contribute but is not
        # the only authority. Detect setsid descendants via subreaper.
        try:
            real_procs, real_zombies = _real_owned_survivors(baseline, runner_pid)
            # Exclude the sentinel itself (expected cooperative child).
            real_procs = [pid for pid in real_procs if pid != sentinel_pid]
            real_zombies = [pid for pid in real_zombies if pid != sentinel_pid]
            # Exclude zombies whose parent already reaped them (transient).
            live_zombies: list[int] = []
            for pid in real_zombies:
                try:
                    current = _process_identity(pid)
                    if current.state == "Z":
                        try:
                            waited, _ = _os.waitpid(pid, _os.WNOHANG)
                            if waited == 0:
                                live_zombies.append(pid)
                        except ChildProcessError:
                            pass
                        except OSError:
                            live_zombies.append(pid)
                except Exception:
                    continue
            if real_procs:
                metrics["process_leak"] += len(real_procs)
                failure_code = failure_code or ErrorCode.STRESS_THRESHOLD_FAILED.value
            if live_zombies:
                metrics["zombie_leak"] += len(live_zombies)
                failure_code = failure_code or ErrorCode.STRESS_THRESHOLD_FAILED.value
        except RunnerError:
            raise
        except Exception:
            metrics["process_leak"] += 1
            failure_code = failure_code or ErrorCode.STRESS_THRESHOLD_FAILED.value
        after = canonical_state(canonical_repo)
        if before != after:
            metrics["evidence_corruption"] += 1
        # ROOTBIND: before any terminal PASS is committed / before sealing,
        # the public pathname must still name the held inode.
        try:
            owned.assert_public_binding()
        except RunnerError as exc:
            if _binding_failure is None:
                _binding_failure = exc.to_dict()
        if _binding_failure is not None:
            incomplete = True
            failure_code = failure_code or ErrorCode.INTEGRITY_MISMATCH.value
        status = (
            "PASS"
            if not incomplete
            and not any(metrics.values())
            and len(results) == total
            and _binding_failure is None
            else "FAIL"
        )
        # ROOTBIND: binding failure can never be overwritten by finalization.
        if _binding_failure is not None:
            status = "FAIL"
        # ERR-06: STRESS_THRESHOLD_FAILED actually emitted on threshold breach.
        error_info: dict[str, Any] | None = None
        if any(metrics.values()) or incomplete or _binding_failure is not None:
            if failure_code is None:
                failure_code = (
                    ErrorCode.STRESS_THRESHOLD_FAILED.value
                    if any(metrics.values())
                    else ErrorCode.INCOMPLETE.value
                )
            error_info = {"code": failure_code}
            if _binding_failure is not None:
                error_info["binding"] = _binding_failure
        summary = {
            "status": status,
            "profile": profile_name,
            "plan": plan,
            "worker_roots": [str(path) for path in worker_roots],
            "metrics": metrics,
            "results": results,
            "expected_executions": total,
            "actual_executions": sum(1 for row in results if "action_id" in row),
            "budget": engine.snapshot(),
            "resources_before": _dataclasses.asdict(resources_before),
            "resources_after": _dataclasses.asdict(resources_after),
            "run_plan": frozen_plan.to_dict(),
            "canonical_before": before,
            "canonical_after": after,
        }
        if error_info is not None:
            summary["error"] = error_info
        if _binding_failure is not None:
            summary["binding_failure"] = _binding_failure
        # The summary is still an in-memory, non-terminal measurement here.
        # Exercise the deterministic late-race boundary, then establish the
        # last terminal predicate before a durable PASS can exist.
        owned.test_event("before_terminal_binding", artifact="stress/summary.json")
        try:
            owned.assert_public_binding()
        except RunnerError as exc:
            if _binding_failure is None:
                _binding_failure = exc.to_dict()
            # Latch: failure cannot be overwritten by successful finalization.
            summary["status"] = "FAIL"
            summary["binding_failure"] = _binding_failure
            if "error" not in summary:
                summary["error"] = {"code": ErrorCode.INTEGRITY_MISMATCH.value}
            summary["error"]["binding"] = _binding_failure
            return summary
        if _binding_failure is not None:
            summary["status"] = "FAIL"
            return summary
        owned.atomic_create_json_rel("stress/summary.json", summary)
        return summary
    finally:
        try:
            owned.close()
        finally:
            if _subreaper_acquired:
                try:
                    from tools.prod_readiness.common import _clear_child_subreaper as _clear
                    _clear()
                except Exception:
                    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-repo", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--run-plan", type=Path, required=True)
    args = parser.parse_args(argv)

    def fake_executor(item: dict[str, Any], _root: Path) -> Mapping[str, Any]:
        return {"status": "PASS", "scenario_id": item["scenario_id"], **_zero_metrics()}

    try:
        result = run_stress_campaign(
            canonical_repo=args.canonical_repo,
            run_root=args.run_root,
            profile_name=args.profile,
            scenarios=["success", "local-failure", "retry", "watchdog"],
            executor=fake_executor,
            run_plan=json.loads(args.run_plan.read_text(encoding="utf-8")),
        )
    except RunnerError as exc:
        print(json.dumps(exc.to_dict(), sort_keys=True))
        return 2
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
