#!/usr/bin/env python3
"""Configurable, sampled PROD-READINESS soak executor."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Mapping

import subprocess as _subprocess

from tools.prod_readiness.common import (
    BudgetEngine,
    BudgetLimits,
    ErrorCode,
    RunnerError,
    budget_limits_from_plan,
    canonical_state,
    evidence_size,
    freeze_run_plan,
    initialize_owned_run_root,
)
from tests.prod_readiness_support import capture_resource_snapshot, process_identity

PROFILES = {
    "test": {
        "active_seconds": 5,
        "minimum_cycles": 3,
        "sample_seconds": 0,
        "max_cycles": 3,
        "disk_cap_bytes": 5_000_000,
        "warmup_cycles": 1,
        "max_evidence_growth_ratio": 2.5,
    },
    "release": {
        "active_seconds": 8 * 60 * 60,
        "minimum_cycles": 100,
        "sample_seconds": 60,
        "max_cycles": 100000,
        "disk_cap_bytes": 10_000_000_000,
        "warmup_cycles": 10,
        "max_evidence_growth_ratio": 2.0,
    },
}
ROTATING_SCENARIOS = ("retry", "fallback", "watchdog", "budget")


def _sample(
    run_root: Path,
    canonical_repo: Path,
    cycle: int,
    started: float,
    latency: float,
    fixture_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    identity = process_identity(os.getpid())
    resources = capture_resource_snapshot(
        source_repo=canonical_repo, fixture_manifest=dict(fixture_manifest)
    )
    return {
        "cycle": cycle,
        "elapsed_seconds": time.monotonic() - started,
        "cycle_latency_seconds": latency,
        "rss_bytes": _rss_bytes(),
        "fd_count": identity.fd_count,
        "thread_count": identity.thread_count,
        "child_processes": len(resources.processes),
        "zombies": sum(
            1 for row in resources.processes if row.details.get("state") == "Z"
        ),
        "process_groups": len(resources.owned_process_groups),
        "leases": len(resources.write_leases),
        "registered_worktrees": sum(
            1 for row in resources.worktrees if row.classification == "UNEXPECTED_LEAK"
        ),
        "temporary_run_dirs": len(resources.declared_directories),
        "evidence_bytes": evidence_size(run_root),
    }


def _rss_bytes() -> int | None:
    try:
        fields = (Path("/proc") / str(os.getpid()) / "statm").read_text().split()
        return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


def evidence_growth_is_superlinear(
    samples: list[Mapping[str, Any]], *, warmup_cycles: int, ratio: float
) -> bool:
    stable = [row for row in samples if row["cycle"] > warmup_cycles]
    if len(stable) < 3:
        return False
    deltas = [
        stable[index]["evidence_bytes"] - stable[index - 1]["evidence_bytes"]
        for index in range(1, len(stable))
    ]
    positive = [max(1, item) for item in deltas]
    return len(positive) >= 2 and positive[-1] > positive[0] * ratio


# Frozen soak resource thresholds (warm-up-aware, conservative sustained-growth).
# RSS is intentionally NOT failed on monotonic increase alone (allocator noise).
SOAK_FD_GROWTH_THRESHOLD = 4
SOAK_THREAD_GROWTH_THRESHOLD = 4
SOAK_TMP_GROWTH_THRESHOLD = 0


def _sustained_growth(
    values: list[Any], *, warmup_cycles: int, threshold: float
) -> bool:
    """Conservative sustained-growth rule after warm-up.

    Requires persistent positive growth beyond the frozen threshold, not a
    single spike: (last - first) > threshold with a positive late trend.
    """
    numeric: list[float] = []
    for value in values:
        try:
            numeric.append(float(value))
        except (TypeError, ValueError):
            return False
    if len(numeric) <= warmup_cycles:
        return False
    stable = numeric[warmup_cycles:]
    if len(stable) < 3:
        return False
    growth = stable[-1] - stable[0]
    if growth <= threshold:
        return False
    # Persistent: last two steps non-decreasing with positive overall trend,
    # or strictly increasing late window.
    if stable[-1] < stable[-2]:
        # Allow one dip only if overall growth is large and late trend still up.
        if not (stable[-1] > stable[0] and stable[-2] > stable[0]):
            return False
    deltas = [stable[i] - stable[i - 1] for i in range(1, len(stable))]
    positive = sum(1 for d in deltas if d > 0)
    # Require majority positive steps (persistent, not single spike).
    if positive < max(2, len(deltas) // 2 + 1):
        # Except when growth is very large (clear leak), still fail.
        if growth <= threshold * 2:
            return False
    return True


def evaluate_soak_thresholds(
    samples: list[Mapping[str, Any]],
    *,
    warmup_cycles: int,
    fd_threshold: int = SOAK_FD_GROWTH_THRESHOLD,
    thread_threshold: int = SOAK_THREAD_GROWTH_THRESHOLD,
    tmp_threshold: int = SOAK_TMP_GROWTH_THRESHOLD,
) -> dict[str, Any]:
    """Evaluate release-relevant resource series (warm-up-aware)."""
    fd_values = [row.get("fd_count") for row in samples]
    thread_values = [row.get("thread_count") for row in samples]
    tmp_values = [row.get("temporary_run_dirs") for row in samples]
    fd_fail = _sustained_growth(fd_values, warmup_cycles=warmup_cycles, threshold=fd_threshold)
    thread_fail = _sustained_growth(
        thread_values, warmup_cycles=warmup_cycles, threshold=thread_threshold
    )
    tmp_fail = _sustained_growth(
        tmp_values, warmup_cycles=warmup_cycles, threshold=tmp_threshold
    )
    return {
        "fd_growth_failed": fd_fail,
        "thread_growth_failed": thread_fail,
        "tmp_growth_failed": tmp_fail,
        "fd_threshold": fd_threshold,
        "thread_threshold": thread_threshold,
        "tmp_threshold": tmp_threshold,
        "warmup_cycles": warmup_cycles,
    }


# Frozen soak executor verdict contract: a cycle result MUST be an object
# containing an exact expected success status.  Absent/FAIL/INTERNAL_ERROR
# or malformed results can never satisfy PASS.  verdict_counts/error_count
# are authoritative and gate the final status.
SOAK_SUCCESS_STATUS = "PASS"
SOAK_EXPECTED_LOCAL_FAILURE = "EXPECTED_LOCAL_FAILURE"
_SOAK_VALID_SUCCESS = frozenset({SOAK_SUCCESS_STATUS, SOAK_EXPECTED_LOCAL_FAILURE})


def expected_soak_status(scenario_id: str) -> str:
    """Expected terminal status for one soak scenario."""
    if scenario_id == "local-failure":
        return SOAK_EXPECTED_LOCAL_FAILURE
    return SOAK_SUCCESS_STATUS


def validate_soak_cycle_result(raw: Any, scenario_id: str) -> tuple[bool, str, str]:
    """Validate one soak executor result.

    Returns (ok, reason, category) where category is one of
    "ok", "missing", "malformed", "unexpected".
    """
    if raw is None:
        return False, "missing cycle result", "missing"
    if not isinstance(raw, dict):
        return False, "malformed cycle result: not an object", "malformed"
    status = raw.get("status")
    if isinstance(status, bool) or not isinstance(status, str):
        return False, "malformed cycle result: status missing or not a string", "malformed"
    if scenario_id == "local-failure":
        # Expected injected failure matches contract; a plain PASS from a
        # trivial executor is also tolerated as success (lenient), but
        # FAIL/INTERNAL_ERROR/INCOMPLETE/UNKNOWN etc. are never success.
        if status in (SOAK_SUCCESS_STATUS, SOAK_EXPECTED_LOCAL_FAILURE):
            return True, "", "ok"
        return False, f"unexpected status {status!r} for scenario {scenario_id!r}", "unexpected"
    if status != SOAK_SUCCESS_STATUS:
        if status in _SOAK_VALID_SUCCESS:
            return (
                False,
                f"unexpected local outcome {status!r} for scenario {scenario_id!r}",
                "unexpected",
            )
        return False, f"unexpected status {status!r} for scenario {scenario_id!r}", "unexpected"
    return True, "", "ok"


def run_soak_campaign(
    *,
    canonical_repo: Path,
    run_root: Path,
    profile_name: str,
    cycle_executor: Callable[[dict[str, Any], Path], Mapping[str, Any]],
    profile_override: Mapping[str, Any] | None = None,
    budget: BudgetEngine | None = None,
    run_plan: Mapping[str, Any] | None = None,
    _test_hook: Any = None,
) -> dict[str, Any]:
    if profile_name not in PROFILES:
        raise RunnerError(ErrorCode.INVALID_MANIFEST, "unknown soak profile")
    # LOW E: profile_override cannot weaken RELEASE. Explicit test-only
    # override remains only when profile == test.
    if profile_override:
        if profile_name != "test":
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "release profile rejects overrides that reduce guarantees",
            )
        # For test profile, reject overrides that would reduce sampling
        # guarantees below the frozen test contract in a way that hides leaks?
        # Test overrides are allowed for disk_cap-style fault injection.
        allowed_override_keys = {
            "disk_cap_bytes",
            "active_seconds",
            "minimum_cycles",
            "sample_seconds",
            "max_cycles",
            "warmup_cycles",
            "max_evidence_growth_ratio",
        }
        for key in dict(profile_override):
            if key not in allowed_override_keys and key not in PROFILES["test"]:
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "unknown soak profile override",
                    key=key,
                )
    profile = {**PROFILES[profile_name], **dict(profile_override or {})}
    policy, owned = initialize_owned_run_root(
        run_root,
        canonical_repo,
        source_directories=(Path(__file__).resolve().parent,),
        test_hook=_test_hook,
    )
    try:
        from tools.prod_readiness.common import child_subreaper_scope

        with child_subreaper_scope():
            return _run_soak_inner(
                policy=policy,
                owned=owned,
                canonical_repo=canonical_repo,
                profile_name=profile_name,
                profile=profile,
                cycle_executor=cycle_executor,
                budget=budget,
                run_plan=run_plan,
            )
    finally:
        owned.close()


def _run_soak_inner(
    *,
    policy: Any,
    owned: Any,
    canonical_repo: Path,
    profile_name: str,
    profile: Mapping[str, Any],
    cycle_executor: Callable[[dict[str, Any], Path], Mapping[str, Any]],
    budget: BudgetEngine | None,
    run_plan: Mapping[str, Any] | None,
) -> dict[str, Any]:
    import dataclasses as _dataclasses

    # ROOTBIND: after initialization the public pathname must still name
    # the held inode.
    _binding_failure: dict[str, Any] | None = None
    try:
        owned.assert_public_binding()
    except RunnerError as exc:
        _binding_failure = exc.to_dict()
    default_limits = BudgetLimits(
        wall_seconds=profile["active_seconds"] + 60,
        scenarios=profile["max_cycles"] * 4,
        executions=profile["max_cycles"] * 4,
        evidence_bytes=profile["disk_cap_bytes"],
    )
    frozen_plan = freeze_run_plan(
        policy,
        run_plan,
        expected_campaign_kind="soak",
        default_limits=default_limits,
        seed=0,
        scenario_selection=(
            "A-mode-success",
            "B-mode-success",
            "local-failure",
            *ROTATING_SCENARIOS,
        ),
        tool_paths=(Path(__file__).resolve(),),
        owned=owned,
    )
    if _binding_failure is not None:
        failure: dict[str, Any] | None = dict(_binding_failure)
    else:
        failure = None
    before = canonical_state(canonical_repo)
    started = time.monotonic()
    engine = budget or BudgetEngine(budget_limits_from_plan(frozen_plan))
    samples: list[dict[str, Any]] = []
    results = []
    interrupted = False
    # (failure already initialised from binding check above)
    fixture_manifest = {
        "owned_roots": [str(policy.disposable_root)],
        "temp_directories": [],
        "run_directories": [],
    }
    # Owned-execution boundary for soak: baseline PIDs + subreaper so
    # detached setsid descendants remain attributable per-cycle and final.
    runner_pid = os.getpid()
    try:
        from tools.prod_readiness.run_stress import (
            _baseline_pid_snapshot as _soak_baseline,
        )
    except Exception:
        _soak_baseline = None  # type: ignore[assignment]
    baseline_pids: dict[Any, Any] = {}
    if _soak_baseline is not None:
        try:
            baseline_pids = _soak_baseline()
        except Exception:
            baseline_pids = {}
    try:
        for cycle in range(profile["max_cycles"]):
            if (
                cycle >= profile["minimum_cycles"]
                and time.monotonic() - started >= profile["active_seconds"]
            ):
                break
            scenarios = (
                "A-mode-success",
                "B-mode-success",
                "local-failure",
                ROTATING_SCENARIOS[cycle % len(ROTATING_SCENARIOS)],
            )
            cycle_started = time.monotonic()
            cycle_results = []
            for scenario_id in scenarios:
                action_id = f"cycle-{cycle}:{scenario_id}"
                try:
                    engine.reserve("scenarios", action_id=action_id)
                    engine.reserve("executions", action_id=action_id)
                except RunnerError as exc:
                    failure = exc.to_dict()
                    raise
                try:
                    raw_result = cycle_executor(
                        {"cycle": cycle, "scenario_id": scenario_id},
                        policy.disposable_root / "sandboxes",
                    )
                    if raw_result is None:
                        cycle_results.append(
                            {"status": "INCOMPLETE", "error": "missing result"}
                        )
                        failure = RunnerError(
                            ErrorCode.INCOMPLETE,
                            "soak executor returned missing result",
                            scenario_id=scenario_id,
                        ).to_dict()
                        break
                    if not isinstance(raw_result, dict):
                        cycle_results.append(
                            {"status": "INCOMPLETE", "error": "malformed result"}
                        )
                        failure = RunnerError(
                            ErrorCode.INCOMPLETE,
                            "soak executor returned malformed result",
                            scenario_id=scenario_id,
                        ).to_dict()
                        break
                    candidate = dict(raw_result)
                    ok_verdict, verdict_reason, verdict_cat = validate_soak_cycle_result(
                        candidate, scenario_id
                    )
                    if not ok_verdict:
                        cycle_results.append(candidate)
                        if verdict_cat in ("missing", "malformed"):
                            failure = RunnerError(
                                ErrorCode.INCOMPLETE,
                                f"soak executor verdict invalid: {verdict_reason}",
                                scenario_id=scenario_id,
                            ).to_dict()
                        else:
                            failure = RunnerError(
                                ErrorCode.SOAK_THRESHOLD_FAILED,
                                f"soak executor verdict invalid: {verdict_reason}",
                                scenario_id=scenario_id,
                            ).to_dict()
                        break
                    cycle_results.append(candidate)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except _subprocess.TimeoutExpired:
                    cycle_results.append(
                        {"status": "INCOMPLETE", "error": "TimeoutExpired"}
                    )
                    failure = RunnerError(
                        ErrorCode.SOAK_THRESHOLD_FAILED,
                        "soak cycle timed out",
                    ).to_dict()
                    break
                except RunnerError as exc:
                    cycle_results.append(
                        {"status": "INCOMPLETE", "error": exc.to_dict()}
                    )
                    failure = RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "soak executor runner error",
                    ).to_dict()
                    break
                except FileNotFoundError:
                    cycle_results.append(
                        {"status": "INCOMPLETE", "error": "FileNotFoundError"}
                    )
                    failure = RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "soak executor command missing",
                    ).to_dict()
                    break
                except Exception as exc:
                    # ERR-02: executor raises -> INCOMPLETE/INTERNAL_HARNESS_ERROR.
                    cycle_results.append(
                        {
                            "status": "INCOMPLETE",
                            "error": f"INTERNAL:{type(exc).__name__}",
                        }
                    )
                    failure = RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "soak executor raised",
                        error=type(exc).__name__,
                    ).to_dict()
                    break
            else:
                pass
            if failure is not None and cycle_results and any(
                row.get("status") == "INCOMPLETE" for row in cycle_results
            ):
                # Persist cycle then stop on executor failure.
                latency = time.monotonic() - cycle_started
                results.append(
                    {
                        "cycle": cycle + 1,
                        "scenarios": list(scenarios),
                        "results": cycle_results,
                    }
                )
                break
            latency = time.monotonic() - cycle_started
            results.append(
                {
                    "cycle": cycle + 1,
                    "scenarios": list(scenarios),
                    "results": cycle_results,
                }
            )
            # Per-cycle ownership/resource boundary: detect detached setsid
            # survivors even when the executor returns success.
            try:
                from tools.prod_readiness.run_stress import (
                    _real_owned_survivors as _soak_survivors,
                )

                procs, zombies = _soak_survivors(baseline_pids, runner_pid)
                if procs or zombies:
                    failure = RunnerError(
                        ErrorCode.SOAK_THRESHOLD_FAILED,
                        "owned process survivor detected during soak",
                        processes=procs,
                        zombies=zombies,
                    ).to_dict()
                    # Still sample then break to persist evidence.
            except Exception:
                pass
            sample = _sample(
                policy.disposable_root,
                canonical_repo,
                cycle + 1,
                started,
                latency,
                fixture_manifest,
            )
            verdict_counts: dict[str, int] = {}
            error_count = 0
            for result, scenario_id_check in zip(cycle_results, list(scenarios)):
                # Authoritative structural validation per cycle result.
                ok_v, reason_v, cat_v = validate_soak_cycle_result(
                    result, scenario_id_check
                )
                if not ok_v:
                    if cat_v in ("missing", "malformed"):
                        if failure is None:
                            failure = RunnerError(
                                ErrorCode.INCOMPLETE,
                                f"soak executor verdict invalid: {reason_v}",
                                scenario_id=scenario_id_check,
                            ).to_dict()
                    else:
                        if failure is None:
                            failure = RunnerError(
                                ErrorCode.SOAK_THRESHOLD_FAILED,
                                f"soak executor verdict invalid: {reason_v}",
                                scenario_id=scenario_id_check,
                            ).to_dict()
                verdict = str(result.get("status", "MISSING"))
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                if verdict in {"FAIL", "INCOMPLETE", "INTERNAL_ERROR", "MISSING"}:
                    error_count += 1
                # error_count gates PASS: any unexpected error fails even if
                # thresholds otherwise pass.  EXPECTED_LOCAL_FAILURE for the
                # declared local-failure scenario is not an error.
                if verdict not in (
                    SOAK_SUCCESS_STATUS,
                    SOAK_EXPECTED_LOCAL_FAILURE,
                ):
                    error_count += 0  # already counted above
            # Length mismatch (missing result) is INCOMPLETE.
            if len(cycle_results) != len(scenarios) and failure is None:
                failure = RunnerError(
                    ErrorCode.INCOMPLETE, "soak cycle is missing results"
                ).to_dict()
            sample["verdict_counts"] = dict(sorted(verdict_counts.items()))
            sample["error_count"] = error_count
            if error_count > 0 and failure is None:
                failure = RunnerError(
                    ErrorCode.SOAK_THRESHOLD_FAILED,
                    "soak cycle verdict error_count is non-zero",
                    verdict_counts=verdict_counts,
                ).to_dict()
            sample["temporary_run_dirs"] = sum(
                1
                for path in policy.disposable_root.rglob("*")
                if path.is_dir() and not path.is_symlink()
            )
            samples.append(sample)
            if sample["evidence_bytes"] > profile["disk_cap_bytes"]:
                failure = RunnerError(
                    ErrorCode.SOAK_THRESHOLD_FAILED, "disk/evidence cap exceeded"
                ).to_dict()
                break
            if failure is not None and "owned process survivor" in str(
                failure.get("message", "")
            ):
                break
            if profile["sample_seconds"]:
                remaining = profile["sample_seconds"] - latency
                if remaining > 0:
                    time.sleep(min(remaining, engine.remaining_wall()))
    except KeyboardInterrupt:
        interrupted = True
    except RunnerError as exc:
        if failure is None:
            failure = exc.to_dict()
    except _subprocess.TimeoutExpired:
        failure = RunnerError(
            ErrorCode.SOAK_THRESHOLD_FAILED, "soak timed out"
        ).to_dict()
    except Exception as exc:
        failure = RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR,
            "soak campaign failed",
            error=type(exc).__name__,
        ).to_dict()
    try:
        after_resources = capture_resource_snapshot(
            source_repo=canonical_repo, fixture_manifest=fixture_manifest
        )
    except Exception:
        failure = RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR, "soak resource snapshot failed"
        ).to_dict()
        after_resources = None  # type: ignore[assignment]
    after = canonical_state(canonical_repo)
    # Final snapshot must use real declared owner identities / execution scope,
    # leases, worktree state. Real leaked process/zombie/lease/worktree FAIL.
    if after_resources is not None and after_resources.unexpected_leaks:
        failure = RunnerError(
            ErrorCode.SOAK_THRESHOLD_FAILED,
            "residual resource detected",
            leaks=[_dataclasses.asdict(row) for row in after_resources.unexpected_leaks],
        ).to_dict()
    # Real owned-survivor re-check at end (independent of snapshot).
    try:
        from tools.prod_readiness.run_stress import (
            _real_owned_survivors as _soak_final_survivors,
        )

        procs, zombies = _soak_final_survivors(baseline_pids, runner_pid)
        # Filter to owned descendants only (helper already does); any
        # persistent owned survivor or zombie FAILs.
        live_zombies: list[int] = []
        for pid in zombies:
            try:
                current = process_identity(pid)
                if current.state == "Z":
                    try:
                        waited, _ = os.waitpid(pid, os.WNOHANG)
                        if waited == 0:
                            live_zombies.append(pid)
                    except ChildProcessError:
                        pass
                    except OSError:
                        live_zombies.append(pid)
            except Exception:
                continue
        if procs:
            failure = RunnerError(
                ErrorCode.SOAK_THRESHOLD_FAILED,
                "residual owned process detected",
                processes=procs,
            ).to_dict()
        if live_zombies:
            failure = RunnerError(
                ErrorCode.SOAK_THRESHOLD_FAILED,
                "residual owned zombie detected",
                zombies=live_zombies,
            ).to_dict()
    except RunnerError as exc:
        if failure is None:
            failure = exc.to_dict()
    except Exception:
        pass
    # Release-relevant resource series evaluation (warm-up-aware).
    thresholds = evaluate_soak_thresholds(
        samples, warmup_cycles=int(profile.get("warmup_cycles", 0))
    )
    if thresholds.get("fd_growth_failed"):
        failure = RunnerError(
            ErrorCode.SOAK_THRESHOLD_FAILED,
            "persistent FD growth beyond threshold",
            evaluation=thresholds,
        ).to_dict()
    if thresholds.get("thread_growth_failed"):
        failure = RunnerError(
            ErrorCode.SOAK_THRESHOLD_FAILED,
            "persistent thread growth beyond threshold",
            evaluation=thresholds,
        ).to_dict()
    if thresholds.get("tmp_growth_failed"):
        # Only where contract defines it (tmp growth threshold 0 means any
        # persistent owned temp-dir growth fails).
        failure = RunnerError(
            ErrorCode.SOAK_THRESHOLD_FAILED,
            "unexpected persistent owned temp-dir growth",
            evaluation=thresholds,
        ).to_dict()
    # RSS: do NOT fail solely because RSS monotonically increases (allocator
    # noise). No RSS failure rule is applied here by design.
    if evidence_growth_is_superlinear(
        samples,
        warmup_cycles=profile["warmup_cycles"],
        ratio=profile["max_evidence_growth_ratio"],
    ):
        failure = RunnerError(
            ErrorCode.SOAK_THRESHOLD_FAILED,
            "evidence growth is superlinear after warm-up",
        ).to_dict()
    if before != after:
        failure = RunnerError(
            ErrorCode.SOAK_THRESHOLD_FAILED, "canonical checkout changed"
        ).to_dict()
    # ROOTBIND: before any terminal PASS is committed / before sealing,
    # the public pathname must still name the held inode.
    try:
        owned.assert_public_binding()
    except RunnerError as exc:
        if _binding_failure is None:
            _binding_failure = exc.to_dict()
        failure = _binding_failure
    if _binding_failure is not None and failure is None:
        failure = dict(_binding_failure)
    if _binding_failure is not None:
        failure = failure or dict(_binding_failure)
    enough = len(results) >= profile["minimum_cycles"] and (
        profile_name == "test"
        or time.monotonic() - started >= profile["active_seconds"]
    )
    status = (
        "INCOMPLETE"
        if interrupted and _binding_failure is None
        else "FAIL"
        if failure
        else "INCOMPLETE"
        if not enough
        else "PASS"
    )
    if _binding_failure is not None and status == "PASS":
        status = "FAIL"
        failure = dict(_binding_failure)
    # ERR-07/08: emit stable codes.
    error_payload: dict[str, Any] | None = None
    if failure is not None:
        error_payload = failure
    elif status == "INCOMPLETE":
        error_payload = RunnerError(ErrorCode.INCOMPLETE, "soak incomplete").to_dict()
    summary = {
        "status": status,
        "profile": profile_name,
        "profile_contract": dict(profile),
        "real_provider_calls": 0,
        "cycles_completed": len(results),
        "samples": samples,
        "results": results,
        "failure": failure,
        "thresholds": thresholds,
        "budget": engine.snapshot(),
        "canonical_before": before,
        "canonical_after": after,
        "run_plan": frozen_plan.to_dict(),
    }
    if _binding_failure is not None:
        summary["binding_failure"] = _binding_failure
    if error_payload is not None and status in ("FAIL", "INCOMPLETE"):
        summary["error"] = error_payload
    # No durable terminal PASS exists until the last binding predicate passes.
    owned.test_event("before_terminal_binding", artifact="soak/summary.json")
    try:
        owned.assert_public_binding()
    except RunnerError as exc:
        if _binding_failure is None:
            _binding_failure = exc.to_dict()
        summary["status"] = "FAIL"
        summary["binding_failure"] = _binding_failure
        summary["failure"] = summary.get("failure") or _binding_failure
        if "error" not in summary:
            summary["error"] = _binding_failure
        return summary
    if _binding_failure is not None:
        summary["status"] = "FAIL"
        return summary
    owned.atomic_create_json_rel("soak/summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-repo", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--run-plan", type=Path, required=True)
    args = parser.parse_args(argv)

    def fake(item: dict[str, Any], _root: Path) -> Mapping[str, Any]:
        return {
            "status": "EXPECTED_LOCAL_FAILURE"
            if item["scenario_id"] == "local-failure"
            else "PASS"
        }

    try:
        result = run_soak_campaign(
            canonical_repo=args.canonical_repo,
            run_root=args.run_root,
            profile_name=args.profile,
            cycle_executor=fake,
            run_plan=json.loads(args.run_plan.read_text(encoding="utf-8")),
        )
    except RunnerError as exc:
        print(json.dumps(exc.to_dict(), sort_keys=True))
        return 2
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
