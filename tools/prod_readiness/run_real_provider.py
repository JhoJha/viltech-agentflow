#!/usr/bin/env python3
"""Explicitly armed, hard-budgeted real-provider E2E campaign runner."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

import subprocess as _subprocess

from tools.prod_readiness.common import (
    BudgetEngine,
    BudgetLimits,
    ErrorCode,
    RunnerError,
    budget_limits_from_plan,
    canonical_state,
    collect_known_secrets,
    command_hash,
    freeze_run_plan,
    initialize_owned_run_root,
    load_json,
    redact_argv,
    redact_text,
    redacted_environment_metadata,
    run_owned_command,
)

ARM_ENV = "AGENTFLOW_ALLOW_REAL_PROVIDER_E2E"
PROVIDER_LIMITS = BudgetLimits(
    wall_seconds=60 * 60,
    scenarios=24,
    executions=24,
    provider_calls=24,
    retries=1,
    fallbacks=1,
    corrections=1,
    evidence_bytes=100_000_000,
)
CAPABILITIES = (
    "normal_execution",
    "structured_output",
    "stdout_stderr_capture",
    "lifecycle_quiescence",
    "provenance",
    "A_mode",
    "B_mode",
    "queue",
    "watchdog",
    "timeout",
    "transient_network",
    "rate_limited",
    "temporarily_unavailable",
    "quota_exhausted",
    "auth_configuration",
    "model_unavailable",
    "retry",
    "fallback",
)
SUPPORT_LEVELS = {"SUPPORTED", "UNSUPPORTED", "DEFERRED"}
FORBIDDEN_COMMANDS = re.compile(
    r"(?:^|\s)(?:git\s+(?:push|merge)|(?:kubectl|helm)\s|deploy(?:ment)?\s)",
    re.IGNORECASE,
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Narrow execution contract: real-provider runner launches ONLY an explicitly
# approved provider executable in direct argv mode (shell=False). No
# shell/interpreter wrapper. This audit constrains the launcher; it is NOT a
# general sandbox for model-generated subprocesses. Canonical integrity and
# disposable-repo isolation remain independent guards.
_REJECTED_LAUNCHER_BASENAMES = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "fish",
        "cmd",
        "powershell",
        "pwsh",
        "git",
        "gh",
        "kubectl",
        "helm",
        "terraform",
        "docker",
        "curl",
        "wget",
    }
)
# Static provider adapter contract: only these basenames may be launched in
# real mode. A future separately approved adapter must explicitly extend this
# set; arbitrary vectors from an untrusted plan are never accepted.
APPROVED_REAL_PROVIDER_EXECUTABLES = frozenset(
    {
        "agentflow-real-provider",
    }
)
# Fake provider test executable is enabled ONLY in explicit test mode
# (backend_kind == "fake" with test allowlist). Real mode never allows it.
FAKE_TEST_EXECUTABLE_BASENAMES = frozenset(
    {
        "python",
        "python3",
    }
)


def require_arming(enable_real_provider: bool, environment: Mapping[str, str]) -> None:
    if enable_real_provider is not True or environment.get(ARM_ENV) != "1":
        raise RunnerError(
            ErrorCode.REAL_PROVIDER_NOT_ARMED,
            "both CLI enablement and exact environment acknowledgement are required",
        )


def _executable_basename(executable: str) -> str:
    # Handle sys.executable absolute paths and plain basenames.
    name = Path(executable).name
    # Strip version suffixes like python3.11 -> python3 for allowlist check,
    # but keep exact matching strict: only known basenames pass.
    return name


def audit_command(
    command: Sequence[str],
    *,
    backend_kind: str = "real",
    test_mode: bool = False,
) -> None:
    """Narrow provider launcher trust boundary (direct argv, shell=False).

    - Rejects outer launcher basenames (sh/bash/git/gh/kubectl/...).
    - Rejects forbidden publication/deployment patterns.
    - Fake test executable allowed ONLY when backend_kind == "fake" and
      test_mode is explicitly enabled.
    - Real mode requires the executable basename to match the static
      provider adapter contract (APPROVED_REAL_PROVIDER_EXECUTABLES).
    """
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "provider command must be a non-empty argv array",
        )
    executable = command[0]
    basename = _executable_basename(executable).lower()
    if basename in _REJECTED_LAUNCHER_BASENAMES:
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET,
            "outer launcher executable is not an approved provider executable; "
            "command audit constrains the launcher and is NOT a general sandbox",
            executable=executable,
        )
    rendered = " ".join(command)
    if FORBIDDEN_COMMANDS.search(rendered):
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET,
            "forbidden publication or deployment command",
            command="[REDACTED]",
        )
    # Additional explicit refusals for publication/deployment tools invoked
    # with any subcommand (git push, gh pr merge, docker push, terraform, etc).
    lowered = rendered.lower()
    for pattern in (
        "git push",
        "git merge",
        "gh pr merge",
        "gh pr create",
        "docker push",
        "terraform apply",
        "terraform destroy",
        "kubectl apply",
        "kubectl delete",
        "helm install",
        "helm upgrade",
    ):
        if pattern in lowered:
            raise RunnerError(
                ErrorCode.UNSAFE_TARGET,
                "forbidden publication or deployment command",
                pattern=pattern,
            )
    # Shell wrapper detection: refuse sh -c / bash -lc style for shell
    # launchers (absolute-path shells resolve to the same rejected basenames
    # above). Python `-c` for the approved fake test executable is allowed
    # only in explicit fake test mode (handled below).
    if len(command) >= 2 and command[1] in ("-c", "-lc", "/c"):
        if basename in _REJECTED_LAUNCHER_BASENAMES or basename in (
            "sh",
            "bash",
            "zsh",
            "fish",
            "cmd",
            "powershell",
            "pwsh",
        ):
            raise RunnerError(
                ErrorCode.UNSAFE_TARGET,
                "shell wrapper commands are forbidden; direct argv only",
            )
        # For non-shell executables, -c is allowed only for the fake test
        # interpreter; real mode still requires the static adapter contract.
        if backend_kind != "fake" and basename not in APPROVED_REAL_PROVIDER_EXECUTABLES:
            # Defer to the real-mode allowlist check below, but explicitly
            # refuse shell-style indirection for unknown launchers.
            if basename in ("sh", "bash", "zsh", "fish"):
                raise RunnerError(
                    ErrorCode.UNSAFE_TARGET,
                    "shell wrapper commands are forbidden; direct argv only",
                )
    if backend_kind == "fake":
        if not test_mode:
            raise RunnerError(
                ErrorCode.UNSAFE_TARGET,
                "fake provider executable requires explicit test mode",
            )
        import sys as _sys

        allowed = set(FAKE_TEST_EXECUTABLE_BASENAMES)
        # Allow the exact current interpreter (fake deterministic CLI).
        current_base = _executable_basename(_sys.executable).lower()
        allowed.add(current_base)
        if basename not in allowed and executable != _sys.executable:
            raise RunnerError(
                ErrorCode.UNSAFE_TARGET,
                "fake backend allows only the approved fake test executable",
                executable=executable,
            )
        return
    # Real mode: must match static adapter contract.
    if basename not in APPROVED_REAL_PROVIDER_EXECUTABLES:
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET,
            "unknown real provider executable; must match static adapter contract",
            executable=executable,
        )


def assert_disposable_remote_safe(repo: Path) -> None:
    """Disposable-repository remote safety for real-provider mode.

    The target repo must be disposable and must not configure any Git remote
    capable of publication. GitHub/remote credentials must not be inherited
    unless explicitly required; deployment credentials must never be exposed.
    Provider prompt/config must prohibit publication/deployment (enforced by
    audit_command above; this guard covers repository state).
    """
    try:
        process = __import__("subprocess").run(
            ["git", "-C", str(repo), "remote", "-v"],
            stdin=__import__("subprocess").DEVNULL,
            stdout=__import__("subprocess").PIPE,
            stderr=__import__("subprocess").PIPE,
            text=True,
            check=False,
        )
    except Exception as exc:
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET, "disposable remote inspection failed"
        ) from exc
    if process.returncode != 0:
        # No git repo or inspection failed -> fail closed for real mode.
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET,
            "disposable repository remote state cannot be proven safe",
            stderr=process.stderr[:500],
        )
    remotes = process.stdout.strip()
    if remotes:
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET,
            "disposable repository must not configure publication-capable remotes",
        )


def launch_provider_process(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
):
    """Single physical provider-launch seam used by fake-safe tests."""
    return run_owned_command(
        command, cwd=cwd, environment=environment, timeout=timeout
    )


def validate_support_matrix(matrix: Mapping[str, Any]) -> None:
    providers = matrix.get("providers")
    if not isinstance(providers, list):
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST, "provider matrix requires providers"
        )
    for provider in providers:
        if (
            not isinstance(provider, dict)
            or not isinstance(provider.get("provider_id"), str)
            or not isinstance(provider.get("capabilities"), dict)
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "malformed provider matrix entry"
            )
        for capability in CAPABILITIES:
            row = provider["capabilities"].get(capability)
            # LOW B: bool is not evidence_level (True == 1 in Python).
            # Require type(value) is int for 1/2/3; reject True/False.
            _ev = row.get("evidence_level") if isinstance(row, dict) else None
            if isinstance(_ev, bool):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "malformed capability evidence: bool is not evidence_level",
                    capability=capability,
                )
            if (
                not isinstance(row, dict)
                or row.get("status") not in SUPPORT_LEVELS
                or _ev not in {1, 2, 3, None}
            ):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "malformed capability evidence",
                    capability=capability,
                )
            if (
                row["status"] == "SUPPORTED"
                and capability == "normal_execution"
                and row.get("evidence_level") != 1
            ):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "normal execution support requires level-1 live evidence",
                )
            if (
                row["status"] == "SUPPORTED"
                and capability
                in {
                    "transient_network",
                    "rate_limited",
                    "temporarily_unavailable",
                    "quota_exhausted",
                    "auth_configuration",
                    "model_unavailable",
                    "retry",
                    "fallback",
                }
                and row.get("evidence_level") not in {1, 2}
            ):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "recovery support requires level-1 or level-2 evidence",
                    capability=capability,
                )


def _validate_provider_limits(limits: BudgetLimits) -> None:
    for field in (
        "wall_seconds",
        "provider_calls",
        "retries",
        "fallbacks",
        "corrections",
    ):
        if getattr(limits, field) > getattr(PROVIDER_LIMITS, field):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "provider plan exceeds a hard maximum",
                budget=field,
            )


def run_provider_matrix_campaign(
    *,
    canonical_repo: Path,
    run_root: Path,
    scenarios: Sequence[Mapping[str, Any]],
    enable_real_provider: bool,
    environment: Mapping[str, str],
    budget: BudgetEngine | None = None,
    run_plan: Mapping[str, Any] | None = None,
    _test_hook: Any = None,
) -> dict[str, Any]:
    """Execute an ordered real-provider matrix under one non-resetting ledger."""
    require_arming(enable_real_provider, environment)
    if not scenarios or len(scenarios) > PROVIDER_LIMITS.provider_calls:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST, "provider scenario count is invalid"
        )
    normalized = []
    for raw in scenarios:
        if not isinstance(raw, Mapping):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "provider scenario is malformed"
            )
        row = dict(raw)
        for field in ("provider_id", "scenario_id", "command"):
            if field not in row:
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "provider scenario field is missing",
                    field=field,
                )
        if not _SAFE_ID.fullmatch(str(row["provider_id"])) or not _SAFE_ID.fullmatch(
            str(row["scenario_id"])
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "provider or scenario ID is unsafe"
            )
        backend_kind = str(row.get("backend_kind", "real"))
        is_fake = backend_kind == "fake"
        audit_command(
            row["command"], backend_kind=backend_kind, test_mode=is_fake
        )
        timeout = row.get("timeout_seconds", 180)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 180
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "per-call timeout exceeds 180 seconds"
            )
        if row.get("attempt_kind", "primary") not in {
            "primary",
            "retry",
            "fallback",
            "correction",
        }:
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "unknown provider attempt kind"
            )
        normalized.append(row)
    policy, owned = initialize_owned_run_root(
        run_root,
        canonical_repo,
        source_directories=(Path(__file__).resolve().parent,),
        test_hook=_test_hook,
    )
    # ROOTBIND: after initialization the public pathname must still name
    # the held inode.
    _binding_failure: dict[str, Any] | None = None
    try:
        owned.assert_public_binding()
    except RunnerError as exc:
        _binding_failure = exc.to_dict()
    try:
        frozen_plan = freeze_run_plan(
            policy,
            run_plan,
            expected_campaign_kind="real-provider",
            default_limits=PROVIDER_LIMITS,
            seed=0,
            scenario_selection=tuple(row["scenario_id"] for row in normalized),
            tool_paths=(Path(__file__).resolve(),),
            owned=owned,
        )
        planned_limits = budget_limits_from_plan(frozen_plan)
        _validate_provider_limits(planned_limits)
        engine = budget or BudgetEngine(planned_limits)
        before = canonical_state(canonical_repo)
        known_secrets = collect_known_secrets(environment)
        results = []
        remote_safety_checks = 0
        for row in normalized:
            scenario_id = row["scenario_id"]
            attempt_kind = row.get("attempt_kind", "primary")
            backend_kind = str(row.get("backend_kind", "real"))
            try:
                engine.reserve("scenarios", action_id=scenario_id)
                engine.reserve("executions", action_id=scenario_id)
            except RunnerError:
                raise
            attempt_budget = {
                "primary": None,
                "retry": "retries",
                "fallback": "fallbacks",
                "correction": "corrections",
            }[attempt_kind]
            if attempt_budget is not None:
                engine.reserve(attempt_budget, action_id=scenario_id)
            reservation = engine.reserve("provider_calls", action_id=scenario_id)
            # Descriptor-anchored sandbox creation (no path-based fallback).
            owned.mkdir_rel(f"sandboxes/{scenario_id}")
            # Resolve sandbox path for subprocess cwd (read-only use; writes
            # remain descriptor-anchored). The cwd itself is not an
            # authoritative write.
            sandbox = policy.disposable_root / "sandboxes" / scenario_id
            owned.atomic_create_bytes_rel(
                f"sandboxes/{scenario_id}/README.md",
                b"# Disposable provider E2E fixture\n",
            )
            try:
                initialized = run_owned_command(
                    ["git", "init", "--quiet"], cwd=sandbox, timeout=30
                )
            except FileNotFoundError as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "disposable provider repository initialization failed",
                ) from exc
            except Exception as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "disposable provider repository initialization failed",
                ) from exc
            if initialized.returncode or not initialized.process_cleanup_verified:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "disposable provider repository initialization failed",
                )
            owned.test_event(
                "before_provider_remote_safety",
                sandbox=str(sandbox),
                backend_kind=backend_kind,
            )
            if backend_kind == "real":
                # Disposable remote safety: refuse publication-capable remotes.
                remote_safety_checks += 1
                try:
                    assert_disposable_remote_safe(sandbox)
                except RunnerError as exc:
                    result = {
                        "status": "FAIL",
                        "provider_id": row["provider_id"],
                        "backend_kind": backend_kind,
                        "attempt_kind": attempt_kind,
                        "scenario_id": scenario_id,
                        "redacted_command": ["[NOT-LAUNCHED]"],
                        "returncode": None,
                        "reservation": reservation,
                        "process_cleanup_verified": True,
                        "error": exc.to_dict(),
                    }
                    owned.atomic_create_json_rel(
                        f"providers/{scenario_id}/result.json", result
                    )
                    results.append(result)
                    continue
            try:
                process = launch_provider_process(
                    row["command"],
                    cwd=sandbox,
                    environment=environment,
                    timeout=min(
                        float(row.get("timeout_seconds", 180)), engine.remaining_wall()
                    ),
                )
            except FileNotFoundError as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "provider executable is missing",
                ) from exc
            except _subprocess.TimeoutExpired as exc:
                raise RunnerError(
                    ErrorCode.BUDGET_EXHAUSTED, "provider call timed out"
                ) from exc
            except RunnerError:
                raise
            except Exception as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "provider execution failed",
                    error=type(exc).__name__,
                ) from exc
            raw_command = list(row["command"])
            raw_hash = command_hash(raw_command)
            try:
                stdout = redact_text(process.stdout, known_secrets=known_secrets)
                stderr = redact_text(process.stderr, known_secrets=known_secrets)
                redacted_cmd = redact_argv(raw_command, known_secrets=known_secrets)
                redacted_env = redacted_environment_metadata(environment)
            except Exception as redaction_exc:
                # Redaction exception => campaign cannot PASS (fail closed).
                redacted_cmd = ["[REDACTED-FAILURE]"]
                redacted_env = {
                    str(key): "[REDACTED]" for key in sorted(environment, key=str)
                }
                stdout = ""
                error_code = (
                    ErrorCode.SECRET_REDACTION_FAILED
                    if isinstance(redaction_exc, RunnerError)
                    else ErrorCode.INTERNAL_HARNESS_ERROR
                )
                stderr = error_code.value
                returncode = None
                after_call = canonical_state(canonical_repo)
                result = {
                    "status": "FAIL",
                    "provider_id": row["provider_id"],
                    "backend_kind": backend_kind,
                    "attempt_kind": attempt_kind,
                    "scenario_id": scenario_id,
                    "redacted_command": redacted_cmd,
                    "command_sha256": raw_hash,
                    "returncode": returncode,
                    "stdout_ref": f"providers/{scenario_id}/stdout.txt",
                    "stderr_ref": f"providers/{scenario_id}/stderr.txt",
                    "environment": redacted_env,
                    "reservation": reservation,
                    "provenance": {
                        "provider_id": row["provider_id"],
                        "backend_kind": backend_kind,
                    },
                    "process_cleanup_verified": False,
                    "redaction_error": True,
                    "error": RunnerError(
                        error_code, "provider evidence redaction failed"
                    ).to_dict(),
                }
                # Persist minimal safe evidence (no raw secrets).
                try:
                    owned.atomic_create_bytes_rel(
                        f"providers/{scenario_id}/stdout.txt", stdout.encode("utf-8")
                    )
                    owned.atomic_create_bytes_rel(
                        f"providers/{scenario_id}/stderr.txt", stderr.encode("utf-8")
                    )
                    owned.atomic_create_json_rel(
                        f"providers/{scenario_id}/result.json", result
                    )
                except RunnerError:
                    pass
                results.append(result)
                continue
            returncode = None if process.timed_out else process.returncode
            for name, content in (("stdout.txt", stdout), ("stderr.txt", stderr)):
                owned.atomic_create_bytes_rel(
                    f"providers/{scenario_id}/{name}", content.encode("utf-8")
                )
            after_call = canonical_state(canonical_repo)
            result = {
                "status": "PASS"
                if returncode == 0
                and before == after_call
                and process.process_cleanup_verified
                else "FAIL",
                "provider_id": row["provider_id"],
                "backend_kind": backend_kind,
                "attempt_kind": attempt_kind,
                "scenario_id": scenario_id,
                "redacted_command": redacted_cmd,
                "command_sha256": raw_hash,
                "returncode": returncode,
                "stdout_ref": f"providers/{scenario_id}/stdout.txt",
                "stderr_ref": f"providers/{scenario_id}/stderr.txt",
                "environment": redacted_env,
                "reservation": reservation,
                "provenance": {
                    "provider_id": row["provider_id"],
                    "backend_kind": backend_kind,
                },
                "process_cleanup_verified": process.process_cleanup_verified,
            }
            owned.atomic_create_json_rel(
                f"providers/{scenario_id}/result.json", result
            )
            results.append(result)
        after = canonical_state(canonical_repo)
        # ROOTBIND: before any terminal PASS is committed / before sealing.
        try:
            owned.assert_public_binding()
        except RunnerError as exc:
            if _binding_failure is None:
                _binding_failure = exc.to_dict()
        if _binding_failure is not None:
            status = "FAIL"
        else:
            status = (
                "PASS"
                if before == after and all(row["status"] == "PASS" for row in results)
                else "FAIL"
            )
        if _binding_failure is not None:
            status = "FAIL"
        summary = {
            "status": status,
            "results": results,
            "budget": engine.snapshot(),
            "canonical_before": before,
            "canonical_after": after,
            "run_plan": frozen_plan.to_dict(),
            "remote_safety_checks": remote_safety_checks,
        }
        if _binding_failure is not None:
            summary["binding_failure"] = _binding_failure
            summary["error"] = _binding_failure
        owned.atomic_create_json_rel("providers/summary.json", summary)
        # ROOTBIND: after sealing completes and before returning PASS.
        try:
            owned.assert_public_binding()
        except RunnerError as exc:
            if _binding_failure is None:
                _binding_failure = exc.to_dict()
            summary["status"] = "FAIL"
            summary["binding_failure"] = _binding_failure
            summary["error"] = _binding_failure
            return summary
        if _binding_failure is not None:
            summary["status"] = "FAIL"
            return summary
        return summary
    finally:
        owned.close()


def run_provider_campaign(
    *,
    canonical_repo: Path,
    run_root: Path,
    command: Sequence[str],
    enable_real_provider: bool,
    environment: Mapping[str, str],
    provider_id: str,
    scenario_id: str,
    backend_kind: str = "real",
    attempt_kind: str = "primary",
    timeout_seconds: float = 180,
    budget: BudgetEngine | None = None,
    run_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    summary = run_provider_matrix_campaign(
        canonical_repo=canonical_repo,
        run_root=run_root,
        scenarios=(
            {
                "command": list(command),
                "provider_id": provider_id,
                "scenario_id": scenario_id,
                "backend_kind": backend_kind,
                "attempt_kind": attempt_kind,
                "timeout_seconds": timeout_seconds,
            },
        ),
        enable_real_provider=enable_real_provider,
        environment=environment,
        budget=budget,
        run_plan=run_plan,
    )
    return {
        **summary["results"][0],
        "budget": summary["budget"],
        "canonical_before": summary["canonical_before"],
        "canonical_after": summary["canonical_after"],
        "run_plan": summary["run_plan"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-repo", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--provider-id", required=True)
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--enable-real-provider", action="store_true")
    parser.add_argument("--run-plan", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        result = run_provider_campaign(
            canonical_repo=args.canonical_repo,
            run_root=args.run_root,
            command=args.command,
            enable_real_provider=args.enable_real_provider,
            environment=os.environ,
            provider_id=args.provider_id,
            scenario_id=args.scenario_id,
            run_plan=load_json(args.run_plan),
        )
    except RunnerError as exc:
        print(json.dumps(exc.to_dict(), sort_keys=True))
        return 2
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
