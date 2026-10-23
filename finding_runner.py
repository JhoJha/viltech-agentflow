"""Finding Pipeline Runner v0: durable coordinator for frozen findings."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import agentflow as af


FINDINGS_DIR = af.RUNS_DIR / "findings"
FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REQUIRED = {
    "finding_id", "repo", "baseline_commit", "risk", "objective", "evidence",
    "allowed_paths", "targeted_validators", "broader_validators", "roles", "max_corrections",
}
OPTIONAL = {"invariants"}
PHASES = ("PROGRAM_STARTED", "PROGRAM_VERIFIED", "BROAD_STARTED", "BROAD_PASSED",
          "CLOSURE_STARTED", "CLOSURE_PASSED", "HUMAN_GATE")


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _read_strict(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=_duplicate_reject)


def _hash_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _persist(path: Path, value: Any) -> None:
    af.atomic_json_fsync(path, value)


def _validate_validators(raw: Any, phase: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise af.AgentFlowError("INVALID_FINDING", f"{phase} must be a non-empty list")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) - {"name", "command", "timeout_seconds"}:
            raise af.AgentFlowError("INVALID_FINDING", f"{phase}[{index}] has invalid fields")
        name, command = item.get("name"), item.get("command")
        timeout = item.get("timeout_seconds", 1800)
        if not isinstance(name, str) or not name.strip() or name in names:
            raise af.AgentFlowError("INVALID_FINDING", f"{phase} validator names must be non-empty and unique")
        if not isinstance(command, list) or not command or any(not isinstance(part, str) or not part for part in command):
            raise af.AgentFlowError("INVALID_FINDING", f"{phase}[{index}].command must be a non-empty string list")
        if type(timeout) is not int or timeout <= 0:
            raise af.AgentFlowError("INVALID_FINDING", f"{phase}[{index}].timeout_seconds must be positive")
        af.safe_validator_argv(command)
        result.append({"name": name, "command": list(command), "timeout_seconds": timeout})
        names.add(name)
    return result


def validate_finding(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise af.AgentFlowError("INVALID_FINDING", "finding must be a JSON object")
    unknown, missing = set(raw) - REQUIRED - OPTIONAL, REQUIRED - set(raw)
    if unknown or missing:
        raise af.AgentFlowError("INVALID_FINDING", f"unknown={sorted(unknown)}, missing={sorted(missing)}")
    finding = dict(raw)
    fid = finding["finding_id"]
    if not isinstance(fid, str) or not FINDING_ID_RE.fullmatch(fid):
        raise af.AgentFlowError("INVALID_FINDING", "finding_id must be a slug-safe string of at most 64 characters")
    repo = finding["repo"]
    if not isinstance(repo, str) or not Path(repo).is_absolute() or not Path(repo).is_dir():
        raise af.AgentFlowError("INVALID_FINDING", "repo must be an absolute existing repository path")
    repo_path = Path(repo).resolve(strict=True)
    if af.git(repo_path, ["rev-parse", "--show-toplevel"]).returncode:
        raise af.AgentFlowError("INVALID_FINDING", "repo is not a Git repository")
    baseline = finding["baseline_commit"]
    if not isinstance(baseline, str) or not af._HEX40_RE.fullmatch(baseline.lower()):
        raise af.AgentFlowError("INVALID_FINDING", "baseline_commit must be a full 40-hex commit SHA")
    baseline = baseline.lower()
    resolved = af.git(repo_path, ["rev-parse", "--verify", f"{baseline}^{{commit}}"])
    if resolved.returncode or resolved.stdout.strip() != baseline:
        raise af.AgentFlowError("INVALID_FINDING", "baseline_commit does not resolve to that commit object")
    finding["repo"] = str(repo_path)
    finding["baseline_commit"] = baseline
    if not isinstance(finding["risk"], str) or finding["risk"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise af.AgentFlowError("INVALID_FINDING", "risk is invalid")
    for field in ("objective", "evidence"):
        if not isinstance(finding[field], str) or not finding[field].strip():
            raise af.AgentFlowError("INVALID_FINDING", f"{field} must be non-empty text")
    paths = finding["allowed_paths"]
    if not isinstance(paths, list) or not paths or any(not isinstance(item, str) for item in paths):
        raise af.AgentFlowError("INVALID_FINDING", "allowed_paths must be a non-empty string list")
    if any("\x00" in item or "\\" in item or ".git" in Path(item).parts for item in paths):
        raise af.AgentFlowError("INVALID_FINDING", "allowed_paths contains an unsafe path")
    finding["allowed_paths"] = af.normalize_allowed(paths)
    if not finding["allowed_paths"]:
        raise af.AgentFlowError("INVALID_FINDING", "allowed_paths must not normalize to empty")
    finding["targeted_validators"] = _validate_validators(finding["targeted_validators"], "targeted_validators")
    finding["broader_validators"] = _validate_validators(finding["broader_validators"], "broader_validators")
    roles = finding["roles"]
    if not isinstance(roles, dict) or set(roles) != {"architect", "worker", "reviewer"}:
        raise af.AgentFlowError("INVALID_FINDING", "roles must contain exactly architect, worker, reviewer")
    if any(not isinstance(value, str) or not value.strip() for value in roles.values()):
        raise af.AgentFlowError("INVALID_FINDING", "role names must be non-empty strings")
    if type(finding["max_corrections"]) is not int or finding["max_corrections"] not in (0, 1):
        raise af.AgentFlowError("INVALID_FINDING", "max_corrections must be exact integer 0 or 1")
    invariants = finding.get("invariants", [])
    if not isinstance(invariants, list) or any(not isinstance(item, str) for item in invariants):
        raise af.AgentFlowError("INVALID_FINDING", "invariants must be a string list")
    finding["invariants"] = invariants
    return finding


def _freeze_profiles(finding: dict[str, Any]) -> dict[str, dict[str, Any]]:
    models = af.load_models()
    frozen: dict[str, dict[str, Any]] = {}
    by_role: dict[str, dict[str, Any]] = {}
    for role in ("architect", "worker", "reviewer"):
        name = finding["roles"][role]
        profile = af._program_profile(models, name, role)
        copied = json.loads(json.dumps(profile))
        frozen[name] = copied
        by_role[role] = copied
    architect, worker, reviewer = (by_role[name] for name in ("architect", "worker", "reviewer"))
    af._check_adjudicator_independence(worker, reviewer, architect)
    if af.model_family(worker) == af.model_family(reviewer):
        raise af.AgentFlowError("REVIEWER_NOT_INDEPENDENT", af.model_family(worker))
    return frozen


def preflight(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    try:
        finding = validate_finding(_read_strict(path.resolve()))
        profiles = _freeze_profiles(finding)
        return finding, profiles
    except af.AgentFlowError:
        raise
    except Exception as exc:
        raise af.AgentFlowError("INVALID_FINDING", f"finding preflight failed: {exc}") from exc


def _new_run_id(finding_id: str) -> str:
    return f"{finding_id}-{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{uuid.uuid4().hex[:16]}"


def _state_write(run_dir: Path, state: str, *, detail: dict[str, Any] | None = None) -> None:
    path = run_dir / "state.json"
    history = []
    if path.is_file():
        current = _read_strict(path)
        history = list(current.get("history", []))
    history.append({"state": state, "at": af.utc_now(), "detail": detail or {}})
    _persist(path, {"finding_run_id": run_dir.name, "state": state, "history": history})


@contextlib.contextmanager
def _coordinator_lock(run_dir: Path):
    path = run_dir / "coordinator.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise af.AgentFlowError("FINDING_RUN_LOCKED", "finding run is already active") from exc
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _write_start_evidence(root: Path, finding: dict[str, Any], profiles: dict[str, Any]) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True)
    while True:
        attempt_id = _new_run_id(finding["finding_id"])
        attempt = root / attempt_id
        try:
            attempt.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            continue
    program_id = f"finding-{finding['finding_id']}"
    program_run_id = _new_run_id(program_id)
    objective = (
        finding["objective"].rstrip() + "\n\nFINDING_EVIDENCE\n" + finding["evidence"].strip()
        + "\nEND_FINDING_EVIDENCE"
    )
    task = {
        "task_id": f"{finding['finding_id']}-targeted", "repo": finding["repo"],
        "risk": finding["risk"], "objective": objective,
        "allowed_paths": finding["allowed_paths"], "invariants": finding["invariants"],
        "validators": finding["targeted_validators"], "max_corrections": finding["max_corrections"],
        "isolation": {"enabled": True, "baseline_commit": finding["baseline_commit"]},
        "finding_candidate_integrity": True,
        "_finding_frozen_profiles": profiles,
    }
    program = {
        "program_id": program_id, "task": "derived-task.json", "roles": finding["roles"],
        "max_corrections": finding["max_corrections"],
    }
    frozen = {
        "finding": finding, "finding_sha256": _hash_json(finding),
        "finding_run_id": attempt_id, "program_run_id": program_run_id,
        "program_id": program_id, "task_id": task["task_id"],
        "derived_task_sha256": _hash_json(task), "derived_program_sha256": _hash_json(program),
        "profiles_sha256": _hash_json(profiles),
    }
    _persist(attempt / "frozen-finding.json", finding)
    _persist(attempt / "derived-task.json", task)
    _persist(attempt / "derived-program.json", program)
    _persist(attempt / "frozen-profiles.json", profiles)
    _persist(attempt / "identity.json", frozen)
    original = af.capture_control_plane_manifest()
    _persist(attempt / "original-control-plane-manifest.json", original)
    frozen["control_plane_digest"] = original["digest"]
    _persist(attempt / "identity.json", frozen)
    _state_write(attempt, "FROZEN")
    return attempt, task, program


def _check_cp(run_dir: Path, phase: str) -> None:
    af._verify_control_plane(run_dir, phase=f"finding-{phase}")


def _manifest_binding(program_outcome: af.ProgramOutcome, finding_run_dir: Path, *, create: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    outcome = program_outcome
    af.verify_program_outcome(outcome)
    final = outcome.final
    binding = final.get("reviewed_candidate")
    if not isinstance(binding, dict) or binding.get("manifest") != "reviewed-candidate-manifest.json":
        raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Program has no reviewed candidate binding")
    path = Path(outcome.run_dir) / binding["manifest"]
    if not path.is_file() or af.sha256_path(path) != binding.get("sha256"):
        raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Reviewed candidate artifact hash mismatch")
    manifest = _read_strict(path)
    digest = af.candidate_manifest_digest(manifest)
    if digest != binding.get("candidate_digest"):
        raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Reviewed candidate digest binding mismatch")
    bound_evidence = {
        "program_run_id": outcome.run_id, "program_final_sha256": outcome.final_sha256,
        "manifest_path": str(path), "manifest_sha256": binding["sha256"], "candidate_digest": digest,
    }
    evidence_path = finding_run_dir / "reviewed-candidate-binding.json"
    if evidence_path.exists():
        if _read_strict(evidence_path) != bound_evidence:
            raise af.AgentFlowError("INVALID_EVIDENCE", "reviewed candidate binding conflicts with Program evidence")
    else:
        if not create:
            raise af.AgentFlowError("INVALID_EVIDENCE", "reviewed candidate binding is missing")
        _persist(evidence_path, bound_evidence)
    return binding, manifest


def _reconstruct_outcome(run_dir: Path) -> af.ProgramOutcome:
    identity = _read_strict(run_dir / "identity.json")
    pdir = af.RUNS_DIR / identity["program_run_id"]
    final_path = pdir / "final.json"
    final = _read_strict(final_path)
    outcome = af.ProgramOutcome(
        run_id=identity["program_run_id"], run_dir=str(pdir), final_path=str(final_path),
        final_sha256=af.sha256_path(final_path), program_id=identity["program_id"], task_id=identity["task_id"],
        verdict=final.get("verdict", ""), status=final.get("status", ""),
        human_gate=final.get("human_gate") is True,
        outcome_class=("HUMAN_GATE" if final.get("verdict") == "HUMAN_GATE" and final.get("human_gate") is True else "PROGRAM_LOCAL_FAILURE"),
        primary_failure=None, secondary_failures=[], budget_dimension=final.get("budget_dimension"),
        execution_repo=final.get("workspace", {}).get("execution_repo", ""),
        baseline_commit=final.get("workspace", {}).get("baseline_commit", ""),
        preservation_status="PROVEN" if final.get("workspace", {}).get("status") == "PRESERVED" else "UNCERTAIN",
        preservation_evidence_path=str(pdir / "workspace.json"), process_quiescence="PROVEN", final=final,
    )
    af.verify_program_outcome(outcome)
    return outcome


def _candidate_live(outcome: af.ProgramOutcome, reviewed_digest: str) -> dict[str, Any]:
    workspace_path = Path(outcome.run_dir) / "workspace.json"
    workspace = _read_strict(workspace_path)
    if workspace.get("status") != "PRESERVED" or workspace.get("execution_repo") != outcome.execution_repo:
        raise af.AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "Candidate preservation binding is invalid")
    candidate = Path(outcome.execution_repo)
    source = Path(workspace["source_repo"])
    current = af.capture_candidate_manifest(candidate, source, outcome.baseline_commit)
    if af.candidate_manifest_digest(current) != reviewed_digest:
        raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Live candidate differs from reviewed candidate")
    return current


def _verify_broad_results(frozen: list[dict[str, Any]], results: Any) -> None:
    if not isinstance(results, list) or len(results) != len(frozen):
        raise af.AgentFlowError("VALIDATOR_FAILED", "Broad validator evidence is incomplete")
    import shlex
    for result, expected in zip(results, frozen):
        if not isinstance(result, dict) or (
            result.get("name") != expected["name"] or result.get("status") != "PASS"
            or type(result.get("exit_code")) is not int or result.get("exit_code") != 0
            or result.get("command") != shlex.join(expected["command"])
        ):
            raise af.AgentFlowError("VALIDATOR_FAILED", "Broad validator evidence does not match frozen validators")


def _strict_program_success(outcome: af.ProgramOutcome) -> None:
    af.verify_program_outcome(outcome)
    final = outcome.final
    if not (
        outcome.verdict == "HUMAN_GATE" and outcome.status == "SUCCESS"
        and outcome.human_gate is True and final.get("human_gate") is True
        and outcome.outcome_class == "HUMAN_GATE" and outcome.preservation_status == "PROVEN"
        and outcome.process_quiescence == "PROVEN"
        and isinstance(final.get("final_reviewer_result"), dict)
    ):
        raise af.AgentFlowError("PROGRAM_DID_NOT_REACH_HUMAN_GATE", "Program outcome is not strict success")
    af.validate_reviewer_result(final["final_reviewer_result"])
    if af.reviewer_blocks(final["final_reviewer_result"]):
        raise af.AgentFlowError("FINAL_REVIEW_BLOCKED", "Program final reviewer blocks")


def _broad_validate(finding: dict[str, Any], run_dir: Path, outcome: af.ProgramOutcome, digest: str) -> list[dict[str, Any]]:
    candidate = Path(outcome.execution_repo)
    _candidate_live(outcome, digest)
    _check_cp(run_dir, "pre-broad-validation")
    try:
        results = af.run_validators(candidate, finding["broader_validators"], run_dir, 1)
    finally:
        _check_cp(run_dir, "post-broad-validation")
        _candidate_live(outcome, digest)
    _candidate_live(outcome, digest)
    _verify_broad_results(finding["broader_validators"], results)
    _persist(run_dir / "broader-evidence.json", {
        "validators": results, "validators_sha256": _hash_json(results), "candidate_digest": digest,
    })
    return results


def _closure(run_dir: Path, finding: dict[str, Any], outcome: af.ProgramOutcome,
             reviewed: dict[str, Any], broad: list[dict[str, Any]], *, persist: bool = True) -> dict[str, Any]:
    if (run_dir / "failure.json").exists():
        raise af.AgentFlowError("INVALID_EVIDENCE", "failure evidence conflicts with successful closure")
    current_state = _read_strict(run_dir / "state.json").get("state")
    if current_state not in {"CLOSURE_STARTED", "CLOSURE_PASSED"}:
        raise af.AgentFlowError("INVALID_EVIDENCE", "closure state boundary is invalid")
    identity = _read_strict(run_dir / "identity.json")
    frozen_task = _read_strict(run_dir / "derived-task.json")
    frozen_program = _read_strict(run_dir / "derived-program.json")
    if (_hash_json(_read_strict(run_dir / "frozen-finding.json")) != identity["finding_sha256"]
            or _hash_json(frozen_task) != identity["derived_task_sha256"]
            or _hash_json(frozen_program) != identity["derived_program_sha256"]):
        raise af.AgentFlowError("INVALID_FINDING", "Frozen finding changed")
    profiles = _read_strict(run_dir / "frozen-profiles.json")
    if _hash_json(profiles) != identity["profiles_sha256"] or _hash_json(profiles) != _hash_json(frozen_task["_finding_frozen_profiles"]):
        raise af.AgentFlowError("ROLE_NOT_ELIGIBLE", "Frozen profiles changed")
    _strict_program_success(outcome)
    binding = _read_strict(run_dir / "reviewed-candidate-binding.json")
    if binding.get("candidate_digest") != reviewed["candidate_digest"]:
        raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Reviewed candidate binding changed")
    current = _candidate_live(outcome, reviewed["candidate_digest"])
    evidence = _read_strict(run_dir / "broader-evidence.json")
    if evidence.get("validators_sha256") != _hash_json(broad) or evidence.get("candidate_digest") != reviewed["candidate_digest"]:
        raise af.AgentFlowError("VALIDATOR_FAILED", "Broad evidence digest mismatch")
    _verify_broad_results(finding["broader_validators"], broad)
    cp = _read_strict(run_dir / "original-control-plane-manifest.json")
    _check_cp(run_dir, "closure")
    af._control_plane_check_poison(run_dir)
    if cp.get("digest") != identity.get("control_plane_digest"):
        raise af.AgentFlowError("CONTROL_PLANE_MUTATED", "original finding control-plane binding changed")
    workspace = _read_strict(Path(outcome.run_dir) / "workspace.json")
    if not af._is_worktree_registered(Path(workspace["source_repo"]), Path(outcome.execution_repo)):
        raise af.AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "Candidate worktree is not registered")
    if not af._worktree_is_detached(Path(outcome.execution_repo)) or af._worktree_head(Path(outcome.execution_repo)) != outcome.baseline_commit:
        raise af.AgentFlowError("GIT_IDENTITY_MOVED", "Candidate worktree identity changed")
    result = {
        "finding_run_id": run_dir.name, "program_run_id": outcome.run_id,
        "finding_sha256": _read_strict(run_dir / "identity.json")["finding_sha256"],
        "program_final_sha256": outcome.final_sha256,
        "reviewed_candidate_digest": reviewed["candidate_digest"],
        "live_candidate_digest": af.candidate_manifest_digest(current),
        "broad_evidence_sha256": af.sha256_path(run_dir / "broader-evidence.json"),
        "control_plane_digest": cp["digest"], "closure": "PROVEN", "closed_at": af.utc_now(),
    }
    if persist:
        _persist(run_dir / "closure.json", result)
    return result


def _terminal(run_dir: Path, finding: dict[str, Any], outcome: af.ProgramOutcome,
              closure: dict[str, Any]) -> dict[str, Any]:
    if (run_dir / "final.json").exists():
        raise af.AgentFlowError("INVALID_EVIDENCE", "terminal evidence already exists at a nonterminal boundary")
    identity = _read_strict(run_dir / "identity.json")
    _strict_program_success(outcome)
    _candidate_live(outcome, closure["reviewed_candidate_digest"])
    _check_cp(run_dir, "pre-human-gate")
    final = {
        "finding_run_id": run_dir.name, "finding_id": finding["finding_id"],
        "program_run_id": outcome.run_id, "verdict": "HUMAN_GATE", "status": "SUCCESS",
        "human_gate": True, "outcome_class": "HUMAN_GATE", "closure_sha256": af.sha256_path(run_dir / "closure.json"),
        "program_final_sha256": outcome.final_sha256,
        "reviewed_candidate_digest": closure["reviewed_candidate_digest"],
        "finished_at": af.utc_now(),
    }
    _persist(run_dir / "final.json", final)
    _state_write(run_dir, "HUMAN_GATE")
    return final


def run(finding_path: Path) -> tuple[int, Path | None, dict[str, Any]]:
    attempt: Path | None = None
    try:
        finding, profiles = preflight(finding_path)
        attempt, task, program = _write_start_evidence(FINDINGS_DIR, finding, profiles)
        with _coordinator_lock(attempt):
            original = _read_strict(attempt / "original-control-plane-manifest.json")
            with af._control_plane_restored_scope(attempt, original):
                identity = _read_strict(attempt / "identity.json")
                program = af.validate_program(program)
                task = af.validate_task(task)
                program_run_id = identity["program_run_id"]
                program_identity = af.RunIdentity(program_run_id, af.RUNS_DIR / program_run_id)
                af._control_plane_check_poison(attempt)
                _state_write(attempt, "PROGRAM_STARTED")
                outcome = af.execute_program(program, task, program_identity, execution_control=None)
                af.verify_program_outcome(outcome)
                _strict_program_success(outcome)
                reviewed, _ = _manifest_binding(outcome, attempt, create=True)
                _state_write(attempt, "PROGRAM_VERIFIED")
                candidate = Path(outcome.execution_repo)
                with af.WriteLease(candidate, task["task_id"], attempt.name):
                    _candidate_live(outcome, reviewed["candidate_digest"])
                    _state_write(attempt, "BROAD_STARTED")
                    broad = _broad_validate(finding, attempt, outcome, reviewed["candidate_digest"])
                    _state_write(attempt, "BROAD_PASSED")
                    _state_write(attempt, "CLOSURE_STARTED")
                    closure = _closure(attempt, finding, outcome, reviewed, broad)
                    _state_write(attempt, "CLOSURE_PASSED")
                    final = _terminal(attempt, finding, outcome, closure)
            return 0, attempt, final
    except BaseException as exc:
        if attempt is not None:
            with contextlib.suppress(Exception):
                _state_write(attempt, "STOPPED", detail={"error": getattr(exc, "code", type(exc).__name__)})
                _persist(attempt / "failure.json", {"error": getattr(exc, "code", "INTERNAL_ERROR"), "message": str(exc)[:4000]})
        return 2, attempt, {"verdict": getattr(exc, "code", "INTERNAL_ERROR"), "status": "STOPPED", "human_gate": False}


def _load_run(run_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise af.AgentFlowError("INVALID_FINDING_RUN_ID", "invalid finding-run-id")
    path = FINDINGS_DIR / run_id
    if not path.is_dir():
        raise af.AgentFlowError("FINDING_RUN_NOT_FOUND", run_id)
    frozen = _read_strict(path / "frozen-finding.json")
    finding = validate_finding(frozen)
    identity = _read_strict(path / "identity.json")
    if identity.get("finding_run_id") != run_id or identity.get("finding_sha256") != _hash_json(finding):
        raise af.AgentFlowError("INVALID_FINDING", "frozen finding or identity mismatch")
    derived_task = _read_strict(path / "derived-task.json")
    derived_program = _read_strict(path / "derived-program.json")
    profiles = _read_strict(path / "frozen-profiles.json")
    cp = _read_strict(path / "original-control-plane-manifest.json")
    if (identity.get("derived_task_sha256") != _hash_json(derived_task)
            or identity.get("derived_program_sha256") != _hash_json(derived_program)
            or identity.get("profiles_sha256") != _hash_json(profiles)
            or identity.get("control_plane_digest") != cp.get("digest")
            or af.canonical_control_plane_digest(cp) != cp.get("digest")):
        raise af.AgentFlowError("INVALID_EVIDENCE", "frozen derived evidence hash mismatch")
    state = _read_strict(path / "state.json")
    if state.get("finding_run_id") != run_id:
        raise af.AgentFlowError("INVALID_FINDING", "state identity mismatch")
    history = state.get("history")
    expected_order = ["FROZEN", "PROGRAM_STARTED", "PROGRAM_VERIFIED", "BROAD_STARTED",
                      "BROAD_PASSED", "CLOSURE_STARTED", "CLOSURE_PASSED", "HUMAN_GATE"]
    if (not isinstance(history, list) or not history or any(not isinstance(item, dict) or not isinstance(item.get("state"), str) for item in history)
            or history[0].get("state") != "FROZEN"):
        raise af.AgentFlowError("INVALID_EVIDENCE", "phase history is malformed")
    seen = [item["state"] for item in history]
    previous = -1
    stopped = False
    for value in seen:
        if value == "STOPPED":
            if stopped:
                continue
            stopped = True
            continue
        if stopped or value not in expected_order:
            raise af.AgentFlowError("INVALID_EVIDENCE", "phase history contains an invalid transition")
        index = expected_order.index(value)
        if index != previous + 1:
            raise af.AgentFlowError("INVALID_EVIDENCE", "phase history skipped or repeated a boundary")
        previous = index
    if state.get("state") != seen[-1]:
        raise af.AgentFlowError("INVALID_EVIDENCE", "phase state does not match history")
    return path, finding, state


def _verify_readonly_control_plane(run_dir: Path) -> None:
    original = _read_strict(run_dir / "original-control-plane-manifest.json")
    if (not isinstance(original, dict) or set(original) != {"root", "captured_at", "files", "digest"}
            or not isinstance(original.get("captured_at"), str)
            or not isinstance(original.get("files"), dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in original["files"].items())):
        raise af.AgentFlowError("CONTROL_PLANE_MUTATED", "original control-plane manifest shape is invalid")
    current = af.capture_control_plane_manifest()
    if original.get("root") != current.get("root") or af.canonical_control_plane_digest(original) != original.get("digest"):
        raise af.AgentFlowError("CONTROL_PLANE_MUTATED", "original control-plane evidence is invalid")
    af.assert_control_plane_unchanged(original, current, context="finding-status")
    poison = af._load_control_plane_poison_entries()
    if any(item.get("digest") == current.get("digest") for item in poison):
        raise af.AgentFlowError("CONTROL_PLANE_MUTATED", "current control plane matches the poison ledger")


def status(run_id: str) -> tuple[int, dict[str, Any]]:
    try:
        path, finding, state = _load_run(run_id)
        final_path = path / "final.json"
        state_name = state.get("state")
        if state_name == "HUMAN_GATE" and final_path.is_file():
            if (path / "failure.json").exists():
                raise af.AgentFlowError("INVALID_EVIDENCE", "failure evidence conflicts with HUMAN_GATE")
            final = _read_strict(final_path)
            if (final.get("finding_run_id") == run_id and final.get("finding_id") == finding["finding_id"]
                    and final.get("verdict") == "HUMAN_GATE" and final.get("status") == "SUCCESS"
                    and final.get("human_gate") is True and final.get("outcome_class") == "HUMAN_GATE"
                    and final.get("closure_sha256") == af.sha256_path(path / "closure.json")):
                outcome = _reconstruct_outcome(path)
                _strict_program_success(outcome)
                if final.get("program_run_id") != outcome.run_id:
                    raise af.AgentFlowError("INVALID_EVIDENCE", "finding terminal Program identity mismatch")
                closure = _read_strict(path / "closure.json")
                if (closure.get("closure") != "PROVEN" or closure.get("finding_run_id") != run_id
                        or closure.get("program_run_id") != outcome.run_id
                        or closure.get("program_final_sha256") != outcome.final_sha256
                        or closure.get("finding_sha256") != _read_strict(path / "identity.json")["finding_sha256"]
                        or closure.get("live_candidate_digest") != closure.get("reviewed_candidate_digest")
                        or closure.get("control_plane_digest") != _read_strict(path / "original-control-plane-manifest.json").get("digest")):
                    raise af.AgentFlowError("INVALID_EVIDENCE", "closure binding is invalid")
                reviewed = outcome.final.get("reviewed_candidate")
                if not isinstance(reviewed, dict):
                    raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Program reviewed candidate binding is missing")
                reviewed_path = Path(outcome.run_dir) / reviewed.get("manifest", "")
                if (not reviewed_path.is_file() or af.sha256_path(reviewed_path) != reviewed.get("sha256")
                        or reviewed.get("candidate_digest") != closure.get("reviewed_candidate_digest")):
                    raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "closure candidate digest mismatch")
                candidate_manifest = _read_strict(reviewed_path)
                if af.candidate_manifest_digest(candidate_manifest) != reviewed["candidate_digest"]:
                    raise af.AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "reviewed candidate artifact is invalid")
                _candidate_live(outcome, reviewed["candidate_digest"])
                broad = _read_strict(path / "broader-evidence.json")
                if (broad.get("validators_sha256") != _hash_json(broad.get("validators"))
                        or broad.get("candidate_digest") != reviewed["candidate_digest"]
                        or closure.get("broad_evidence_sha256") != af.sha256_path(path / "broader-evidence.json")):
                    raise af.AgentFlowError("INVALID_EVIDENCE", "broad evidence binding is invalid")
                _verify_broad_results(finding["broader_validators"], broad.get("validators"))
                _verify_readonly_control_plane(path)
                return 0, final
        return 2, {"finding_run_id": run_id, "state": state_name, "status": "INCOMPLETE", "human_gate": False}
    except Exception as exc:
        return 2, {"finding_run_id": run_id, "verdict": getattr(exc, "code", "INVALID_EVIDENCE"), "status": "STOPPED", "human_gate": False}


def resume(run_id: str) -> tuple[int, dict[str, Any]]:
    lock_acquired = False
    try:
        path, finding, state = _load_run(run_id)
        with _coordinator_lock(path):
            lock_acquired = True
            path, finding, state = _load_run(run_id)
            state_name = state["state"]
            if state_name in {"HUMAN_GATE", "STOPPED"}:
                return status(run_id)
            allowed = {"FROZEN", "PROGRAM_VERIFIED", "BROAD_PASSED", "CLOSURE_PASSED"}
            if state_name not in allowed:
                raise af.AgentFlowError("AMBIGUOUS_PHASE", f"cannot replay incomplete boundary {state_name}")
            original = _read_strict(path / "original-control-plane-manifest.json")
            with af._control_plane_restored_scope(path, original):
                identity = _read_strict(path / "identity.json")
                task = af.validate_task(_read_strict(path / "derived-task.json"))
                profiles = _read_strict(path / "frozen-profiles.json")
                if state_name == "FROZEN":
                    program = af.validate_program(_read_strict(path / "derived-program.json"))
                    prun = identity["program_run_id"]
                    candidate = af._worktree_destination(prun)
                    pdir = af.RUNS_DIR / prun
                    if pdir.exists() or candidate.exists() or af._is_worktree_registered(Path(finding["repo"]), candidate):
                        raise af.AgentFlowError("AMBIGUOUS_PHASE", "Program or candidate allocation exists")
                    _state_write(path, "PROGRAM_STARTED")
                    outcome = af.execute_program(program, task, af.RunIdentity(prun, pdir), execution_control=None)
                    af.verify_program_outcome(outcome)
                    _strict_program_success(outcome)
                    state_name = "PROGRAM_VERIFIED"
                else:
                    outcome = _reconstruct_outcome(path)
                reviewed, _manifest = _manifest_binding(outcome, path, create=(state.get("state") == "FROZEN"))
                if state.get("state") == "FROZEN":
                    _state_write(path, "PROGRAM_VERIFIED")
                candidate = Path(outcome.execution_repo)
                with af.WriteLease(candidate, task["task_id"], run_id):
                    _candidate_live(outcome, reviewed["candidate_digest"])
                    if state_name == "PROGRAM_VERIFIED":
                        if (path / "validators-cycle-1.json").exists() or (path / "broader-evidence.json").exists():
                            raise af.AgentFlowError("AMBIGUOUS_PHASE", "orphan broad validator evidence exists")
                        _state_write(path, "BROAD_STARTED")
                        broad = _broad_validate(finding, path, outcome, reviewed["candidate_digest"])
                        _state_write(path, "BROAD_PASSED")
                        state_name = "BROAD_PASSED"
                    else:
                        evidence = _read_strict(path / "broader-evidence.json")
                        broad = evidence["validators"]
                    if state_name == "BROAD_PASSED":
                        _state_write(path, "CLOSURE_STARTED")
                        closure = _closure(path, finding, outcome, reviewed, broad)
                        _state_write(path, "CLOSURE_PASSED")
                        state_name = "CLOSURE_PASSED"
                    else:
                        closure = _read_strict(path / "closure.json")
                        if closure.get("closure") != "PROVEN":
                            raise af.AgentFlowError("INVALID_EVIDENCE", "closure evidence incomplete")
                        checked_closure = _closure(
                            path, finding, outcome, reviewed,
                            _read_strict(path / "broader-evidence.json")["validators"], persist=False,
                        )
                        if {k: v for k, v in checked_closure.items() if k != "closed_at"} != {
                            k: v for k, v in closure.items() if k != "closed_at"
                        }:
                            raise af.AgentFlowError("INVALID_EVIDENCE", "closure evidence conflicts with fresh predicates")
                        if (path / "final.json").exists():
                            existing_final = _read_strict(path / "final.json")
                            if not (
                                existing_final.get("finding_run_id") == run_id
                                and existing_final.get("finding_id") == finding["finding_id"]
                                and existing_final.get("program_run_id") == outcome.run_id
                                and existing_final.get("verdict") == "HUMAN_GATE"
                                and existing_final.get("status") == "SUCCESS"
                                and existing_final.get("human_gate") is True
                                and existing_final.get("outcome_class") == "HUMAN_GATE"
                                and existing_final.get("closure_sha256") == af.sha256_path(path / "closure.json")
                            ):
                                raise af.AgentFlowError("INVALID_EVIDENCE", "partial terminal evidence is conflicting")
                            _state_write(path, "HUMAN_GATE")
                            return 0, existing_final
                    final = _terminal(path, finding, outcome, closure)
                return 0, final
    except BaseException as exc:
        with contextlib.suppress(Exception):
            if lock_acquired and 'path' in locals():
                _state_write(path, "STOPPED", detail={"error": getattr(exc, "code", type(exc).__name__)})
        return 2, {"finding_run_id": run_id, "verdict": getattr(exc, "code", "INTERNAL_ERROR"), "status": "STOPPED", "human_gate": False}


def cli(command: str, argument: str) -> int:
    try:
        if command == "run":
            code, run_dir, final = run(Path(argument))
            print(json.dumps({"finding_run_id": run_dir.name if run_dir else None, **final}, indent=2))
            return code
        code, result = status(argument) if command == "status" else resume(argument)
        print(json.dumps(result, indent=2))
        return code
    except Exception as exc:
        print(json.dumps({"verdict": getattr(exc, "code", "INVALID_FINDING"), "status": "STOPPED", "human_gate": False}, indent=2))
        return 2
