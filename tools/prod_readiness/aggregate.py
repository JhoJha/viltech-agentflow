#!/usr/bin/env python3
"""Deterministic, read-only aggregation of sealed Stage B evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from tools.prod_readiness.common import (
    ErrorCode,
    RunnerError,
    finalize_integrity,
    load_json,
    open_owned_run_root,
    seal_artifacts_owned,
    sha256_path,
    validate_external_run_root,
)
from tools.prod_readiness.verify_evidence import verify_evidence

# ONE explicit allowed terminal review status (frozen contract).
ALLOWED_REVIEW_STATUS = "COMPLETE"

SUITE_PATHS = tuple(f"suites/pr-{index:02d}.json" for index in range(1, 8))
OTHER_PATHS = (
    "regression/full.json",
    "telemetry/verify.json",
    "resources/result.json",
    "providers/support-matrix.json",
    "findings/register.json",
    "review/status.json",
    "canonical/integrity.json",
)
REQUIRED_PATHS = SUITE_PATHS + OTHER_PATHS
ZERO_SAFETY = (
    "false_human_gate",
    "unauthorized_writes",
    "unrelated_signals",
    "evidence_corruption",
    "persistent_resource_leaks",
    "candidate_worktree_loss",
)


def _status(document: Mapping[str, Any]) -> str | None:
    value = document.get("status")
    return value if isinstance(value, str) else None


def evaluate_gate(documents: Mapping[str, Mapping[str, Any]]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    for relative in SUITE_PATHS:
        if _status(documents[relative]) != "PASS":
            reasons.append(f"{relative}: status is not PASS")
    findings = documents["findings/register.json"].get("findings")
    if not isinstance(findings, list):
        reasons.append("finding register malformed")
    else:
        for finding in findings:
            if not isinstance(finding, dict):
                reasons.append("finding register entry malformed")
                continue
            severity, state = finding.get("severity"), finding.get("status")
            if severity not in {"BLOCKER", "HIGH", "MEDIUM", "LOW"}:
                reasons.append("finding severity is malformed")
                continue
            if state not in {"OPEN", "CLOSED", "ACCEPTED"}:
                reasons.append("finding status is malformed")
                continue
            if severity in {"BLOCKER", "HIGH", "MEDIUM"} and state == "OPEN":
                reasons.append(f"open {severity} finding")
            if severity == "LOW" and state not in {"CLOSED", "ACCEPTED"}:
                reasons.append("unaccepted LOW finding")
    safety = documents["suites/pr-04.json"].get("metrics")
    if not isinstance(safety, dict):
        reasons.append("PR-04 safety metrics missing")
    else:
        for key in ZERO_SAFETY:
            if type(safety.get(key)) is not int or safety.get(key) != 0:
                reasons.append(f"safety metric {key} is not zero")
        if safety.get("automatic_git_publication") is not False:
            reasons.append("automatic Git publication not explicitly false")
        if safety.get("automatic_human_gate_acceptance") is not False:
            reasons.append("automatic Human Gate acceptance not explicitly false")
    mutations = documents["suites/pr-05.json"]
    if (
        mutations.get("critical_total") != mutations.get("critical_killed")
        or type(mutations.get("critical_total")) is not int
        or type(mutations.get("critical_killed")) is not int
        or mutations.get("critical_total", 0) <= 0
    ):
        reasons.append("CRITICAL mutation kill rate is not 100%")
    if mutations.get("important_threshold_satisfied") is not True:
        reasons.append("IMPORTANT mutation threshold is not satisfied")
    if documents["suites/pr-03.json"].get("crash_matrix") != "PASS":
        reasons.append("crash matrix is not PASS")
    if documents["suites/pr-06.json"].get("stress") != "PASS":
        reasons.append("stress is not PASS")
    pr07 = documents["suites/pr-07.json"]
    if pr07.get("soak") != "PASS":
        reasons.append("soak is not PASS")
    if pr07.get("required_real_provider_support") != "PASS":
        reasons.append("required real-provider support is not PASS")
    for relative in (
        "regression/full.json",
        "telemetry/verify.json",
        "resources/result.json",
        "canonical/integrity.json",
    ):
        if _status(documents[relative]) != "PASS":
            reasons.append(f"{relative}: status is not PASS")
    review = documents["review/status.json"]
    if review.get("integrity") != "CLEAN":
        reasons.append("review integrity is not CLEAN")
    # Aggregator requires BOTH integrity CLEAN and explicit terminal status.
    # INCOMPLETE/RUNNING/UNKNOWN/missing/null => NOT_READY even if CLEAN.
    if review.get("status") != ALLOWED_REVIEW_STATUS:
        reasons.append(
            f"review status is not {ALLOWED_REVIEW_STATUS} "
            f"(integrity CLEAN alone is insufficient)"
        )
    matrix = documents["providers/support-matrix.json"]
    providers = matrix.get("providers")
    if not isinstance(providers, list) or not providers:
        reasons.append("support matrix malformed")
    else:
        required_capabilities = 0
        for provider in providers:
            if not isinstance(provider, dict):
                reasons.append("support matrix entry malformed")
                continue
            capabilities = provider.get("capabilities")
            if not isinstance(capabilities, dict):
                reasons.append("provider capability map malformed")
                continue
            for capability, evidence in capabilities.items():
                if not isinstance(evidence, dict):
                    reasons.append(f"capability {capability} malformed")
                    continue
                if (
                    evidence.get("required") is True
                    and evidence.get("status") != "SUPPORTED"
                ):
                    reasons.append(f"required capability {capability} is not SUPPORTED")
                if evidence.get("required") is True:
                    required_capabilities += 1
                # LOW B: bool is not evidence_level (True == 1).
                _ev_level = evidence.get("evidence_level")
                if isinstance(_ev_level, bool):
                    reasons.append(
                        f"capability {capability} evidence_level bool is invalid"
                    )
                    continue
                if (
                    evidence.get("status") == "SUPPORTED"
                    and _ev_level == 3
                ):
                    reasons.append(f"capability {capability} relies only on simulation")
                if (
                    capability == "normal_execution"
                    and evidence.get("status") == "SUPPORTED"
                    and _ev_level != 1
                ):
                    reasons.append("normal execution lacks level-1 evidence")
        if required_capabilities == 0:
            reasons.append("support matrix declares no required capabilities")
    return ("PASS" if not reasons else "NOT_READY", sorted(set(reasons)))


def aggregate(
    run_root: Path,
    *,
    expected_candidate_sha: str | None = None,
    expected_candidate_tree: str | None = None,
    expected_run_id: str | None = None,
    _test_hook: Any = None,
) -> dict[str, Any]:
    root = run_root.resolve(strict=True)
    canonical_repo = Path(__file__).resolve().parents[2]
    policy = validate_external_run_root(
        root,
        canonical_repo,
        source_directories=(Path(__file__).resolve().parent,),
        must_be_empty=False,
    )
    # Descriptor-anchored capability for all authoritative aggregator writes.
    # No path-based fallback for assessment/integrity evidence.
    owned = open_owned_run_root(policy.disposable_root, test_hook=_test_hook)
    try:
        return _aggregate_inner(
            policy=policy,
            owned=owned,
            expected_candidate_sha=expected_candidate_sha,
            expected_candidate_tree=expected_candidate_tree,
            expected_run_id=expected_run_id,
        )
    finally:
        owned.close()


def _aggregate_inner(
    *,
    policy: Any,
    owned: Any,
    expected_candidate_sha: str | None,
    expected_candidate_tree: str | None,
    expected_run_id: str | None,
) -> dict[str, Any]:
    # ROOTBIND: after initialization the public pathname must still name
    # the held inode; otherwise no PASS/sealed success may be committed.
    _binding_init_failure: RunnerError | None = None
    try:
        owned.assert_public_binding()
    except RunnerError as exc:
        _binding_init_failure = exc
    # ROOTBIND early fail-closed: if the public pathname already fails to
    # name the held inode, do not use the decoy tree for verification.
    if _binding_init_failure is not None:
        try:
            owned.mkdir_rel("integrity")
        except RunnerError:
            pass
        try:
            owned.mkdir_rel("assessment")
        except RunnerError:
            pass
        _reasons = ["public run-root binding failed after initialization"]
        _assessment = {
            "decision": "NOT_READY",
            "candidate_sha": None,
            "candidate_tree": None,
            "run_id": None,
            "static_input_manifest_hash": None,
            "environment_id": None,
            "support_matrix_sha256": None,
            "evidence_manifest_hash": None,
            "verification": {"status": "FAIL"},
            "reasons": _reasons,
            "reruns": 0,
            "retries": 0,
        }
        try:
            from tools.prod_readiness.common import canonical_json_bytes as _cjb2
            owned.atomic_create_bytes_rel(
                "assessment/prod-readiness-final.json", _cjb2(_assessment)
            )
        except RunnerError:
            pass
        return {**_assessment, "final_integrity": {"status": "FAIL", "binding_failure": True}}
    root = policy.disposable_root
    evidence_root = root / "evidence"
    if not evidence_root.is_dir() or evidence_root.is_symlink():
        raise RunnerError(
            ErrorCode.EVIDENCE_VERIFY_FAILED,
            "sealed evidence root is missing or linked",
        )
    before = {
        path.relative_to(evidence_root).as_posix(): sha256_path(path)
        for path in evidence_root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    verification = verify_evidence(
        evidence_root,
        expected_candidate_sha=expected_candidate_sha,
        require_sealed=True,
    )
    documents: dict[str, Mapping[str, Any]] = {}
    reasons: list[str] = []
    for relative in REQUIRED_PATHS:
        path = evidence_root / relative
        try:
            value = load_json(path)
            if not isinstance(value, dict):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "gate evidence must be a JSON object",
                    path=relative,
                )
            documents[relative] = value
        except RunnerError:
            reasons.append(f"missing or malformed required input: {relative}")
            documents[relative] = {}
    if verification["status"] != "PASS":
        reasons.append("PR-HARNESS-001 evidence verification failed")
    gate, gate_reasons = evaluate_gate(documents)
    reasons.extend(gate_reasons)
    decision = (
        "PASS"
        if gate == "PASS" and verification["status"] == "PASS" and not reasons
        else "NOT_READY"
    )
    try:
        manifest = (
            load_json(evidence_root / "run-manifest.json")
            if (evidence_root / "run-manifest.json").is_file()
            else {}
        )
    except RunnerError:
        # Never repair/rewrite missing or malformed input (H2-13): record
        # the failure and continue to NOT_READY without creating evidence.
        reasons.append("missing or malformed required input: run-manifest.json")
        manifest = {}
    if not isinstance(manifest, dict):
        reasons.append("missing or malformed required input: run-manifest.json")
        manifest = {}
        decision = "NOT_READY"
    # LOW C: release aggregation requires explicit expected identities and
    # binds run manifest identity to the invocation. Missing or mismatched
    # expected candidate_sha/tree/run_id => NOT_READY. Run_id is bound to
    # the manifest's explicit identity, not directory basename.
    if (
        not expected_candidate_sha
        or not expected_candidate_tree
        or not expected_run_id
    ):
        reasons.append(
            "release aggregation requires explicit expected "
            "candidate_sha/candidate_tree/run_id"
        )
        decision = "NOT_READY"
    else:
        for key, expected in (
            ("candidate_sha", expected_candidate_sha),
            ("candidate_tree", expected_candidate_tree),
            ("run_id", expected_run_id),
        ):
            actual = manifest.get(key)
            if actual != expected:
                reasons.append(
                    f"run manifest {key} differs from expected invocation identity"
                )
                decision = "NOT_READY"
    # Recompute decision after identity binding (pure conjunction).
    if reasons:
        decision = "NOT_READY"
    # ROOTBIND: before any terminal PASS is committed / before sealing
    # begins, the public pathname must still name the held inode.
    if _binding_init_failure is not None:
        reasons.append("public run-root binding failed after initialization")
        decision = "NOT_READY"
    try:
        owned.assert_public_binding()
    except RunnerError:
        reasons.append("public run-root binding failed before sealing")
        decision = "NOT_READY"
    relative_inputs = [f"evidence/{relative}" for relative in sorted(before)]
    # Seal via descriptor-anchored capability is not possible for the legacy
    # path-based seal_artifacts helper; instead perform the seal through the
    # held fd by pre-creating integrity dir and writing via owned handle.
    # We still call seal_artifacts for hashing, but authoritative publication
    # goes through owned (create-once, 0600, fsync). To avoid double-write
    # races, write assessment/integrity exclusively via owned.
    try:
        owned.mkdir_rel("integrity")
        owned.mkdir_rel("assessment")
        evidence_manifest = seal_artifacts_owned(
            owned,
            root,
            relative_inputs,
            candidate_sha=str(manifest.get("candidate_sha")),
            candidate_tree=str(manifest.get("candidate_tree")),
            run_id=str(manifest.get("run_id")),
        )
    except RunnerError:
        # ROOTBIND: if sealing fails while the public binding no longer holds
        # (decoy tree), fail closed with NOT_READY instead of using the decoy.
        try:
            owned.assert_public_binding()
        except RunnerError:
            _reasons2 = sorted(set(reasons + ["public run-root binding failed during sealing"]))
            _assessment2 = {
                "decision": "NOT_READY",
                "candidate_sha": manifest.get("candidate_sha"),
                "candidate_tree": manifest.get("candidate_tree"),
                "run_id": manifest.get("run_id"),
                "static_input_manifest_hash": None,
                "environment_id": manifest.get("environment_id"),
                "support_matrix_sha256": None,
                "evidence_manifest_hash": None,
                "verification": verification,
                "reasons": _reasons2,
                "reruns": 0,
                "retries": 0,
            }
            return {**_assessment2, "final_integrity": {"status": "FAIL", "binding_failure": True}}
        raise
    assessment = {
        "decision": decision,
        "candidate_sha": manifest.get("candidate_sha"),
        "candidate_tree": manifest.get("candidate_tree"),
        "run_id": manifest.get("run_id"),
        "static_input_manifest_hash": sha256_path(evidence_root / "run-manifest.json")
        if (evidence_root / "run-manifest.json").is_file()
        else None,
        "environment_id": manifest.get("environment_id"),
        "support_matrix_sha256": sha256_path(
            evidence_root / "providers/support-matrix.json"
        )
        if (evidence_root / "providers/support-matrix.json").is_file()
        else None,
        "evidence_manifest_hash": __import__(
            "tools.prod_readiness.common", fromlist=["sha256_owned_rel"]
        ).sha256_owned_rel(owned, "integrity/evidence-manifest.json"),
        "verification": verification,
        "reasons": sorted(set(reasons)),
        "reruns": 0,
        "retries": 0,
    }
    # Descriptor-anchored authoritative writes (ROOTFD-05): never via
    # run_root / "assessment/..." path fallback.
    from tools.prod_readiness.common import canonical_json_bytes as _cjb

    # Sealing the non-terminal evidence manifest is complete.  Trigger the
    # deterministic late-race point and establish the final public binding
    # before publishing any assessment that can claim PASS.
    owned.test_event(
        "before_terminal_binding",
        artifact="assessment/prod-readiness-final.json",
    )
    try:
        owned.assert_public_binding()
    except RunnerError:
        reasons.append("public run-root binding failed before terminal assessment")
        return {
            **assessment,
            "decision": "NOT_READY",
            "reasons": sorted(set(reasons)),
            "final_integrity": {"status": "FAIL", "binding_failure": True},
        }

    owned.atomic_create_bytes_rel(
        "assessment/prod-readiness-final.json", _cjb(assessment)
    )
    lines = [
        "# PROD-READINESS final assessment",
        "",
        f"Decision: **{decision}**",
        "",
        f"Candidate: `{assessment['candidate_sha']}`",
        f"Run: `{assessment['run_id']}`",
        "",
        "## Gate findings",
        "",
    ]
    lines.extend(
        [f"- {reason}" for reason in assessment["reasons"]]
        or ["- All exact release gates satisfied."]
    )
    owned.atomic_create_bytes_rel(
        "assessment/prod-readiness-report.md", ("\n".join(lines) + "\n").encode()
    )
    final = finalize_integrity(
        root,
        evidence_manifest=evidence_manifest,
        assessment_paths=(
            "assessment/prod-readiness-final.json",
            "assessment/prod-readiness-report.md",
        ),
        owned=owned,
    )
    after = {
        path.relative_to(evidence_root).as_posix(): sha256_path(path)
        for path in evidence_root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if before != after:
        raise RunnerError(
            ErrorCode.INTEGRITY_MISMATCH, "aggregator changed sealed input evidence"
        )
    return {**assessment, "final_integrity": final}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--candidate-sha")
    parser.add_argument("--candidate-tree")
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    try:
        result = aggregate(
            args.run_root,
            expected_candidate_sha=args.candidate_sha,
            expected_candidate_tree=args.candidate_tree,
            expected_run_id=args.run_id,
        )
    except RunnerError as exc:
        print(json.dumps(exc.to_dict(), sort_keys=True))
        return 2
    print(result["decision"])
    return 0 if result["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
