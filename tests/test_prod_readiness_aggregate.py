"""Exact release-gate and integrity tests for PR-HARNESS-002."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_prod_readiness_safety import CANDIDATE, build_valid_evidence
from tools.prod_readiness.aggregate import REQUIRED_PATHS, aggregate, evaluate_gate
from tools.prod_readiness.common import verify_final_integrity


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def passing_documents() -> dict[str, dict[str, object]]:
    documents: dict[str, dict[str, object]] = {
        relative: {"status": "PASS"} for relative in REQUIRED_PATHS
    }
    documents["suites/pr-03.json"]["crash_matrix"] = "PASS"
    documents["suites/pr-04.json"]["metrics"] = {
        "false_human_gate": 0,
        "unauthorized_writes": 0,
        "unrelated_signals": 0,
        "evidence_corruption": 0,
        "persistent_resource_leaks": 0,
        "candidate_worktree_loss": 0,
        "automatic_git_publication": False,
        "automatic_human_gate_acceptance": False,
    }
    documents["suites/pr-05.json"].update(
        critical_total=22,
        critical_killed=22,
        important_threshold_satisfied=True,
    )
    documents["suites/pr-06.json"]["stress"] = "PASS"
    documents["suites/pr-07.json"].update(
        soak="PASS", required_real_provider_support="PASS"
    )
    documents["findings/register.json"] = {"findings": []}
    documents["review/status.json"] = {"integrity": "CLEAN", "status": "COMPLETE"}
    documents["providers/support-matrix.json"] = {
        "providers": [
            {
                "provider_id": "fixture",
                "capabilities": {
                    "normal_execution": {
                        "required": True,
                        "status": "SUPPORTED",
                        "evidence_level": 1,
                    },
                    "optional-unreachable": {
                        "required": False,
                        "status": "DEFERRED",
                        "evidence_level": None,
                    },
                },
            }
        ]
    }
    return documents


class GateEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.docs = passing_documents()

    def decision(self, mutate=None):
        documents = copy.deepcopy(self.docs)
        if mutate:
            mutate(documents)
        return evaluate_gate(documents)

    def test_AGG_01_all_pass(self):
        self.assertEqual("PASS", self.decision()[0])

    def test_AGG_02_H2_11_missing_suite(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(lambda docs: docs["suites/pr-02.json"].clear())[0],
        )

    def test_AGG_03_04_05_findings(self):
        for severity in ("BLOCKER", "HIGH", "MEDIUM"):
            with self.subTest(severity=severity):
                decision = self.decision(
                    lambda docs, severity=severity: docs[
                        "findings/register.json"
                    ].update(findings=[{"severity": severity, "status": "OPEN"}])
                )[0]
                self.assertEqual("NOT_READY", decision)

    def test_AGG_06_unaccepted_low(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(
                lambda docs: docs["findings/register.json"].update(
                    findings=[{"severity": "LOW", "status": "OPEN"}]
                )
            )[0],
        )

    def test_AGG_07_critical_survivor(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(
                lambda docs: docs["suites/pr-05.json"].update(critical_killed=21)
            )[0],
        )

    def test_AGG_08_stress_failure(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(lambda docs: docs["suites/pr-06.json"].update(stress="FAIL"))[
                0
            ],
        )

    def test_AGG_09_soak_failure(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(lambda docs: docs["suites/pr-07.json"].update(soak="FAIL"))[
                0
            ],
        )

    def test_AGG_10_H2_10_required_deferred(self):
        def mutate(docs):
            docs["providers/support-matrix.json"]["providers"][0]["capabilities"][
                "normal_execution"
            ]["status"] = "DEFERRED"

        self.assertEqual("NOT_READY", self.decision(mutate)[0])

    def test_AGG_11_optional_deferred_eligible(self):
        self.assertEqual("PASS", self.decision()[0])

    def test_AGG_14_dirty_review(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(
                lambda docs: docs["review/status.json"].update(integrity="DIRTY")
            )[0],
        )

    def test_AGG_15_false_human_gate(self):
        def mutate(docs):
            docs["suites/pr-04.json"]["metrics"]["false_human_gate"] = 1

        self.assertEqual("NOT_READY", self.decision(mutate)[0])

    def test_H2_failure_publication_controls(self):
        for key in ("automatic_git_publication", "automatic_human_gate_acceptance"):
            with self.subTest(key=key):

                def mutate(docs, key=key):
                    docs["suites/pr-04.json"]["metrics"][key] = True

                self.assertEqual("NOT_READY", self.decision(mutate)[0])


class AggregateIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pr-harness-002-aggregate-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        environment = mock.patch.dict(
            os.environ, {"PROD_READINESS_RUN_ROOT": str(self.base)}, clear=False
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.root = self.base / "aggregate-run"
        self.root.mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        manifest = build_valid_evidence(self.evidence)
        manifest["candidate_tree"] = "tree-fixture"
        manifest["environment_id"] = "env-fixture"
        sequence = max(entry["sequence"] for entry in manifest["artifacts"])
        for relative, value in passing_documents().items():
            _write(self.evidence / relative, value)
            sequence += 1
            manifest["artifacts"].append(
                {
                    "path": relative,
                    "sha256": _digest(self.evidence / relative),
                    "kind": "release-gate-input",
                    "logical_id": relative,
                    "immutable": True,
                    "sequence": sequence,
                }
            )
            manifest["required_artifacts"].append(relative)
        _write(self.evidence / "run-manifest.json", manifest)

    def snapshot(self):
        return {
            path.relative_to(self.evidence).as_posix(): _digest(path)
            for path in self.evidence.rglob("*")
            if path.is_file()
        }

    def _aggregate_pass(self):
        return aggregate(
            self.root,
            expected_candidate_sha=CANDIDATE,
            expected_candidate_tree="tree-fixture",
            expected_run_id="evidence-run-1",
        )

    def test_AGG_01_16_17_H2_13_sealed_pass_is_read_only(self):
        before = self.snapshot()
        result = self._aggregate_pass()
        self.assertEqual("PASS", result["decision"])
        self.assertEqual(0, result["reruns"])
        self.assertEqual(0, result["retries"])
        self.assertEqual(before, self.snapshot())
        self.assertTrue(verify_final_integrity(self.root))
        self.assertTrue((self.root / "assessment/prod-readiness-final.json").is_file())
        self.assertTrue((self.root / "assessment/prod-readiness-report.md").is_file())

    def test_AGG_12_13_hash_mismatch_and_verifier_failure(self):
        path = self.evidence / "suites/pr-01.json"
        _write(path, {"status": "PASS", "tampered": True})
        result = aggregate(
            self.root,
            expected_candidate_sha=CANDIDATE,
            expected_candidate_tree="tree-fixture",
            expected_run_id="evidence-run-1",
        )
        self.assertEqual("NOT_READY", result["decision"])
        self.assertEqual("FAIL", result["verification"]["status"])

    def test_H2_12_post_seal_mutation_detected(self):
        self._aggregate_pass()
        path = self.evidence / "suites/pr-01.json"
        path.write_text(path.read_text() + " ", encoding="utf-8")
        self.assertFalse(verify_final_integrity(self.root))

    def test_R3HNEW_06_TERMROOT_03_SEALPASS_03_late_swap_has_no_pass_assessment(self):
        state: dict[str, object] = {"done": False}

        def hook(event, _details):
            if event != "before_terminal_binding" or state["done"]:
                return
            backup = self.base / "aggregate-terminal-original"
            os.rename(self.root, backup)
            self.root.mkdir(mode=0o700)
            (self.root / "decoy.txt").write_text("decoy", encoding="utf-8")
            state.update(done=True, backup=backup)

        try:
            result = aggregate(
                self.root,
                expected_candidate_sha=CANDIDATE,
                expected_candidate_tree="tree-fixture",
                expected_run_id="evidence-run-1",
                _test_hook=hook,
            )
            self.assertEqual("NOT_READY", result["decision"])
            backup = state["backup"]
            final_path = backup / "assessment/prod-readiness-final.json"
            if final_path.exists():
                self.assertNotEqual("PASS", json.loads(final_path.read_text())["decision"])
            self.assertFalse(verify_final_integrity(backup))
        finally:
            backup = state.get("backup")
            if isinstance(backup, Path):
                import shutil

                if self.root.exists():
                    shutil.rmtree(self.root)
                os.rename(backup, self.root)

    def test_SEALPASS_04_normal_run_has_one_terminal_pass(self):
        result = self._aggregate_pass()
        self.assertEqual("PASS", result["decision"])
        finals = list(self.root.rglob("prod-readiness-final.json"))
        self.assertEqual(1, len(finals))
        self.assertEqual("PASS", json.loads(finals[0].read_text())["decision"])
        self.assertTrue(verify_final_integrity(self.root))

    def test_SEALPASS_05_crash_before_terminal_predicate_has_no_pass(self):
        def crash(event, _details):
            if event == "before_terminal_binding":
                raise RuntimeError("simulated crash")

        with self.assertRaises(RuntimeError):
            aggregate(
                self.root,
                expected_candidate_sha=CANDIDATE,
                expected_candidate_tree="tree-fixture",
                expected_run_id="evidence-run-1",
                _test_hook=crash,
            )
        final_path = self.root / "assessment/prod-readiness-final.json"
        self.assertFalse(final_path.exists())


class ReviewCompletenessTests(unittest.TestCase):
    def setUp(self):
        self.docs = passing_documents()

    def decision(self, mutate=None):
        documents = copy.deepcopy(self.docs)
        if mutate:
            mutate(documents)
        return evaluate_gate(documents)

    def test_REV_01_clean_complete_eligible(self):
        self.assertEqual("PASS", self.decision()[0])

    def test_REV_02_clean_incomplete_not_ready(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(
                lambda docs: docs["review/status.json"].update(status="INCOMPLETE")
            )[0],
        )

    def test_REV_03_clean_running_not_ready(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(
                lambda docs: docs["review/status.json"].update(status="RUNNING")
            )[0],
        )

    def test_REV_04_missing_status_not_ready(self):
        def mutate(docs):
            docs["review/status.json"].pop("status", None)

        self.assertEqual("NOT_READY", self.decision(mutate)[0])

    def test_REV_05_dirty_not_ready(self):
        self.assertEqual(
            "NOT_READY",
            self.decision(
                lambda docs: docs["review/status.json"].update(integrity="DIRTY")
            )[0],
        )

    def test_R1H_08_status_ignored_killed(self):
        # Mutant ignoring review status would PASS with INCOMPLETE; we require NOT_READY.
        docs = copy.deepcopy(self.docs)
        docs["review/status.json"] = {"integrity": "CLEAN", "status": "INCOMPLETE"}
        decision, _ = evaluate_gate(docs)
        self.assertEqual("NOT_READY", decision)


class AggregatorIdentityBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pr-harness-002-id-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        environment = mock.patch.dict(
            os.environ, {"PROD_READINESS_RUN_ROOT": str(self.base)}, clear=False
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.root = self.base / "id-run"
        self.root.mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        manifest = build_valid_evidence(self.evidence)
        manifest["candidate_tree"] = "tree-id"
        manifest["environment_id"] = "env-id"
        sequence = max(entry["sequence"] for entry in manifest["artifacts"])
        for relative, value in passing_documents().items():
            _write(self.evidence / relative, value)
            sequence += 1
            manifest["artifacts"].append(
                {
                    "path": relative,
                    "sha256": _digest(self.evidence / relative),
                    "kind": "release-gate-input",
                    "logical_id": relative,
                    "immutable": True,
                    "sequence": sequence,
                }
            )
            manifest["required_artifacts"].append(relative)
        _write(self.evidence / "run-manifest.json", manifest)

    def test_identity_omitted_not_ready(self):
        result = aggregate(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("NOT_READY", result["decision"])

    def test_identity_mismatch_not_ready(self):
        result = aggregate(
            self.root,
            expected_candidate_sha="0" * 40,
            expected_candidate_tree="tree-id",
            expected_run_id="evidence-run-1",
        )
        self.assertEqual("NOT_READY", result["decision"])

    def test_identity_tree_mismatch_not_ready(self):
        result = aggregate(
            self.root,
            expected_candidate_sha=CANDIDATE,
            expected_candidate_tree="wrong-tree",
            expected_run_id="evidence-run-1",
        )
        self.assertEqual("NOT_READY", result["decision"])

    def test_identity_run_mismatch_not_ready(self):
        result = aggregate(
            self.root,
            expected_candidate_sha=CANDIDATE,
            expected_candidate_tree="tree-id",
            expected_run_id="wrong-run",
        )
        self.assertEqual("NOT_READY", result["decision"])

    def test_identity_match_pass(self):
        result = aggregate(
            self.root,
            expected_candidate_sha=CANDIDATE,
            expected_candidate_tree="tree-id",
            expected_run_id="evidence-run-1",
        )
        self.assertEqual("PASS", result["decision"])


class FinalIntegrityFileSetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pr-harness-002-fs-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        environment = mock.patch.dict(
            os.environ, {"PROD_READINESS_RUN_ROOT": str(self.base)}, clear=False
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.root = self.base / "fs-run"
        self.root.mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        manifest = build_valid_evidence(self.evidence)
        manifest["candidate_tree"] = "tree-fs"
        sequence = max(entry["sequence"] for entry in manifest["artifacts"])
        for relative, value in passing_documents().items():
            _write(self.evidence / relative, value)
            sequence += 1
            manifest["artifacts"].append(
                {
                    "path": relative,
                    "sha256": _digest(self.evidence / relative),
                    "kind": "release-gate-input",
                    "logical_id": relative,
                    "immutable": True,
                    "sequence": sequence,
                }
            )
            manifest["required_artifacts"].append(relative)
        _write(self.evidence / "run-manifest.json", manifest)

    def _pass(self):
        return aggregate(
            self.root,
            expected_candidate_sha=CANDIDATE,
            expected_candidate_tree="tree-fs",
            expected_run_id="evidence-run-1",
        )

    def test_new_json_invalidates(self):
        self._pass()
        _write(self.root / "assessment" / "extra.json", {"x": 1})
        self.assertFalse(verify_final_integrity(self.root))

    def test_new_uppercase_json_invalidates(self):
        self._pass()
        _write(self.root / "assessment" / "EXTRA.JSON", {"x": 1})
        self.assertFalse(verify_final_integrity(self.root))

    def test_new_nonjson_invalidates(self):
        self._pass()
        target = self.root / "assessment" / "extra.txt"
        target.write_text("x", encoding="utf-8")
        self.assertFalse(verify_final_integrity(self.root))

    def test_unexpected_symlink_invalidates(self):
        self._pass()
        link = self.root / "assessment" / "link.json"
        try:
            link.symlink_to(self.root / "assessment" / "prod-readiness-final.json")
        except OSError:
            self.skipTest("symlink not supported")
        self.assertFalse(verify_final_integrity(self.root))


if __name__ == "__main__":
    unittest.main()
