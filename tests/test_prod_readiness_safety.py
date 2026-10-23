"""Evidence, containment, resource, and sentinel harness self-tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tests.prod_readiness_support import (
    ContainmentPolicy,
    HarnessSafetyError,
    SignalSentinel,
    capture_resource_snapshot,
    clear_owned_process_registry,
    register_owned_process,
)
from tools.prod_readiness.verify_evidence import verify_evidence


CANONICAL_REPO = Path(__file__).resolve().parents[1]
CANDIDATE = "a" * 40


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_json(root: Path, relative: str, value: Any) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_valid_evidence(root: Path) -> dict[str, Any]:
    plan = {
        "queue_id": "queue-1",
        "queue_run_id": "queue-run-1",
        "items": [
            {
                "ordinal": index,
                "item_id": f"item-{index}",
                "program": {"program_id": f"program-{index}"},
                "task": {"task_id": f"task-{index}"},
                "baseline_commit": CANDIDATE,
            }
            for index in (1, 2)
        ],
    }
    documents: list[tuple[str, dict[str, Any], str, str, bool]] = [
        ("queue-plan.json", plan, "queue-plan", "queue-1", True),
        (
            "queue-started.json",
            {"queue_id": "queue-1", "queue_run_id": "queue-run-1", "item_count": 2},
            "queue-started",
            "queue-run-1",
            True,
        ),
    ]
    summaries = []
    for ordinal in (1, 2):
        item_id = f"item-{ordinal}"
        run_id = f"program-run-{ordinal}"
        program_id = f"program-{ordinal}"
        task_id = f"task-{ordinal}"
        item_dir = f"programs/{ordinal:02d}-{item_id}"
        final_path = f"runs/{run_id}/final.json"
        final = {
            "program_id": program_id,
            "task_id": task_id,
            "run_id": run_id,
            "candidate_sha": CANDIDATE,
            "verdict": "HUMAN_GATE",
            "status": "SUCCESS",
            "human_gate": True,
        }
        _write_json(root, final_path, final)
        outcome = {
            **final,
            "final_path": final_path,
            "final_sha256": _digest(root / final_path),
            "outcome_class": "HUMAN_GATE",
            "baseline_commit": CANDIDATE,
            "preservation_status": "NOT_REQUIRED",
            "preservation_evidence_path": None,
            "process_quiescence": "PROVEN",
        }
        start = {
            "ordinal": ordinal,
            "item_id": item_id,
            "program_id": program_id,
            "task_id": task_id,
            "run_id": run_id,
        }
        terminal = {"ordinal": ordinal, "item_id": item_id, "program_outcome": outcome}
        documents.extend(
            [
                (f"{item_dir}/item-started.json", start, "item-started", item_id, True),
                (final_path, final, "program-final", run_id, True),
                (f"{item_dir}/item-terminal.json", terminal, "item-terminal", item_id, True),
            ]
        )
        summaries.append(
            {
                "ordinal": ordinal,
                "item_id": item_id,
                "program_id": program_id,
                "task_id": task_id,
                "run_id": run_id,
                "verdict": "HUMAN_GATE",
                "status": "SUCCESS",
                "outcome_class": "HUMAN_GATE",
            }
        )
    queue_final = {
        "queue_id": "queue-1",
        "queue_run_id": "queue-run-1",
        "verdict": "HUMAN_GATES_READY",
        "status": "SUCCESS",
        "completed_items": summaries,
        "not_started_items": [],
        "pending_human_gates": copy.deepcopy(summaries),
    }
    documents.extend(
        [
            ("final.json", queue_final, "queue-final", "queue-run-1", True),
            (
                "queue-state.json",
                {
                    "queue_id": "queue-1",
                    "status": "SUCCESS",
                    "current_item_id": None,
                    "completed_item_ids": ["item-1", "item-2"],
                },
                "diagnostic-queue-state",
                "queue-state",
                False,
            ),
            (
                "budget-state.json",
                {
                    "queue_id": "queue-1",
                    "used": {"model_calls": 0, "retries": 0, "fallbacks": 0, "corrections": 0},
                    "reservations": [],
                },
                "diagnostic-budget-state",
                "budget-state",
                False,
            ),
        ]
    )
    # Write again in the declared evidence order. The final files were already
    # created solely so item terminals could include their exact hashes.
    artifacts = []
    for sequence, (relative, value, kind, logical_id, immutable) in enumerate(documents, 1):
        _write_json(root, relative, value)
        artifacts.append(
            {
                "path": relative,
                "sha256": _digest(root / relative),
                "kind": kind,
                "logical_id": logical_id,
                "immutable": immutable,
                "sequence": sequence,
            }
        )
    manifest = {
        "schema_version": 1,
        "run_id": "evidence-run-1",
        "queue_id": "queue-1",
        "queue_run_id": "queue-run-1",
        "candidate_sha": CANDIDATE,
        "sealed": True,
        "required_artifacts": [entry["path"] for entry in artifacts if entry["immutable"]],
        "artifacts": artifacts,
    }
    _write_json(root, "run-manifest.json", manifest)
    return manifest


def rewrite_manifest_digests(root: Path) -> None:
    path = root / "run-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for entry in manifest["artifacts"]:
        artifact = root / entry["path"]
        if artifact.is_file():
            entry["sha256"] = _digest(artifact)
    _write_json(root, "run-manifest.json", manifest)


def codes(result: dict[str, Any]) -> set[str]:
    return {item["code"] for item in result["errors"]}


class EvidenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-evidence-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def verify(self, **kwargs: Any) -> dict[str, Any]:
        return verify_evidence(self.root, **kwargs)

    def mutate_json(self, relative: str, change) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        _write_json(self.root, relative, value)
        rewrite_manifest_digests(self.root)

    def test_valid_evidence_passes_and_verification_is_read_only(self):
        before = {
            path.relative_to(self.root).as_posix(): _digest(path)
            for path in self.root.rglob("*")
            if path.is_file()
        }
        result = self.verify(expected_candidate_sha=CANDIDATE)
        after = {
            path.relative_to(self.root).as_posix(): _digest(path)
            for path in self.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual("PASS", result["status"], result)
        self.assertEqual([], result["errors"])
        self.assertEqual(before, after)

    def test_ev01_missing_required_artifact(self):
        (self.root / "queue-started.json").unlink()
        self.assertIn("EV-01", codes(self.verify()))

    def test_ev02_malformed_json(self):
        (self.root / "queue-plan.json").write_text('{"queue_id": nope}', encoding="utf-8")
        self.assertIn("EV-02", codes(self.verify()))

    def test_ev03_truncated_json(self):
        (self.root / "queue-plan.json").write_text('{"queue_id":"queue-1",', encoding="utf-8")
        self.assertIn("EV-03", codes(self.verify()))

    def test_ev04_digest_mismatch(self):
        self.mutate_json("queue-started.json", lambda value: value.update(item_count=99))
        manifest = json.loads((self.root / "run-manifest.json").read_text())
        entry = next(item for item in manifest["artifacts"] if item["path"] == "queue-started.json")
        entry["sha256"] = "0" * 64
        _write_json(self.root, "run-manifest.json", manifest)
        self.assertIn("EV-04", codes(self.verify()))

    def test_ev05_duplicate_immutable_logical_marker(self):
        manifest = json.loads((self.root / "run-manifest.json").read_text())
        first, second = manifest["artifacts"][0:2]
        second["kind"] = first["kind"]
        second["logical_id"] = first["logical_id"]
        _write_json(self.root, "run-manifest.json", manifest)
        self.assertIn("EV-05", codes(self.verify()))

    def test_ev06_broken_reference(self):
        def break_ref(value):
            value["program_outcome"]["final_path"] = "runs/missing/final.json"
        self.mutate_json("programs/01-item-1/item-terminal.json", break_ref)
        self.assertIn("EV-06", codes(self.verify()))

    def test_ev07_candidate_sha_mismatch(self):
        result = self.verify(expected_candidate_sha="b" * 40)
        self.assertIn("EV-07", codes(result))

    def test_candidate_tree_identity_mismatch(self):
        self.mutate_json("queue-plan.json", lambda value: value.update(candidate_tree="wrong-tree"))
        manifest = json.loads((self.root / "run-manifest.json").read_text())
        manifest["candidate_tree"] = "expected-tree"
        _write_json(self.root, "run-manifest.json", manifest)
        self.assertIn("EV-07", codes(self.verify()))

    def test_ev08_cross_id_mismatch(self):
        self.mutate_json("runs/program-run-1/final.json", lambda value: value.update(task_id="wrong"))
        self.assertIn("EV-08", codes(self.verify()))

    def test_ev09_verdict_status_mismatch(self):
        self.mutate_json("runs/program-run-1/final.json", lambda value: value.update(status="STOPPED"))
        self.assertIn("EV-09", codes(self.verify()))

    def test_ev10_invalid_human_gate_reference(self):
        def invalidate(value):
            value["completed_items"][0]["outcome_class"] = "PROGRAM_LOCAL_FAILURE"
        self.mutate_json("final.json", invalidate)
        self.assertIn("EV-10", codes(self.verify()))

    def test_ev11_counter_reservation_inconsistency(self):
        def invalidate(value):
            value["used"]["model_calls"] = 1
        self.mutate_json("budget-state.json", invalidate)
        self.assertIn("EV-11", codes(self.verify()))

    def test_ev12_leading_diagnostic_snapshot(self):
        def lead(value):
            value["completed_item_ids"].append("item-never-terminal")
        self.mutate_json("queue-state.json", lead)
        self.assertIn("EV-12", codes(self.verify()))

    def test_ev13_item_terminal_without_program_terminal_contract(self):
        def invalidate(value):
            value.pop("program_outcome")
        self.mutate_json("programs/01-item-1/item-terminal.json", invalidate)
        self.assertIn("EV-13", codes(self.verify()))

    def test_ev14_next_item_before_prior_terminal(self):
        manifest = json.loads((self.root / "run-manifest.json").read_text())
        entries = {entry["path"]: entry for entry in manifest["artifacts"]}
        entries["programs/02-item-2/item-started.json"]["sequence"] = 2
        _write_json(self.root, "run-manifest.json", manifest)
        self.assertIn("EV-14", codes(self.verify()))

    def test_ev15_unlisted_authority_before_seal(self):
        manifest = json.loads((self.root / "run-manifest.json").read_text())
        manifest["sealed"] = False
        _write_json(self.root, "run-manifest.json", manifest)
        _write_json(self.root, "extra/item-terminal.json", {"item_id": "extra"})
        self.assertIn("EV-01", codes(self.verify()))
        self.assertIn("EV-15", codes(self.verify(require_sealed=False)))

    def test_ev16_unexpected_authority_after_seal(self):
        _write_json(self.root, "extra/item-terminal.json", {"item_id": "extra"})
        self.assertIn("EV-16", codes(self.verify()))

    def test_lagging_diagnostic_is_warning_only(self):
        def lag(value):
            value["completed_item_ids"] = ["item-1"]
        self.mutate_json("queue-state.json", lag)
        result = self.verify()
        self.assertEqual("PASS", result["status"], result)
        self.assertIn("EV-W01", {item["code"] for item in result["warnings"]})

    def test_non_json_static_input_is_hashed_without_parsing(self):
        static = self.root / "inputs/prompt.md"
        static.parent.mkdir(parents=True)
        static.write_bytes(b"# immutable prompt\nnot json\n")
        manifest = json.loads((self.root / "run-manifest.json").read_text())
        manifest["static_inputs"] = [
            {"path": "inputs/prompt.md", "sha256": _digest(static), "kind": "static-input"}
        ]
        _write_json(self.root, "run-manifest.json", manifest)
        self.assertEqual("PASS", self.verify()["status"])

    def test_release_verification_fails_unsealed_evidence_with_ev01(self):
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["sealed"] = False
        _write_json(self.root, "run-manifest.json", manifest)
        result = self.verify()
        self.assertEqual("FAIL", result["status"])
        self.assertIn("EV-01", codes(result))
        in_prog = self.verify(require_sealed=False)
        self.assertEqual("PASS", in_prog["status"], in_prog)


class SafetySupportTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-safety-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.policy = ContainmentPolicy.create(self.root, CANONICAL_REPO)

    def test_canonical_target_refused(self):
        with self.assertRaises(HarnessSafetyError):
            self.policy.require_owned_target(CANONICAL_REPO)

    def test_canonical_git_common_dir_refused(self):
        with self.assertRaises(HarnessSafetyError):
            self.policy.require_owned_target(CANONICAL_REPO / ".git")

    def test_symlink_alias_into_canonical_repo_refused(self):
        alias = self.root / "canonical-alias"
        alias.symlink_to(CANONICAL_REPO, target_is_directory=True)
        with self.assertRaises(HarnessSafetyError):
            self.policy.require_owned_target(alias / "tests")

    def test_parent_escape_refused(self):
        with self.assertRaises(HarnessSafetyError):
            self.policy.require_owned_target(self.root / ".." / "escape")

    def test_owned_nested_target_allowed(self):
        target = self.root / "nested" / "target"
        self.assertEqual(target.resolve(strict=False), self.policy.require_owned_target(target))

    def test_owned_symlink_cleanup_removes_link_not_target(self):
        target = self.root / "owned-target"
        target.mkdir()
        (target / "keep.txt").write_text("keep\n", encoding="utf-8")
        alias = self.root / "owned-alias"
        alias.symlink_to(target, target_is_directory=True)
        self.policy.remove_owned(alias)
        self.assertFalse(alias.exists())
        self.assertTrue((target / "keep.txt").is_file())

    def test_resource_snapshot_repeatability(self):
        declared = self.root / "declared"
        declared.mkdir()
        manifest = {"temp_directories": [str(declared)]}
        first = capture_resource_snapshot(fixture_manifest=manifest)
        second = capture_resource_snapshot(fixture_manifest=manifest)
        self.assertEqual(first, second)

    def test_unexpected_active_owned_process_is_a_leak(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
        self.addCleanup(cleanup)
        snapshot = capture_resource_snapshot(owner_pids=[proc.pid])
        self.assertTrue(any(item.kind == "process" for item in snapshot.unexpected_leaks))
        proc.kill()
        proc.wait(timeout=5)

    def test_expected_and_unexpected_leases_are_distinguished(self):
        expected = self.root / "expected.lease"
        unexpected = self.root / "unexpected.lease"
        expected.write_text("{}", encoding="utf-8")
        unexpected.write_text("{}", encoding="utf-8")
        snapshot = capture_resource_snapshot(
            fixture_manifest={
                "write_leases": [str(expected), str(unexpected)],
                "expected_preserved_leases": [str(expected)],
            }
        )
        classes = {Path(item.identity).name: item.classification for item in snapshot.write_leases}
        self.assertEqual("EXPECTED_PRESERVED", classes[expected.name])
        self.assertEqual("UNEXPECTED_LEAK", classes[unexpected.name])

    def test_expected_preserved_and_unexpected_worktrees_are_distinguished(self):
        repo = self.root / "source"
        expected = self.root / "preserved-worktree"
        unexpected = self.root / "leaked-worktree"
        repo.mkdir()
        commands = [
            ["git", "init", str(repo)],
            ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
            ["git", "-C", str(repo), "config", "user.name", "Harness Test"],
        ]
        for argv in commands:
            subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-m", "baseline"], check=True, stdout=subprocess.PIPE)
        for worktree in (expected, unexpected):
            subprocess.run(
                ["git", "-C", str(repo), "worktree", "add", "--detach", str(worktree), "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        snapshot = capture_resource_snapshot(
            source_repo=repo,
            fixture_manifest={
                "temp_directories": [str(self.root)],
                "expected_preserved_worktrees": [str(expected)],
            },
        )
        classes = {Path(item.identity).name: item.classification for item in snapshot.worktrees}
        self.assertEqual("EXPECTED_PRESERVED", classes[expected.name])
        self.assertEqual("UNEXPECTED_LEAK", classes[unexpected.name])

    def test_sentinel_survives_crash_harness_and_reports_no_signal(self):
        from tests.prod_readiness_support import CrashDriver

        with SignalSentinel(self.policy) as sentinel:
            CrashDriver(self.policy).run("sentinel-neighbor", "before_authoritative_write")
            sentinel.assert_untouched()
            self.assertEqual((), sentinel.signal_events())

    def test_sentinel_assertion_detects_recorded_signal_without_sending_one(self):
        with SignalSentinel(self.policy, "signal-evidence") as sentinel:
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"kind": "SIGNAL", "signal": 15}) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            with self.assertRaisesRegex(AssertionError, "received signal"):
                sentinel.assert_untouched()


class RelativeTargetContractR3Tests(unittest.TestCase):
    """REL-01..08/R3-M1: CWD never influences destructive targets."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-relative-r3-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.policy = ContainmentPolicy.create(self.root, CANONICAL_REPO)
        self.original_cwd = Path.cwd()
        self.addCleanup(os.chdir, self.original_cwd)

    def test_REL01_FC01_R3_M1_parent_relative_target_is_rejected(self):
        cwd = self.root / "sub/deep"
        cwd.mkdir(parents=True)
        canary = self.root / "sub/canary.txt"
        canary.write_text("safe\n", encoding="utf-8")
        os.chdir(cwd)
        with self.assertRaisesRegex(HarnessSafetyError, "PARENT_TRAVERSAL"):
            self.policy.remove_owned(Path(".."))
        self.assertTrue(canary.is_file())

    def test_REL02_relative_target_is_disposable_root_relative(self):
        cwd = self.root / "a"
        cwd.mkdir()
        root_target = self.root / "b"
        cwd_target = cwd / "b"
        root_target.mkdir()
        cwd_target.mkdir()
        (root_target / "delete.txt").write_text("delete", encoding="utf-8")
        (cwd_target / "keep.txt").write_text("keep", encoding="utf-8")
        os.chdir(cwd)
        self.policy.remove_owned(Path("b"))
        self.assertFalse(root_target.exists())
        self.assertTrue((cwd_target / "keep.txt").is_file())

    def test_REL03_cwd_change_after_authorization_does_not_retarget(self):
        target = self.root / "victim"
        target.mkdir()
        decoy_cwd = self.root / "elsewhere"
        decoy_cwd.mkdir()
        decoy = decoy_cwd / "victim"
        decoy.mkdir()
        (decoy / "keep.txt").write_text("keep", encoding="utf-8")

        def hook(stage, _data):
            if stage == "after_authorization":
                os.chdir(decoy_cwd)

        self.policy.set_test_hook(hook)
        try:
            self.policy.remove_owned(Path("victim"))
        finally:
            self.policy.set_test_hook(None)
        self.assertFalse(target.exists())
        self.assertTrue((decoy / "keep.txt").is_file())

    def test_REL04_relative_authorization_is_identical_from_three_cwds(self):
        expected = self.root / "same-target"
        observed = []
        for name in ("one", "two", "three"):
            cwd = self.root / name
            cwd.mkdir()
            os.chdir(cwd)
            observed.append(self.policy.require_owned_target(Path("same-target")))
        self.assertEqual([expected, expected, expected], observed)

    def test_REL05_absolute_owned_target_deletes(self):
        target = self.root / "absolute-target"
        target.mkdir()
        self.policy.remove_owned(target)
        self.assertFalse(target.exists())

    def test_REL06_absolute_outside_root_is_rejected(self):
        with self.assertRaisesRegex(HarnessSafetyError, "OUTSIDE_DISPOSABLE_ROOT"):
            self.policy.remove_owned(CANONICAL_REPO)

    def test_REL07_relative_parent_escape_is_rejected(self):
        with self.assertRaisesRegex(HarnessSafetyError, "PARENT_TRAVERSAL"):
            self.policy.remove_owned(Path("nested/../../escape"))

    def test_REL08_dot_is_explicitly_rejected(self):
        with self.assertRaisesRegex(HarnessSafetyError, "IS_DISPOSABLE_ROOT"):
            self.policy.remove_owned(Path("."))

    def test_G1B_nested_walk_remains_root_fd_relative(self):
        target = self.root / "nested/leaf"
        target.mkdir(parents=True)
        foreign_cwd = self.root / "foreign"
        decoy = foreign_cwd / "nested/leaf"
        decoy.mkdir(parents=True)
        (decoy / "keep.txt").write_text("keep", encoding="utf-8")

        def hook(stage, _data):
            if stage == "before_walk_step":
                os.chdir(foreign_cwd)

        self.policy.set_test_hook(hook)
        try:
            self.policy.remove_owned(Path("nested/leaf"))
        finally:
            self.policy.set_test_hook(None)
        self.assertFalse(target.exists())
        self.assertTrue((decoy / "keep.txt").is_file())

    def test_G2_opened_protected_inode_is_rejected(self):
        from dataclasses import replace

        target = self.root / "inode-protected"
        target.mkdir()
        st = os.stat(target)
        policy = replace(
            self.policy,
            protected_dev_ino=self.policy.protected_dev_ino
            | {(st.st_dev, st.st_ino)},
        )
        with self.assertRaisesRegex(HarnessSafetyError, "DESTRUCTIVE_TARGET_PROTECTED"):
            policy.remove_owned(target)
        self.assertTrue(target.is_dir())


def _init_temp_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    for argv in (
        ["git", "init", str(repo)],
        ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
        ["git", "-C", str(repo), "config", "user.name", "Harness Test"],
    ):
        subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "baseline"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class BidirectionalContainmentTests(unittest.TestCase):
    """BLOCKER C1-C4 + R9: protected ancestors/descendants never overlap."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-contain-")
        self.addCleanup(self._temp.cleanup)
        self.base = Path(self._temp.name).resolve()

    def test_C1_parent_containing_registered_worktree_rejected(self):
        repo = self.base / "repo"
        _init_temp_repo(repo)
        scratch = self.base / "scratch"
        scratch.mkdir()
        policy = ContainmentPolicy.create(scratch, repo)
        inner = scratch / "inner-wt"
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach", str(inner), "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # The worktree itself is protected.
        with self.assertRaises(HarnessSafetyError):
            policy.require_owned_target(inner)
        # Its parent contains a protected resource and must never be an
        # authorized destructive target.
        with self.assertRaises(HarnessSafetyError):
            policy.require_owned_target(scratch)
        with self.assertRaises(HarnessSafetyError):
            policy.remove_owned(scratch)

    def test_C2_canonical_parent_cannot_be_disposable_root(self):
        with self.assertRaisesRegex(HarnessSafetyError, "DISPOSABLE_ROOT_PROTECTED"):
            ContainmentPolicy.create(CANONICAL_REPO.parent, CANONICAL_REPO)

    def test_C2b_temp_parent_containing_repo_rejected_as_root(self):
        repo = self.base / "repo"
        _init_temp_repo(repo)
        with self.assertRaises(HarnessSafetyError):
            ContainmentPolicy.create(self.base, repo)

    def test_C3_parent_containing_git_common_dir_rejected(self):
        scratch = self.base / "scratch2"
        scratch.mkdir()
        policy = ContainmentPolicy.create(scratch, CANONICAL_REPO)
        # canonical_git_common_dir.parent contains the common dir; a directory
        # containing a protected resource must never be authorized.
        common_parent = policy.canonical_git_common_dir.parent
        with self.assertRaises(HarnessSafetyError):
            policy.require_owned_target(common_parent)

    def test_C4_normal_disposable_sibling_tree_remains_allowed(self):
        disp = self.base / "disp"
        disp.mkdir()
        policy = ContainmentPolicy.create(disp, CANONICAL_REPO)
        target = self.base / "disp" / "sibling" / "child"
        self.assertEqual(
            target.resolve(strict=False), policy.require_owned_target(target)
        )

    def test_R9_directory_containing_registered_worktree_rejected(self):
        repo = self.base / "r9repo"
        _init_temp_repo(repo)
        scratch = self.base / "r9scratch"
        scratch.mkdir()
        policy = ContainmentPolicy.create(scratch, repo)
        wt = self.base / "r9wt"
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with self.assertRaises(HarnessSafetyError):
            policy.require_owned_target(wt.parent / wt.name)
        # The directory containing the worktree (base) contains protected state.
        with self.assertRaises(HarnessSafetyError):
            ContainmentPolicy.create(self.base, repo)

    def test_C5_symlink_swap_fails_closed_and_protects_target(self):
        import shutil

        disp = self.base / "disp5"
        disp.mkdir()
        policy = ContainmentPolicy.create(disp, CANONICAL_REPO)
        inner = disp / "swap" / "inner"
        inner.mkdir(parents=True)
        (inner / "data.txt").write_text("owned\n", encoding="utf-8")
        target = disp / "swap" / "inner"
        # Authorize while safe.
        policy.require_owned_target(target)
        protected_marker = CANONICAL_REPO / "agentflow.py"
        self.assertTrue(protected_marker.is_file())
        before = protected_marker.read_bytes()
        # Swap one path component to a symlink pointing at protected state.
        shutil.rmtree(disp / "swap")
        (disp / "swap").symlink_to(CANONICAL_REPO, target_is_directory=True)
        with self.assertRaises(HarnessSafetyError):
            policy.remove_owned(target)
        # Protected target is untouched.
        self.assertTrue(protected_marker.is_file())
        self.assertEqual(before, protected_marker.read_bytes())

    def test_R4_symlink_swap_toctou_killed(self):
        import shutil

        disp = self.base / "dispR4"
        disp.mkdir()
        policy = ContainmentPolicy.create(disp, CANONICAL_REPO)
        victim_parent = disp / "level"
        victim_parent.mkdir()
        (victim_parent / "keep.txt").write_text("keep\n", encoding="utf-8")
        target = victim_parent / "keep.txt"
        policy.require_owned_target(target)
        shutil.rmtree(victim_parent)
        victim_parent.symlink_to(CANONICAL_REPO, target_is_directory=True)
        with self.assertRaises(HarnessSafetyError):
            policy.remove_owned(target)
        self.assertTrue((CANONICAL_REPO / "agentflow.py").is_file())


class ReparentedDescendantTests(unittest.TestCase):
    """HIGH RPROC-01..03 + R3: durable execution identity survives reparenting."""

    def _spawn_reparented(self):
        import signal as _signal
        import time as _time

        from tests.prod_readiness_support import process_identity as _pi

        leader = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "print(p.pid,flush=True); time.sleep(5)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        assert leader.stdout is not None
        child_pid = int(leader.stdout.readline().strip())
        identity = _pi(leader.pid)
        # Leader exits quickly; child reparents but keeps PGID/SID.
        leader.wait(timeout=10)
        self.assertIsNotNone(leader.poll())
        if leader.stdout is not None:
            leader.stdout.close()
        # Reap not needed for leader (already waited). Ensure child alive.
        child_identity = _pi(child_pid)
        self.assertEqual(identity.pgid, child_identity.pgid)
        self.assertEqual(identity.sid, child_identity.sid)

        def _cleanup():
            try:
                os.kill(child_pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            for _ in range(50):
                try:
                    _pi(child_pid)
                except (FileNotFoundError, ProcessLookupError):
                    break
                _time.sleep(0.1)

        self.addCleanup(_cleanup)
        return identity, child_pid

    def test_RPROC01_leader_exits_child_reparents_still_detected(self):
        from tests.prod_readiness_support import process_identity

        identity, child_pid = self._spawn_reparented()
        # Child reparented (PPID no longer leader) but must still be reported.
        live = process_identity(child_pid)
        self.assertNotEqual(live.ppid, identity.pid)
        snapshot = capture_resource_snapshot(owner_identities=[identity])
        pids = {int(item.identity) for item in snapshot.processes}
        self.assertIn(child_pid, pids)
        self.assertTrue(snapshot.unexpected_leaks)

    def test_R3_reparented_child_detected(self):
        identity, child_pid = self._spawn_reparented()
        snapshot = capture_resource_snapshot(owner_identities=[identity])
        self.assertTrue(
            any(int(item.identity) == child_pid for item in snapshot.unexpected_leaks)
        )

    def test_RPROC02_foreign_coincident_pgid_not_claimed(self):
        from unittest import mock

        from tests.prod_readiness_support import ProcessIdentity

        leader = ProcessIdentity(
            pid=400001,
            ppid=1,
            pgid=499991,
            sid=499991,
            start_time=100000,
            state="S",
            boot_id="real-boot-id",
            fd_count=None,
            thread_count=None,
        )
        foreign = ProcessIdentity(
            pid=400002,
            ppid=1,
            pgid=499991,
            sid=499991,
            start_time=200000,
            state="S",
            boot_id="other-boot-id",
            fd_count=None,
            thread_count=None,
        )
        with mock.patch(
            "tests.prod_readiness_support._scan_processes_with_uncertainty",
            return_value=((foreign,), False),
        ):
            snapshot = capture_resource_snapshot(owner_identities=[leader])
        pids = {item.identity for item in snapshot.processes}
        self.assertNotIn(str(foreign.pid), pids)
        self.assertEqual((), snapshot.unexpected_leaks)

    def test_RPROC02b_older_foreign_start_time_not_claimed(self):
        from unittest import mock

        from tests.prod_readiness_support import ProcessIdentity

        leader = ProcessIdentity(
            pid=400011,
            ppid=1,
            pgid=499981,
            sid=499981,
            start_time=500000,
            state="S",
            boot_id="same-boot",
            fd_count=None,
            thread_count=None,
        )
        older = ProcessIdentity(
            pid=400012,
            ppid=1,
            pgid=499981,
            sid=499981,
            start_time=1000,
            state="S",
            boot_id="same-boot",
            fd_count=None,
            thread_count=None,
        )
        with mock.patch(
            "tests.prod_readiness_support._scan_processes_with_uncertainty",
            return_value=((older,), False),
        ):
            snapshot = capture_resource_snapshot(owner_identities=[leader])
        self.assertEqual((), snapshot.unexpected_leaks)

    def test_RPROC03_churn_does_not_become_false_clean(self):
        from unittest import mock

        from tests.prod_readiness_support import ProcessIdentity

        leader = ProcessIdentity(
            pid=400021,
            ppid=1,
            pgid=499971,
            sid=499971,
            start_time=100000,
            state="S",
            boot_id="churn-boot",
            fd_count=None,
            thread_count=None,
        )
        child = ProcessIdentity(
            pid=400022,
            ppid=1,
            pgid=499971,
            sid=499971,
            start_time=100050,
            state="S",
            boot_id="churn-boot",
            fd_count=None,
            thread_count=None,
        )
        # /proc churn elsewhere (uncertainty flag) must not hide the owned
        # descendant: under R2, persistent uncertainty raises HarnessSafetyError
        # even if an owned process is present.
        with mock.patch(
            "tests.prod_readiness_support._scan_processes_with_uncertainty",
            return_value=((child,), True),
        ):
            with self.assertRaises(HarnessSafetyError):
                capture_resource_snapshot(owner_identities=[leader])


class ProcFailClosedTests(unittest.TestCase):
    """MEDIUM PROC-FC01..04 + R10: uncertainty never becomes CLEAN."""

    def test_PROCFG01_missing_proc_fails_closed(self):
        from unittest import mock

        with mock.patch(
            "tests.prod_readiness_support.LINUX_PROC_ROOT", Path("/nonexistent-proc-xyz")
        ):
            with self.assertRaises(HarnessSafetyError):
                capture_resource_snapshot(owner_pids=[1])

    def test_R10_missing_proc_fail_closed(self):
        from unittest import mock

        with mock.patch(
            "tests.prod_readiness_support.LINUX_PROC_ROOT", Path("/nonexistent-proc-xyz")
        ):
            with self.assertRaises(HarnessSafetyError):
                capture_resource_snapshot(owner_pids=[os.getpid()])

    def test_PROCFG02_malformed_stat_fails_closed(self):
        import tests.prod_readiness_support as sup
        from unittest import mock

        real = sup.process_identity
        with mock.patch.object(
            sup, "process_identity", side_effect=HarnessSafetyError("malformed stat")
        ):
            with self.assertRaises(HarnessSafetyError):
                capture_resource_snapshot(owner_pids=[os.getpid()])
        # Sanity: real helper still works for a live pid.
        self.assertIsNotNone(real(os.getpid()).pgid)

    def test_PROCFG03_persistent_unreadable_fails_closed(self):
        import tests.prod_readiness_support as sup
        from unittest import mock

        with mock.patch.object(
            sup, "process_identity", side_effect=PermissionError("denied")
        ):
            with self.assertRaises(HarnessSafetyError):
                capture_resource_snapshot(owner_pids=[os.getpid()])

    def test_PROCFG04_confirmed_disappearance_may_be_clean(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"]
        )
        pid = proc.pid
        proc.kill()
        proc.wait(timeout=5)
        snapshot = capture_resource_snapshot(owner_pids=[pid])
        self.assertEqual((), snapshot.unexpected_leaks)


class SealedCompletenessTests(unittest.TestCase):
    """HIGH EV15-A..E + R2: sealed bundles classify every .json explicitly."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-sealed-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_EV15A_unlisted_audit_json_fails(self):
        _write_json(self.root, "audit.json", {"audit": True})
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_EV15B_unlisted_run_result_json_fails(self):
        _write_json(self.root, "run_result.json", {"result": 1})
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_EV15C_unlisted_gate_decision_json_fails(self):
        _write_json(self.root, "gate_decision.json", {"gate": "open"})
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_EV15D_permitted_diagnostic_current_json_allowed(self):
        _write_json(self.root, "current.json", {"current_item_id": None})
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)

    def test_EV15E_arbitrary_unknown_json_fails(self):
        _write_json(self.root, "mystery-unknown.json", {"x": 1})
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_R2_unlisted_authoritative_json_killed(self):
        _write_json(
            self.root, "extra/item-terminal.json", {"item_id": "extra", "program_outcome": {}}
        )
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"])
        self.assertTrue({"EV-05", "EV-16"} & codes(result))


class DiagnosticCurrentItemTests(unittest.TestCase):
    """MEDIUM DL-01..03: diagnostic current_item_id must be proven."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-current-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def _set_current(self, value) -> None:
        path = self.root / "queue-state.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["current_item_id"] = value
        _write_json(self.root, "queue-state.json", doc)
        rewrite_manifest_digests(self.root)

    def test_DL01_current_with_missing_prior_terminal_fails(self):
        self.mutate_terminal_item("programs/01-item-1/item-terminal.json", "item-X")
        self._set_current("item-2")
        self.assertIn("EV-12", codes(verify_evidence(self.root)))

    def test_DL02_current_without_own_start_fails(self):
        self.mutate_start_item("programs/02-item-2/item-started.json", "item-X")
        self._set_current("item-2")
        self.assertIn("EV-12", codes(verify_evidence(self.root)))

    def test_DL03_valid_current_with_prior_terminal_and_start_allowed(self):
        self._set_current("item-2")
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)

    def mutate_terminal_item(self, relative: str, new_id: str) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        value["item_id"] = new_id
        _write_json(self.root, relative, value)
        rewrite_manifest_digests(self.root)

    def mutate_start_item(self, relative: str, new_id: str) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        value["item_id"] = new_id
        _write_json(self.root, relative, value)
        rewrite_manifest_digests(self.root)


class DuplicateMarkerTests(unittest.TestCase):
    """MEDIUM DUPE-01..03 + R6: semantic duplicate detection."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-dupe-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_DUPE01_terminal_duplicated_as_alt_name_fails(self):
        src = self.root / "programs/01-item-1/item-terminal.json"
        dst = self.root / "programs/01-item-1/terminal-alt.json"
        dst.write_bytes(src.read_bytes())
        self.assertIn("EV-05", codes(verify_evidence(self.root)))

    def test_DUPE02_same_terminal_with_alternate_kind_fails(self):
        src = self.root / "programs/01-item-1/item-terminal.json"
        dst_rel = "programs/01-item-1/item-terminal-copy.json"
        (self.root / dst_rel).write_bytes(src.read_bytes())
        manifest = json.loads((self.root / "run-manifest.json").read_text())
        manifest["artifacts"].append(
            {
                "path": dst_rel,
                "sha256": _digest(self.root / dst_rel),
                "kind": "custom-terminal-kind",
                "logical_id": "item-1-copy",
                "immutable": True,
                "sequence": len(manifest["artifacts"]) + 1,
            }
        )
        manifest["required_artifacts"].append(dst_rel)
        _write_json(self.root, "run-manifest.json", manifest)
        self.assertIn("EV-05", codes(verify_evidence(self.root)))

    def test_DUPE03_two_different_items_remain_valid(self):
        self.assertEqual("PASS", verify_evidence(self.root)["status"])

    def test_R6_duplicate_alt_kind_killed(self):
        self.test_DUPE02_same_terminal_with_alternate_kind_fails()


class SentinelBindingTests(unittest.TestCase):
    """LOW SENT-01..03 + R5: sentinel evidence bound to current instance."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-sent-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.policy = ContainmentPolicy.create(self.root, CANONICAL_REPO)

    def test_SENT01_stale_signal_cannot_fail_fresh_sentinel(self):
        stale = self.root / "sentinels" / "stale-one.jsonl"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text(json.dumps({"kind": "SIGNAL", "signal": 15}) + "\n")
        with SignalSentinel(self.policy, "stale-one") as sentinel:
            sentinel.assert_untouched()

    def test_SENT02_current_signal_is_detected(self):
        with SignalSentinel(self.policy, "live-signal") as sentinel:
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "kind": "SIGNAL",
                            "signal": 15,
                            "pid": sentinel.proc.pid,
                            "token": sentinel.run_token,
                        }
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            with self.assertRaisesRegex(AssertionError, "received signal"):
                sentinel.assert_untouched()

    def test_SENT03_foreign_pid_token_not_attributed(self):
        with SignalSentinel(self.policy, "foreign-evt") as sentinel:
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {"kind": "SIGNAL", "signal": 15, "pid": 999999999, "token": "foreign"}
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            sentinel.assert_untouched()

    def test_SENT04_token_and_pid_both_required(self):
        with SignalSentinel(self.policy, "dual-binding") as sentinel:
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                # 1. Correct token, foreign PID: not attributed
                handle.write(
                    json.dumps(
                        {"kind": "SIGNAL", "signal": 15, "pid": 999999998, "token": sentinel.run_token}
                    )
                    + "\n"
                )
                # 2. Correct PID, wrong token: not attributed
                handle.write(
                    json.dumps(
                        {"kind": "SIGNAL", "signal": 15, "pid": sentinel.proc.pid, "token": "wrong-token"}
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            sentinel.assert_untouched()

            # 3. Both correct token and correct PID: attributed
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "kind": "SIGNAL",
                            "signal": 15,
                            "pid": sentinel.proc.pid,
                            "token": sentinel.run_token,
                        }
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            with self.assertRaisesRegex(AssertionError, "received signal"):
                sentinel.assert_untouched()

    def test_SENT05_partial_json_fails_closed(self):
        with SignalSentinel(self.policy, "partial-json") as sentinel:
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                handle.write('{"kind": "SIGNAL", "signal": 15\n')
                handle.flush()
                os.fsync(handle.fileno())
            with self.assertRaisesRegex(HarnessSafetyError, "SENTINEL_EVIDENCE_UNCERTAIN"):
                sentinel.events()

    def test_R5_stale_sentinel_killed(self):
        self.test_SENT01_stale_signal_cannot_fail_fresh_sentinel()


class ReviewerMutationClosureTests(unittest.TestCase):
    """CORRECTION 8: H1b, R7, R9 (+ R1/R8 recheck anchors)."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-closure-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_H1b_internal_candidate_sha_mismatch_fails(self):
        path = self.root / "runs/program-run-1/final.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["candidate_sha"] = "b" * 40
        _write_json(self.root, "runs/program-run-1/final.json", value)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("FAIL", result["status"], result)
        self.assertIn("EV-07", codes(result))

    def test_R7_diagnostic_reservation_ahead_of_evidence_fails(self):
        path = self.root / "budget-state.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["reservations"] = [
            {"logical_invocation": "inv-9", "attempt": "FIRST", "reservation_id": 1}
        ]
        value["used"] = {"model_calls": 1, "retries": 0, "fallbacks": 0, "corrections": 0}
        _write_json(self.root, "budget-state.json", value)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"], result)
        self.assertIn("EV-12", codes(result))

    def test_R1_symlink_alias_still_killed(self):
        disp = self.root / "disp"
        disp.mkdir(parents=True, exist_ok=True)
        policy = ContainmentPolicy.create(disp, CANONICAL_REPO)
        alias = self.root / "disp" / "alias"
        alias.parent.mkdir(parents=True, exist_ok=True)
        alias.symlink_to(CANONICAL_REPO, target_is_directory=True)
        with self.assertRaises(HarnessSafetyError):
            policy.require_owned_target(alias / "tests")

    def test_R8_owner_identity_mismatch_still_killed(self):
        from dataclasses import replace as _replace

        from tests.prod_readiness_support import (
            process_identity as _pi,
        )
        from tests.prod_readiness_support import (
            terminate_owned_process_group as _term,
        )

        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        try:
            identity = _pi(proc.pid)
            forged = _replace(identity, start_time=(identity.start_time or 0) + 1)
            with self.assertRaisesRegex(HarnessSafetyError, "PROCESS_IDENTITY_CHANGED"):
                _term(proc, forged)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)


class BlockerTOCTOUTests(unittest.TestCase):
    """BLOCKER 1: Descriptor-anchored deletion resistant to concurrent swap attacks."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-bto-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.disp = self.root / "disp"
        self.disp.mkdir()
        self.policy = ContainmentPolicy.create(self.disp, CANONICAL_REPO)
        self.protected = self.root / "protected_repo"
        self.protected.mkdir()
        (self.protected / "canary.txt").write_text("DO_NOT_DELETE\n", encoding="utf-8")

    def assertProtectedIntact(self):
        canary = self.protected / "canary.txt"
        self.assertTrue(canary.is_file(), "CRITICAL: Protected file was deleted!")
        self.assertEqual("DO_NOT_DELETE\n", canary.read_text(encoding="utf-8"))

    def test_BTO01_swap_ancestor_after_authorization_before_destructive_traversal(self):
        ancestor = self.disp / "ancestor"
        target = ancestor / "nested" / "leaf"
        target.mkdir(parents=True)
        (target / "disposable.txt").write_text("clean me")

        def hook(stage, data):
            if stage == "after_authorization":
                shutil.rmtree(ancestor)
                ancestor.symlink_to(self.protected, target_is_directory=True)

        self.policy.set_test_hook(hook)
        try:
            with self.assertRaises(HarnessSafetyError):
                self.policy.remove_owned(target)
        finally:
            self.policy.set_test_hook(None)
        self.assertProtectedIntact()

    def test_BTO02_swap_after_stat_before_open(self):
        target = self.disp / "target_dir"
        target.mkdir(parents=True)
        (target / "child.txt").write_text("clean me")

        def hook(stage, data):
            if stage == "before_target_open":
                shutil.rmtree(target)
                target.symlink_to(self.protected, target_is_directory=True)

        self.policy.set_test_hook(hook)
        try:
            with self.assertRaises(HarnessSafetyError):
                self.policy.remove_owned(target)
        finally:
            self.policy.set_test_hook(None)
        self.assertProtectedIntact()

    def test_BTO03_deterministic_swap_at_all_exposed_cleanup_boundaries(self):
        stages_to_test = [
            "after_authorization",
            "before_open_root",
            "before_walk_step",
            "before_target_stat",
            "before_target_open",
            "after_target_open",
        ]
        for stage_name in stages_to_test:
            with self.subTest(stage=stage_name):
                sub = self.disp / f"sub_{stage_name}"
                target = sub / "dir"
                target.mkdir(parents=True, exist_ok=True)
                (target / "junk.txt").write_text("junk")

                def make_hook(trigger):
                    def hook(stage, data):
                        if stage == trigger:
                            try:
                                if (sub / "dir").exists() and not (sub / "dir").is_symlink():
                                    shutil.rmtree(sub / "dir")
                                    (sub / "dir").symlink_to(self.protected, target_is_directory=True)
                                elif sub.exists() and not sub.is_symlink():
                                    shutil.rmtree(sub)
                                    sub.symlink_to(self.protected, target_is_directory=True)
                            except OSError:
                                pass
                    return hook

                self.policy.set_test_hook(make_hook(stage_name))
                try:
                    self.policy.remove_owned(target)
                except (HarnessSafetyError, OSError):
                    pass
                finally:
                    self.policy.set_test_hook(None)
                self.assertProtectedIntact()

    def test_BTO04_concurrent_high_volume_ancestor_swap_attack(self):
        ancestor = self.disp / "flapping_ancestor"
        real_target = ancestor / "nested" / "victim"

        stop_event = threading.Event()

        def swapper():
            while not stop_event.is_set():
                try:
                    if ancestor.is_symlink():
                        ancestor.unlink()
                        ancestor.mkdir(exist_ok=True)
                        (ancestor / "nested" / "victim").mkdir(parents=True, exist_ok=True)
                    else:
                        shutil.rmtree(ancestor, ignore_errors=True)
                        ancestor.symlink_to(self.protected, target_is_directory=True)
                except OSError:
                    pass
                time.sleep(0.001)

        t = threading.Thread(target=swapper, daemon=True)
        t.start()
        try:
            for _ in range(50):
                try:
                    real_target.mkdir(parents=True, exist_ok=True)
                    (real_target / "file.txt").write_text("data")
                    self.policy.remove_owned(real_target)
                except (HarnessSafetyError, OSError):
                    pass
                self.assertProtectedIntact()
        finally:
            stop_event.set()
            t.join(timeout=2)
        self.assertProtectedIntact()

    def test_BTO05_directory_replaced_with_file_after_stat_fails_closed(self):
        target = self.disp / "target_dir"
        target.mkdir()
        (target / "child.txt").write_text("data")

        def hook(stage, data):
            if stage == "before_target_open":
                shutil.rmtree(target)
                target.write_text("now a file")

        self.policy.set_test_hook(hook)
        try:
            with self.assertRaises(HarnessSafetyError):
                self.policy.remove_owned(target)
        finally:
            self.policy.set_test_hook(None)
        self.assertProtectedIntact()

    def test_BTO06_descriptor_identity_mismatch_fails_closed(self):
        target = self.disp / "target_dir"
        replacement = self.disp / "replacement_dir"
        target.mkdir()
        replacement.mkdir()
        (replacement / "replacement_canary.txt").write_text(
            "REPLACEMENT_NOT_DELETED\n", encoding="utf-8"
        )
        # Both directories coexist, so they cannot legitimately share one
        # directory inode.  This deterministically pre-establishes the two
        # distinct descriptor identities the mismatch branch must compare.
        target_identity = (os.stat(target).st_dev, os.stat(target).st_ino)
        replacement_identity = (
            os.stat(replacement).st_dev,
            os.stat(replacement).st_ino,
        )
        self.assertNotEqual(target_identity, replacement_identity)

        def hook(stage, data):
            if stage == "before_target_open":
                shutil.rmtree(target)
                os.rename(
                    replacement.name,
                    target.name,
                    src_dir_fd=data["parent_fd"],
                    dst_dir_fd=data["parent_fd"],
                )

        self.policy.set_test_hook(hook)
        try:
            with self.assertRaisesRegex(HarnessSafetyError, "DESCRIPTOR_IDENTITY_MISMATCH"):
                self.policy.remove_owned(target)
        finally:
            self.policy.set_test_hook(None)
        # The identity mismatch must fail closed before the replacement's
        # contents are recursively traversed or destroyed.
        canary = target / "replacement_canary.txt"
        self.assertTrue(canary.is_file())
        self.assertEqual(
            "REPLACEMENT_NOT_DELETED\n", canary.read_text(encoding="utf-8")
        )
        self.assertProtectedIntact()

    def test_BTO07_ordinary_owned_disposable_directory_deletes_correctly(self):
        target = self.disp / "normal" / "tree"
        target.mkdir(parents=True)
        (target / "file1.txt").write_text("1")
        (target / "sub").mkdir()
        (target / "sub" / "file2.txt").write_text("2")
        self.policy.remove_owned(target)
        self.assertFalse(target.exists())

    def test_BTO08_owned_symlink_removed_without_touching_target(self):
        target = self.disp / "owned_target"
        target.mkdir()
        (target / "keep.txt").write_text("keep\n", encoding="utf-8")
        symlink = self.disp / "link_to_target"
        symlink.symlink_to(target, target_is_directory=True)
        self.policy.remove_owned(symlink)
        self.assertFalse(symlink.exists())
        self.assertTrue((target / "keep.txt").is_file())
        self.assertProtectedIntact()


class NestedCandidateIdentityTests(unittest.TestCase):
    """HIGH 1: Verify nested candidate identity fields across authoritative evidence."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-id-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_ID01_nested_program_outcome_candidate_sha_mismatch_fails(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["program_outcome"]["candidate_sha"] = "b" * 40
        _write_json(self.root, "programs/01-item-1/item-terminal.json", value)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("FAIL", result["status"], result)
        self.assertIn("EV-07", codes(result))

    def test_ID02_nested_value_matching_passes(self):
        result = verify_evidence(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("PASS", result["status"], result)

    def test_ID03_unrelated_hash_field_not_mistaken_for_candidate_identity(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotEqual(CANDIDATE, value["program_outcome"]["final_sha256"])
        result = verify_evidence(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("PASS", result["status"], result)


class UnlistedPermittedDiagnosticTests(unittest.TestCase):
    """MEDIUM 1: Unlisted permitted diagnostic (e.g. current.json) undergoes semantic validation."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-dg-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_DG01_unlisted_current_json_claiming_item_without_start_fails(self):
        (self.root / "programs/02-item-2/item-started.json").unlink()
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"] = [a for a in manifest["artifacts"] if a["path"] != "programs/02-item-2/item-started.json"]
        manifest["required_artifacts"] = [p for p in manifest["required_artifacts"] if p != "programs/02-item-2/item-started.json"]
        _write_json(self.root, "run-manifest.json", manifest)
        _write_json(self.root, "current.json", {"current_item_id": "item-2"})
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"], result)
        self.assertIn("EV-12", codes(result))

    def test_DG02_unlisted_current_json_claiming_item2_before_item1_terminal_fails(self):
        (self.root / "programs/01-item-1/item-terminal.json").unlink()
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"] = [a for a in manifest["artifacts"] if a["path"] != "programs/01-item-1/item-terminal.json"]
        manifest["required_artifacts"] = [p for p in manifest["required_artifacts"] if p != "programs/01-item-1/item-terminal.json"]
        _write_json(self.root, "run-manifest.json", manifest)
        _write_json(self.root, "current.json", {"current_item_id": "item-2"})
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"], result)
        self.assertIn("EV-12", codes(result))

    def test_DG03_valid_unlisted_current_json_passes(self):
        _write_json(self.root, "current.json", {"current_item_id": None})
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)

    def test_DG04_malformed_allowed_diagnostic_fails_closed(self):
        (self.root / "current.json").write_text("{bad json", encoding="utf-8")
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"], result)
        self.assertTrue({"EV-02", "EV-03"} & codes(result))


class DuplicateFinalsTests(unittest.TestCase):
    """MEDIUM 2: Uniqueness of program-final and queue-final logical markers."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-dupf-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_DUPF01_duplicate_program_final_alternate_filename_fails(self):
        src = self.root / "runs/program-run-1/final.json"
        alt = self.root / "runs/program-run-1/final-alt.json"
        alt.write_bytes(src.read_bytes())
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"].append({
            "path": "runs/program-run-1/final-alt.json",
            "sha256": _digest(alt),
            "kind": "program-final",
            "logical_id": "program-run-1",
            "immutable": True,
            "sequence": len(manifest["artifacts"]) + 1,
        })
        manifest["required_artifacts"].append("runs/program-run-1/final-alt.json")
        _write_json(self.root, "run-manifest.json", manifest)
        result = verify_evidence(self.root)
        self.assertIn("EV-05", codes(result))

    def test_DUPF02_duplicate_program_final_alternate_kind_fails(self):
        src = self.root / "runs/program-run-1/final.json"
        alt = self.root / "runs/program-run-1/final-copy.json"
        alt.write_bytes(src.read_bytes())
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"].append({
            "path": "runs/program-run-1/final-copy.json",
            "sha256": _digest(alt),
            "kind": "custom-kind-final",
            "logical_id": "program-run-1-custom",
            "immutable": True,
            "sequence": len(manifest["artifacts"]) + 1,
        })
        manifest["required_artifacts"].append("runs/program-run-1/final-copy.json")
        _write_json(self.root, "run-manifest.json", manifest)
        result = verify_evidence(self.root)
        self.assertIn("EV-05", codes(result))

    def test_DUPF03_conflicting_program_final_verdict_fails(self):
        src = self.root / "runs/program-run-1/final.json"
        doc = json.loads(src.read_text(encoding="utf-8"))
        doc["verdict"] = "FAILURE"
        doc["status"] = "FAILURE"
        alt = self.root / "runs/program-run-1/final-conflict.json"
        _write_json(self.root, "runs/program-run-1/final-conflict.json", doc)
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"].append({
            "path": "runs/program-run-1/final-conflict.json",
            "sha256": _digest(alt),
            "kind": "program-final",
            "logical_id": "program-run-1",
            "immutable": True,
            "sequence": len(manifest["artifacts"]) + 1,
        })
        manifest["required_artifacts"].append("runs/program-run-1/final-conflict.json")
        _write_json(self.root, "run-manifest.json", manifest)
        result = verify_evidence(self.root)
        self.assertIn("EV-05", codes(result))

    def test_DUPF04_duplicate_queue_final_fails(self):
        src = self.root / "final.json"
        alt = self.root / "final-alt.json"
        alt.write_bytes(src.read_bytes())
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"].append({
            "path": "final-alt.json",
            "sha256": _digest(alt),
            "kind": "queue-final",
            "logical_id": "queue-run-1",
            "immutable": True,
            "sequence": len(manifest["artifacts"]) + 1,
        })
        manifest["required_artifacts"].append("final-alt.json")
        _write_json(self.root, "run-manifest.json", manifest)
        result = verify_evidence(self.root)
        self.assertIn("EV-05", codes(result))

    def test_DUPF05_conflicting_queue_final_fails(self):
        src = self.root / "final.json"
        doc = json.loads(src.read_text(encoding="utf-8"))
        doc["verdict"] = "FAILURE"
        doc["status"] = "FAILURE"
        alt = self.root / "final-conflict.json"
        _write_json(self.root, "final-conflict.json", doc)
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"].append({
            "path": "final-conflict.json",
            "sha256": _digest(alt),
            "kind": "queue-final",
            "logical_id": "queue-run-1",
            "immutable": True,
            "sequence": len(manifest["artifacts"]) + 1,
        })
        manifest["required_artifacts"].append("final-conflict.json")
        _write_json(self.root, "run-manifest.json", manifest)
        result = verify_evidence(self.root)
        self.assertIn("EV-05", codes(result))

    def test_DUPF06_two_genuinely_distinct_program_runs_pass(self):
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)


class OwnershipUncertaintyTests(unittest.TestCase):
    """MEDIUM 3: Ownership scans must fail closed upon persistent uncertainty."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-unc-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()

    def test_UNC01_unreadable_potentially_owned_child_with_expected_owner_fails(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: (proc.kill() if proc.poll() is None else None, proc.wait()))
        with patch("tests.prod_readiness_support._scan_processes_with_uncertainty", return_value=((), True)):
            with self.assertRaisesRegex(HarnessSafetyError, "PROC_OWNER_IDENTITY_UNREADABLE"):
                capture_resource_snapshot(owner_pids=[proc.pid])

    def test_UNC02_malformed_potentially_owned_child_with_other_owned_member_fails(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: (proc.kill() if proc.poll() is None else None, proc.wait()))
        with patch("tests.prod_readiness_support._scan_processes_with_uncertainty", side_effect=HarnessSafetyError("STAT_MALFORMED")):
            with self.assertRaisesRegex(HarnessSafetyError, "STAT_MALFORMED"):
                capture_resource_snapshot(owner_pids=[proc.pid])

    def test_UNC03_persistent_permission_error_fails(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: (proc.kill() if proc.poll() is None else None, proc.wait()))
        with patch("tests.prod_readiness_support._scan_processes_with_uncertainty", side_effect=PermissionError("denied")):
            with self.assertRaises(HarnessSafetyError):
                capture_resource_snapshot(owner_pids=[proc.pid])

    def test_UNC04_confirmed_enoent_disappearance_tolerated(self):
        snapshot = capture_resource_snapshot(owner_pids=[999999999])
        self.assertIsInstance(snapshot.processes, tuple)

    def test_UNC05_no_uncertainty_with_expected_preservation_passes(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: (proc.kill() if proc.poll() is None else None, proc.wait()))
        snapshot = capture_resource_snapshot(
            owner_pids=[proc.pid],
            fixture_manifest={"expected_preserved_processes": [proc.pid]},
        )
        self.assertEqual(0, len(snapshot.unexpected_leaks))
        p_item = next(p for p in snapshot.processes if p.identity == str(proc.pid))
        self.assertEqual("EXPECTED_PRESERVED", p_item.classification)


class ReferenceContainmentTests(unittest.TestCase):
    """MEDIUM 4: Authoritative evidence references must be internal and contained."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-ref-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_REF01_absolute_final_path_fails(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        val = json.loads(path.read_text(encoding="utf-8"))
        val["program_outcome"]["final_path"] = "/etc/passwd"
        _write_json(self.root, "programs/01-item-1/item-terminal.json", val)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertIn("EV-06", codes(result))

    def test_REF02_dot_dot_escape_fails(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        val = json.loads(path.read_text(encoding="utf-8"))
        val["program_outcome"]["final_path"] = "../../outside/final.json"
        _write_json(self.root, "programs/01-item-1/item-terminal.json", val)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertIn("EV-06", codes(result))

    def test_REF03_symlink_to_external_fails(self):
        ext = self.root.parent / "external_final_target"
        ext.mkdir(exist_ok=True)
        ext_file = ext / "final.json"
        ext_file.write_bytes((self.root / "runs/program-run-1/final.json").read_bytes())
        self.addCleanup(lambda: (ext_file.unlink(missing_ok=True), ext.rmdir() if ext.exists() else None))

        sym = self.root / "runs/program-run-1/final-symlink.json"
        sym.symlink_to(ext_file)

        path = self.root / "programs/01-item-1/item-terminal.json"
        val = json.loads(path.read_text(encoding="utf-8"))
        val["program_outcome"]["final_path"] = "runs/program-run-1/final-symlink.json"
        _write_json(self.root, "programs/01-item-1/item-terminal.json", val)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertTrue({"EV-06", "EV-17"} & codes(result))

    def test_REF04_normalized_internal_relative_path_passes(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        val = json.loads(path.read_text(encoding="utf-8"))
        val["program_outcome"]["final_path"] = "runs/program-run-1/./final.json"
        _write_json(self.root, "programs/01-item-1/item-terminal.json", val)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)

    def test_REF05_missing_internal_reference_fails(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        val = json.loads(path.read_text(encoding="utf-8"))
        val["program_outcome"]["final_path"] = "runs/program-run-1/missing.json"
        _write_json(self.root, "programs/01-item-1/item-terminal.json", val)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertIn("EV-06", codes(result))


class SymlinkedEvidenceTests(unittest.TestCase):
    """MEDIUM 5: Physical walk rejects directory and file symlinks in sealed bundles."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-sym-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_SYM01_symlinked_directory_containing_audit_json_fails(self):
        real_audit_dir = self.root.parent / "real_audit_dir"
        real_audit_dir.mkdir(exist_ok=True)
        _write_json(real_audit_dir, "audit.json", {"audit": True})
        self.addCleanup(lambda: (real_audit_dir / "audit.json").unlink(missing_ok=True) or real_audit_dir.rmdir())
        sym_dir = self.root / "sym_audit"
        sym_dir.symlink_to(real_audit_dir, target_is_directory=True)
        result = verify_evidence(self.root)
        self.assertIn("EV-17", codes(result))

    def test_SYM02_symlinked_directory_containing_valid_final_fails(self):
        real_runs = self.root.parent / "real_runs"
        real_runs.mkdir(exist_ok=True)
        _write_json(real_runs, "extra_final.json", {"run_id": "extra"})
        self.addCleanup(lambda: (real_runs / "extra_final.json").unlink(missing_ok=True) or real_runs.rmdir())
        sym_dir = self.root / "sym_runs"
        sym_dir.symlink_to(real_runs, target_is_directory=True)
        result = verify_evidence(self.root)
        self.assertIn("EV-17", codes(result))

    def test_SYM03_symlinked_json_file_fails(self):
        real_file = self.root.parent / "real_file.json"
        _write_json(self.root.parent, "real_file.json", {"item": 1})
        self.addCleanup(real_file.unlink)
        sym_file = self.root / "sym_file.json"
        sym_file.symlink_to(real_file)
        result = verify_evidence(self.root)
        self.assertIn("EV-17", codes(result))

    def test_SYM04_normal_physical_nested_directory_passes(self):
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)


class SetsidDescendantTests(unittest.TestCase):
    """MEDIUM 6: Retention of setsid-escaped descendants via exact Linux execution identity."""

    def setUp(self):
        clear_owned_process_registry()
        self.addCleanup(clear_owned_process_registry)

    def test_SID01_setsid_escaped_descendant_is_unexpected_leak(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            pid_file = f.name
        self.addCleanup(lambda: os.unlink(pid_file) if os.path.exists(pid_file) else None)

        script = (
            "import os, sys, time\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    with open(sys.argv[1], 'w') as out: out.write(str(os.getpid()))\n"
            "    time.sleep(30)\n"
            "    sys.exit(0)\n"
            "else:\n"
            "    sys.exit(0)\n"
        )
        leader = subprocess.Popen([sys.executable, "-c", script, pid_file])
        leader.wait(timeout=5)

        child_pid = None
        for _ in range(50):
            if os.path.exists(pid_file) and os.path.getsize(pid_file) > 0:
                with open(pid_file, encoding="utf-8") as pf:
                    child_pid = int(pf.read().strip())
                break
            time.sleep(0.05)
        self.assertIsNotNone(child_pid)

        def cleanup():
            try:
                os.kill(child_pid, 9)
            except OSError:
                pass
        self.addCleanup(cleanup)

        register_owned_process(child_pid)
        snapshot = capture_resource_snapshot()
        self.assertTrue(
            any(
                item.kind == "process"
                and item.identity == str(child_pid)
                and item.classification == "UNEXPECTED_LEAK"
                for item in snapshot.processes
            )
        )
        self.assertTrue(any(item.identity == str(child_pid) for item in snapshot.unexpected_leaks))

    def test_SID02_foreign_session_process_is_not_claimed(self):
        foreign = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        self.addCleanup(lambda: (foreign.kill() if foreign.poll() is None else None, foreign.wait()))
        snapshot = capture_resource_snapshot()
        self.assertFalse(any(item.identity == str(foreign.pid) for item in snapshot.processes))

    def test_SID03_escaped_child_terminates_snapshot_becomes_clean(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
            pid_file = f.name
        self.addCleanup(lambda: os.unlink(pid_file) if os.path.exists(pid_file) else None)

        script = (
            "import os, sys, time\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid()\n"
            "    with open(sys.argv[1], 'w') as out: out.write(str(os.getpid()))\n"
            "    time.sleep(30)\n"
            "    sys.exit(0)\n"
            "else:\n"
            "    sys.exit(0)\n"
        )
        leader = subprocess.Popen([sys.executable, "-c", script, pid_file])
        leader.wait(timeout=5)

        child_pid = None
        for _ in range(50):
            if os.path.exists(pid_file) and os.path.getsize(pid_file) > 0:
                with open(pid_file, encoding="utf-8") as pf:
                    child_pid = int(pf.read().strip())
                break
            time.sleep(0.05)
        self.assertIsNotNone(child_pid)

        register_owned_process(child_pid)
        try:
            os.kill(child_pid, 9)
        except OSError:
            pass
        for _ in range(50):
            if not Path(f"/proc/{child_pid}").exists():
                break
            time.sleep(0.05)

        snapshot = capture_resource_snapshot()
        self.assertFalse(any(item.identity == str(child_pid) for item in snapshot.unexpected_leaks))


class DurableRegistryScopeR3Tests(unittest.TestCase):
    """REG-01..05/G3b: durable identities belong to one execution scope."""

    def setUp(self):
        self.scope_a = f"scope-a-{id(self)}"
        self.scope_b = f"scope-b-{id(self)}"
        self.addCleanup(clear_owned_process_registry, self.scope_a)
        self.addCleanup(clear_owned_process_registry, self.scope_b)
        self.processes = [
            subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                start_new_session=True,
            )
            for _ in range(2)
        ]
        for proc in self.processes:
            self.addCleanup(self._stop, proc)

    @staticmethod
    def _stop(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)

    def test_REG01_REG04_clear_and_snapshot_are_scope_local(self):
        proc_a, proc_b = self.processes
        register_owned_process(proc_a.pid, owner_scope=self.scope_a)
        register_owned_process(proc_b.pid, owner_scope=self.scope_b)

        snap_a = capture_resource_snapshot(owner_scope=self.scope_a)
        snap_b = capture_resource_snapshot(owner_scope=self.scope_b)
        self.assertTrue(any(row.identity == str(proc_a.pid) for row in snap_a.processes))
        self.assertTrue(any(row.identity == str(proc_b.pid) for row in snap_b.processes))

        clear_owned_process_registry(self.scope_a)
        cleared_a = capture_resource_snapshot(owner_scope=self.scope_a)
        remaining_b = capture_resource_snapshot(owner_scope=self.scope_b)
        self.assertFalse(any(row.identity == str(proc_b.pid) for row in cleared_a.processes))
        self.assertTrue(
            any(row.identity == str(proc_b.pid) for row in remaining_b.unexpected_leaks)
        )

    def test_REG05_recycled_pid_or_wrong_start_time_is_not_claimed(self):
        from dataclasses import replace

        from tests.prod_readiness_support import process_identity

        proc = self.processes[0]
        actual = process_identity(proc.pid)
        stale = replace(actual, start_time=(actual.start_time or 0) + 1)
        register_owned_process(stale, owner_scope=self.scope_a)
        snapshot = capture_resource_snapshot(owner_scope=self.scope_a)
        self.assertFalse(any(row.identity == str(proc.pid) for row in snapshot.processes))

    def test_G3B_registry_requires_start_time_and_boot_id(self):
        from dataclasses import replace

        from tests.prod_readiness_support import process_identity

        actual = process_identity(self.processes[0].pid)
        with self.assertRaisesRegex(HarnessSafetyError, "IDENTITY_MALFORMED"):
            register_owned_process(
                replace(actual, start_time=None), owner_scope=self.scope_a
            )
        with self.assertRaisesRegex(HarnessSafetyError, "IDENTITY_MALFORMED"):
            register_owned_process(
                replace(actual, boot_id=None), owner_scope=self.scope_a
            )


class EvidenceAuthorityR3Tests(unittest.TestCase):
    """AUTH/QF/LOW-DIAG/R3-M2/M3 authoritative-ingestion closure."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-evidence-r3-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        build_valid_evidence(self.root)

    def _point_first_terminal_at_unlisted(
        self, relative: str, *, candidate_sha: str = CANDIDATE, run_id: str = "program-run-1"
    ) -> None:
        source = json.loads(
            (self.root / "runs/program-run-1/final.json").read_text(encoding="utf-8")
        )
        source["candidate_sha"] = candidate_sha
        source["run_id"] = run_id
        _write_json(self.root, relative, source)
        terminal_path = self.root / "programs/01-item-1/item-terminal.json"
        terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
        terminal["program_outcome"]["final_path"] = relative
        terminal["program_outcome"]["final_sha256"] = _digest(self.root / relative)
        _write_json(self.root, "programs/01-item-1/item-terminal.json", terminal)
        rewrite_manifest_digests(self.root)

    def _move_first_program_final(
        self, relative: str, *, candidate_sha: str = CANDIDATE
    ) -> None:
        old_relative = "runs/program-run-1/final.json"
        old = self.root / old_relative
        value = json.loads(old.read_text(encoding="utf-8"))
        value["candidate_sha"] = candidate_sha
        _write_json(self.root, relative, value)
        old.unlink()

        terminal_path = self.root / "programs/01-item-1/item-terminal.json"
        terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
        terminal["program_outcome"]["final_path"] = relative
        terminal["program_outcome"]["final_sha256"] = _digest(self.root / relative)
        _write_json(self.root, "programs/01-item-1/item-terminal.json", terminal)

        manifest_path = self.root / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["required_artifacts"] = [
            relative if item == old_relative else item
            for item in manifest["required_artifacts"]
        ]
        for entry in manifest["artifacts"]:
            if entry["path"] == old_relative:
                entry["path"] = relative
                entry["sha256"] = _digest(self.root / relative)
        _write_json(self.root, "run-manifest.json", manifest)
        rewrite_manifest_digests(self.root)

    def _append_artifact(
        self, relative: str, value: Any, *, kind: str, logical_id: str
    ) -> None:
        _write_json(self.root, relative, value)
        manifest_path = self.root / "run-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["artifacts"].append(
            {
                "path": relative,
                "sha256": _digest(self.root / relative),
                "kind": kind,
                "logical_id": logical_id,
                "immutable": True,
                "sequence": len(manifest["artifacts"]) + 1,
            }
        )
        manifest["required_artifacts"].append(relative)
        _write_json(self.root, "run-manifest.json", manifest)

    def test_AUTH01_FC02_R3_M2_unlisted_extensionless_final_fails(self):
        self._point_first_terminal_at_unlisted("runs/program-run-1/final", candidate_sha="b" * 40)
        result = verify_evidence(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("FAIL", result["status"])
        self.assertIn("EV-16", codes(result))

    def test_AUTH02_unlisted_final_txt_fails(self):
        self._point_first_terminal_at_unlisted("runs/program-run-1/final.txt")
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_AUTH03_unlisted_final_uppercase_json_fails(self):
        self._point_first_terminal_at_unlisted(
            "runs/program-run-1/final.JSON", candidate_sha="b" * 40
        )
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_AUTH04_listed_uppercase_json_with_valid_identity_passes(self):
        self._move_first_program_final("runs/program-run-1/final.JSON")
        result = verify_evidence(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("PASS", result["status"], result)

    def test_AUTH05_listed_referenced_wrong_candidate_is_ev07(self):
        self._move_first_program_final(
            "runs/program-run-1/final.JSON", candidate_sha="b" * 40
        )
        self.assertIn(
            "EV-07", codes(verify_evidence(self.root, expected_candidate_sha=CANDIDATE))
        )

    def test_AUTH06_unlisted_uppercase_queue_final_duplicate_fails(self):
        value = json.loads((self.root / "final.json").read_text(encoding="utf-8"))
        _write_json(self.root, "QUEUE-FINAL.JSON", value)
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"])
        self.assertTrue({"EV-05", "EV-16"}.issubset(codes(result)))

    def test_AUTH07_uppercase_diagnostic_like_json_is_not_authority(self):
        _write_json(self.root, "CURRENT.JSON", {"current_item_id": None})
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_AUTH08_reference_to_another_run_artifact_fails(self):
        self._point_first_terminal_at_unlisted(
            "other-run/final", run_id="program-run-other"
        )
        self.assertIn("EV-16", codes(verify_evidence(self.root)))

    def test_QF01_R3_M3_single_queue_final_missing_run_id_fails(self):
        path = self.root / "final.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value.pop("queue_run_id")
        _write_json(self.root, "final.json", value)
        rewrite_manifest_digests(self.root)
        self.assertIn("EV-08", codes(verify_evidence(self.root)))

    def test_QF02_FC03_two_queue_finals_one_missing_run_id_fail(self):
        value = json.loads((self.root / "final.json").read_text(encoding="utf-8"))
        value.pop("queue_run_id")
        self._append_artifact(
            "queue-final-missing.json",
            value,
            kind="queue-final",
            logical_id="queue-final-missing",
        )
        self.assertIn("EV-08", codes(verify_evidence(self.root)))

    def test_FC03_conflicting_queue_finals_both_without_identity_fail(self):
        path = self.root / "final.json"
        first = json.loads(path.read_text(encoding="utf-8"))
        first.pop("queue_run_id")
        _write_json(self.root, "final.json", first)
        second = {**first, "status": "FAILURE", "verdict": "FAILURE"}
        self._append_artifact(
            "queue-final-no-identity.json",
            second,
            kind="queue-final",
            logical_id="queue-final-no-identity",
        )
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"])
        self.assertIn("EV-08", codes(result))

    def test_QF03_conflicting_queue_finals_same_run_id_are_ev05(self):
        value = json.loads((self.root / "final.json").read_text(encoding="utf-8"))
        value["status"] = "FAILURE"
        self._append_artifact(
            "queue-final-conflict.json",
            value,
            kind="queue-final",
            logical_id="queue-run-1-conflict",
        )
        self.assertIn("EV-05", codes(verify_evidence(self.root)))

    def test_QF04_alternate_name_and_kind_same_run_id_are_ev05(self):
        value = json.loads((self.root / "final.json").read_text(encoding="utf-8"))
        self._append_artifact(
            "odd-queue-result.dat",
            value,
            kind="custom-result",
            logical_id="custom-logical-id",
        )
        self.assertIn("EV-05", codes(verify_evidence(self.root)))

    def test_QF05_valid_single_queue_final_passes(self):
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)

    def test_QF06_queue_run_id_inconsistent_with_manifest_fails(self):
        path = self.root / "final.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["queue_run_id"] = "other-queue-run"
        _write_json(self.root, "final.json", value)
        rewrite_manifest_digests(self.root)
        self.assertIn("EV-08", codes(verify_evidence(self.root)))

    def test_LOW_DIAG01_FC04_unlisted_current_array_fails(self):
        _write_json(self.root, "current.json", ["not", "an", "object"])
        self.assertIn("EV-02", codes(verify_evidence(self.root)))

    def test_LOW_DIAG02_budget_state_scalar_fails(self):
        _write_json(self.root, "budget-state.json", 42)
        rewrite_manifest_digests(self.root)
        self.assertIn("EV-02", codes(verify_evidence(self.root)))

    def test_LOW_DIAG03_valid_diagnostic_object_keeps_normal_semantics(self):
        _write_json(self.root, "current.json", {"current_item_id": None})
        result = verify_evidence(self.root)
        self.assertEqual("PASS", result["status"], result)

    def test_G7_program_final_marker_includes_program_id(self):
        from tools.prod_readiness.verify_evidence import _canonical_logical_marker

        first = {
            "run_id": "shared-run",
            "program_id": "program-a",
            "verdict": "SUCCESS",
        }
        second = {**first, "program_id": "program-b"}
        self.assertNotEqual(
            _canonical_logical_marker("first.dat", None, first),
            _canonical_logical_marker("second.dat", None, second),
        )


class ReviewerMutationClosureR2Tests(unittest.TestCase):
    """Permanent killing of reviewer mutations F8..F21."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-mut-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.manifest = build_valid_evidence(self.root)

    def test_F8_sentinel_token_without_pid_is_not_attributed(self):
        policy = ContainmentPolicy.create(self.root, CANONICAL_REPO)
        with SignalSentinel(policy, "mut-f8") as sentinel:
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {"kind": "SIGNAL", "signal": 15, "pid": 999999997, "token": sentinel.run_token}
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            sentinel.assert_untouched()

    def test_F10_unlisted_sealed_evidence_detected(self):
        _write_json(self.root, "hidden_doc.json", {"key": "value"})
        result = verify_evidence(self.root)
        self.assertIn("EV-16", codes(result))

    def test_F11_F19_ownership_scan_uncertainty_with_other_process_fails(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: (proc.kill() if proc.poll() is None else None, proc.wait()))
        with patch("tests.prod_readiness_support._scan_processes_with_uncertainty", return_value=((), True)):
            with self.assertRaises(HarnessSafetyError):
                capture_resource_snapshot(owner_pids=[proc.pid])

    def test_F12_F14_ignore_program_outcome_candidate_sha_killed(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["program_outcome"]["candidate_sha"] = "b" * 40
        _write_json(self.root, "programs/01-item-1/item-terminal.json", value)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root, expected_candidate_sha=CANDIDATE)
        self.assertEqual("FAIL", result["status"])
        self.assertIn("EV-07", codes(result))

    def test_F13_fd_anchored_deletion_resists_path_rmtree_swap(self):
        disp = self.root / "disp"
        disp.mkdir()
        policy = ContainmentPolicy.create(disp, CANONICAL_REPO)
        protected = self.root / "prot"
        protected.mkdir()
        canary = protected / "canary.txt"
        canary.write_text("safe")

        target = disp / "target"
        target.mkdir()
        (target / "junk.txt").write_text("junk")

        def hook(stage, data):
            if stage == "before_target_open":
                shutil.rmtree(target)
                target.symlink_to(protected, target_is_directory=True)

        policy.set_test_hook(hook)
        try:
            with self.assertRaises(HarnessSafetyError):
                policy.remove_owned(target)
        finally:
            policy.set_test_hook(None)
        self.assertTrue(canary.is_file())

    def test_F15_unlisted_current_json_semantic_check_killed(self):
        _write_json(self.root, "current.json", {"current_item_id": "nonexistent_item"})
        result = verify_evidence(self.root)
        self.assertEqual("FAIL", result["status"])
        self.assertIn("EV-12", codes(result))

    def test_F16_duplicate_program_finals_killed(self):
        src = self.root / "runs/program-run-1/final.json"
        alt = self.root / "runs/program-run-1/final-dup.json"
        alt.write_bytes(src.read_bytes())
        manifest = json.loads((self.root / "run-manifest.json").read_text(encoding="utf-8"))
        manifest["artifacts"].append({
            "path": "runs/program-run-1/final-dup.json",
            "sha256": _digest(alt),
            "kind": "program-final",
            "logical_id": "program-run-1",
            "immutable": True,
            "sequence": len(manifest["artifacts"]) + 1,
        })
        manifest["required_artifacts"].append("runs/program-run-1/final-dup.json")
        _write_json(self.root, "run-manifest.json", manifest)
        result = verify_evidence(self.root)
        self.assertIn("EV-05", codes(result))

    def test_F17_absolute_reference_bounds_killed(self):
        path = self.root / "programs/01-item-1/item-terminal.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["program_outcome"]["final_path"] = "/etc/shadow"
        _write_json(self.root, "programs/01-item-1/item-terminal.json", value)
        rewrite_manifest_digests(self.root)
        result = verify_evidence(self.root)
        self.assertIn("EV-06", codes(result))

    def test_F18_symlink_directory_during_sealed_scan_killed(self):
        out = self.root.parent / "out_dir"
        out.mkdir(exist_ok=True)
        self.addCleanup(lambda: out.rmdir() if out.exists() else None)
        sym = self.root / "sym_dir"
        sym.symlink_to(out, target_is_directory=True)
        result = verify_evidence(self.root)
        self.assertIn("EV-17", codes(result))

    def test_F20_tracked_setsid_escaped_descendant_killed(self):
        clear_owned_process_registry()
        self.addCleanup(clear_owned_process_registry)
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        self.addCleanup(lambda: (proc.kill() if proc.poll() is None else None, proc.wait()))
        register_owned_process(proc.pid)
        snapshot = capture_resource_snapshot()
        self.assertTrue(any(item.identity == str(proc.pid) for item in snapshot.unexpected_leaks))

    def test_F21_malformed_current_sentinel_record_killed(self):
        policy = ContainmentPolicy.create(self.root, CANONICAL_REPO)
        with SignalSentinel(policy, "mut-f21") as sentinel:
            with sentinel.events_path.open("a", encoding="utf-8") as handle:
                handle.write("{truncated\n")
                handle.flush()
                os.fsync(handle.fileno())
            with self.assertRaises(HarnessSafetyError):
                sentinel.events()


if __name__ == "__main__":
    unittest.main()
