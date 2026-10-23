import contextlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentflow
import finding_runner


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, capture_output=True)


_ARCHITECT_PLAN = {
    "objective_interpretation": "apply the frozen finding",
    "implementation_steps": ["update tracked.txt"],
    "invariants": [],
    "allowed_scope": ["tracked.txt"],
    "do_not_change": [],
    "validation_expectations": [],
    "known_risks": [],
}


def _finding_profiles():
    def profile(model, roles):
        return {"backend": "codex", "command": sys.executable, "provider": "vendor",
                "model": model, "variant": None, "available": True, "eligible_roles": roles}
    return {
        "program_architect": profile("vendor/arch-x", ["architect", "adjudicator"]),
        "program_worker": profile("vendor/work-x", ["worker"]),
        "program_reviewer": profile("vendor/rev-x", ["reviewer"]),
    }


def _model_result(role, **extra):
    result = {"role": role, "verdict": "PASS", "findings": [], "files_changed": [],
              "validators": {}, "open_risks": []}
    result.update(extra)
    return result


def _program_invoke(*, mutate_on_final_review=False):
    """Deterministic A-mode model double for the real program state machine."""
    def invoke(**kwargs):
        role, cycle = kwargs["role"], kwargs["cycle"]
        repo = Path(kwargs["exec_repo"])
        if role == "architect":
            return _model_result("architect", verdict="PLAN_READY",
                                 architect_plan=json.loads(json.dumps(_ARCHITECT_PLAN))), {}
        if role == "worker":
            (repo / "tracked.txt").write_text(f"worker-cycle-{cycle}\n", encoding="utf-8")
            return _model_result("worker"), {}
        if role == "reviewer" and cycle == 0:
            return _model_result("reviewer"), {}
        if role == "adjudicator":
            return _model_result("adjudicator", verdict="ADJUDICATION_COMPLETE", adjudication={
                "correction_required": False, "classifications": {}, "accepted_refs": [],
                "correction_brief": None, "stop_reason": None,
            }), {}
        if role == "reviewer" and cycle == 1:
            if mutate_on_final_review:
                (repo / "ignored.tmp").write_text("mutated during final review\n", encoding="utf-8")
            return _model_result("reviewer"), {}
        raise AssertionError(f"unexpected invocation role={role} cycle={cycle}")
    return invoke


def _finding_fixture(root):
    """Real Git repo plus a durable frozen finding attempt at FROZEN."""
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "runner@example.invalid")
    git(repo, "config", "user.name", "Runner Test")
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    (repo / ".gitignore").write_text("ignored.tmp\n", encoding="utf-8")
    git(repo, "add", "tracked.txt", ".gitignore")
    git(repo, "commit", "-qm", "baseline")
    sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    finding = finding_runner.validate_finding({
        "finding_id": "integrity", "repo": str(repo), "baseline_commit": sha,
        "risk": "LOW", "objective": "apply frozen change", "evidence": "repro",
        "allowed_paths": ["tracked.txt"],
        "targeted_validators": [{"name": "targeted", "command": ["true"]}],
        "broader_validators": [{"name": "broad", "command": ["true"]}],
        "roles": {"architect": "program_architect", "worker": "program_worker",
                  "reviewer": "program_reviewer"},
        "max_corrections": 0,
    })
    attempt, task, program = finding_runner._write_start_evidence(
        root / "findings", finding, _finding_profiles(),
    )
    return repo, sha, finding, attempt, task, program


def _execute_program(attempt, task, program, invoke):
    identity = json.loads((attempt / "identity.json").read_text(encoding="utf-8"))
    program = agentflow.validate_program(dict(program))
    task = agentflow.validate_task(dict(task))
    run_identity = agentflow.RunIdentity(
        identity["program_run_id"], agentflow.RUNS_DIR / identity["program_run_id"],
    )
    with mock.patch.object(agentflow, "invoke_model", side_effect=invoke):
        return agentflow.execute_program(program, task, run_identity, execution_control=None)


@contextlib.contextmanager
def _isolated_agentflow_home(root):
    findings, runs, locks, worktrees = (root / name for name in
                                        ("findings", "runs", "locks", "worktrees"))
    for path in (findings, runs, locks, worktrees):
        path.mkdir(parents=True, exist_ok=True)
    with mock.patch.object(agentflow, "RUNS_DIR", runs), \
         mock.patch.object(agentflow, "LOCKS_DIR", locks), \
         mock.patch.object(finding_runner, "FINDINGS_DIR", findings), \
         mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(worktrees)}):
        yield


class FindingRunnerInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "runner@example.invalid")
        git(self.repo, "config", "user.name", "Runner Test")
        (self.repo / "tracked.txt").write_text("baseline\n")
        git(self.repo, "add", "tracked.txt")
        git(self.repo, "commit", "-qm", "baseline")
        self.sha = git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.raw = {
            "finding_id": "issue-7", "repo": str(self.repo), "baseline_commit": self.sha.upper(),
            "risk": "LOW", "objective": "Fix issue", "evidence": "Reproduces with input X",
            "allowed_paths": ["tracked.txt"], "targeted_validators": [
                {"name": "target", "command": ["true"]}],
            "broader_validators": [{"name": "broad", "command": ["true"]}],
            "roles": {"architect": "a", "worker": "w", "reviewer": "r"}, "max_corrections": 1,
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_required_unknown_and_sha_normalization(self):
        normalized = finding_runner.validate_finding(self.raw)
        self.assertEqual(normalized["baseline_commit"], self.sha)
        missing = dict(self.raw); del missing["evidence"]
        with self.assertRaises(agentflow.AgentFlowError): finding_runner.validate_finding(missing)
        unknown = dict(self.raw, extra=True)
        with self.assertRaises(agentflow.AgentFlowError): finding_runner.validate_finding(unknown)

    def test_duplicate_json_keys_rejected(self):
        path = Path(self.tmp.name) / "duplicate.json"
        path.write_text('{"finding_id":"one","finding_id":"two"}')
        with self.assertRaises(ValueError): finding_runner._read_strict(path)

    def test_refs_and_abbreviated_sha_rejected(self):
        for sha in ("HEAD", self.sha[:12]):
            with self.subTest(sha=sha), self.assertRaises(agentflow.AgentFlowError):
                finding_runner.validate_finding(dict(self.raw, baseline_commit=sha))

    def test_bool_corrections_rejected(self):
        with self.assertRaises(agentflow.AgentFlowError):
            finding_runner.validate_finding(dict(self.raw, max_corrections=True))

    def test_same_finding_id_gets_exclusive_unique_attempts(self):
        finding = finding_runner.validate_finding(self.raw)
        root = Path(self.tmp.name) / "attempts"
        profiles = {"architect": {}, "worker": {}, "reviewer": {}}
        first, _, _ = finding_runner._write_start_evidence(root, finding, profiles)
        second, _, _ = finding_runner._write_start_evidence(root, finding, profiles)
        self.assertNotEqual(first.name, second.name)
        self.assertTrue(first.is_dir() and second.is_dir())


class CandidateManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.source = root / "source"
        self.source.mkdir()
        git(self.source, "init", "-q")
        git(self.source, "config", "user.email", "runner@example.invalid")
        git(self.source, "config", "user.name", "Runner Test")
        (self.source / "tracked.txt").write_text("baseline\n")
        git(self.source, "add", "tracked.txt")
        git(self.source, "commit", "-qm", "baseline")
        self.sha = git(self.source, "rev-parse", "HEAD").stdout.strip()
        self.candidate = root / "candidate"
        git(self.source, "worktree", "add", "--detach", str(self.candidate), self.sha)

    def tearDown(self):
        self.tmp.cleanup()

    def test_ignored_preexisting_file_is_in_semantic_manifest(self):
        git(self.candidate, "config", "core.excludesfile", "/dev/null")
        (self.candidate / ".gitignore").write_text("ignored.tmp\n")
        (self.candidate / "ignored.tmp").write_text("kept\n")
        # .gitignore itself is candidate state; make the same state for comparison.
        baseline = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        same = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertEqual(agentflow.candidate_manifest_digest(baseline), agentflow.candidate_manifest_digest(same))
        (self.candidate / "ignored.tmp").write_text("changed\n")
        changed = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertNotEqual(agentflow.candidate_manifest_digest(baseline), agentflow.candidate_manifest_digest(changed))

    def test_file_mode_and_symlink_changes_are_bound(self):
        before = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        path = self.candidate / "tracked.txt"
        path.chmod(0o755)
        mode_changed = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertNotEqual(before["candidate_digest"], mode_changed["candidate_digest"])
        link = self.candidate / "link"
        link.symlink_to("tracked.txt")
        link_a = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        link.unlink(); link.symlink_to("missing-target")
        link_b = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertNotEqual(link_a["candidate_digest"], link_b["candidate_digest"])

    def test_untracked_membership_and_semantic_index_are_bound(self):
        before = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        untracked = self.candidate / "new.txt"
        untracked.write_text("new\n")
        added = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertNotEqual(before["candidate_digest"], added["candidate_digest"])
        before_index = added["candidate_digest"]
        git(self.candidate, "add", "-N", "new.txt")
        index_changed = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertNotEqual(before_index, index_changed["candidate_digest"])

    def test_nested_repository_fails_closed(self):
        nested = self.candidate / "nested"
        nested.mkdir()
        git(nested, "init", "-q")
        with self.assertRaises(agentflow.AgentFlowError) as error:
            agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertEqual(error.exception.code, "CANDIDATE_INTEGRITY_CHANGED")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_special_file_fails_closed(self):
        os.mkfifo(self.candidate / "pipe")
        with self.assertRaises(agentflow.AgentFlowError) as error:
            agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertEqual(error.exception.code, "CANDIDATE_INTEGRITY_CHANGED")

    def test_gitlink_submodule_index_entry_fails_closed(self):
        git(self.candidate, "update-index", "--add", "--cacheinfo",
            f"160000,{self.sha},submodule")
        with self.assertRaises(agentflow.AgentFlowError) as error:
            agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        self.assertEqual(error.exception.code, "CANDIDATE_INTEGRITY_CHANGED")


class BroadValidationTests(CandidateManifestTests):
    def _broad_context(self, command):
        run_dir = Path(self.tmp.name) / "finding-run"
        run_dir.mkdir(exist_ok=True)
        workspace = {"status": "PRESERVED", "execution_repo": str(self.candidate),
                     "source_repo": str(self.source)}
        (Path(self.tmp.name) / "program-run").mkdir(exist_ok=True)
        (Path(self.tmp.name) / "program-run" / "workspace.json").write_text(json.dumps(workspace))
        outcome = type("Outcome", (), {
            "execution_repo": str(self.candidate), "baseline_commit": self.sha,
            "run_dir": str(Path(self.tmp.name) / "program-run"),
        })()
        finding = {"broader_validators": [{"name": "broad", "command": command, "timeout_seconds": 10}]}
        reviewed = agentflow.capture_candidate_manifest(self.candidate, self.source, self.sha)
        digest = agentflow.candidate_manifest_digest(reviewed)
        return run_dir, outcome, digest, finding

    def _broad(self, command):
        run_dir, outcome, digest, finding = self._broad_context(command)
        return finding_runner._broad_validate(finding, run_dir, outcome, digest)

    def test_zero_mutation_broad_passes(self):
        results = self._broad(["true"])
        self.assertEqual(results[0]["status"], "PASS")

    def test_broad_mutation_stops_even_when_validator_passes(self):
        with self.assertRaises(agentflow.AgentFlowError) as error:
            self._broad(["touch", ".pytest_cache-marker"])
        self.assertEqual(error.exception.code, "CANDIDATE_INTEGRITY_CHANGED")

    def test_invalid_broad_evidence_cannot_reach_broad_passed(self):
        run_dir, outcome, digest, finding = self._broad_context(["true"])
        malformed = [{"name": "broad", "command": "true", "status": "TIMEOUT", "exit_code": None}]
        with mock.patch.object(agentflow, "run_validators", return_value=malformed):
            with self.assertRaises(agentflow.AgentFlowError) as error:
                finding_runner._broad_validate(finding, run_dir, outcome, digest)
        self.assertEqual(error.exception.code, "VALIDATOR_FAILED")
        self.assertFalse((run_dir / "broader-evidence.json").exists())
        self.assertFalse((run_dir / "validators-cycle-1.json").exists())


class BroadEvidenceVerificationTests(unittest.TestCase):
    FROZEN = [
        {"name": "unit", "command": ["echo", "unit"], "timeout_seconds": 10},
        {"name": "lint", "command": ["echo", "lint"], "timeout_seconds": 10},
    ]

    @staticmethod
    def _result(name, command, status="PASS", exit_code=0):
        return {"name": name, "command": command, "status": status, "exit_code": exit_code}

    def _valid(self):
        return [self._result("unit", "echo unit"), self._result("lint", "echo lint")]

    def _assert_rejected(self, results):
        with self.assertRaises(agentflow.AgentFlowError) as error:
            finding_runner._verify_broad_results(self.FROZEN, results)
        self.assertEqual(error.exception.code, "VALIDATOR_FAILED")

    def test_broad_validator_malformed_evidence_fails_closed(self):
        valid = self._valid()
        cases = {
            "none": None,
            "not_a_list": {"unit": valid[0]},
            "empty": [],
            "incomplete": valid[:1],
            "extra": valid + [self._result("extra", "echo extra")],
            "duplicate": [valid[0], valid[0]],
            "substituted_name": [self._result("other", "echo unit"), valid[1]],
            "substituted_command": [self._result("unit", "echo other"), valid[1]],
            "nonzero_exit": [self._result("unit", "echo unit", exit_code=1), valid[1]],
            "bool_exit_code": [self._result("unit", "echo unit", exit_code=False), valid[1]],
            "missing_exit_code": [{"name": "unit", "command": "echo unit", "status": "PASS"}, valid[1]],
            "non_pass_status": [self._result("unit", "echo unit", status="FAIL"), valid[1]],
            "timeout": [self._result("unit", "echo unit", status="TIMEOUT", exit_code=None), valid[1]],
        }
        for label, results in cases.items():
            with self.subTest(label=label):
                self._assert_rejected(results)
        finding_runner._verify_broad_results(self.FROZEN, valid)


class FindingInvariantTests(unittest.TestCase):
    def test_candidate_verdict_is_queue_fatal(self):
        self.assertIn("CANDIDATE_INTEGRITY_CHANGED", agentflow._QUEUE_FATAL_VERDICTS)
        for verdict in ("CONTROL_PLANE_MUTATED", "GIT_IDENTITY_MOVED", "UNAUTHORIZED_PATH_CHANGE"):
            self.assertIn(verdict, agentflow._QUEUE_FATAL_VERDICTS)

    def test_candidate_verdict_outcome_is_queue_fatal(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            program = {"program_id": "p"}
            task = {"task_id": "t", "repo": temp}
            identity = agentflow.RunIdentity("r", run_dir)
            final = {"program_id": "p", "task_id": "t", "run_id": "r",
                     "verdict": "CANDIDATE_INTEGRITY_CHANGED", "status": "STOPPED", "human_gate": False}
            agentflow.atomic_json_fsync(run_dir / "final.json", final)
            outcome = agentflow._verified_program_outcome(
                program=program, task=task, run_identity=identity,
                returned_final=final, execution_control=None,
            )
            self.assertEqual(outcome.outcome_class, "QUEUE_FATAL_FAILURE")

    def test_queue_fatal_classification_matrix_unchanged(self):
        verdicts = ("CANDIDATE_INTEGRITY_CHANGED", "CONTROL_PLANE_MUTATED", "GIT_IDENTITY_MOVED",
                    "INTERNAL_ERROR", "WRITE_LEASE_CONFLICT")
        for verdict in verdicts:
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as temp:
                self.assertIn(verdict, agentflow._QUEUE_FATAL_VERDICTS)
                run_dir = Path(temp)
                identity = agentflow.RunIdentity("r", run_dir)
                final = {"program_id": "p", "task_id": "t", "run_id": "r",
                         "verdict": verdict, "status": "STOPPED", "human_gate": False}
                agentflow.atomic_json_fsync(run_dir / "final.json", final)
                outcome = agentflow._verified_program_outcome(
                    program={"program_id": "p"}, task={"task_id": "t", "repo": temp},
                    run_identity=identity, returned_final=final, execution_control=None,
                )
                self.assertEqual(outcome.outcome_class, "QUEUE_FATAL_FAILURE")
                self.assertIs(outcome.human_gate, False)

    def test_finding_program_does_not_use_queue_control(self):
        source = Path(finding_runner.__file__).read_text()
        self.assertNotIn("ExecutionControl(", source)
        self.assertNotIn("run_task(", source)

    def test_effective_profiles_keep_program_profile_names(self):
        profiles = {
            "architect_profile": {"model": "vendor/architect-x", "backend": "codex", "command": sys.executable,
                                  "available": True, "eligible_roles": ["architect", "adjudicator"]},
            "worker_profile": {"model": "vendor/worker-x", "backend": "codex", "command": sys.executable,
                               "available": True, "eligible_roles": ["worker"]},
            "reviewer_profile": {"model": "vendor/reviewer-x", "backend": "codex", "command": sys.executable,
                                 "available": True, "eligible_roles": ["reviewer"]},
        }
        finding = {"roles": {"architect": "architect_profile", "worker": "worker_profile",
                             "reviewer": "reviewer_profile"}}
        with mock.patch.object(finding_runner.af, "load_models", return_value={"profiles": profiles}):
            frozen = finding_runner._freeze_profiles(finding)
        self.assertEqual(set(frozen), set(profiles))

    def test_verified_program_architect_is_frozen_with_independent_roles(self):
        models = json.loads(agentflow.MODELS_FILE.read_text(encoding="utf-8"))
        finding = {"roles": {"architect": "program_architect",
                             "worker": "primary_worker",
                             "reviewer": "independent_reviewer"}}
        with mock.patch.object(finding_runner.af, "load_models", return_value=models), \
             mock.patch.object(finding_runner.af.shutil, "which", return_value="/usr/bin/true"):
            frozen = finding_runner._freeze_profiles(finding)
        architect = frozen["program_architect"]
        self.assertEqual("opencode", architect["backend"])
        self.assertEqual("opencode-go", architect["provider"])
        self.assertEqual("opencode-go/muse-spark-1.3-contributor", architect["model"])
        self.assertEqual("high", architect["variant"])
        self.assertEqual("agentflow-architect", architect["agent"])
        self.assertNotEqual("opencode/muse-spark-1.2-contributor-free", architect["model"])
        agentflow._check_role_eligible(architect, "architect")
        agentflow._check_role_eligible(architect, "adjudicator")
        for role in ("worker", "reviewer"):
            with self.assertRaises(agentflow.AgentFlowError):
                agentflow._check_role_eligible(architect, role)
        agentflow._check_adjudicator_independence(
            frozen["primary_worker"], frozen["independent_reviewer"], architect)
        self.assertNotEqual(agentflow.model_family(frozen["primary_worker"]),
                            agentflow.model_family(frozen["independent_reviewer"]))
        self.assertEqual(models["profiles"]["program_architect"], architect)

        stale = json.loads(json.dumps(models))
        stale["profiles"]["program_architect"].update({
            "model": "opencode/muse-spark-1.2-contributor-free", "available": False,
        })
        with mock.patch.object(finding_runner.af, "load_models", return_value=stale), \
             mock.patch.object(finding_runner.af.shutil, "which", return_value="/usr/bin/true"):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                finding_runner._freeze_profiles(finding)
        self.assertEqual("MODEL_UNAVAILABLE", raised.exception.code)

    def test_original_control_plane_restore_is_bounded_and_covers_runner(self):
        manifest = agentflow.capture_control_plane_manifest()
        self.assertIn("finding_runner.py", manifest["files"])
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            with self.assertRaises(KeyboardInterrupt):
                with agentflow._control_plane_restored_scope(run_dir, manifest):
                    active = agentflow._CONTROL_PLANE_BASELINE.get()
                    self.assertEqual(active["manifest"]["digest"], manifest["digest"])
                    raise KeyboardInterrupt()
            self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

    def test_malformed_persisted_control_plane_manifest_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(agentflow.AgentFlowError):
                with agentflow._control_plane_restored_scope(Path(temp), {"root": "/wrong"}):
                    self.fail("malformed baseline must not enter the scope")

    def test_run_composes_exactly_one_existing_program_without_queue_control(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "runner@example.invalid")
            git(repo, "config", "user.name", "Runner Test")
            (repo / "file.txt").write_text("x\n")
            git(repo, "add", "file.txt")
            git(repo, "commit", "-qm", "baseline")
            sha = git(repo, "rev-parse", "HEAD").stdout.strip()
            finding = finding_runner.validate_finding({
                "finding_id": "compose", "repo": str(repo),
                "baseline_commit": sha, "risk": "LOW", "objective": "fix", "evidence": "repro",
                "allowed_paths": ["a"], "targeted_validators": [{"name": "t", "command": ["true"]}],
                "broader_validators": [{"name": "b", "command": ["true"]}],
                "roles": {"architect": "a", "worker": "w", "reviewer": "r"}, "max_corrections": 0,
            })
            outcome = type("Outcome", (), {"execution_repo": temp, "run_id": "program-run"})()
            lease = mock.MagicMock()
            lease.__enter__.return_value = lease
            with mock.patch.object(finding_runner, "FINDINGS_DIR", Path(temp) / "findings"), \
                 mock.patch.object(finding_runner, "preflight", return_value=(finding, {})), \
                 mock.patch.object(finding_runner.af, "validate_task", side_effect=lambda value: value), \
                 mock.patch.object(finding_runner.af, "validate_program", side_effect=lambda value: value), \
                 mock.patch.object(finding_runner.af, "execute_program", return_value=outcome) as execute, \
                 mock.patch.object(finding_runner.af, "verify_program_outcome"), \
                 mock.patch.object(finding_runner, "_strict_program_success"), \
                 mock.patch.object(finding_runner, "_manifest_binding", return_value=({"candidate_digest": "d"}, {})), \
                 mock.patch.object(finding_runner.af, "WriteLease", return_value=lease), \
                 mock.patch.object(finding_runner, "_candidate_live", return_value={}), \
                 mock.patch.object(finding_runner, "_broad_validate", return_value=[]), \
                 mock.patch.object(finding_runner, "_closure", return_value={"closure": "PROVEN"}), \
                 mock.patch.object(finding_runner, "_terminal", return_value={"verdict": "HUMAN_GATE"}):
                code, _, _ = finding_runner.run(Path(temp) / "finding.json")
            self.assertEqual(code, 0)
            execute.assert_called_once()
            self.assertIsNone(execute.call_args.kwargs["execution_control"])

    def test_f06_human_gate_true_validator_failure_never_reaches_broad_or_finding_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"
            repo.mkdir()
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "runner@example.invalid")
            git(repo, "config", "user.name", "Runner Test")
            (repo / "file.txt").write_text("x\n")
            git(repo, "add", "file.txt")
            git(repo, "commit", "-qm", "baseline")
            sha = git(repo, "rev-parse", "HEAD").stdout.strip()
            finding = finding_runner.validate_finding({
                "finding_id": "f06", "repo": str(repo), "baseline_commit": sha,
                "risk": "LOW", "objective": "fix", "evidence": "repro", "allowed_paths": ["file.txt"],
                "targeted_validators": [{"name": "t", "command": ["true"]}],
                "broader_validators": [{"name": "b", "command": ["true"]}],
                "roles": {"architect": "a", "worker": "w", "reviewer": "r"}, "max_corrections": 0,
            })
            runs = Path(temp) / "runs"
            findings = Path(temp) / "findings"
            def execute(program, task, identity, execution_control=None):
                identity.run_dir.mkdir(parents=True)
                final = {"program_id": program["program_id"], "task_id": task["task_id"],
                         "run_id": identity.run_id, "verdict": "VALIDATOR_FAILED", "status": "STOPPED",
                         "human_gate": True}
                agentflow.atomic_json_fsync(identity.run_dir / "final.json", final)
                return agentflow._verified_program_outcome(
                    program=program, task=task, run_identity=identity, returned_final=final,
                    execution_control=execution_control,
                )
            with mock.patch.object(finding_runner, "FINDINGS_DIR", findings), \
                 mock.patch.object(finding_runner.af, "RUNS_DIR", runs), \
                 mock.patch.object(finding_runner, "preflight", return_value=(finding, {})), \
                 mock.patch.object(finding_runner.af, "execute_program", side_effect=execute) as execute_mock, \
                 mock.patch.object(finding_runner.af, "WriteLease") as lease_mock, \
                 mock.patch.object(finding_runner, "_broad_validate") as broad_mock:
                code, run_dir, _ = finding_runner.run(Path(temp) / "finding.json")
                self.assertEqual(code, 2)
                self.assertEqual(finding_runner.status(run_dir.name)[0], 2)
                self.assertEqual(finding_runner.resume(run_dir.name)[0], 2)
            execute_mock.assert_called_once()
            self.assertIsNone(execute_mock.call_args.kwargs["execution_control"])
            lease_mock.assert_not_called()
            broad_mock.assert_not_called()

    def test_concurrent_resume_lock_refusal_does_not_stop_owner_run(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with mock.patch.object(finding_runner, "_load_run", return_value=(path, {}, {"state": "FROZEN"})), \
                 mock.patch.object(finding_runner, "_state_write") as state_write:
                with finding_runner._coordinator_lock(path):
                    code, _ = finding_runner.resume("run-1")
                self.assertEqual(code, 2)
                state_write.assert_not_called()


class FinalReviewBindingTests(unittest.TestCase):
    def test_final_review_mutation_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with _isolated_agentflow_home(root):
                _repo, _sha, _finding, attempt, task, program = _finding_fixture(root)
                outcome = _execute_program(
                    attempt, task, program, _program_invoke(mutate_on_final_review=True),
                )
                self.assertEqual(outcome.verdict, "CANDIDATE_INTEGRITY_CHANGED")
                self.assertEqual(outcome.status, "STOPPED")
                self.assertIs(outcome.human_gate, False)
                self.assertEqual(outcome.outcome_class, "QUEUE_FATAL_FAILURE")
                self.assertNotEqual(outcome.final.get("verdict"), "HUMAN_GATE")
                self.assertFalse(
                    (Path(outcome.run_dir) / "reviewed-candidate-manifest.json").exists(),
                )

    def test_pre_gate_mutation_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with _isolated_agentflow_home(root):
                _repo, _sha, _finding, attempt, task, program = _finding_fixture(root)
                identity = json.loads((attempt / "identity.json").read_text(encoding="utf-8"))
                candidate = agentflow._worktree_destination(identity["program_run_id"])
                original_gate = agentflow._verify_control_plane_before_gate
                state = {"mutated": False}

                def mutate_then_verify(run_dir):
                    if not state["mutated"]:
                        state["mutated"] = True
                        (candidate / "ignored.tmp").write_text(
                            "mutated before gate\n", encoding="utf-8",
                        )
                    return original_gate(run_dir)

                with mock.patch.object(agentflow, "_verify_control_plane_before_gate",
                                       side_effect=mutate_then_verify):
                    outcome = _execute_program(attempt, task, program, _program_invoke())
                self.assertTrue(state["mutated"])
                self.assertEqual(outcome.verdict, "CANDIDATE_INTEGRITY_CHANGED")
                self.assertIs(outcome.human_gate, False)
                self.assertEqual(outcome.outcome_class, "QUEUE_FATAL_FAILURE")
                self.assertNotEqual(outcome.final.get("verdict"), "HUMAN_GATE")
                # The reviewed binding exists, proving the mutation landed after
                # final reviewer acceptance and before the pre-gate verification.
                self.assertTrue(
                    (Path(outcome.run_dir) / "reviewed-candidate-manifest.json").is_file(),
                )


class ResumeBoundaryTests(unittest.TestCase):
    def _assert_ambiguous_incomplete(self, states):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with _isolated_agentflow_home(root):
                _repo, _sha, _finding, attempt, _task, _program = _finding_fixture(root)
                for state in states:
                    finding_runner._state_write(attempt, state)
                code, result = finding_runner.resume(attempt.name)
                self.assertEqual(code, 2)
                self.assertEqual(result["verdict"], "AMBIGUOUS_PHASE")
                self.assertIs(result["human_gate"], False)
                self.assertFalse((attempt / "final.json").exists())
                self.assertFalse((attempt / "broader-evidence.json").exists())
                self.assertFalse((attempt / "closure.json").exists())
                persisted = json.loads((attempt / "state.json").read_text(encoding="utf-8"))
                self.assertEqual(persisted["state"], "STOPPED")

    def test_resume_incomplete_boundaries_fail_closed(self):
        cases = {
            "PROGRAM_STARTED": ("PROGRAM_STARTED",),
            "BROAD_STARTED": ("PROGRAM_STARTED", "PROGRAM_VERIFIED", "BROAD_STARTED"),
            "CLOSURE_STARTED": ("PROGRAM_STARTED", "PROGRAM_VERIFIED", "BROAD_STARTED",
                                "BROAD_PASSED", "CLOSURE_STARTED"),
        }
        for boundary, states in cases.items():
            with self.subTest(boundary=boundary):
                self._assert_ambiguous_incomplete(states)

    def test_resume_program_verified_orphan_evidence_fails_closed(self):
        for orphan_name in ("validators-cycle-1.json", "broader-evidence.json"):
            with self.subTest(orphan=orphan_name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with _isolated_agentflow_home(root):
                    repo, _sha, _finding, attempt, _task, _program = _finding_fixture(root)
                    finding_runner._state_write(attempt, "PROGRAM_STARTED")
                    finding_runner._state_write(attempt, "PROGRAM_VERIFIED")
                    (attempt / orphan_name).write_text("[]", encoding="utf-8")
                    fake_outcome = mock.MagicMock()
                    fake_outcome.execution_repo = str(repo)
                    fake_outcome.run_id = "program-run"
                    with mock.patch.object(finding_runner, "_reconstruct_outcome",
                                           return_value=fake_outcome), \
                         mock.patch.object(finding_runner, "_manifest_binding",
                                           return_value=({"candidate_digest": "d"}, {})), \
                         mock.patch.object(finding_runner, "_candidate_live"), \
                         mock.patch.object(finding_runner.af, "WriteLease"), \
                         mock.patch.object(finding_runner, "_broad_validate") as broad:
                        code, result = finding_runner.resume(attempt.name)
                    self.assertEqual(code, 2)
                    self.assertEqual(result["verdict"], "AMBIGUOUS_PHASE")
                    self.assertIs(result["human_gate"], False)
                    broad.assert_not_called()
                    self.assertFalse((attempt / "closure.json").exists())
                    self.assertFalse((attempt / "final.json").exists())

    def test_resume_from_program_verified_continues_to_human_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with _isolated_agentflow_home(root):
                _repo, _sha, _finding, attempt, task, program = _finding_fixture(root)
                outcome = _execute_program(attempt, task, program, _program_invoke())
                self.assertEqual(outcome.verdict, "HUMAN_GATE")
                finding_runner._manifest_binding(outcome, attempt, create=True)
                finding_runner._state_write(attempt, "PROGRAM_STARTED")
                finding_runner._state_write(attempt, "PROGRAM_VERIFIED")
                self.assertFalse((attempt / "broader-evidence.json").exists())
                code, final = finding_runner.resume(attempt.name)
                self.assertEqual(code, 0)
                self.assertEqual(final["verdict"], "HUMAN_GATE")
                self.assertIs(final["human_gate"], True)
                self.assertTrue((attempt / "validators-cycle-1.json").is_file())
                self.assertTrue((attempt / "broader-evidence.json").is_file())
                self.assertTrue((attempt / "closure.json").is_file())
                self.assertTrue((attempt / "final.json").is_file())
                self.assertEqual(finding_runner.status(attempt.name)[0], 0)

    def test_resume_from_broad_passed_continues_to_human_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with _isolated_agentflow_home(root):
                _repo, _sha, finding, attempt, task, program = _finding_fixture(root)
                outcome = _execute_program(attempt, task, program, _program_invoke())
                self.assertEqual(outcome.verdict, "HUMAN_GATE")
                reviewed, _binding = finding_runner._manifest_binding(outcome, attempt, create=True)
                finding_runner._state_write(attempt, "PROGRAM_STARTED")
                finding_runner._state_write(attempt, "PROGRAM_VERIFIED")
                finding_runner._state_write(attempt, "BROAD_STARTED")
                broad = finding_runner._broad_validate(
                    finding, attempt, outcome, reviewed["candidate_digest"],
                )
                self.assertTrue(broad)
                self.assertEqual(broad[0]["status"], "PASS")
                finding_runner._state_write(attempt, "BROAD_PASSED")
                code, final = finding_runner.resume(attempt.name)
                self.assertEqual(code, 0)
                self.assertEqual(final["verdict"], "HUMAN_GATE")
                self.assertIs(final["human_gate"], True)
                self.assertEqual(finding_runner.status(attempt.name)[0], 0)


class ModuleIdentityTests(unittest.TestCase):
    @staticmethod
    def _run_driver(driver):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(
            [sys.executable, "-c", driver],
            cwd=str(Path(agentflow.__file__).resolve().parent),
            env=env, text=True, capture_output=True,
        )

    def test_canonical_finding_dispatch_shares_one_agentflow_module(self):
        script = Path(agentflow.__file__).resolve()
        driver = (
            "import contextlib, io, json, runpy, sys\n"
            "sys.argv = ['agentflow.py', 'finding', 'status', 'missing-run']\n"
            "try:\n"
            "    with contextlib.redirect_stdout(io.StringIO()):\n"
            f"        runpy.run_path({str(script)!r}, run_name='__main__')\n"
            "except SystemExit:\n"
            "    pass\n"
            "import finding_runner\n"
            "af = sys.modules['agentflow']\n"
            "print(json.dumps({'name': af.__name__, 'same_af': finding_runner.af is af,\n"
            "                  'same_f04': finding_runner.af._CONTROL_PLANE_BASELINE"
            " is af._CONTROL_PLANE_BASELINE}))\n"
        )
        proc = self._run_driver(driver)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["name"], "__main__")
        self.assertTrue(payload["same_af"])
        self.assertTrue(payload["same_f04"])

    def test_plain_import_keeps_one_canonical_agentflow_module(self):
        driver = (
            "import json, sys\n"
            "import agentflow, finding_runner\n"
            "print(json.dumps({'name': agentflow.__name__,\n"
            "                  'canonical': sys.modules['agentflow'] is agentflow,\n"
            "                  'same_af': finding_runner.af is agentflow}))\n"
        )
        proc = self._run_driver(driver)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["name"], "agentflow")
        self.assertTrue(payload["canonical"])
        self.assertTrue(payload["same_af"])


if __name__ == "__main__":
    unittest.main()
