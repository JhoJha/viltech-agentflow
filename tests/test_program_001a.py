import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentflow


def _make_result(task_id="t1", role="worker", verdict="PASS", findings=None,
                 files_changed=None, open_risks=None, **extra):
    result = {
        "task_id": task_id,
        "role": role,
        "harness": "opencode",
        "provider": "opencode",
        "model": "test/model",
        "variant": None,
        "files_changed": files_changed or [],
        "validators": {},
        "findings": findings or [],
        "open_risks": open_risks or [],
        "verdict": verdict,
    }
    result.update(extra)
    return result


def _make_record(role="worker", cycle=0):
    return {
        "profile": "test_profile", "role": role,
        "harness": "opencode", "provider": "opencode",
        "model": "test/model", "variant": None,
        "agent": "test-agent", "cycle": cycle,
        "invoked_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "exit_code": 0,
    }


_ARCH_PLAN = {
    "objective_interpretation": "Add feature to project",
    "implementation_steps": ["Create src/foo.py", "Update main module"],
    "invariants": ["All tests must pass"],
    "allowed_scope": ["src/"],
    "do_not_change": ["README.md"],
    "validation_expectations": ["py_compile passes"],
    "known_risks": ["None identified"],
}

_ARCHITECT_RESULT = _make_result(
    role="architect", verdict="PLAN_READY", files_changed=[], architect_plan=dict(_ARCH_PLAN),
)
_WORKER_RESULT_0 = _make_result(role="worker", verdict="PASS", files_changed=["src/foo.py"])
_REVIEWER_RESULT_0 = _make_result(
    role="reviewer", verdict="BLOCKER",
    findings=[
        {"severity": "HIGH", "text": "Bug in error handling"},
        {"severity": "MEDIUM", "text": "Missing docstring"},
        {"severity": "LOW", "text": "Style issue"},
    ],
)
_ADJUDICATOR_RESULT_CORRECTION = _make_result(
    role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
    adjudication={
        "correction_required": True,
        "classifications": {
            "R1-F1": "ACTIONABLE_REQUIRED",
            "R1-F2": "ACTIONABLE_OPTIONAL",
            "R1-F3": "NON_ACTIONABLE",
        },
        "accepted_refs": ["R1-F1", "R1-F2"],
        "correction_brief": {"required_changes": ["Fix error handling", "Add docstring"]},
        "stop_reason": None,
    },
)
_ADJUDICATOR_RESULT_NO_CORRECTION = _make_result(
    role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
    adjudication={
        "correction_required": False,
        "classifications": {
            "R1-F1": "NON_ACTIONABLE",
            "R1-F2": "OUT_OF_SCOPE",
            "R1-F3": "INCORRECT",
        },
        "accepted_refs": [],
        "correction_brief": None,
        "stop_reason": None,
    },
)
_WORKER_RESULT_1 = _make_result(role="worker", verdict="PASS", files_changed=["src/foo.py"])
_REVIEWER_RESULT_1_PASS = _make_result(role="reviewer", verdict="PASS")
_REVIEWER_RESULT_1_BLOCKING = _make_result(
    role="reviewer", verdict="BLOCKER",
    findings=[{"severity": "BLOCKER", "text": "Critical issue remains"}],
)

_DEFAULT_MODELS = {
    "profiles": {
        "program_architect": {
            "backend": "opencode", "command": "opencode",
            "provider": "opencode", "model": "opencode/muse-spark-1.2",
            "variant": "high", "agent": "agentflow-architect", "available": True,
            "eligible_roles": ["architect", "adjudicator"],
        },
        "program_worker": {
            "backend": "opencode", "command": "opencode",
            "provider": "opencode", "model": "opencode/nemotron-3-ultra-free",
            "variant": None, "agent": "agentflow-worker", "available": True,
            "eligible_roles": ["worker"],
        },
        "program_reviewer": {
            "backend": "opencode", "command": "opencode",
            "provider": "opencode-go", "model": "opencode-go/deepseek-v4.1-flash",
            "variant": "max", "agent": "agentflow-reviewer", "available": True,
            "eligible_roles": ["reviewer"],
        },
    },
}

_DEFAULT_TASK = {
    "task_id": "test-task-001", "repo": "/tmp/fake-repo", "risk": "HIGH",
    "objective": "Add a helper function", "allowed_paths": ["src/"],
    "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
    "invariants": ["All tests pass"], "forbidden_actions": ["git commit"],
    "expected_baseline": {},
}

_DEFAULT_PROGRAM = {
    "program_id": "program-001a-test", "task": "task.json",
    "roles": {
        "architect": "program_architect",
        "worker": "program_worker",
        "reviewer": "program_reviewer",
    },
    "max_corrections": 1,
}


class Program001ATests(unittest.TestCase):

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)

        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        (self.repo / "src").mkdir()

        self.runs_dir = self.tmp / "runs"
        self.runs_dir.mkdir()
        self.locks_dir = self.tmp / "locks"
        self.locks_dir.mkdir()
        self.prompts_dir = self.tmp / "prompts"
        self.prompts_dir.mkdir()

        self.program_file = self.tmp / "program.json"
        self.task_file = self.tmp / "task.json"
        self.program_file.write_text(json.dumps(_DEFAULT_PROGRAM), encoding="utf-8")
        self.task = dict(_DEFAULT_TASK)
        self.task["repo"] = str(self.repo)
        self.task_file.write_text(json.dumps(self.task), encoding="utf-8")

        for name in ("architect", "adjudicator", "worker", "reviewer"):
            (self.prompts_dir / f"{name}.md").write_text(f"# {name}\nReturn JSON.", encoding="utf-8")

        self._baseline_obj = {
            "captured_at": "2026-01-01T00:00:00+00:00",
            "repo": str(self.repo), "branch": "main", "head": "abc123",
            "dirty_paths": [], "untracked_paths": [],
            "path_state": {"src/foo.py": "hash1"},
            "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
        }

        self._patches = []

        for attr, target in [
            ("RUNS_DIR", self.runs_dir), ("LOCKS_DIR", self.locks_dir), ("ROOT", self.tmp),
        ]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)

        # --- read_json ---
        self.read_json_patcher = mock.patch("agentflow.read_json")
        self.mock_read_json = self.read_json_patcher.start()
        self._patches.append(self.read_json_patcher)
        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        def _read_json(path):
            p = Path(path).resolve()
            if p == program_resolved:
                return dict(_DEFAULT_PROGRAM)
            if p == task_resolved:
                t = dict(self.task); t["repo"] = str(self.repo); return t
            return {}
        self.mock_read_json.side_effect = _read_json

        # --- capture_baseline: returns SAME dict reference every time ---
        self.capture_baseline_patcher = mock.patch("agentflow.capture_baseline")
        self.mock_capture_baseline = self.capture_baseline_patcher.start()
        self._patches.append(self.capture_baseline_patcher)
        self._baseline_snapshot = dict(self._baseline_obj)
        self.mock_capture_baseline.return_value = self._baseline_snapshot

        # --- changed_since: counter-based side_effect ---
        self.changed_since_patcher = mock.patch("agentflow.changed_since")
        self.mock_changed_since = self.changed_since_patcher.start()
        self._patches.append(self.changed_since_patcher)
        self._cs_counter = 0
        self._cs_schedule = []
        def _changed_since(before, after):
            idx = self._cs_counter
            self._cs_counter += 1
            if idx < len(self._cs_schedule):
                return self._cs_schedule[idx]
            return []
        self.mock_changed_since.side_effect = _changed_since

        # --- invoke_model ---
        self.invoke_patcher = mock.patch("agentflow.invoke_model")
        self.mock_invoke = self.invoke_patcher.start()
        self._patches.append(self.invoke_patcher)

        # --- run_validators ---
        self.validators_patcher = mock.patch("agentflow.run_validators")
        self.mock_validators = self.validators_patcher.start()
        self._patches.append(self.validators_patcher)
        self.mock_validators.return_value = [
            {"name": "lint", "command": "/usr/bin/true",
             "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
             "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
        ]

        # --- shutil.which ---
        self.which_patcher = mock.patch("shutil.which")
        self.mock_which = self.which_patcher.start()
        self._patches.append(self.which_patcher)
        self.mock_which.return_value = "/usr/bin/opencode"

        # --- git ---
        self.git_patcher = mock.patch("agentflow.git")
        self.mock_git = self.git_patcher.start()
        self._patches.append(self.git_patcher)
        mock_proc = mock.MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "diff --git a/src/foo.py\n+new\n"
        mock_proc.stderr = ""
        self.mock_git.return_value = mock_proc

        # --- WriteLease ---
        self.lease_patcher = mock.patch("agentflow.WriteLease")
        self.mock_lease_cls = self.lease_patcher.start()
        self._patches.append(self.lease_patcher)
        mock_lease = mock.MagicMock()
        mock_lease.__enter__ = mock.MagicMock(return_value=mock_lease)
        mock_lease.__exit__ = mock.MagicMock(return_value=False)
        self.mock_lease_cls.return_value = mock_lease

        # --- load_models ---
        self.load_models_patcher = mock.patch("agentflow.load_models")
        self.mock_load_models = self.load_models_patcher.start()
        self._patches.append(self.load_models_patcher)
        self.mock_load_models.return_value = dict(_DEFAULT_MODELS)

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    def _set_cs(self, *results):
        """Configure changed_since call schedule.

        Index 0 = architect readonly, 1 = worker cycle delta,
        2 = post-validator scope check, 3 = reviewer readonly,
        4 = adjudicator readonly, 5 = correction worker delta,
        6 = post-correction-validator scope check, 7 = final reviewer readonly.
        """
        self._cs_counter = 0
        self._cs_schedule = list(results)

    def _run(self):
        return agentflow.run_program(self.program_file)

    def _invoke_roles(self):
        return [c.kwargs.get("role") or c.args[0] for c in self.mock_invoke.call_args_list]

    # ------------------------------------------------------------------
    # 1. HAPPY PATH
    # ------------------------------------------------------------------
    def test_happy_path(self):
        # cs0: architect readonly, cs1: worker delta, cs2: reviewer readonly,
        # cs3: adjudicator readonly, cs4: final reviewer readonly
        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(0, code)
        self.assertEqual("SUCCESS", final["status"])
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertIs(True, final["human_gate"])
        self.assertIsInstance(final["initial_reviewer"], dict)
        self.assertIsInstance(final["final_reviewer"], dict)
        self.assertEqual(0, final["initial_reviewer_cycle"])
        self.assertEqual(1, final["final_reviewer_cycle"])
        self.assertEqual(5, self.mock_invoke.call_count)
        self.assertEqual(
            ["architect", "worker", "reviewer", "adjudicator", "reviewer"],
            self._invoke_roles(),
        )

    def test_adjudicator_contract_repair_keeps_worker_and_validators_single(self):
        self._set_cs([], ["src/foo.py"], [], [], [])
        real_invoke = self.invoke_patcher.temp_original
        physical = mock.Mock(side_effect=[
            agentflow.AgentFlowError(
                "INVALID_MODEL_OUTPUT", "adjudication missing fields: ['stop_reason']"
            ),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
        ])
        roles = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        def dispatch(**kwargs):
            if kwargs["role"] == "adjudicator":
                return real_invoke(**kwargs)
            return roles.pop(0)
        self.mock_invoke.side_effect = dispatch
        with mock.patch("agentflow._invoke_model_once", physical):
            code, _run_dir, final = self._run()
        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual(2, physical.call_count)
        self.assertEqual(1, self._invoke_roles().count("worker"))
        self.assertEqual(1, self.mock_validators.call_count)
        self.assertEqual([], roles)

    # ------------------------------------------------------------------
    # 2. CORRECTION PATH
    # ------------------------------------------------------------------
    def test_correction_path(self):
        # cs0 architect ro, cs1 worker0 delta, cs2 post-validator0,
        # cs3 reviewer ro, cs4 adjudicator ro, cs5 correction worker delta,
        # cs6 post-validator1, cs7 final reviewer ro
        self._set_cs([], ["src/foo.py"], [], [], [], ["src/foo.py"], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_CORRECTION, _make_record("adjudicator", 0)),
            (_WORKER_RESULT_1, _make_record("worker", 1)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(0, code)
        self.assertEqual("SUCCESS", final["status"])
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual(6, self.mock_invoke.call_count)
        self.assertEqual(1, final["correction_cycles"])
        self.assertEqual(
            ["architect", "worker", "reviewer", "adjudicator", "worker", "reviewer"],
            self._invoke_roles(),
        )
        correction_call = self.mock_invoke.call_args_list[4]
        ctx = correction_call.kwargs.get("context")
        self.assertIsNotNone(ctx)
        self.assertEqual("adjudicated_correction", ctx["kind"])

    # ------------------------------------------------------------------
    # 3. FINAL REVIEW BLOCKS
    # ------------------------------------------------------------------
    def test_final_review_blocks(self):
        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (_REVIEWER_RESULT_1_BLOCKING, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("FINAL_REVIEW_BLOCKED", final["verdict"])
        self.assertEqual(5, self.mock_invoke.call_count)

    # ------------------------------------------------------------------
    # 4. ADJUDICATOR REJECTS ALL
    # ------------------------------------------------------------------
    def test_adjudicator_rejects_all(self):
        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(0, code)
        self.assertEqual("SUCCESS", final["status"])
        roles = self._invoke_roles()
        self.assertNotIn("worker", roles[3:])
        self.assertEqual(1, sum(1 for r in roles if r == "worker"))

    # ------------------------------------------------------------------
    # 5. ADJUDICATION FILTER
    # ------------------------------------------------------------------
    def test_adjudication_filter(self):
        reviewer_result = _make_result(
            role="reviewer", verdict="BLOCKER",
            findings=[
                {"severity": "HIGH", "text": "Accepted finding text"},
                {"severity": "MEDIUM", "text": "Rejected finding text"},
                {"severity": "LOW", "text": "Another rejected finding"},
            ],
        )
        adjudication_result = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": True,
                "classifications": {
                    "R1-F1": "ACTIONABLE_REQUIRED",
                    "R1-F2": "NON_ACTIONABLE",
                    "R1-F3": "OUT_OF_SCOPE",
                },
                "accepted_refs": ["R1-F1"],
                "correction_brief": {"required_changes": ["Fix the accepted finding"]},
                "stop_reason": None,
            },
        )
        self._set_cs([], ["src/foo.py"], [], [], [], ["src/foo.py"], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (reviewer_result, _make_record("reviewer", 0)),
            (adjudication_result, _make_record("adjudicator", 0)),
            (_WORKER_RESULT_1, _make_record("worker", 1)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(0, code)
        correction_call = self.mock_invoke.call_args_list[4]
        ctx = correction_call.kwargs.get("context")
        self.assertIsNotNone(ctx)
        self.assertEqual("adjudicated_correction", ctx["kind"])
        self.assertEqual(["R1-F1"], ctx["accepted_refs"])
        correction_text = json.dumps(ctx)
        self.assertNotIn("Rejected finding text", correction_text)
        self.assertNotIn("Another rejected finding", correction_text)

    # ------------------------------------------------------------------
    # 6. ARCHITECT MUTATION
    # ------------------------------------------------------------------
    def test_architect_mutation(self):
        # changed_since call 0 = architect readonly → returns mutation
        self._set_cs(["src/foo.py"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("READONLY_ROLE_WROTE_REPO", final["verdict"])
        self.assertIn("architect", final["message"].lower())

    # ------------------------------------------------------------------
    # 7. ADJUDICATOR MUTATION
    # ------------------------------------------------------------------
    def test_adjudicator_mutation(self):
        self._set_cs([], ["src/foo.py"], [], [], ["src/secret.py"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("READONLY_ROLE_WROTE_REPO", final["verdict"])

    # ------------------------------------------------------------------
    # 8. INITIAL REVIEWER MUTATION
    # ------------------------------------------------------------------
    def test_initial_reviewer_mutation(self):
        self._set_cs([], ["src/foo.py"], [], ["src/tainted.py"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("READONLY_ROLE_WROTE_REPO", final["verdict"])

    # ------------------------------------------------------------------
    # 9. FINAL REVIEWER MUTATION
    # ------------------------------------------------------------------
    def test_final_reviewer_mutation(self):
        # cs0: architect ro [], cs1: worker delta [], cs2: post-validator [],
        # cs3: reviewer ro [], cs4: adjudicator ro [],
        # cs5: final reviewer ro ["src/tainted.py"]
        self._set_cs([], [], [], [], [], ["src/tainted.py"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("READONLY_ROLE_WROTE_REPO", final["verdict"])

    # ------------------------------------------------------------------
    # 10. WORKER UNAUTHORIZED PATH
    # ------------------------------------------------------------------
    def test_worker_unauthorized_path(self):
        self._set_cs([], ["secret.txt"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])

    # ------------------------------------------------------------------
    # 10b. POST-VALIDATOR PATH GUARD (F-01)
    # ------------------------------------------------------------------
    def test_initial_validator_mutation_inside_scope_continues(self):
        # cs0 architect ro, cs1 worker delta, cs2 validator delta (in scope),
        # cs3 reviewer ro, cs4 adjudicator ro, cs5 final reviewer ro
        self._set_cs([], ["src/foo.py"], ["src/generated.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(0, code)
        self.assertEqual("SUCCESS", final["status"])
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertIs(True, final["human_gate"])

    def test_initial_validator_mutation_outside_scope_stops(self):
        # cs0 architect ro, cs1 worker delta, cs2 validator delta outside scope
        self._set_cs([], ["src/foo.py"], ["secret.txt"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])
        self.assertFalse(final["human_gate"])
        self.assertNotIn("reviewer", self._invoke_roles())

    def test_correction_validator_mutation_outside_scope_stops(self):
        # cs0 architect ro, cs1 worker0 delta, cs2 post-validator0,
        # cs3 reviewer0 ro, cs4 adjudicator ro, cs5 correction worker delta,
        # cs6 post-correction-validator delta outside scope
        self._set_cs([], ["src/foo.py"], [], [], [], ["src/foo.py"], ["secret.txt"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_CORRECTION, _make_record("adjudicator", 0)),
            (_WORKER_RESULT_1, _make_record("worker", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])
        self.assertFalse(final["human_gate"])
        roles = self._invoke_roles()
        self.assertEqual("worker", roles[-1])
        self.assertEqual(1, sum(1 for role in roles if role == "reviewer"))

    # ------------------------------------------------------------------
    # 11. INITIAL VALIDATOR FAILURE
    # ------------------------------------------------------------------
    def test_initial_validator_failure(self):
        self._set_cs([], ["src/foo.py"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
        ]
        self.mock_validators.return_value = [
            {"name": "lint", "command": "/usr/bin/false",
             "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
             "exit_code": 1, "status": "FAIL", "stdout": "", "stderr": "lint error"},
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        self.assertNotIn("reviewer", self._invoke_roles())

    # ------------------------------------------------------------------
    # 12. CORRECTION VALIDATOR FAILURE
    # ------------------------------------------------------------------
    def test_correction_validator_failure(self):
        val_count = [0]
        def _validators(*a, **kw):
            val_count[0] += 1
            if val_count[0] == 1:
                return [{"name": "lint", "command": "/usr/bin/true",
                         "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
                         "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""}]
            return [{"name": "lint", "command": "/usr/bin/false",
                     "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
                     "exit_code": 1, "status": "FAIL", "stdout": "", "stderr": "correction lint error"}]
        self._set_cs([], ["src/foo.py"], [], [], [], ["src/foo.py"])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_CORRECTION, _make_record("adjudicator", 0)),
            (_WORKER_RESULT_1, _make_record("worker", 1)),
        ]
        self.mock_validators.side_effect = _validators
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        roles = self._invoke_roles()
        self.assertEqual(5, len(roles))
        self.assertEqual("worker", roles[-1])

    # ------------------------------------------------------------------
    # 13. INVALID ARCHITECT PLAN
    # ------------------------------------------------------------------
    def test_invalid_architect_plan(self):
        bad = _make_result(role="architect", verdict="PLAN_READY", files_changed=[],
                           architect_plan={"objective_interpretation": "ok"})
        self._set_cs()
        self.mock_invoke.side_effect = [(bad, _make_record("architect", 0))]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])

    def test_architect_plan_without_nested_files_changed(self):
        plan = dict(_ARCH_PLAN)
        plan.pop("files_changed", None)
        validated = agentflow._validate_architect_plan({"architect_plan": plan})
        self.assertNotIn("files_changed", validated)
        self.assertEqual(plan["implementation_steps"], validated["implementation_steps"])

    def test_architect_plan_with_nested_files_changed_rejected(self):
        plan = dict(_ARCH_PLAN)
        plan["files_changed"] = ["x.py"]
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_architect_plan({"architect_plan": plan})
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_program_baseline_drift_stops_before_architect(self):
        task = dict(self.task)
        task["expected_baseline"] = {"head": "different-head"}
        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        def _read_json(path):
            p = Path(path).resolve()
            if p == program_resolved:
                return dict(_DEFAULT_PROGRAM)
            if p == task_resolved:
                t = dict(task); t["repo"] = str(self.repo); return t
            return {}
        self.mock_read_json.side_effect = _read_json
        self._set_cs()
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("BASELINE_DRIFT", final["verdict"])
        self.assertEqual(0, self.mock_invoke.call_count)
        self.assertTrue((run_dir / "final.json").is_file())

    # ------------------------------------------------------------------
    # 14. INVALID ADJUDICATION
    # ------------------------------------------------------------------
    def test_invalid_adjudication_correction_true_empty_accepted(self):
        bad = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": True,
                "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                "accepted_refs": [],
                "correction_brief": {"required_changes": ["fix something"]},
                "stop_reason": None,
            },
        )
        self._set_cs([], ["src/foo.py"], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (bad, _make_record("adjudicator", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])

    def test_invalid_adjudication_incomplete_classifications(self):
        # Adjudication classifies only 1 of the 2 issued reviewer refs.
        bad = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": False,
                "classifications": {"R1-F1": "NON_ACTIONABLE"},
                "accepted_refs": [],
                "correction_brief": None,
                "stop_reason": None,
            },
        )
        reviewer_two = _make_result(
            role="reviewer", verdict="BLOCKER",
            findings=[
                {"severity": "HIGH", "text": "finding one"},
                {"severity": "MEDIUM", "text": "finding two"},
            ],
        )
        self._set_cs([], ["src/foo.py"], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (reviewer_two, _make_record("reviewer", 0)),
            (bad, _make_record("adjudicator", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        # The final reviewer must not run on an invalid adjudication.
        self.assertEqual(4, self.mock_invoke.call_count)

    def test_invalid_adjudication_fabricated_ref(self):
        # Issued refs are R1-F1 and R1-F2; the adjudicator invents R1-F99.
        bad = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": False,
                "classifications": {
                    "R1-F1": "NON_ACTIONABLE",
                    "R1-F2": "NON_ACTIONABLE",
                    "R1-F99": "NON_ACTIONABLE",
                },
                "accepted_refs": [],
                "correction_brief": None,
                "stop_reason": None,
            },
        )
        reviewer_two = _make_result(
            role="reviewer", verdict="BLOCKER",
            findings=[
                {"severity": "HIGH", "text": "finding one"},
                {"severity": "MEDIUM", "text": "finding two"},
            ],
        )
        self._set_cs([], ["src/foo.py"], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (reviewer_two, _make_record("reviewer", 0)),
            (bad, _make_record("adjudicator", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertEqual(4, self.mock_invoke.call_count)

    def test_validate_adjudication_rejects_unissued_accepted_ref(self):
        result = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": True,
                "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                "accepted_refs": ["R1-F99"],
                "correction_brief": {"required_changes": ["fix"]},
                "stop_reason": None,
            },
        )
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_adjudication(result, ["R1-F1"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_validate_adjudication_zero_findings_requires_empty_classifications(self):
        result = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": False,
                "classifications": {},
                "accepted_refs": [],
                "correction_brief": None,
                "stop_reason": None,
            },
        )
        self.assertIs(agentflow._validate_adjudication(result, []), result["adjudication"])
        result["adjudication"]["classifications"] = {"R1-F1": "NON_ACTIONABLE"}
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_adjudication(result, [])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    # ------------------------------------------------------------------
    # 15. MODEL FAMILY INDEPENDENCE
    # ------------------------------------------------------------------
    def test_model_family_independence(self):
        same_family = {
            "profiles": {
                "program_architect": {
                    "backend": "opencode", "command": "opencode",
                    "provider": "opencode", "model": "opencode/nemotron-3-ultra-free",
                    "variant": None, "agent": "agentflow-architect", "available": True,
                    "eligible_roles": ["architect", "adjudicator"],
                },
                "program_worker": {
                    "backend": "opencode", "command": "opencode",
                    "provider": "opencode", "model": "opencode/nemotron-3-ultra-free",
                    "variant": None, "agent": "agentflow-worker", "available": True,
                    "eligible_roles": ["worker"],
                },
                "program_reviewer": {
                    "backend": "opencode", "command": "opencode",
                    "provider": "opencode", "model": "opencode/nemotron-3-flash",
                    "variant": None, "agent": "agentflow-reviewer", "available": True,
                    "eligible_roles": ["reviewer"],
                },
            },
        }
        self._set_cs()
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
        ]
        self.mock_load_models.return_value = same_family
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("REVIEWER_NOT_INDEPENDENT", final["verdict"])

    # ------------------------------------------------------------------
    # 15b. F-05 ADJUDICATOR INDEPENDENCE (architect == adjudicator)
    # ------------------------------------------------------------------
    @staticmethod
    def _f05_models(architect_model, worker_model, reviewer_model):
        def profile(model, agent, roles):
            return {
                "backend": "opencode", "command": "opencode", "provider": "p",
                "model": model, "variant": None, "agent": agent,
                "available": True, "eligible_roles": list(roles),
            }
        return {"profiles": {
            "program_architect": profile(
                architect_model, "agentflow-architect", ("architect", "adjudicator")),
            "program_worker": profile(
                worker_model, "agentflow-worker", ("worker",)),
            "program_reviewer": profile(
                reviewer_model, "agentflow-reviewer", ("reviewer",)),
        }}

    def _run_until_independence_error(self, models):
        self.mock_load_models.return_value = models
        self._set_cs([], ["src/foo.py"], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
        ]
        return self._run()

    def test_adjudicator_independence_rejects_worker_same_family(self):
        # F-05: rejection is pre-worker. A same-family worker/adjudicator pair
        # must never get a worker process spawn or workspace mutation.
        code, _run_dir, final = self._run_until_independence_error(
            self._f05_models("p/alpha-1", "p/alpha-2", "p/beta-1"))
        self.assertEqual(2, code)
        self.assertEqual("ADJUDICATOR_NOT_INDEPENDENT", final["verdict"])
        self.assertNotIn("worker", self._invoke_roles())
        self.assertNotIn("reviewer", self._invoke_roles())

    def test_adjudicator_independence_rejects_reviewer_same_family(self):
        # Worker/reviewer/adjudicator are all resolved before the worker runs,
        # so a same-family reviewer/adjudicator pair is rejected pre-worker.
        code, _run_dir, final = self._run_until_independence_error(
            self._f05_models("p/alpha-1", "p/beta-1", "p/alpha-2"))
        self.assertEqual(2, code)
        self.assertEqual("ADJUDICATOR_NOT_INDEPENDENT", final["verdict"])
        self.assertNotIn("worker", self._invoke_roles())
        self.assertNotIn("reviewer", self._invoke_roles())

    # ------------------------------------------------------------------
    # 16. MAX_CORRECTIONS ZERO
    # ------------------------------------------------------------------
    def test_max_corrections_zero(self):
        program = dict(_DEFAULT_PROGRAM)
        program["max_corrections"] = 0
        self.program_file.write_text(json.dumps(program), encoding="utf-8")
        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        def _read_json(path):
            p = Path(path).resolve()
            if p == program_resolved:
                return program
            if p == task_resolved:
                t = dict(self.task); t["repo"] = str(self.repo); return t
            return {}
        self.mock_read_json.side_effect = _read_json

        self._set_cs([], ["src/foo.py"], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_CORRECTION, _make_record("adjudicator", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("ADJUDICATION_STOP", final["verdict"])
        self.assertEqual(4, self.mock_invoke.call_count)
        roles = self._invoke_roles()
        self.assertNotIn("worker", roles[3:])

    # ------------------------------------------------------------------
    # 17. TASK MAX_CORRECTIONS TWO
    # ------------------------------------------------------------------
    def test_task_max_corrections_two(self):
        task = dict(self.task)
        task["max_corrections"] = 2
        self.task_file.write_text(json.dumps(task), encoding="utf-8")
        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        def _read_json(path):
            p = Path(path).resolve()
            if p == program_resolved:
                return dict(_DEFAULT_PROGRAM)
            if p == task_resolved:
                t = dict(task); t["repo"] = str(self.repo); return t
            return {}
        self.mock_read_json.side_effect = _read_json

        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(0, code)
        self.assertEqual("SUCCESS", final["status"])
        self.assertEqual("HUMAN_GATE", final["verdict"])

    # ------------------------------------------------------------------
    # 18. LEGACY REGRESSION
    # ------------------------------------------------------------------
    def test_baseline_drift_still_detected(self):
        actual = {
            "branch": "main", "head": "abc",
            "dirty_paths": ["a.py"], "untracked_paths": [],
            "git_diff_check": {"exit_code": 0},
        }
        mismatch = agentflow.baseline_mismatches(actual, {"head": "different"})
        self.assertEqual(1, len(mismatch))
        self.assertIn("head", mismatch[0])

    def test_parse_json_from_machine_event(self):
        packet = {
            "task_id": "x", "role": "worker", "harness": "claimed",
            "provider": "claimed", "model": "claimed", "variant": None,
            "files_changed": [], "validators": {}, "findings": [],
            "open_risks": [], "verdict": "PASS",
        }
        raw = json.dumps({"type": "text", "part": {"text": json.dumps(packet)}})
        self.assertEqual("PASS", agentflow.parse_model_result(raw)["verdict"])

    def test_forbidden_validator_hits_human_gate(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.safe_validator_argv("git commit -m nope")
        self.assertEqual("HUMAN_GATE", raised.exception.code)

    def test_allowed_path_matching(self):
        self.assertTrue(agentflow.path_allowed("tests/a.py", ["tests"]))
        self.assertFalse(agentflow.path_allowed("app/a.py", ["tests"]))

    def test_validate_program_rejects_missing_fields(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_program({})
        self.assertEqual("INVALID_PROGRAM", raised.exception.code)

    def test_validate_program_rejects_max_corrections_two(self):
        program = {
            "program_id": "test", "task": "task.json",
            "roles": {"architect": "a", "worker": "w", "reviewer": "r"},
            "max_corrections": 2,
        }
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_program(program)
        self.assertEqual("INVALID_PROGRAM", raised.exception.code)

    def test_validate_task_defaults_max_corrections(self):
        task = {
            "task_id": "t", "repo": "/tmp/r", "risk": "LOW",
            "objective": "test", "allowed_paths": ["src/"],
            "validators": [{"name": "v", "command": ["/usr/bin/true"]}],
        }
        validated = agentflow.validate_task(task)
        self.assertEqual(2, validated["max_corrections"])

    def test_reviewer_blocks_high_severity(self):
        result = _make_result(role="reviewer", verdict="PASS",
                              findings=[{"severity": "HIGH", "text": "issue"}])
        self.assertTrue(agentflow.reviewer_blocks(result))

    def test_reviewer_blocks_verdict(self):
        self.assertTrue(agentflow.reviewer_blocks(_make_result(role="reviewer", verdict="BLOCKER")))

    def test_reviewer_no_block_on_pass(self):
        self.assertFalse(agentflow.reviewer_blocks(_make_result(role="reviewer", verdict="PASS")))

    def test_result_valid_rejects_missing_fields(self):
        ok, reason = agentflow.result_valid({"verdict": "PASS"})
        self.assertFalse(ok)
        self.assertIn("missing", reason)

    def test_result_valid_accepts_architect(self):
        result = _make_result(
            role="architect", verdict="PLAN_READY", files_changed=[],
            architect_plan={
                "objective_interpretation": "test",
                "implementation_steps": ["step1"],
                "invariants": [], "allowed_scope": [],
                "do_not_change": [], "validation_expectations": [],
                "known_risks": [],
            },
        )
        ok, reason = agentflow.result_valid(result)
        self.assertTrue(ok, reason)

    def test_result_valid_rejects_architect_with_files(self):
        result = _make_result(
            role="architect", verdict="PLAN_READY", files_changed=["a.py"],
            architect_plan={
                "objective_interpretation": "test",
                "implementation_steps": ["step1"],
                "invariants": [], "allowed_scope": [],
                "do_not_change": [], "validation_expectations": [],
                "known_risks": [],
            },
        )
        ok, reason = agentflow.result_valid(result)
        self.assertFalse(ok)
        self.assertIn("files_changed", reason)

    # ------------------------------------------------------------------
    # 19. CONTROLLED PROGRAM INPUT / MODEL ERRORS
    # ------------------------------------------------------------------
    def test_missing_task_input_is_invalid_program(self):
        program = dict(_DEFAULT_PROGRAM)
        program["task"] = "missing-task.json"
        def _read_json(path):
            p = Path(path).resolve()
            if p == self.program_file.resolve():
                return program
            raise FileNotFoundError(str(p))
        self.mock_read_json.side_effect = _read_json
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            self._run()
        self.assertEqual("INVALID_PROGRAM", raised.exception.code)
        self.assertIsInstance(raised.exception, agentflow.AgentFlowError)

    def test_missing_program_input_is_invalid_program(self):
        self.mock_read_json.side_effect = FileNotFoundError("missing program")
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.run_program(self.tmp / "absent-program.json")
        self.assertEqual("INVALID_PROGRAM", raised.exception.code)

    def test_unknown_role_profile_is_model_unavailable(self):
        program = dict(_DEFAULT_PROGRAM)
        program["roles"] = {**_DEFAULT_PROGRAM["roles"], "architect": "no_such_profile"}
        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        def _read_json(path):
            p = Path(path).resolve()
            if p == program_resolved:
                return program
            if p == task_resolved:
                t = dict(self.task); t["repo"] = str(self.repo); return t
            return {}
        self.mock_read_json.side_effect = _read_json
        self._set_cs()
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("MODEL_UNAVAILABLE", final["verdict"])
        self.assertEqual(0, self.mock_invoke.call_count)

    def test_unavailable_role_profile_is_model_unavailable(self):
        models = json.loads(json.dumps(_DEFAULT_MODELS))
        models["profiles"]["program_architect"]["available"] = False
        self.mock_load_models.return_value = models
        self._set_cs()
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("MODEL_UNAVAILABLE", final["verdict"])
        self.assertEqual(0, self.mock_invoke.call_count)

    def test_unreadable_models_config_is_model_unavailable(self):
        self.mock_load_models.side_effect = FileNotFoundError("models.json")
        self._set_cs()
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("MODEL_UNAVAILABLE", final["verdict"])
        self.assertEqual(0, self.mock_invoke.call_count)

    def test_validate_program_rejects_bool_max_corrections(self):
        base = {
            "program_id": "test", "task": "task.json",
            "roles": {"architect": "a", "worker": "w", "reviewer": "r"},
        }
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_program({**base, "max_corrections": value})
                self.assertEqual("INVALID_PROGRAM", raised.exception.code)
        self.assertEqual(0, agentflow.validate_program({**base, "max_corrections": 0})["max_corrections"])
        self.assertEqual(1, agentflow.validate_program({**base, "max_corrections": 1})["max_corrections"])

    # ------------------------------------------------------------------
    # 20. F-02 REVIEWER CONTRACT (role-aware, fail-closed)
    # ------------------------------------------------------------------
    def test_initial_reviewer_unknown_verdict_fails_before_adjudicator(self):
        unknown = _make_result(role="reviewer", verdict="NEEDS_WORK")
        self._set_cs([], ["src/foo.py"], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (unknown, _make_record("reviewer", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertNotIn("adjudicator", self._invoke_roles())

    def test_initial_reviewer_contradiction_fails_before_adjudicator(self):
        contradictory = _make_result(
            role="reviewer", verdict="PASS",
            findings=[{"severity": "HIGH", "text": "contradiction"}])
        self._set_cs([], ["src/foo.py"], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (contradictory, _make_record("reviewer", 0)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotIn("adjudicator", self._invoke_roles())

    def test_initial_reviewer_verdict_reaches_adjudicator_normalized(self):
        blocking = _make_result(
            role="reviewer", verdict=" blocker ",
            findings=[{"severity": "MEDIUM", "text": "minor"}])
        adjudicator = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": False,
                "classifications": {"R1-F1": "NON_ACTIONABLE"},
                "accepted_refs": [],
                "correction_brief": None,
                "stop_reason": None,
            },
        )
        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (blocking, _make_record("reviewer", 0)),
            (adjudicator, _make_record("adjudicator", 0)),
            (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])
        context = self.mock_invoke.call_args_list[3].kwargs["context"]
        self.assertEqual("BLOCKER", context["initial_reviewer_verdict"])
        self.assertEqual(
            ["R1-F1"], [finding["ref"] for finding in context["initial_review_findings"]]
        )

    def test_final_reviewer_unknown_verdict_never_human_gate(self):
        unknown_final = _make_result(role="reviewer", verdict="FAILED")
        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (unknown_final, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertIsNot(True, final.get("human_gate"))

    def test_final_reviewer_contradiction_is_invalid_not_final_blocked(self):
        contradiction = _make_result(
            role="reviewer", verdict="PASS",
            findings=[{"severity": "BLOCKER", "text": "contradiction"}])
        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (contradiction, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("FINAL_REVIEW_BLOCKED", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])

    def test_final_reviewer_string_finding_never_human_gate(self):
        malformed = _make_result(
            role="reviewer", verdict="PASS", findings=["free text"])
        self._set_cs([], ["src/foo.py"], [], [], [])
        self.mock_invoke.side_effect = [
            (_ARCHITECT_RESULT, _make_record("architect", 0)),
            (_WORKER_RESULT_0, _make_record("worker", 0)),
            (_REVIEWER_RESULT_0, _make_record("reviewer", 0)),
            (_ADJUDICATOR_RESULT_NO_CORRECTION, _make_record("adjudicator", 0)),
            (malformed, _make_record("reviewer", 1)),
        ]
        code, run_dir, final = self._run()
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])


class ReviewerContractTests(unittest.TestCase):
    """F-02: canonical role-aware fail-closed reviewer contract matrix."""

    VALID_VERDICTS = ("PASS", "Pass", " pass ", "BLOCKER", "blocker", "BLOCKER\n")
    INVALID_VERDICTS = (
        "NEEDS_WORK", "BLOCK", "FAILED", "REJECTED", "BLOCKED", "NOT_PASS",
        "APPROVE", "APPROVED", "FAIL", "REJECT", "CHANGES_REQUIRED",
        "", "   ",
    )
    INVALID_VERDICT_VALUES = (None, 0, {}, [], True)

    def _reviewer(self, **overrides):
        values = {"role": "reviewer", "verdict": "PASS", **overrides}
        return _make_result(**values)

    def test_valid_verdicts_normalize_and_are_role_aware(self):
        for verdict in self.VALID_VERDICTS:
            with self.subTest(verdict=verdict):
                result = self._reviewer(verdict=verdict)
                agentflow.validate_reviewer_result(result)
                normalized = agentflow.normalize_reviewer_verdict(verdict)
                self.assertIn(normalized, {"PASS", "BLOCKER"})
                self.assertIs(normalized == "BLOCKER", agentflow.reviewer_blocks(result))

    def test_unknown_verdicts_are_invalid_model_output(self):
        for verdict in self.INVALID_VERDICTS:
            with self.subTest(verdict=verdict):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_reviewer_result(self._reviewer(verdict=verdict))
                self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_missing_and_non_string_verdicts_are_invalid_model_output(self):
        missing = self._reviewer()
        del missing["verdict"]
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_reviewer_result(missing)
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)
        for verdict in self.INVALID_VERDICT_VALUES:
            with self.subTest(verdict=verdict):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_reviewer_result(self._reviewer(verdict=verdict))
                self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_valid_findings_contract(self):
        cases = (
            ("PASS", [], False),
            ("PASS", [{"severity": "MEDIUM", "text": "doc"}], False),
            ("PASS", [{"severity": " low ", "text": "nit"}], False),
            ("BLOCKER", [], True),
            ("BLOCKER", [{"severity": "HIGH", "text": "regression"}], True),
            ("BLOCKER", [{"severity": "blocker", "text": "broken"}], True),
            ("BLOCKER", [{"severity": "LOW", "text": "nit"}], True),
        )
        for verdict, findings, blocks in cases:
            with self.subTest(verdict=verdict, findings=findings):
                result = self._reviewer(verdict=verdict, findings=findings)
                agentflow.validate_reviewer_result(result)
                self.assertIs(blocks, agentflow.reviewer_blocks(result))

    def test_findings_violations_are_invalid_model_output(self):
        cases = (
            ("PASS", [{"severity": "HIGH", "text": "contradiction"}]),
            ("PASS", [{"severity": "BLOCKER", "text": "contradiction"}]),
            ("PASS", ["free text"]),
            ("PASS", [{"text": "missing severity"}]),
            ("PASS", [{"severity": "", "text": "empty"}]),
            ("PASS", [{"severity": "  ", "text": "blank"}]),
            ("PASS", [{"severity": None, "text": "non-string"}]),
            ("PASS", [{"severity": 3, "text": "non-string"}]),
            ("PASS", [{"severity": "CRITICAL", "text": "not in contract"}]),
            ("PASS", [{"severity": "UNKNOWN", "text": "not in contract"}]),
            ("BLOCKER", ["free text"]),
            ("BLOCKER", [{"severity": "CRITICAL"}]),
            ("PASS", "free text"),
        )
        for verdict, findings in cases:
            with self.subTest(verdict=verdict, findings=findings):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_reviewer_result(
                        self._reviewer(verdict=verdict, findings=findings))
                self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_role_guards_reject_non_reviewer_results(self):
        for role in ("worker", "architect", "adjudicator"):
            with self.subTest(role=role):
                result = _make_result(role=role, verdict="PASS", files_changed=[])
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_reviewer_result(result)
                self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.reviewer_blocks(result)
                self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_worker_contract_unchanged(self):
        cases = (
            ("PASS", False),
            ("CHANGES_REQUIRED", True),
            (" changes_required ", True),
            ("BLOCKER", True),
        )
        for verdict, blocks in cases:
            with self.subTest(verdict=verdict):
                result = _make_result(role="worker", verdict=verdict)
                self.assertIs(blocks, agentflow.worker_blocks(result))
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.worker_blocks(_make_result(role="reviewer", verdict="PASS"))
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_result_valid_requires_non_empty_reviewer_verdict(self):
        for verdict in ("", "   "):
            with self.subTest(verdict=verdict):
                ok, reason = agentflow.result_valid(self._reviewer(verdict=verdict))
                self.assertFalse(ok)
                self.assertIn("verdict", reason)
        # Vocabulary stays role-aware in validate_reviewer_result, not in the
        # generic envelope check.
        ok, reason = agentflow.result_valid(self._reviewer(verdict="NEEDS_WORK"))
        self.assertTrue(ok, reason)


class ProgramExampleSpecTests(unittest.TestCase):
    """Verify the shipped example spec resolves under the canonical path rule."""

    def test_example_program_task_resolves_to_existing_task(self):
        repo_root = Path(__file__).resolve().parent.parent
        program_file = repo_root / "programs" / "example.json"
        program = json.loads(program_file.read_text(encoding="utf-8"))
        self.assertIsInstance(program, dict)
        task_value = program["task"]
        self.assertIsInstance(task_value, str)
        task_path = Path(task_value)
        self.assertFalse(task_path.is_absolute(), "example program.task must be program-relative")
        resolved = (program_file.parent / task_path).resolve()
        self.assertEqual(repo_root / "tasks", resolved.parent)
        self.assertTrue(resolved.is_file(), f"example task does not resolve: {resolved}")
        task = json.loads(resolved.read_text(encoding="utf-8"))
        self.assertIsInstance(task, dict)
        for key in ("task_id", "repo", "risk", "objective", "allowed_paths", "validators"):
            self.assertIn(key, task)


if __name__ == "__main__":
    unittest.main()
