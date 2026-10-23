"""PROGRAM-001B sequential subtasks tests (phased implementation)."""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentflow


def _base_program(**overrides):
    program = {
        "program_id": "program-001b-test",
        "task": "task.json",
        "roles": {"architect": "a", "worker": "w", "reviewer": "r"},
        "max_corrections": 1,
    }
    program.update(overrides)
    return program


def _base_plan(**overrides):
    plan = {
        "objective_interpretation": "test",
        "implementation_steps": ["step1"],
        "invariants": [],
        "allowed_scope": ["src/"],
        "do_not_change": [],
        "validation_expectations": [],
        "known_risks": [],
    }
    plan.update(overrides)
    return plan


def _subtask(subtask_id="s1", allowed=("src/",), **overrides):
    item = {
        "subtask_id": subtask_id,
        "objective": f"objective for {subtask_id}",
        "allowed_paths": list(allowed),
        "invariants": ["inv"],
        "expected_outputs": ["out"],
    }
    item.update(overrides)
    return item


class BModeValidationTests(unittest.TestCase):
    def test_001a_compat_absent_max_subtasks(self):
        program = _base_program()
        validated = agentflow.validate_program(program)
        self.assertNotIn("max_subtasks", validated)

    def test_max_subtasks_valid_range(self):
        for value in (1, 2, 3, 4):
            with self.subTest(value=value):
                validated = agentflow.validate_program(_base_program(max_subtasks=value))
                self.assertEqual(value, validated["max_subtasks"])

    def test_max_subtasks_rejects_zero_and_five(self):
        for value in (0, 5, -1, 100):
            with self.subTest(value=value):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_program(_base_program(max_subtasks=value))
                self.assertEqual("INVALID_PROGRAM", raised.exception.code)

    def test_max_subtasks_rejects_bool(self):
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_program(_base_program(max_subtasks=value))
                self.assertEqual("INVALID_PROGRAM", raised.exception.code)

    def test_max_subtasks_rejects_non_int(self):
        for value in ("2", 2.0, None, [2]):
            with self.subTest(value=value):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_program(_base_program(max_subtasks=value))
                self.assertEqual("INVALID_PROGRAM", raised.exception.code)

    def test_bmode_requires_isolation(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._require_bmode_isolation({"task_id": "t"})
        self.assertEqual("INVALID_PROGRAM", raised.exception.code)
        with self.assertRaises(agentflow.AgentFlowError):
            agentflow._require_bmode_isolation({"isolation": {"enabled": False}})
        # enabled true passes
        agentflow._require_bmode_isolation({"isolation": {"enabled": True}})

    def test_subtasks_happy_path(self):
        subs = agentflow._validate_bmode_subtasks(
            [_subtask("s1", ("src/",)), _subtask("s2", ("src/", "tests/"))],
            2, ["src/", "tests/"],
        )
        self.assertEqual(2, len(subs))
        self.assertEqual(["s1", "s2"], [s["subtask_id"] for s in subs])

    def test_subtasks_zero_rejected(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks([], 2, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_subtasks_non_list_rejected(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks("nope", 2, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_subtasks_duplicate_rejected(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks(
                [_subtask("dup"), _subtask("dup")], 2, ["src/"],
            )
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_subtasks_invalid_id_rejected(self):
        for bad in ("Upper", "-lead", "_lead", ".lead", "a" * 66, "", "has space", "s!"):
            with self.subTest(bad=bad):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._validate_bmode_subtasks([_subtask(bad)], 1, ["src/"])
                self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_subtasks_unknown_fields_rejected(self):
        bad = _subtask("s1")
        bad["repo"] = "evil"
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks([bad], 1, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_architect_cannot_invent_validators(self):
        bad = _subtask("s1")
        bad["validators"] = [{"name": "v"}]
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks([bad], 1, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_architect_cannot_invent_forbidden_fields(self):
        for field in ("repo", "risk", "validators", "forbidden_actions", "isolation",
                      "timeouts", "max_corrections", "dependencies", "routing"):
            with self.subTest(field=field):
                bad = _subtask("s1")
                bad[field] = "evil"
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._validate_bmode_subtasks([bad], 1, ["src/"])
                self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_subtasks_over_max_rejected(self):
        subs = [_subtask(f"s{i}") for i in range(3)]
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks(subs, 2, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_subtasks_hard_max_four(self):
        subs = [_subtask(f"s{i}") for i in range(5)]
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks(subs, 5, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)
        # also via validate: max_subtasks=5 rejected at program validation
        with self.assertRaises(agentflow.AgentFlowError):
            agentflow.validate_program(_base_program(max_subtasks=5))

    def test_child_cannot_broaden_parent_scope(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_subtasks([_subtask("s1", ("other/",))], 1, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_bmode_architect_plan_requires_subtasks(self):
        result = {"architect_plan": _base_plan()}
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._validate_bmode_architect_plan(result, 2, ["src/"])
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)

    def test_bmode_architect_plan_happy(self):
        plan = _base_plan(subtasks=[_subtask("s1", ("src/",))])
        result = {"architect_plan": plan}
        validated_plan, subs = agentflow._validate_bmode_architect_plan(result, 1, ["src/"])
        self.assertEqual(1, len(subs))
        self.assertEqual("s1", subs[0]["subtask_id"])


def _make_result(task_id="t1", role="worker", verdict="PASS", **extra):
    result = {
        "task_id": task_id, "role": role, "harness": "opencode",
        "provider": "opencode", "model": "test/model", "variant": None,
        "files_changed": [], "validators": {}, "findings": [],
        "open_risks": [], "verdict": verdict,
    }
    result.update(extra)
    return result


def _make_record(role="worker", cycle=0):
    return {
        "profile": "p", "role": role, "harness": "opencode",
        "provider": "opencode", "model": "test/model", "variant": None,
        "agent": "a", "cycle": cycle,
        "invoked_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "exit_code": 0,
    }


_ARCH_PLAN_B = {
    "objective_interpretation": "oi",
    "implementation_steps": ["s1"],
    "invariants": [],
    "allowed_scope": ["src/"],
    "do_not_change": [],
    "validation_expectations": [],
    "known_risks": [],
}

_DEFAULT_MODELS_B = {
    "profiles": {
        "pa": {"backend": "opencode", "command": "opencode", "provider": "opencode",
               "model": "m/a", "variant": None, "agent": "agentflow-architect",
               "available": True, "eligible_roles": ["architect", "adjudicator"]},
        "pw": {"backend": "opencode", "command": "opencode", "provider": "opencode",
               "model": "m/b", "variant": None, "agent": "agentflow-worker",
               "available": True, "eligible_roles": ["worker"]},
        "pr": {"backend": "opencode", "command": "opencode", "provider": "other",
               "model": "o/c", "variant": None, "agent": "agentflow-reviewer",
               "available": True, "eligible_roles": ["reviewer"]},
    },
}


class BModeChildConstructionTests(unittest.TestCase):
    def test_child_inheritance(self):
        from pathlib import Path as _P
        parent = {
            "task_id": "pt", "repo": "/tmp/r", "risk": "HIGH",
            "objective": "parent obj", "allowed_paths": ["src/", "tests/"],
            "validators": [{"name": "v", "command": ["/usr/bin/true"]}],
            "forbidden_actions": ["git commit"],
            "invariants": ["parent-inv"],
            "model_timeout_seconds": 100,
            "model_inactivity_timeout_seconds": 10,
        }
        subtask = {
            "subtask_id": "s1", "objective": "child obj",
            "allowed_paths": ["src"], "invariants": ["child-inv"],
            "expected_outputs": ["out"],
        }
        child = agentflow._build_bmode_child_task(parent, subtask, _P("/tmp/exec"))
        self.assertEqual(str(_P("/tmp/exec")), child["repo"])
        self.assertEqual("HIGH", child["risk"])
        self.assertEqual(parent["validators"], child["validators"])
        self.assertIsNot(parent["validators"], child["validators"])
        self.assertEqual(parent["forbidden_actions"], child["forbidden_actions"])
        self.assertEqual(["parent-inv", "child-inv"], child["invariants"])
        self.assertEqual(100, child["model_timeout_seconds"])
        self.assertEqual(10, child["model_inactivity_timeout_seconds"])
        self.assertEqual("child obj", child["objective"])
        self.assertEqual(["src"], child["allowed_paths"])
        self.assertEqual(0, child["max_corrections"])
        self.assertTrue(child["task_id"].startswith("pt__"))

    def test_child_validators_exact_copy(self):
        parent = {
            "task_id": "pt", "repo": "/tmp/r", "risk": "LOW",
            "objective": "o", "allowed_paths": ["src"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"], "timeout_seconds": 5}],
            "forbidden_actions": [], "invariants": [],
        }
        subtask = {"subtask_id": "s1", "objective": "o",
                   "allowed_paths": ["src"], "invariants": [], "expected_outputs": []}
        from pathlib import Path as _P
        child = agentflow._build_bmode_child_task(parent, subtask, _P("/tmp/exec"))
        self.assertEqual(parent["validators"], child["validators"])
        child["validators"][0]["name"] = "mutated"
        self.assertNotEqual(parent["validators"], child["validators"])

    def test_continuity_equality(self):
        a = {"head": "h", "dirty_paths": ["b"], "untracked_paths": [],
             "path_state": {"b": "1"}}
        b = {"head": "h", "dirty_paths": ["b"], "untracked_paths": [],
             "path_state": {"b": "1"}, "captured_at": "different", "repo": "x"}
        self.assertTrue(agentflow._baselines_equal_for_continuity(a, b))
        c = dict(b, path_state={"b": "2"})
        self.assertFalse(agentflow._baselines_equal_for_continuity(a, c))
        d = dict(b, head="other")
        self.assertFalse(agentflow._baselines_equal_for_continuity(a, d))

    def test_scope_check(self):
        agentflow._bmode_check_scope(["src/a.py"], ["src"])
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._bmode_check_scope(["other/a.py"], ["src"])
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", raised.exception.code)


class BModeHarness(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        (self.repo / "src").mkdir()
        (self.repo / "tests").mkdir()
        self.runs_dir = self.tmp / "runs"
        self.runs_dir.mkdir()
        self.locks_dir = self.tmp / "locks"
        self.locks_dir.mkdir()
        self.prompts_dir = self.tmp / "prompts"
        self.prompts_dir.mkdir()
        for name in ("architect", "adjudicator", "worker", "reviewer"):
            (self.prompts_dir / f"{name}.md").write_text(f"# {name}\n", encoding="utf-8")
        self.program_file = self.tmp / "program.json"
        self.task_file = self.tmp / "task.json"
        self.program = {
            "program_id": "p1", "task": "task.json",
            "roles": {"architect": "pa", "worker": "pw", "reviewer": "pr"},
            "max_corrections": 1, "max_subtasks": 2,
        }
        self.task = {
            "task_id": "t1", "repo": str(self.repo), "risk": "HIGH",
            "objective": "obj", "allowed_paths": ["src/", "tests/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": ["pinv"], "forbidden_actions": ["git commit"],
            "expected_baseline": {},
            "isolation": {"enabled": True, "baseline_commit": "a" * 40},
        }
        self.program_file.write_text(json.dumps(self.program), encoding="utf-8")
        self.task_file.write_text(json.dumps(self.task), encoding="utf-8")
        self._patches = []
        for attr, target in [("RUNS_DIR", self.runs_dir), ("LOCKS_DIR", self.locks_dir), ("ROOT", self.tmp)]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)
        self._baseline = {
            "captured_at": "t", "repo": str(self.repo), "branch": None,
            "head": "a" * 40, "dirty_paths": [], "untracked_paths": [],
            "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
        }
        self._cs_counter = 0
        self._cs_schedule: list = []

    def tearDown(self):
        for p in reversed(self._patches):
            with mock.patch("agentflow.read_json"):
                pass
            try:
                p.stop()
            except Exception:
                pass
        mock.patch.stopall()

    def _arch_plan(self, subtasks):
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        return plan

    def _run_bmode(self, *, subtasks, cs_schedule=None, invoke_side_effect,
                   validators_side_effect=None, capture_side_effect=None,
                   program_override=None, task_override=None,
                   models_override=None):
        if program_override is not None:
            self.program = program_override
            self.program_file.write_text(json.dumps(self.program), encoding="utf-8")
        if task_override is not None:
            self.task = task_override
            self.task_file.write_text(json.dumps(self.task), encoding="utf-8")
        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        prog = dict(self.program)
        tsk = dict(self.task)
        self._cs_counter = 0
        self._cs_schedule = list(cs_schedule or [])

        def _changed_since(before, after):
            idx = self._cs_counter
            self._cs_counter += 1
            if idx < len(self._cs_schedule):
                return self._cs_schedule[idx]
            return []

        pass_validators = [
            {"name": "lint", "command": "/usr/bin/true", "started_at": "t",
             "finished_at": "t", "exit_code": 0, "status": "PASS",
             "stdout": "", "stderr": ""},
        ]
        patches = [
            mock.patch("agentflow.read_json", side_effect=lambda p: (
                dict(prog) if Path(p).resolve() == program_resolved
                else (dict(tsk, repo=str(self.repo)) if Path(p).resolve() == task_resolved else {})
            )),
            mock.patch("agentflow.capture_baseline",
                       side_effect=capture_side_effect) if capture_side_effect
            else mock.patch("agentflow.capture_baseline", return_value=dict(self._baseline)),
            mock.patch("agentflow.changed_since", side_effect=_changed_since),
            mock.patch("agentflow.invoke_model", side_effect=invoke_side_effect),
            mock.patch("agentflow.run_validators",
                       side_effect=validators_side_effect) if validators_side_effect
            else mock.patch("agentflow.run_validators", return_value=list(pass_validators)),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
            mock.patch("agentflow.load_models",
                       return_value=dict(models_override or _DEFAULT_MODELS_B)),
        ]
        mock_git = mock.MagicMock(returncode=0, stdout="", stderr="")
        patches.append(mock.patch("agentflow.git", return_value=mock_git))
        # Mocked harness proves folder checks; Git registration proof is
        # mocked True here so otherwise-good runs reach HUMAN_GATE.
        # Real-Git registration is proven in BModeRealGitTests.
        patches.append(mock.patch("agentflow._is_worktree_registered", return_value=True))
        mock_lease = mock.MagicMock()
        mock_lease.__enter__ = mock.MagicMock(return_value=mock_lease)
        mock_lease.__exit__ = mock.MagicMock(return_value=False)
        patches.append(mock.patch("agentflow.WriteLease", return_value=mock_lease))
        fake_ctx = mock.MagicMock()
        fake_ctx.isolated = True
        fake_ctx.source_repo = self.repo
        fake_ctx.execution_repo = self.repo
        fake_ctx.baseline_commit = "a" * 40
        patches.append(mock.patch("agentflow.build_execution_context", return_value=fake_ctx))
        for p in patches:
            p.start()
            self._patches.append(p)
        self._fake_ctx = fake_ctx
        self._mock_git = mock_git
        return agentflow.run_program(self.program_file)


class BModeExecutionTests(BModeHarness):
    def _std_invoke(self, subtasks, *, correction=False, final_block=False):
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        w1 = _make_result(role="worker", verdict="PASS")
        w2 = _make_result(role="worker", verdict="PASS")
        rev0 = _make_result(role="reviewer", verdict="PASS")
        if correction:
            adj = _make_result(
                role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                adjudication={"correction_required": True,
                              "classifications": {},
                              "accepted_refs": [],
                              "correction_brief": None,
                              "stop_reason": None})
            # fix classifications for zero findings: empty is valid
        else:
            adj = _make_result(
                role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                adjudication={"correction_required": False,
                              "classifications": {},
                              "accepted_refs": [],
                              "correction_brief": None,
                              "stop_reason": None})
        rev1 = _make_result(role="reviewer", verdict="BLOCKER" if final_block else "PASS",
                            findings=[{"severity": "BLOCKER", "text": "x"}] if final_block else [])
        seq = [(arch, _make_record("architect", 0)),
               (w1, _make_record("worker", 0)),
               (w2, _make_record("worker", 0)),
               (rev0, _make_record("reviewer", 0)),
               (adj, _make_record("adjudicator", 0))]
        if correction:
            seq.append((_make_result(role="worker", verdict="PASS"), _make_record("worker", 1)))
        seq.append((rev1, _make_record("reviewer", 1)))
        return seq

    @staticmethod
    def _f05_models(architect_model, worker_model, reviewer_model):
        def profile(model, agent, roles):
            return {
                "backend": "opencode", "command": "opencode", "provider": "p",
                "model": model, "variant": None, "agent": agent,
                "available": True, "eligible_roles": list(roles),
            }
        return {"profiles": {
            "pa": profile(architect_model, "agentflow-architect",
                          ("architect", "adjudicator")),
            "pw": profile(worker_model, "agentflow-worker", ("worker",)),
            "pr": profile(reviewer_model, "agentflow-reviewer", ("reviewer",)),
        }}

    def _run_until_independence_error(self, models):
        subtasks = [{"subtask_id": "s1", "objective": "o1",
                     "allowed_paths": ["src/"], "invariants": [],
                     "expected_outputs": []}]
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        return self._run_bmode(
            subtasks=subtasks, cs_schedule=[[]],
            invoke_side_effect=[(arch, _make_record("architect", 0))],
            models_override=models,
        )

    def _invoke_roles(self):
        return [c.kwargs.get("role") for c in agentflow.invoke_model.call_args_list]

    def test_adjudicator_independence_rejects_worker_same_family(self):
        # F-05: B-mode retains pre-worker rejection.
        code, _run_dir, final = self._run_until_independence_error(
            self._f05_models("m/alpha-1", "m/alpha-2", "m/beta-1"))
        self.assertEqual(2, code)
        self.assertEqual("ADJUDICATOR_NOT_INDEPENDENT", final["verdict"])
        self.assertNotIn("worker", self._invoke_roles())
        self.assertNotIn("reviewer", self._invoke_roles())

    def test_adjudicator_independence_rejects_reviewer_same_family(self):
        # F-05: B-mode retains pre-worker rejection.
        code, _run_dir, final = self._run_until_independence_error(
            self._f05_models("m/alpha-1", "m/beta-1", "m/alpha-2"))
        self.assertEqual(2, code)
        self.assertEqual("ADJUDICATOR_NOT_INDEPENDENT", final["verdict"])
        self.assertNotIn("worker", self._invoke_roles())
        self.assertNotIn("reviewer", self._invoke_roles())

    def test_disjoint_scopes_succeed(self):
        subtasks = [
            {"subtask_id": "backend", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "tests", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        # cs order: arch-ro [], child1 worker child/parent, child1 valid child/parent,
        # child2 worker child/parent, child2 valid child/parent, accumulated, review-ro, adj-ro, final-acc, final-ro
        cs = [[], ["src/a.py"], ["src/a.py"],
              ["src/a.py"], ["src/a.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["src/a.py", "tests/b.py"], [], [], ["src/a.py", "tests/b.py"], []]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=self._std_invoke(subtasks))
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertTrue((run_dir / "program-plan.json").is_file())
        self.assertTrue((run_dir / "program-state.json").is_file())
        self.assertTrue((run_dir / "subtasks" / "1-backend" / "completed.json").is_file())
        self.assertTrue((run_dir / "subtasks" / "2-tests" / "completed.json").is_file())
        state = json.loads((run_dir / "program-state.json").read_text(encoding="utf-8"))
        self.assertEqual("COMPLETED", state["status"])

    def test_noop_child_works(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        cs = [[], [], [], [], [], [], [], [], [], [], [], [], []]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=self._std_invoke(subtasks))
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])

    def test_child2_modifying_child1_file_fails(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        # child2 worker delta includes src/a.py outside child2 scope
        cs = [[], ["src/a.py"], ["src/a.py"], ["src/a.py"], ["src/a.py"],
              ["src/a.py", "tests/b.py"], ["src/a.py", "tests/b.py"]]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=self._std_invoke(subtasks))
        self.assertEqual(2, code)
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])
        self.assertTrue((run_dir / "subtasks" / "1-s1" / "completed.json").is_file())
        self.assertTrue((run_dir / "subtasks" / "2-s2" / "failed.json").is_file())
        self.assertFalse((run_dir / "subtasks" / "2-s2" / "completed.json").exists())

    def test_validator_mutation_obeys_child_scope(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        # worker clean, validator dirties outside scope
        cs = [[], [], [], ["other/evil.py"], ["other/evil.py"]]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=self._std_invoke(subtasks),
            program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])

    def test_validator_mutation_inside_child_scope_reaches_gate(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        cs = [[], ["src/gen.py"], ["src/gen.py"], ["src/gen.py"], ["src/gen.py"],
              ["src/gen.py"], [], [], ["src/gen.py"], []]
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        adj = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE",
            adjudication={"correction_required": False, "classifications": {},
                          "accepted_refs": [], "correction_brief": None,
                          "stop_reason": None})
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker", verdict="PASS"), _make_record("worker", 0)),
               (_make_result(role="reviewer", verdict="PASS"), _make_record("reviewer", 0)),
               (adj, _make_record("adjudicator", 0)),
               (_make_result(role="reviewer", verdict="PASS"), _make_record("reviewer", 1))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("SUCCESS", final["status"])
        self.assertEqual("HUMAN_GATE", final["verdict"])

    def test_failure_prevents_later_children(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        cs = [[], ["src/a.py"], ["src/a.py"]]
        calls = []

        def _validators(repo, validators, run_dir, cycle):
            calls.append((str(run_dir), cycle))
            if len(calls) == 1:
                return [{"name": "lint", "command": "x", "started_at": "t",
                         "finished_at": "t", "exit_code": 1, "status": "FAIL",
                         "stdout": "", "stderr": "bad"}]
            return [{"name": "lint", "command": "x", "started_at": "t",
                     "finished_at": "t", "exit_code": 0, "status": "PASS",
                     "stdout": "", "stderr": ""}]

        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs, invoke_side_effect=seq,
            validators_side_effect=_validators)
        self.assertEqual(2, code)
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        self.assertFalse((run_dir / "subtasks" / "2-s2").exists())

    def test_continuity_mismatch_blocks_worker(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        base1 = dict(self._baseline)
        base2 = dict(self._baseline, path_state={"src/drift.py": "x"},
                     dirty_paths=["src/drift.py"])
        calls = {"n": 0}

        def _capture(repo):
            calls["n"] += 1
            # source(1) original(2) arch-before(3) arch-after(4)
            # child1-start(5) child1-after-worker(6) child1-after-valid(7)
            # child2-start(8) drifts.
            if calls["n"] <= 7:
                return dict(base1)
            return dict(base2)

        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], []],
            invoke_side_effect=seq, capture_side_effect=_capture)
        self.assertEqual(2, code)
        self.assertEqual("PROGRAM_WORKSPACE_DRIFT", final["verdict"])

    def test_subtask_worker_blocked(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        blocked = _make_result(role="worker", verdict="BLOCKER",
                               findings=[{"severity": "BLOCKER", "text": "nope"}])
        seq = [(arch, _make_record("architect", 0)), (blocked, _make_record("worker", 0))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], []],
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("SUBTASK_WORKER_BLOCKED", final["verdict"])

    def test_subtask_worker_changes_required_blocked(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        blocked = _make_result(role="worker", verdict=" changes_required ")
        seq = [(arch, _make_record("architect", 0)), (blocked, _make_record("worker", 0))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], []],
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("SUBTASK_WORKER_BLOCKED", final["verdict"])

    def test_integrated_reviewer_unknown_verdict_is_invalid(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        unknown = _make_result(role="reviewer", verdict="NEEDS_WORK")
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker", verdict="PASS"), _make_record("worker", 0)),
               (unknown, _make_record("reviewer", 0))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[],
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertFalse(final.get("human_gate", False))

    def test_final_reviewer_unknown_verdict_never_human_gate(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        adjudicator = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE",
            adjudication={"correction_required": False, "classifications": {},
                          "accepted_refs": [], "correction_brief": None,
                          "stop_reason": None})
        unknown_final = _make_result(role="reviewer", verdict="NOT_PASS")
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker", verdict="PASS"), _make_record("worker", 0)),
               (_make_result(role="reviewer", verdict="PASS"), _make_record("reviewer", 0)),
               (adjudicator, _make_record("adjudicator", 0)),
               (unknown_final, _make_record("reviewer", 1))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[],
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("FINAL_REVIEW_BLOCKED", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertFalse(final.get("human_gate", False))

    def test_invalid_subtask_plan_fails_execution(self):
        bad_sub = {"subtask_id": "BAD!", "objective": "o",
                   "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []}
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = [bad_sub]
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0))]
        code, run_dir, final = self._run_bmode(
            subtasks=[bad_sub], cs_schedule=[],
            invoke_side_effect=seq)
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])

    def test_bmode_without_isolation_rejected(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        task_noiso = dict(self.task)
        task_noiso.pop("isolation", None)
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        seq = [(arch, _make_record("architect", 0))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[],
            invoke_side_effect=seq, task_override=task_noiso,
            program_override=dict(self.program, max_subtasks=1))
        self.assertEqual(2, code)
        self.assertEqual("INVALID_PROGRAM", final["verdict"])

    def test_single_shared_worktree(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        seen_repos = []
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks))
        base_seq = [(arch, _make_record("architect", 0)),
                    (_make_result(role="worker"), _make_record("worker", 0)),
                    (_make_result(role="worker"), _make_record("worker", 0)),
                    (_make_result(role="reviewer"), _make_record("reviewer", 0)),
                    (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                                  adjudication={"correction_required": False,
                                                "classifications": {},
                                                "accepted_refs": [],
                                                "correction_brief": None,
                                                "stop_reason": None}),
                     _make_record("adjudicator", 0)),
                    (_make_result(role="reviewer"), _make_record("reviewer", 1))]

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None):
            seen_repos.append(str(exec_repo))
            nxt = base_seq.pop(0)
            return nxt

        cs = [[], [], [], [], [], [], [], [], [], [], [], [], []]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs, invoke_side_effect=_invoke)
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual(1, len(set(seen_repos)))


class BModeCrashOrderTests(BModeHarness):
    def test_crash_order_artifacts(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        arch = _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=self._arch_plan(subtasks) if hasattr(self, "_arch_plan") else None)
        # build plan manually
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        cs = [[], [], [], [], [], [], [], [], [], [], [], [], []]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs, invoke_side_effect=seq)
        self.assertEqual(0, code, final.get("message"))
        plan_p = run_dir / "program-plan.json"
        s1_started = run_dir / "subtasks" / "1-s1" / "started.json"
        s1_done = run_dir / "subtasks" / "1-s1" / "completed.json"
        s2_started = run_dir / "subtasks" / "2-s2" / "started.json"
        s2_done = run_dir / "subtasks" / "2-s2" / "completed.json"
        state_p = run_dir / "program-state.json"
        for p in (plan_p, s1_started, s1_done, s2_started, s2_done, state_p):
            self.assertTrue(p.is_file(), p)
        # mtime order: plan < s1_started < s1_done < s2_started < s2_done
        self.assertLess(plan_p.stat().st_mtime_ns, s1_started.stat().st_mtime_ns)
        self.assertLess(s1_started.stat().st_mtime_ns, s1_done.stat().st_mtime_ns)
        self.assertLess(s1_done.stat().st_mtime_ns, s2_started.stat().st_mtime_ns)
        self.assertLess(s2_started.stat().st_mtime_ns, s2_done.stat().st_mtime_ns)
        # validators artifacts per subtask
        self.assertTrue((run_dir / "subtasks" / "1-s1" / "worker-cycle-0-result.json").is_file())

    def test_next_child_requires_completed(self):
        # Simulate validator failure in child1: child2 dir must not exist
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0))]

        def _validators(repo, validators, run_dir, cycle):
            return [{"name": "lint", "command": "x", "started_at": "t",
                     "finished_at": "t", "exit_code": 1, "status": "FAIL",
                     "stdout": "", "stderr": ""}]

        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], []],
            invoke_side_effect=seq, validators_side_effect=_validators)
        self.assertEqual(2, code)
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        self.assertTrue((run_dir / "subtasks" / "1-s1" / "failed.json").is_file())
        self.assertFalse((run_dir / "subtasks" / "1-s1" / "completed.json").exists())
        self.assertFalse((run_dir / "subtasks" / "2-s2").exists())

    def test_completed_marker_before_state_completed_order(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        events: list = []
        real_fsync = agentflow.atomic_json_fsync

        def _recording(path, value):
            if Path(path).name == "completed.json":
                events.append(("completed", str(path)))
            elif Path(path).name == "program-state.json":
                status = value.get("status") if isinstance(value, dict) else None
                completed = list(value.get("completed_subtasks", [])) if isinstance(value, dict) else []
                events.append(("state:" + str(status) + ":" + ",".join(completed), str(path)))
            return real_fsync(path, value)

        with mock.patch("agentflow.atomic_json_fsync", side_effect=_recording):
            code, run_dir, final = self._run_bmode(
                subtasks=subtasks,
                cs_schedule=[[], [], [], [], [], [], [], [], [], [], [], [], []],
                invoke_side_effect=seq)
        self.assertEqual(0, code, final.get("message"))
        kinds = [k for k, _ in events]
        # Find deterministic logical order: each completed.json must precede
        # any program-state that claims that child completed or COMPLETED.
        idx_c1 = next(i for i, (k, p) in enumerate(events)
                      if k == "completed" and "1-s1" in p)
        idx_c2 = next(i for i, (k, p) in enumerate(events)
                      if k == "completed" and "2-s2" in p)
        # First state claiming s1 completed (RUNNING with s1 in list)
        idx_s1_claim = next(i for i, (k, _) in enumerate(events)
                            if k.startswith("state:") and "s1" in k)
        # Final COMPLETED state must come after both markers.
        idx_completed_state = next(i for i, (k, _) in enumerate(events)
                                   if k.startswith("state:COMPLETED"))
        self.assertLess(idx_c1, idx_s1_claim,
                        "completed.json for s1 must precede state claiming s1")
        self.assertLess(idx_c1, idx_completed_state)
        self.assertLess(idx_c2, idx_completed_state,
                        "completed.json for s2 must precede COMPLETED state")
        self.assertLess(idx_c1, idx_c2)
        # State must never lead the immutable marker: no COMPLETED claim
        # may appear at or before the last completed marker.
        for i, (k, _) in enumerate(events):
            if k.startswith("state:COMPLETED"):
                self.assertGreater(i, idx_c2)


class BModeCorrectionTests(BModeHarness):
    def _correction_invoke(self, subtasks, *, mutate_earlier_inside=True):
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        w1 = _make_result(role="worker", verdict="PASS")
        w2 = _make_result(role="worker", verdict="PASS")
        rev0 = _make_result(role="reviewer", verdict="PASS")
        adj = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE",
            adjudication={"correction_required": True,
                          "classifications": {},
                          "accepted_refs": [],
                          "correction_brief": {"required_changes": ["fix"]},
                          "stop_reason": None})
        # adjudication with zero findings: classifications empty valid, but
        # correction_required True requires non-empty accepted_refs -> use one finding
        rev0b = _make_result(role="reviewer", verdict="BLOCKER",
                             findings=[{"severity": "LOW", "text": "nit"}])
        adj2 = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE",
            adjudication={"correction_required": True,
                          "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                          "accepted_refs": ["R1-F1"],
                          "correction_brief": {"required_changes": ["fix nit"]},
                          "stop_reason": None})
        corr = _make_result(role="worker", verdict="PASS")
        rev1 = _make_result(role="reviewer", verdict="PASS")
        return [(arch, _make_record("architect", 0)),
                (w1, _make_record("worker", 0)),
                (w2, _make_record("worker", 0)),
                (rev0b, _make_record("reviewer", 0)),
                (adj2, _make_record("adjudicator", 0)),
                (corr, _make_record("worker", 1)),
                (rev1, _make_record("reviewer", 1))]

    def test_adjudication_context_carries_initial_reviewer_verdict(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        seq = self._correction_invoke(subtasks)
        seen: dict = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "adjudicator":
                seen["context"] = context
            return seq.pop(0)

        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[], invoke_side_effect=_invoke)
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual("BLOCKER", seen["context"]["initial_reviewer_verdict"])
        self.assertEqual(
            ["R1-F1"],
            [finding["ref"] for finding in seen["context"]["initial_review_findings"]],
        )

    def test_correction_keeps_history_immutable(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        cs = [[], ["src/a.py"], ["src/a.py"], ["src/a.py"], ["src/a.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["src/a.py", "tests/b.py"], [], [],
              ["src/a.py", "tests/b.py", "src/fix.py"],
              ["src/a.py", "tests/b.py", "src/fix.py"],
              ["src/a.py", "tests/b.py", "src/fix.py"],
              ["src/a.py", "tests/b.py", "src/fix.py"], []]
        seq = self._correction_invoke(subtasks)
        pre_bytes: dict = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            # Capture exact pre-correction bytes BEFORE integrated correction
            # executes. Correction then mutates an earlier child's worktree
            # file (within parent scope); completed.json must stay identical.
            if role == "worker" and cycle == 1:
                for ordinal, sub in enumerate(subtasks, start=1):
                    p = Path(run_dir) / "subtasks" / f"{ordinal}-{sub['subtask_id']}" / "completed.json"
                    self.assertTrue(p.is_file(), f"completed.json missing before correction: {p}")
                    pre_bytes[sub["subtask_id"]] = p.read_bytes()
                repo = Path(exec_repo)
                (repo / "src").mkdir(parents=True, exist_ok=True)
                (repo / "src" / "fix.py").write_text("fix\n", encoding="utf-8")
            nxt = seq.pop(0)
            return nxt

        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=_invoke)
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual(1, final["correction_cycles"])
        self.assertEqual({"s1", "s2"}, set(pre_bytes.keys()))
        for ordinal, sub in enumerate(subtasks, start=1):
            p = run_dir / "subtasks" / f"{ordinal}-{sub['subtask_id']}" / "completed.json"
            self.assertTrue(p.is_file(), p)
            before_hash = hashlib.sha256(pre_bytes[sub["subtask_id"]]).hexdigest()
            after_hash = hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(before_hash, after_hash,
                             f"completed.json for {sub['subtask_id']} mutated by correction")
        self.assertTrue((run_dir / "correction-started.json").is_file())
        self.assertTrue((run_dir / "correction-completed.json").is_file())
        self.assertIn("validators_cycle_1", final)

    def test_correction_outside_parent_scope_fails(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        rev0b = _make_result(role="reviewer", verdict="BLOCKER",
                             findings=[{"severity": "LOW", "text": "nit"}])
        adj2 = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE",
            adjudication={"correction_required": True,
                          "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                          "accepted_refs": ["R1-F1"],
                          "correction_brief": {"required_changes": ["fix"]},
                          "stop_reason": None})
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (rev0b, _make_record("reviewer", 0)),
               (adj2, _make_record("adjudicator", 0)),
               (_make_result(role="worker"), _make_record("worker", 1)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        # correction delta escapes parent: pad readonly/accumulated slots first
        cs = [[], [], [], [], [], [], [], [],
              ["other/evil.py"], ["other/evil.py"], ["other/evil.py"]]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs, invoke_side_effect=seq,
            program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])

    def test_post_correction_validator_outside_parent_scope_fails(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        rev0b = _make_result(role="reviewer", verdict="BLOCKER",
                             findings=[{"severity": "LOW", "text": "nit"}])
        adj2 = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE",
            adjudication={"correction_required": True,
                          "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                          "accepted_refs": ["R1-F1"],
                          "correction_brief": {"required_changes": ["fix"]},
                          "stop_reason": None})
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (rev0b, _make_record("reviewer", 0)),
               (adj2, _make_record("adjudicator", 0)),
               (_make_result(role="worker"), _make_record("worker", 1)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        # correction worker stays in scope; post-correction validator escapes.
        cs = [[], [], [], [], [], [], [], [],
              ["src/fix.py"], ["other/evil.py"], ["other/evil.py"]]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs, invoke_side_effect=seq,
            program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])

    def test_final_reviewer_blocked(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        blocked_final = _make_result(role="reviewer", verdict="BLOCKER",
                                     findings=[{"severity": "BLOCKER", "text": "still broken"}])
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (blocked_final, _make_record("reviewer", 1))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], [], [], [], []],
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(2, code)
        self.assertEqual("FINAL_REVIEW_BLOCKED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final.get("human_gate", False))
        persisted = json.loads((run_dir / "final.json").read_text(encoding="utf-8"))
        self.assertEqual("FINAL_REVIEW_BLOCKED", persisted["verdict"])
        stored = final.get("final_reviewer_result", {})
        self.assertEqual("BLOCKER", stored.get("verdict"))

    def test_post_correction_validators_fail_blocks_gate(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        rev0b = _make_result(role="reviewer", verdict="BLOCKER",
                             findings=[{"severity": "LOW", "text": "nit"}])
        adj2 = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE",
            adjudication={"correction_required": True,
                          "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                          "accepted_refs": ["R1-F1"],
                          "correction_brief": {"required_changes": ["fix nit"]},
                          "stop_reason": None})
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (rev0b, _make_record("reviewer", 0)),
               (adj2, _make_record("adjudicator", 0)),
               (_make_result(role="worker"), _make_record("worker", 1)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        seen_final_reviewer = {"count": 0}
        orig_invoke = None

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "reviewer" and cycle == 1:
                seen_final_reviewer["count"] += 1
            nxt = seq.pop(0)
            return nxt

        def _validators(repo, validators, run_dir, cycle):
            # Initial subtasks succeed; correction-state validators FAIL.
            self.assertTrue(list(validators), "parent validators must be present post-correction")
            if cycle == 1:
                return [{"name": "lint", "command": "x", "started_at": "t",
                         "finished_at": "t", "exit_code": 1, "status": "FAIL",
                         "stdout": "post-correction breakage", "stderr": ""}]
            return [{"name": "lint", "command": "x", "started_at": "t",
                     "finished_at": "t", "exit_code": 0, "status": "PASS",
                     "stdout": "", "stderr": ""}]

        cs = [[], ["src/a.py"], ["src/a.py"], ["src/a.py"], ["src/a.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["src/a.py", "tests/b.py"], [], [],
              ["src/a.py", "tests/b.py", "src/fix.py"],
              ["src/a.py", "tests/b.py", "src/fix.py"],
              ["src/a.py", "tests/b.py", "src/fix.py"],
              ["src/a.py", "tests/b.py", "src/fix.py"], []]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=_invoke, validators_side_effect=_validators)
        self.assertEqual(2, code)
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final.get("human_gate", False))
        # Final reviewer must not run after post-correction validator failure.
        self.assertEqual(0, seen_final_reviewer["count"])
        self.assertNotIn("final_reviewer", final)
        # Semantic failure, not merely missing metadata.
        self.assertNotEqual("HUMAN_GATE", final["verdict"])

    def test_integrated_review_context_complete(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        seen = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None):
            if role == "reviewer" and cycle == 1:
                seen["ctx"] = context
            nxt = seq.pop(0)
            return nxt

        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], [], [], [], []],
            invoke_side_effect=_invoke, program_override=prog)
        self.assertEqual(0, code, final.get("message"))
        ctx = seen.get("ctx")
        self.assertIsNotNone(ctx)
        for key in ("original_program_execution_baseline",
                    "historical_subtask_completions",
                    "integrated_correction",
                    "current_final_candidate_baseline",
                    "accumulated_changed_paths_from_program_baseline",
                    "accumulated_diff_from_program_baseline",
                    "paths_later_modified_by_correction"):
            self.assertIn(key, ctx, key)

    def test_integrated_review_context_multi_child(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        seen = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "reviewer" and cycle == 1:
                seen["ctx"] = context
            nxt = seq.pop(0)
            return nxt

        cs = [[], ["src/a.py"], ["src/a.py"],
              ["src/a.py"], ["src/a.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["tests/b.py"], ["src/a.py", "tests/b.py"],
              ["src/a.py", "tests/b.py"], [], [], ["src/a.py", "tests/b.py"], []]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=cs,
            invoke_side_effect=_invoke)
        self.assertEqual(0, code, final.get("message"))
        ctx = seen.get("ctx")
        self.assertIsNotNone(ctx)
        hist = ctx["historical_subtask_completions"]
        self.assertEqual(2, len(hist))
        self.assertEqual(["s1", "s2"], [h["subtask_id"] for h in hist])
        self.assertEqual([1, 2], [h["ordinal"] for h in hist])
        acc = ctx["accumulated_changed_paths_from_program_baseline"]
        self.assertIn("src/a.py", acc)
        self.assertIn("tests/b.py", acc)
        # Accumulated scope must cover more than the last child alone.
        last_child_paths = hist[-1]["child_changed_paths"]
        self.assertNotEqual(sorted(acc), sorted(last_child_paths))
        self.assertTrue(any(p.startswith("src/") for p in acc))
        self.assertTrue(any(p.startswith("tests/") for p in acc))


class BModePreservationTests(BModeHarness):
    def test_preservation_required_for_gate(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], [], [], [], []],
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(0, code)
        # Now break preservation: remove workspace.json and verify helper fails
        (run_dir / "workspace.json").unlink()
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._bmode_verify_preservation(
                {"status": "PRESERVED"}, self.repo, self.repo, run_dir)
        self.assertEqual("WORKSPACE_PRESERVATION_FAILED", raised.exception.code)

    def test_preservation_requires_git_registration(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], [], [], [], []],
            invoke_side_effect=seq, program_override=prog)
        self.assertEqual(0, code)
        ws = json.loads((run_dir / "workspace.json").read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", ws["status"])
        # Folder still exists but Git registration proof fails -> fail closed.
        self.assertTrue(self.repo.is_dir())
        with mock.patch("agentflow._is_worktree_registered", return_value=False):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._bmode_verify_preservation(ws, self.repo, self.repo, run_dir)
        self.assertEqual("WORKSPACE_PRESERVATION_FAILED", raised.exception.code)
        # Missing source_repo fails closed even when the folder exists.
        with self.assertRaises(agentflow.AgentFlowError) as raised2:
            agentflow._bmode_verify_preservation(ws, None, self.repo, run_dir)
        self.assertEqual("WORKSPACE_PRESERVATION_FAILED", raised2.exception.code)

    def test_unregistered_worktree_blocks_gate(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        prog_c = dict(prog)
        tsk_c = dict(self.task)
        cs_sched: list = [[], [], [], [], [], [], [], []]
        counter = [0]

        def _cs(b, a):
            i = counter[0]
            counter[0] += 1
            return cs_sched[i] if i < len(cs_sched) else []

        pv = [{"name": "lint", "command": "x", "started_at": "t", "finished_at": "t",
               "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""}]
        with mock.patch("agentflow.read_json", side_effect=lambda p: (
                dict(prog_c) if Path(p).resolve() == program_resolved
                else (dict(tsk_c, repo=str(self.repo)) if Path(p).resolve() == task_resolved else {}))), \
             mock.patch("agentflow.capture_baseline", return_value=dict(self._baseline)), \
             mock.patch("agentflow.changed_since", side_effect=_cs), \
             mock.patch("agentflow.invoke_model", side_effect=seq), \
             mock.patch("agentflow.run_validators", return_value=list(pv)), \
             mock.patch("shutil.which", return_value="/usr/bin/opencode"), \
             mock.patch("agentflow.git", return_value=mock.MagicMock(returncode=0, stdout="", stderr="")), \
             mock.patch("agentflow._is_worktree_registered", return_value=False), \
             mock.patch("agentflow.WriteLease", return_value=(
                 (lambda m: (setattr(m, "__enter__", mock.MagicMock(return_value=m)),
                             setattr(m, "__exit__", mock.MagicMock(return_value=False)), m)[-1])(mock.MagicMock()))), \
             mock.patch("agentflow.load_models", return_value=dict(_DEFAULT_MODELS_B)), \
             mock.patch("agentflow.build_execution_context", return_value=(
                 (lambda c: (setattr(c, "isolated", True), setattr(c, "source_repo", self.repo),
                             setattr(c, "execution_repo", self.repo),
                             setattr(c, "baseline_commit", "a" * 40), c)[-1])(mock.MagicMock()))):
            code, run_dir, final = agentflow.run_program(self.program_file)
        self.assertEqual(2, code)
        self.assertEqual("WORKSPACE_PRESERVATION_FAILED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final.get("human_gate", False))

    def test_preservation_failure_blocks_gate(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        # Force preservation verification to fail via missing worktree dir
        orig_verify = agentflow._bmode_verify_preservation

        def _fail(*args, **kwargs):
            raise agentflow.AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "forced")

        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        prog_c = dict(prog)
        tsk_c = dict(self.task)
        cs_sched: list = [[], [], [], [], [], [], [], []]
        counter = [0]

        def _cs(b, a):
            i = counter[0]
            counter[0] += 1
            return cs_sched[i] if i < len(cs_sched) else []

        pv = [{"name": "lint", "command": "x", "started_at": "t", "finished_at": "t",
               "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""}]
        with mock.patch("agentflow.read_json", side_effect=lambda p: (
                dict(prog_c) if Path(p).resolve() == program_resolved
                else (dict(tsk_c, repo=str(self.repo)) if Path(p).resolve() == task_resolved else {}))), \
             mock.patch("agentflow.capture_baseline", return_value=dict(self._baseline)), \
             mock.patch("agentflow.changed_since", side_effect=_cs), \
             mock.patch("agentflow.invoke_model", side_effect=seq), \
             mock.patch("agentflow.run_validators", return_value=list(pv)), \
             mock.patch("shutil.which", return_value="/usr/bin/opencode"), \
             mock.patch("agentflow.git", return_value=mock.MagicMock(returncode=0, stdout="", stderr="")), \
             mock.patch("agentflow.WriteLease", return_value=(
                 (lambda m: (setattr(m, "__enter__", mock.MagicMock(return_value=m)),
                             setattr(m, "__exit__", mock.MagicMock(return_value=False)), m)[-1])(mock.MagicMock()))), \
             mock.patch("agentflow.load_models", return_value=dict(_DEFAULT_MODELS_B)), \
             mock.patch("agentflow.build_execution_context", return_value=(
                 (lambda c: (setattr(c, "isolated", True), setattr(c, "execution_repo", self.repo),
                             setattr(c, "baseline_commit", "a" * 40), c)[-1])(mock.MagicMock()))), \
             mock.patch("agentflow._bmode_verify_preservation", side_effect=_fail):
            code, run_dir, final = agentflow.run_program(self.program_file)
        self.assertEqual(2, code)
        self.assertEqual("WORKSPACE_PRESERVATION_FAILED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final.get("human_gate", False))

    def test_prior_failure_survives_preservation_failure(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0))]

        def _validators(repo, validators, run_dir, cycle):
            return [{"name": "lint", "command": "x", "started_at": "t",
                     "finished_at": "t", "exit_code": 1, "status": "FAIL",
                     "stdout": "", "stderr": ""}]

        program_resolved = self.program_file.resolve()
        task_resolved = self.task_file.resolve()
        prog_c = dict(prog)
        tsk_c = dict(self.task)
        counter = [0]
        cs_sched = [[], [], []]

        def _cs(b, a):
            i = counter[0]
            counter[0] += 1
            return cs_sched[i] if i < len(cs_sched) else []

        def _fail(*args, **kwargs):
            raise agentflow.AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "late failure")

        with mock.patch("agentflow.read_json", side_effect=lambda p: (
                dict(prog_c) if Path(p).resolve() == program_resolved
                else (dict(tsk_c, repo=str(self.repo)) if Path(p).resolve() == task_resolved else {}))), \
             mock.patch("agentflow.capture_baseline", return_value=dict(self._baseline)), \
             mock.patch("agentflow.changed_since", side_effect=_cs), \
             mock.patch("agentflow.invoke_model", side_effect=seq), \
             mock.patch("agentflow.run_validators", side_effect=_validators), \
             mock.patch("shutil.which", return_value="/usr/bin/opencode"), \
             mock.patch("agentflow.git", return_value=mock.MagicMock(returncode=0, stdout="", stderr="")), \
             mock.patch("agentflow.WriteLease", return_value=(
                 (lambda m: (setattr(m, "__enter__", mock.MagicMock(return_value=m)),
                             setattr(m, "__exit__", mock.MagicMock(return_value=False)), m)[-1])(mock.MagicMock()))), \
             mock.patch("agentflow.load_models", return_value=dict(_DEFAULT_MODELS_B)), \
             mock.patch("agentflow.build_execution_context", return_value=(
                 (lambda c: (setattr(c, "isolated", True), setattr(c, "execution_repo", self.repo),
                             setattr(c, "baseline_commit", "a" * 40), c)[-1])(mock.MagicMock()))), \
             mock.patch("agentflow._bmode_verify_preservation", side_effect=_fail):
            code, run_dir, final = agentflow.run_program(self.program_file)
        self.assertEqual(2, code)
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        self.assertIn("preservation_failure", final)
        self.assertEqual("WORKSPACE_PRESERVATION_FAILED",
                         final["preservation_failure"]["code"])


class BModeWatchdogTests(BModeHarness):
    def test_subtask2_stall_detected_no_retry(self):
        from agentflow import AbortedProcessError, AbortRequest
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        req = AbortRequest(code="STALL_DETECTED", message="stall", details={})

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if getattr(_invoke, "n", 0) == 0:
                _invoke.n = 1
                return (arch, _make_record("architect", 0))
            if getattr(_invoke, "n", 1) == 1:
                _invoke.n = 2
                return (_make_result(role="worker"), _make_record("worker", 0))
            _invoke.n = 3
            raise AbortedProcessError(req, b"partial", b"", None)

        _invoke.n = 0
        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], []],
            invoke_side_effect=_invoke)
        self.assertEqual(2, code)
        self.assertEqual("STALL_DETECTED", final["verdict"])
        self.assertEqual(3, _invoke.n)
        self.assertTrue((run_dir / "subtasks" / "1-s1" / "completed.json").is_file())
        self.assertTrue((run_dir / "subtasks" / "2-s2" / "failed.json").is_file())
        self.assertFalse((run_dir / "subtasks" / "2-s2" / "completed.json").exists())

    def test_subtask2_timeout_no_retry(self):
        import subprocess as _sp
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []},
        ]
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        state = {"n": 0}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            state["n"] += 1
            if state["n"] == 1:
                return (arch, _make_record("architect", 0))
            if state["n"] == 2:
                return (_make_result(role="worker"), _make_record("worker", 0))
            raise _sp.TimeoutExpired(cmd=["x"], timeout=1)

        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], []],
            invoke_side_effect=_invoke)
        self.assertEqual(2, code)
        self.assertEqual("PROCESS_TIMEOUT", final["verdict"])
        self.assertEqual(3, state["n"])

    def test_watchdog_threshold_inherited(self):
        parent = {
            "task_id": "pt", "repo": "/tmp/r", "risk": "LOW",
            "objective": "o", "allowed_paths": ["src"],
            "validators": [{"name": "v", "command": ["/usr/bin/true"]}],
            "forbidden_actions": [], "invariants": [],
            "model_timeout_seconds": 50,
            "model_inactivity_timeout_seconds": 5,
        }
        subtask = {"subtask_id": "s1", "objective": "o",
                   "allowed_paths": ["src"], "invariants": [], "expected_outputs": []}
        from pathlib import Path as _P
        child = agentflow._build_bmode_child_task(parent, subtask, _P("/tmp/exec"))
        self.assertEqual(50, child["model_timeout_seconds"])
        self.assertEqual(5, child["model_inactivity_timeout_seconds"])


def _init_git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True, capture_output=True)
    (path / "README.md").write_text("init\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True)
    return path


def _head_sha(repo: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


class BModeRealGitTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)
        self.source = _init_git_repo(self.tmp / "source")
        self.head = _head_sha(self.source)
        self.runs_dir = self.tmp / "runs"
        self.runs_dir.mkdir()
        self.locks_dir = self.tmp / "locks"
        self.locks_dir.mkdir()
        self.work_root = self.tmp / "worktrees"
        self.work_root.mkdir()
        self.prompts_dir = self.tmp / "prompts"
        self.prompts_dir.mkdir()
        for name in ("architect", "adjudicator", "worker", "reviewer"):
            (self.prompts_dir / f"{name}.md").write_text(f"# {name}\n", encoding="utf-8")
        self._patches = []
        for attr, target in [("RUNS_DIR", self.runs_dir), ("LOCKS_DIR", self.locks_dir), ("ROOT", self.tmp)]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)
        self._patches.append(mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(self.work_root)}).start() if hasattr(mock.patch, "dict") else None)
        # fix env patch handle
        self._patches = [p for p in self._patches if p is not None]

    def tearDown(self):
        for p in reversed(self._patches):
            try:
                p.stop()
            except Exception:
                pass
        mock.patch.stopall()

    def _write_program_task(self, subtasks, allowed):
        task = {
            "task_id": "t-real", "repo": str(self.source), "risk": "LOW",
            "objective": "real", "allowed_paths": allowed,
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": ["git commit"],
            "expected_baseline": {},
            "isolation": {"enabled": True, "baseline_commit": self.head},
        }
        task_path = self.tmp / "task.json"
        task_path.write_text(json.dumps(task), encoding="utf-8")
        program = {
            "program_id": "p-real", "task": "task.json",
            "roles": {"architect": "pa", "worker": "pw", "reviewer": "pr"},
            "max_corrections": 1, "max_subtasks": len(subtasks),
        }
        program_path = self.tmp / "program.json"
        program_path.write_text(json.dumps(program), encoding="utf-8")
        return program_path, task_path

    def test_shared_worktree_sees_prior_changes_and_no_commits(self):
        log_before = subprocess.run(["git", "log", "--oneline"], cwd=self.source,
                                    capture_output=True, text=True).stdout
        subtasks = [
            {"subtask_id": "backend", "objective": "make backend",
             "allowed_paths": ["backend/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "tests", "objective": "make tests",
             "allowed_paths": ["tests/"], "invariants": [], "expected_outputs": []},
        ]
        program_path, _ = self._write_program_task(subtasks, ["backend/", "tests/"])
        plan = dict(_ARCH_PLAN_B)
        plan["allowed_scope"] = ["backend/", "tests/"]
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seen = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            repo = Path(exec_repo)
            if role == "architect":
                return (arch, _make_record("architect", 0))
            if role == "worker":
                ordinal = (context or {}).get("ordinal", 0)
                if ordinal == 1:
                    (repo / "backend").mkdir(exist_ok=True)
                    (repo / "backend" / "app.py").write_text("x=1\n", encoding="utf-8")
                elif ordinal == 2:
                    # must see child1 file
                    seen["saw_child1"] = (repo / "backend" / "app.py").exists()
                    (repo / "tests").mkdir(exist_ok=True)
                    (repo / "tests" / "test_app.py").write_text("ok\n", encoding="utf-8")
                else:
                    (repo / "backend" / "fix.py").write_text("fix\n", encoding="utf-8")
                return (_make_result(role="worker"), _make_record("worker", cycle))
            if role == "reviewer":
                return (_make_result(role="reviewer"), _make_record("reviewer", cycle))
            if role == "adjudicator":
                return (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                                     adjudication={"correction_required": False,
                                                   "classifications": {},
                                                   "accepted_refs": [],
                                                   "correction_brief": None,
                                                   "stop_reason": None}),
                        _make_record("adjudicator", 0))
            return (_make_result(role=role), _make_record(role, cycle))

        with mock.patch("agentflow.invoke_model", side_effect=_invoke), \
             mock.patch("agentflow.load_models", return_value=dict(_DEFAULT_MODELS_B)), \
             mock.patch("shutil.which", return_value="/usr/bin/opencode"):
            code, run_dir, final = agentflow.run_program(program_path)
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertTrue(seen.get("saw_child1"), "child2 must see child1 changes on shared worktree")
        log_after = subprocess.run(["git", "log", "--oneline"], cwd=self.source,
                                   capture_output=True, text=True).stdout
        self.assertEqual(log_before, log_after)
        # one detached worktree, still registered
        ws = json.loads((run_dir / "workspace.json").read_text(encoding="utf-8"))
        exec_repo = Path(ws["execution_repo"])
        proc = subprocess.run(["git", "symbolic-ref", "--quiet", "HEAD"], cwd=exec_repo,
                              capture_output=True)
        self.assertNotEqual(0, proc.returncode)
        # cleanup worktree for temp hygiene
        subprocess.run(["git", "worktree", "remove", "--force", str(exec_repo)],
                       cwd=self.source, capture_output=True)

    def test_real_scope_transitions_enforced(self):
        # Untracked outside scope must fail; deletion/type transitions covered via capture_baseline
        subtasks = [
            {"subtask_id": "s1", "objective": "o",
             "allowed_paths": ["allowed/"], "invariants": [], "expected_outputs": []},
        ]
        program_path, _ = self._write_program_task(subtasks, ["allowed/", "backend/"])
        # adjust plan scope
        plan = dict(_ARCH_PLAN_B)
        plan["allowed_scope"] = ["allowed/"]
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)

        def _invoke(*, role, profile_name, profile, task, run_dir,
                    cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "architect":
                return (arch, _make_record("architect", 0))
            if role == "worker":
                repo = Path(exec_repo)
                (repo / "forbidden").mkdir(exist_ok=True)
                # untracked file outside child scope
                (repo / "forbidden" / "evil.txt").write_text("evil\n", encoding="utf-8")
                return (_make_result(role="worker"), _make_record("worker", cycle))
            if role == "reviewer":
                return (_make_result(role="reviewer"), _make_record("reviewer", cycle))
            return (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                                 adjudication={"correction_required": False,
                                               "classifications": {},
                                               "accepted_refs": [],
                                               "correction_brief": None,
                                               "stop_reason": None}),
                    _make_record("adjudicator", 0))

        with mock.patch("agentflow.invoke_model", side_effect=_invoke), \
             mock.patch("agentflow.load_models", return_value=dict(_DEFAULT_MODELS_B)), \
             mock.patch("shutil.which", return_value="/usr/bin/opencode"):
            code, run_dir, final = agentflow.run_program(program_path)
        self.assertEqual(2, code)
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])
        ws = json.loads((run_dir / "workspace.json").read_text(encoding="utf-8"))
        with mock.patch("subprocess.run"):
            pass
        subprocess.run(["git", "worktree", "remove", "--force", ws["execution_repo"]],
                       cwd=self.source, capture_output=True)

    def test_preservation_requires_git_registration_real_git(self):
        # Valid B-mode isolated execution: real detached worktree.
        run_id = "bmode-preservation-probe"
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source, baseline_commit=self.head, run_id=run_id)
        try:
            self.assertTrue(agentflow._is_worktree_registered(self.source, dest))
            run_dir = self.tmp / "probe-run"
            run_dir.mkdir()
            ws = {"status": "PRESERVED", "execution_repo": str(dest)}
            (run_dir / "workspace.json").write_text(json.dumps(ws), encoding="utf-8")
            # Otherwise-good state passes while registered.
            agentflow._bmode_verify_preservation(ws, self.source, dest, run_dir)
            # Corrupt registration in Git admin metadata but keep the folder.
            admin = self.source / ".git" / "worktrees"
            if admin.is_dir():
                import shutil as _shutil
                for child in list(admin.iterdir()):
                    _shutil.rmtree(child, ignore_errors=True)
            subprocess.run(["git", "worktree", "prune"], cwd=self.source,
                           capture_output=True)
            self.assertTrue(dest.is_dir(), "execution folder must still exist")
            self.assertFalse(agentflow._is_worktree_registered(self.source, dest))
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._bmode_verify_preservation(ws, self.source, dest, run_dir)
            self.assertEqual("WORKSPACE_PRESERVATION_FAILED", raised.exception.code)
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(dest)],
                           cwd=self.source, capture_output=True)
            import shutil as _shutil2
            with __import__("contextlib").suppress(Exception):
                _shutil2.rmtree(str(dest), ignore_errors=True)


class BModeSchemaTests(unittest.TestCase):
    def test_findings_schema_allows_structured_objects(self):
        schema = json.loads((Path(agentflow.__file__).parent / "schemas" / "result.schema.json").read_text(encoding="utf-8"))
        findings = schema["properties"]["findings"]
        self.assertEqual("array", findings.get("type"))
        items = findings.get("items", {})
        text = json.dumps(items)
        # Must not be strings-only: structured dict findings are canonical.
        self.assertNotEqual({"type": "string"}, items,
                            "findings schema must not be strings-only")
        self.assertIn("object", text)

    def test_canonical_findings_validate_against_schema(self):
        import jsonschema
        schema = json.loads((Path(agentflow.__file__).parent / "schemas" / "result.schema.json").read_text(encoding="utf-8"))
        base = {"task_id": "t", "role": "reviewer", "harness": "h",
                "provider": "p", "model": "m", "variant": None,
                "files_changed": [], "validators": [],
                "open_risks": [], "verdict": "PASS"}
        canonical = [
            {"severity": "BLOCKER", "text": "broken"},
            {"severity": "HIGH", "text": "risk", "file": "src/a.py"},
            {"severity": "LOW", "text": "nit"},
        ]
        candidate = dict(base, findings=list(canonical))
        jsonschema.validate(candidate, schema)
        # Runtime role-aware contract: a canonical BLOCKER verdict blocks,
        # while PASS with a blocking finding is an invalid contradiction
        # rather than a silent warning.
        self.assertTrue(agentflow.reviewer_blocks(
            dict(base, verdict="BLOCKER", findings=canonical)))
        self.assertFalse(agentflow.reviewer_blocks(
            dict(base, verdict="PASS", findings=[{"severity": "LOW", "text": "x"}])))
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_reviewer_result(
                dict(base, verdict="PASS", findings=[{"severity": "BLOCKER", "text": "x"}]))
        self.assertEqual("INVALID_MODEL_OUTPUT", raised.exception.code)
        refs = agentflow._assign_finding_refs(canonical)
        self.assertEqual(["R1-F1", "R1-F2", "R1-F3"], [r["ref"] for r in refs])


_REAL_ROOT = Path(agentflow.__file__).resolve().parent


class FinalRenameParserTests(unittest.TestCase):
    """R1b: porcelain -z rename/copy records retain BOTH endpoints."""

    def _entries_for(self, stdout):
        fake = mock.MagicMock(returncode=0, stdout=stdout, stderr="")
        with mock.patch("agentflow.git", return_value=fake):
            return agentflow.status_entries(Path("/tmp/irrelevant"))

    def test_staged_rename_keeps_both_endpoints(self):
        entries = self._entries_for("R  outside/leaked.txt\0allowed/keep.txt\0")
        self.assertEqual(
            sorted(p for _, p in entries),
            ["allowed/keep.txt", "outside/leaked.txt"],
        )

    def test_rename_plus_destination_modify_keeps_both(self):
        entries = self._entries_for("RM outside/leaked.txt\0allowed/keep.txt\0")
        self.assertEqual(
            sorted(p for _, p in entries),
            ["allowed/keep.txt", "outside/leaked.txt"],
        )

    def test_allowed_to_allowed_rename_keeps_both(self):
        entries = self._entries_for("R  allowed/renamed.txt\0allowed/keep.txt\0")
        self.assertEqual(
            sorted(p for _, p in entries),
            ["allowed/keep.txt", "allowed/renamed.txt"],
        )

    def test_copy_record_keeps_both_endpoints(self):
        entries = self._entries_for("C  allowed/copy.txt\0allowed/keep.txt\0")
        self.assertEqual(
            sorted(p for _, p in entries),
            ["allowed/copy.txt", "allowed/keep.txt"],
        )

    def test_ordinary_entries_unchanged(self):
        entries = self._entries_for(
            "M  allowed/mod.txt\0A  allowed/new.txt\0"
            "D  allowed/del.txt\0?? allowed/untracked.txt\0"
        )
        self.assertEqual(
            entries,
            [("M ", "allowed/mod.txt"), ("A ", "allowed/new.txt"),
             ("D ", "allowed/del.txt"), ("??", "allowed/untracked.txt")],
        )


class FinalStagedCoverageTests(unittest.TestCase):
    """Staged add/modify/delete (and renames) stay visible to scope checks."""

    def test_staged_add_modify_delete_visible(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _init_git_repo(Path(td) / "r")
            (repo / "allowed").mkdir()
            (repo / "allowed" / "tracked.txt").write_text("v1\n", encoding="utf-8")
            (repo / "allowed" / "condemned.txt").write_text("bye\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "base"], cwd=repo,
                           check=True, capture_output=True)
            before = agentflow.capture_baseline(repo)
            (repo / "allowed" / "staged-new.txt").write_text("new\n", encoding="utf-8")
            subprocess.run(["git", "add", "allowed/staged-new.txt"], cwd=repo,
                           check=True, capture_output=True)
            (repo / "allowed" / "tracked.txt").write_text("v2\n", encoding="utf-8")
            subprocess.run(["git", "add", "allowed/tracked.txt"], cwd=repo,
                           check=True, capture_output=True)
            subprocess.run(["git", "rm", "-q", "allowed/condemned.txt"], cwd=repo,
                           check=True, capture_output=True)
            after = agentflow.capture_baseline(repo)
            delta = agentflow.changed_since(before, after)
            for path in ("allowed/staged-new.txt", "allowed/tracked.txt",
                         "allowed/condemned.txt"):
                self.assertIn(path, delta, path)

    def test_shared_helper_blocks_001a_style_scope_on_staged_rename(self):
        # PROGRAM-001A uses the same status_entries/changed_since machinery
        # plus path_allowed; a staged allowed->outside rename must be
        # unauthorized there too.
        with tempfile.TemporaryDirectory() as td:
            repo = _init_git_repo(Path(td) / "r")
            (repo / "allowed").mkdir()
            (repo / "allowed" / "keep.txt").write_text("hello\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "base"], cwd=repo,
                           check=True, capture_output=True)
            before = agentflow.capture_baseline(repo)
            (repo / "outside").mkdir(exist_ok=True)
            subprocess.run(["git", "mv", "allowed/keep.txt", "outside/leaked.txt"],
                           cwd=repo, check=True, capture_output=True)
            after = agentflow.capture_baseline(repo)
            delta = agentflow.changed_since(before, after)
            unauthorized = [p for p in delta
                            if not agentflow.path_allowed(p, ["allowed/"])]
            self.assertIn("outside/leaked.txt", unauthorized)


class FinalRealGitCorrectionTests(unittest.TestCase):
    """R1/R1c/R2/R4 real-git end-to-end correction tests."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)
        self.source = _init_git_repo(self.tmp / "source")
        (self.source / "allowed").mkdir(exist_ok=True)
        (self.source / "allowed" / "keep.txt").write_text("hello\n", encoding="utf-8")
        (self.source / "outside").mkdir(exist_ok=True)
        (self.source / "outside" / "secret.txt").write_text("shh\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.source,
                       check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "fixtures"], cwd=self.source,
                       check=True, capture_output=True)
        self.head = _head_sha(self.source)
        self.runs_dir = self.tmp / "runs"
        self.runs_dir.mkdir()
        self.locks_dir = self.tmp / "locks"
        self.locks_dir.mkdir()
        self.work_root = self.tmp / "worktrees"
        self.work_root.mkdir()
        self.prompts_dir = self.tmp / "prompts"
        self.prompts_dir.mkdir()
        for name in ("architect", "adjudicator", "worker", "reviewer"):
            (self.prompts_dir / f"{name}.md").write_text(f"# {name}\n", encoding="utf-8")
        self._patches = []
        for attr, target in [("RUNS_DIR", self.runs_dir), ("LOCKS_DIR", self.locks_dir),
                             ("ROOT", self.tmp)]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)
        env_patch = mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(self.work_root)})
        env_patch.start()
        self._patches.append(env_patch)

    def tearDown(self):
        for p in reversed(self._patches):
            try:
                p.stop()
            except Exception:
                pass
        mock.patch.stopall()
        subprocess.run(["git", "worktree", "prune"], cwd=self.source, capture_output=True)

    def _write_program_task(self, subtasks, allowed):
        task = {
            "task_id": "t-final", "repo": str(self.source), "risk": "LOW",
            "objective": "final", "allowed_paths": allowed,
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": ["git commit"],
            "expected_baseline": {},
            "isolation": {"enabled": True, "baseline_commit": self.head},
        }
        task_path = self.tmp / "task.json"
        task_path.write_text(json.dumps(task), encoding="utf-8")
        program = {
            "program_id": "p-final", "task": "task.json",
            "roles": {"architect": "pa", "worker": "pw", "reviewer": "pr"},
            "max_corrections": 1, "max_subtasks": len(subtasks),
        }
        program_path = self.tmp / "program.json"
        program_path.write_text(json.dumps(program), encoding="utf-8")
        return program_path

    def _std_tail(self):
        return [
            (_make_result(role="reviewer"), _make_record("reviewer", 0)),
            (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                          adjudication={"correction_required": False,
                                        "classifications": {},
                                        "accepted_refs": [],
                                        "correction_brief": None,
                                        "stop_reason": None}),
             _make_record("adjudicator", 0)),
            (_make_result(role="reviewer"), _make_record("reviewer", 1)),
        ]

    def _run(self, program_path, invoke):
        with mock.patch("agentflow.invoke_model", side_effect=invoke), \
             mock.patch("agentflow.load_models", return_value=dict(_DEFAULT_MODELS_B)), \
             mock.patch("shutil.which", return_value="/usr/bin/opencode"):
            return agentflow.run_program(program_path)

    def test_r1_staged_rename_allowed_to_outside_blocked(self):
        subtasks = [{"subtask_id": "s1", "objective": "o",
                     "allowed_paths": ["allowed/"], "invariants": [], "expected_outputs": []}]
        program_path = self._write_program_task(subtasks, ["allowed/"])
        plan = dict(_ARCH_PLAN_B)
        plan["allowed_scope"] = ["allowed/"]
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        saved = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                     cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "architect":
                return (arch, _make_record("architect", 0))
            if role == "worker":
                saved["exec"] = str(exec_repo)
                repo = Path(exec_repo)
                (repo / "outside").mkdir(exist_ok=True)
                subprocess.run(["git", "mv", "allowed/keep.txt", "outside/leaked.txt"],
                               cwd=repo, check=True, capture_output=True)
                (repo / "outside" / "leaked.txt").write_text("hello evil\n",
                                                             encoding="utf-8")
                return (_make_result(role="worker"), _make_record("worker", cycle))
            nxt = list(self._std_tail())
            return nxt[0] if role == "reviewer" and cycle == 0 else nxt[-1] \
                if role == "reviewer" else nxt[1]

        code, run_dir, final = self._run(program_path, _invoke)
        self.assertEqual(2, code)
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final.get("human_gate", False))
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        # The exploit condition really reproduced: destination exists.
        self.assertIn("exec", saved)
        self.assertTrue((Path(saved["exec"]) / "outside" / "leaked.txt").is_file())

    def test_r1c_reverse_rename_source_still_in_child_delta(self):
        subtasks = [{"subtask_id": "s1", "objective": "o",
                     "allowed_paths": ["allowed/"], "invariants": [], "expected_outputs": []}]
        program_path = self._write_program_task(subtasks, ["allowed/", "outside/"])
        plan = dict(_ARCH_PLAN_B)
        plan["allowed_scope"] = ["allowed/"]
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)

        def _invoke(*, role, profile_name, profile, task, run_dir,
                     cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "architect":
                return (arch, _make_record("architect", 0))
            if role == "worker":
                repo = Path(exec_repo)
                subprocess.run(["git", "mv", "outside/secret.txt", "allowed/secret.txt"],
                               cwd=repo, check=True, capture_output=True)
                return (_make_result(role="worker"), _make_record("worker", cycle))
            nxt = list(self._std_tail())
            return nxt[0] if role == "reviewer" and cycle == 0 else nxt[-1] \
                if role == "reviewer" else nxt[1]

        code, run_dir, final = self._run(program_path, _invoke)
        self.assertEqual(2, code)
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final.get("human_gate", False))

    def test_r2_detached_to_branch_same_head_is_drift(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["allowed/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["allowed/"], "invariants": [], "expected_outputs": []},
        ]
        program_path = self._write_program_task(subtasks, ["allowed/"])
        plan = dict(_ARCH_PLAN_B)
        plan["allowed_scope"] = ["allowed/"]
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        real_capture = agentflow.capture_baseline
        attached = {"done": False}
        worker_ordinals = []

        def _hooked_capture(repo):
            if not attached["done"]:
                hits = list(self.runs_dir.rglob("completed.json"))
                if any(p.parent.name.startswith("1-") for p in hits):
                    subprocess.run(["git", "checkout", "-qb", "temp-branch"],
                                   cwd=repo, check=True, capture_output=True)
                    attached["done"] = True
            return real_capture(repo)

        def _invoke(*, role, profile_name, profile, task, run_dir,
                     cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "architect":
                return (arch, _make_record("architect", 0))
            if role == "worker":
                ordinal = (context or {}).get("ordinal", 0)
                worker_ordinals.append(ordinal)
                repo = Path(exec_repo)
                (repo / "allowed" / f"w{ordinal}.txt").write_text("x\n", encoding="utf-8")
                return (_make_result(role="worker"), _make_record("worker", cycle))
            nxt = list(self._std_tail())
            return nxt[0] if role == "reviewer" and cycle == 0 else nxt[-1] \
                if role == "reviewer" else nxt[1]

        with mock.patch("agentflow.invoke_model", side_effect=_invoke), \
             mock.patch("agentflow.load_models", return_value=dict(_DEFAULT_MODELS_B)), \
             mock.patch("shutil.which", return_value="/usr/bin/opencode"), \
             mock.patch("agentflow.capture_baseline", side_effect=_hooked_capture):
            code, run_dir, final = agentflow.run_program(program_path)
        self.assertTrue(attached["done"], "branch-attach condition never reproduced")
        self.assertEqual(2, code)
        self.assertEqual("PROGRAM_WORKSPACE_DRIFT", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertNotIn(2, worker_ordinals, "child2 worker must not start after drift")
        self.assertFalse(final.get("human_gate", False))

    def test_r2_branch_identity_direct(self):
        base = {"branch": None, "head": "h", "dirty_paths": [],
                "untracked_paths": [], "path_state": {}}
        attached = dict(base, branch="temp-branch")
        self.assertFalse(agentflow._baselines_equal_for_continuity(base, attached))
        self.assertFalse(agentflow._baselines_equal_for_continuity(attached, base))
        self.assertTrue(agentflow._baselines_equal_for_continuity(base, dict(base)))
        other = dict(base, branch="other")
        self.assertFalse(agentflow._baselines_equal_for_continuity(attached, other))

    def test_r4_reviewer_sees_staged_changes(self):
        subtasks = [
            {"subtask_id": "s1", "objective": "o1",
             "allowed_paths": ["allowed/"], "invariants": [], "expected_outputs": []},
            {"subtask_id": "s2", "objective": "o2",
             "allowed_paths": ["allowed/"], "invariants": [], "expected_outputs": []},
        ]
        program_path = self._write_program_task(subtasks, ["allowed/"])
        plan = dict(_ARCH_PLAN_B)
        plan["allowed_scope"] = ["allowed/"]
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seen = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                     cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "architect":
                return (arch, _make_record("architect", 0))
            if role == "worker":
                repo = Path(exec_repo)
                ordinal = (context or {}).get("ordinal", 0)
                if ordinal == 1:
                    (repo / "allowed" / "keep.txt").write_text(
                        "hello\nSTAGED_MARKER_Z9\n", encoding="utf-8")
                    subprocess.run(["git", "add", "allowed/keep.txt"],
                                   cwd=repo, check=True, capture_output=True)
                elif ordinal == 2:
                    subprocess.run(
                        ["git", "mv", "allowed/keep.txt", "allowed/renamed.txt"],
                        cwd=repo, check=True, capture_output=True)
                return (_make_result(role="worker"), _make_record("worker", cycle))
            if role == "reviewer":
                if cycle == 1:
                    seen["ctx"] = context
                return (_make_result(role="reviewer"), _make_record("reviewer", cycle))
            return (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                                 adjudication={"correction_required": False,
                                               "classifications": {},
                                               "accepted_refs": [],
                                               "correction_brief": None,
                                               "stop_reason": None}),
                    _make_record("adjudicator", 0))

        code, run_dir, final = self._run(program_path, _invoke)
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])
        ctx = seen.get("ctx")
        self.assertIsNotNone(ctx, "final reviewer context was never captured")
        acc = ctx["accumulated_changed_paths_from_program_baseline"]
        self.assertIn("allowed/keep.txt", acc)
        self.assertIn("allowed/renamed.txt", acc)
        diff = ctx["accumulated_diff_from_program_baseline"]
        self.assertTrue(diff.strip(), "accumulated diff must not be silently empty")
        self.assertIn("STAGED_MARKER_Z9", diff)


class FinalArchitectSignalTests(BModeHarness):
    """R3: the ACTUAL model-visible B-mode architect request carries the signal."""

    def _render_real(self, role, task, record, context):
        with mock.patch.object(agentflow, "ROOT", _REAL_ROOT):
            return agentflow.render_prompt(role, task, record, context)

    def test_r3_bmode_request_visibly_asks_for_subtasks(self):
        subtasks = [{"subtask_id": "s1", "objective": "o1",
                     "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []}]
        prog = dict(self.program, max_subtasks=1)
        plan = dict(_ARCH_PLAN_B)
        plan["subtasks"] = subtasks
        arch = _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)
        seq = [(arch, _make_record("architect", 0)),
               (_make_result(role="worker"), _make_record("worker", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 0)),
               (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                             adjudication={"correction_required": False,
                                           "classifications": {},
                                           "accepted_refs": [],
                                           "correction_brief": None,
                                           "stop_reason": None}),
                _make_record("adjudicator", 0)),
               (_make_result(role="reviewer"), _make_record("reviewer", 1))]
        seen = {}

        def _invoke(*, role, profile_name, profile, task, run_dir,
                     cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "architect":
                seen["context"] = context
                seen["task"] = task
            return seq.pop(0)

        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], [], [], [], [], []],
            invoke_side_effect=_invoke, program_override=prog)
        self.assertEqual(0, code, final.get("message"))
        prompt = self._render_real("architect", seen["task"],
                                   _make_record("architect", 0), seen["context"])
        self.assertIn("program_001b_architect_planning", prompt)
        self.assertIn("sequential", prompt.lower())
        self.assertIn('"max_subtasks": 1', prompt)
        self.assertIn("non-empty ordered", prompt)
        self.assertIn("subtasks", prompt)

    def test_r3b_amode_request_unchanged(self):
        task = {"task_id": "t", "repo": "/tmp/r", "risk": "LOW",
                "objective": "o", "allowed_paths": ["src/"],
                "forbidden_actions": [], "invariants": []}
        prompt = self._render_real("architect", task, _make_record("architect", 0), None)
        self.assertNotIn("program_001b_architect_planning", prompt)
        self.assertNotIn("sequential_subtasks_requested", prompt)

    def test_r3c_prompt_compliant_architect_reaches_happy_path(self):
        subtasks = [{"subtask_id": "s1", "objective": "o1",
                     "allowed_paths": ["src/"], "invariants": [], "expected_outputs": []}]
        prog = dict(self.program, max_subtasks=1)

        def _invoke(*, role, profile_name, profile, task, run_dir,
                     cycle, context=None, lease=None, exec_repo=None, on_activity=None):
            if role == "architect":
                prompt = self._render_real(role, task, _make_record(role, cycle), context)
                plan = dict(_ARCH_PLAN_B)
                # Prompt-compliant: emit subtasks ONLY when the visible
                # B-mode instruction is present.
                if ("program_001b_architect_planning" in prompt
                        and "sequential" in prompt.lower()):
                    plan["subtasks"] = subtasks
                return (_make_result(role="architect", verdict="PLAN_READY",
                                     architect_plan=plan),
                        _make_record(role, cycle))
            if role == "worker":
                return (_make_result(role="worker"), _make_record(role, cycle))
            if role == "reviewer":
                return (_make_result(role="reviewer"), _make_record(role, cycle))
            return (_make_result(role="adjudicator", verdict="ADJUDICATION_COMPLETE",
                                 adjudication={"correction_required": False,
                                               "classifications": {},
                                               "accepted_refs": [],
                                               "correction_brief": None,
                                               "stop_reason": None}),
                    _make_record("adjudicator", 0))

        code, run_dir, final = self._run_bmode(
            subtasks=subtasks, cs_schedule=[[], [], [], [], [], [], [], [], []],
            invoke_side_effect=_invoke, program_override=prog)
        self.assertEqual(0, code, final.get("message"))
        self.assertEqual("HUMAN_GATE", final["verdict"])


if __name__ == "__main__":
    unittest.main()
