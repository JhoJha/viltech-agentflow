"""F-03 adversarial regression: Git identity movement fails closed.

State-based detection (branch/HEAD) is the protection, not command denylists.
Covers invoke_model continuity, legacy/A-mode/B-mode runners, validators
bypass, diff anchoring, and queue fatal classification.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentflow


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=path, check=True, capture_output=True)
    (path / "src").mkdir(exist_ok=True)
    (path / "src" / "allowed.txt").write_text("v1\n", encoding="utf-8")
    (path / "README.md").write_text("init\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True)
    return path


def _head(repo: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def _branch(repo: Path):
    p = subprocess.run(
        ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=repo, capture_output=True, text=True,
    )
    return p.stdout.strip() if p.returncode == 0 else None


def _porcelain(repo: Path) -> str:
    return subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def _make_result(role="worker", verdict="PASS", **extra):
    r = {
        "task_id": "t1", "role": role, "harness": "opencode",
        "provider": "p", "model": "m", "variant": None,
        "files_changed": [], "validators": {}, "findings": [],
        "open_risks": [], "verdict": verdict,
    }
    r.update(extra)
    return r


def _make_record(role="worker", cycle=0):
    return {
        "profile": "p", "role": role, "harness": "opencode",
        "provider": "p", "model": "m", "variant": None,
        "agent": "a", "cycle": cycle,
        "invoked_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "exit_code": 0,
    }


def _commit(repo: Path, rel: str, content: str, msg="sneaky"):
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", rel], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=repo, check=True, capture_output=True)


MODELS = {
    "profiles": {
        "w": {"backend": "opencode", "command": "/usr/bin/true", "provider": "p",
              "model": "p/worker-1", "variant": None, "agent": "agentflow-worker",
              "available": True, "eligible_roles": ["worker"]},
        "r": {"backend": "opencode", "command": "/usr/bin/true", "provider": "p",
              "model": "p/reviewer-1", "variant": None, "agent": "agentflow-reviewer",
              "available": True, "eligible_roles": ["reviewer"]},
        "a": {"backend": "opencode", "command": "/usr/bin/true", "provider": "p",
              "model": "p/architect-1", "variant": None, "agent": "agentflow-architect",
              "available": True, "eligible_roles": ["architect", "adjudicator"]},
    },
    "routing": {"LOW": ["w"], "MEDIUM": ["w"], "HIGH": ["w"], "CRITICAL": ["w"]},
}


class GitIdentityHelperTests(unittest.TestCase):
    def test_equal_passes(self):
        agentflow.assert_git_identity_unchanged(
            {"branch": "main", "head": "abc"}, {"branch": "main", "head": "abc"},
            context="t",
        )

    def test_head_move_raises(self):
        with self.assertRaises(agentflow.AgentFlowError) as c:
            agentflow.assert_git_identity_unchanged(
                {"branch": "main", "head": "aaa"}, {"branch": "main", "head": "bbb"},
                context="t",
            )
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)

    def test_branch_attach_same_sha_raises(self):
        with self.assertRaises(agentflow.AgentFlowError) as c:
            agentflow.assert_git_identity_unchanged(
                {"branch": None, "head": "aaa"}, {"branch": "main", "head": "aaa"},
                context="t",
            )
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)

    def test_non_repo_none_is_noop(self):
        agentflow.assert_git_identity_unchanged(None, None, context="t")
        agentflow.assert_git_identity_unchanged(None, {"branch": "x", "head": "y"})
        # mocked {} harness tolerance
        agentflow.assert_git_identity_unchanged({}, {}, context="t")

    def test_read_identity_none_for_non_repo(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(agentflow.read_git_identity(Path(d)))

    def test_expected_known_actual_none_raises(self):
        with self.assertRaises(agentflow.AgentFlowError) as c:
            agentflow.assert_git_identity_unchanged(
                {"branch": "main", "head": "aaa"}, None, context="t"
            )
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)


class InvokeModelGitContinuityTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.repo = _init_repo(self.tmp / "repo")
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self.task = {
            "task_id": "t1", "repo": str(self.repo), "risk": "LOW",
            "objective": "o", "allowed_paths": ["src/"],
            "validators": [], "invariants": [], "forbidden_actions": [],
            "expected_baseline": {}, "max_corrections": 0,
        }
        self.profile = dict(MODELS["profiles"]["w"])
        # ensure no queue control leaks
        try:
            agentflow._ACTIVE_EXECUTION_CONTROL.set(None)
        except Exception:
            pass

    def _invoke(self, side_effect, **kw):
        with mock.patch("agentflow._invoke_model_once", side_effect=side_effect):
            return agentflow.invoke_model(
                role=kw.get("role", "worker"), profile_name="w",
                profile=self.profile, task=self.task,
                run_dir=self.run_dir, cycle=0, context=None,
                lease=None, exec_repo=self.repo,
            )

    def test_in_scope_commit_raises(self):
        def eff(**k):
            _commit(self.repo, "src/allowed.txt", "evil inscope\n")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)

    def test_out_of_scope_commit_raises(self):
        def eff(**k):
            _commit(self.repo, "outside.txt", "evil\n")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)

    def test_git_c_commit_raises(self):
        def eff(**k):
            (self.repo / "src" / "allowed.txt").write_text("evil c\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/allowed.txt"], cwd=self.repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "-c", "user.name=sneaky", "-c", "user.email=s@s",
                 "commit", "-m", "sneaky"],
                cwd=self.repo, check=True, capture_output=True,
            )
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)

    def test_git_capital_c_commit_raises(self):
        def eff(**k):
            (self.repo / "src" / "allowed.txt").write_text("evil C\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/allowed.txt"], cwd=self.repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(self.repo), "commit", "-m", "sneaky"],
                cwd=self.tmp, check=True, capture_output=True,
            )
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)

    def test_moved_head_clean_tree_zero_delta(self):
        before = agentflow.capture_baseline(self.repo)

        def eff(**k):
            _commit(self.repo, "src/allowed.txt", "evil clean\n")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)
        after = agentflow.capture_baseline(self.repo)
        self.assertEqual("", _porcelain(self.repo))
        self.assertEqual([], agentflow.changed_since(before, after))
        self.assertNotEqual(before["head"], after["head"])

    def test_detached_to_branch_same_sha_raises(self):
        # repo starts on a branch; move to a new branch at same SHA
        start_head = _head(self.repo)

        def eff(**k):
            subprocess.run(["git", "checkout", "-b", "sneaky-branch"],
                           cwd=self.repo, check=True, capture_output=True)
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)
        self.assertEqual(start_head, _head(self.repo))

    def test_failed_worker_commits_then_fails_is_identity_moved(self):
        calls = []

        def eff(**k):
            calls.append(1)
            _commit(self.repo, "src/allowed.txt", "evil then fail\n")
            raise agentflow.AgentFlowError("PROVIDER_TRANSIENT", "boom")
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)
        self.assertEqual(1, len(calls))

    def test_failed_worker_commits_then_fails_control_suppresses_retry(self):
        ctrl_dir = self.tmp / "q"
        ctrl_dir.mkdir()
        item_dir = self.tmp / "item"
        item_dir.mkdir()
        control = agentflow.ExecutionControl(
            queue_id="q", queue_run_dir=ctrl_dir, item_dir=item_dir,
            budgets={"wall_clock_seconds": 60, "model_calls": 10, "retries": 2,
                      "fallbacks": 2, "corrections": 1},
            fallback_profiles={}, models=MODELS,
        )
        control.start()
        token = agentflow._ACTIVE_EXECUTION_CONTROL.set(control)
        try:
            calls = []

            def eff(**k):
                calls.append(1)
                _commit(self.repo, "src/allowed.txt", "evil retry\n")
                raise agentflow.AgentFlowError("PROVIDER_TRANSIENT", "boom")

            with mock.patch("agentflow._invoke_model_once", side_effect=eff):
                with self.assertRaises(agentflow.AgentFlowError) as c:
                    agentflow.invoke_model(
                        role="worker", profile_name="w", profile=self.profile,
                        task=self.task, run_dir=self.run_dir, cycle=0,
                        context=None, lease=mock.Mock(), exec_repo=self.repo,
                    )
            self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)
            self.assertEqual(1, len(calls))
            self.assertEqual(0, control.used["retries"])
            self.assertEqual(0, control.used["fallbacks"])
        finally:
            agentflow._ACTIVE_EXECUTION_CONTROL.reset(token)

    def test_clean_failed_worker_still_retries(self):
        ctrl_dir = self.tmp / "q2"
        ctrl_dir.mkdir()
        item_dir = self.tmp / "item2"
        item_dir.mkdir()
        control = agentflow.ExecutionControl(
            queue_id="q", queue_run_dir=ctrl_dir, item_dir=item_dir,
            budgets={"wall_clock_seconds": 60, "model_calls": 10, "retries": 2,
                      "fallbacks": 2, "corrections": 1},
            fallback_profiles={}, models=MODELS,
        )
        control.start()
        token = agentflow._ACTIVE_EXECUTION_CONTROL.set(control)
        try:
            ok = (_make_result(), _make_record())

            def eff(**k):
                if len(calls) == 0:
                    calls.append(1)
                    raise agentflow.AgentFlowError("PROVIDER_TRANSIENT", "boom")
                calls.append(2)
                return ok

            calls: list = []
            with mock.patch("agentflow._invoke_model_once", side_effect=eff):
                got = agentflow.invoke_model(
                    role="reviewer", profile_name="w", profile=self.profile,
                    task=self.task, run_dir=self.run_dir, cycle=0,
                    context=None, lease=None, exec_repo=self.repo,
                )
            self.assertEqual(ok, got)
            self.assertEqual(2, len(calls))
        finally:
            agentflow._ACTIVE_EXECUTION_CONTROL.reset(token)

    def test_normal_uncommitted_change_passes(self):
        def eff(**k):
            (self.repo / "src" / "allowed.txt").write_text("dirty ok\n", encoding="utf-8")
            return (_make_result(), _make_record())
        got, _rec = self._invoke(eff)
        self.assertIn("task_id", got)

    def test_readonly_role_commit_raises(self):
        def eff(**k):
            _commit(self.repo, "src/allowed.txt", "reviewer evil\n")
            return (_make_result(role="reviewer", verdict="PASS"), _make_record("reviewer"))
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff, role="reviewer")
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)


class RunnerGateTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.source = _init_repo(self.tmp / "source")
        self.source_head = _head(self.source)
        self.runs = self.tmp / "runs"
        self.runs.mkdir()
        self.locks = self.tmp / "locks"
        self.locks.mkdir()
        self.wt_root = self.tmp / "wts"
        self.wt_root.mkdir()
        self._patches = []
        for attr, target in [("RUNS_DIR", self.runs), ("LOCKS_DIR", self.locks),
                             ("ROOT", self.tmp)]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)
        ep = mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(self.wt_root)})
        ep.start()
        self._patches.append(ep)
        try:
            agentflow._ACTIVE_EXECUTION_CONTROL.set(None)
        except Exception:
            pass

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    def _legacy_task_file(self, repo: Path):
        task = {
            "task_id": "t1", "repo": str(repo), "risk": "LOW",
            "objective": "obj", "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": [],
            "expected_baseline": {}, "max_corrections": 0,
            "preferred_worker": "w",
        }
        p = self.tmp / "task.json"
        p.write_text(json.dumps(task), encoding="utf-8")
        return p

    def _pass_validators(self):
        return [{
            "name": "lint", "command": "/usr/bin/true",
            "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
            "exit_code": 0, "status": "PASS", "stdout": "", "stderr": "",
        }]

    def test_legacy_worker_commit_is_identity_moved_no_human_gate(self):
        repo = _init_repo(self.tmp / "leg")
        task_path = self._legacy_task_file(repo)

        def eff(**k):
            r = k.get("exec_repo") or Path(k["task"]["repo"])
            _commit(Path(r), "src/allowed.txt", "evil legacy\n")
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, run_dir, final = agentflow.run_task(task_path)
        self.assertEqual(2, code)
        self.assertEqual("GIT_IDENTITY_MOVED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])

    def test_legacy_happy_uncommitted_reaches_human_gate(self):
        repo = _init_repo(self.tmp / "legok")
        task_path = self._legacy_task_file(repo)

        def eff(**k):
            r = Path(k.get("exec_repo") or k["task"]["repo"])
            (r / "src" / "allowed.txt").write_text("dirty ok\n", encoding="utf-8")
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, run_dir, final = agentflow.run_program if False else agentflow.run_task(task_path)
        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual("SUCCESS", final["status"])

    def _amode_files(self, repo: Path, max_corrections=1):
        task = {
            "task_id": "t1", "repo": str(repo), "risk": "HIGH",
            "objective": "obj", "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": [],
            "expected_baseline": {}, "max_corrections": 0,
        }
        program = {
            "program_id": "p1", "task": "task.json",
            "roles": {"architect": "a", "worker": "w", "reviewer": "r"},
            "max_corrections": max_corrections,
        }
        d = self.tmp / "amode"
        d.mkdir(exist_ok=True)
        (d / "task.json").write_text(json.dumps(task), encoding="utf-8")
        (d / "program.json").write_text(json.dumps(program), encoding="utf-8")
        return d / "program.json"

    def _arch(self, **over):
        plan = {
            "objective_interpretation": "o", "implementation_steps": ["s"],
            "invariants": [], "allowed_scope": ["src/"], "do_not_change": [],
            "validation_expectations": [], "known_risks": [],
        }
        return _make_result(role="architect", verdict="PLAN_READY",
                            architect_plan=plan, **over)

    def test_amode_initial_worker_commit_stops_before_reviewer(self):
        repo = _init_repo(self.tmp / "am1")
        prog = self._amode_files(repo)
        calls = []

        def eff(**k):
            calls.append(k.get("role"))
            if k.get("role") == "architect":
                return (self._arch(), _make_record("architect"))
            _commit(Path(k.get("exec_repo")), "src/allowed.txt", "evil amode\n")
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(2, code)
        self.assertEqual("GIT_IDENTITY_MOVED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertNotIn("reviewer", calls)
        self.assertNotEqual("HUMAN_GATE", final["verdict"])

    def test_amode_correction_worker_commit_stops(self):
        repo = _init_repo(self.tmp / "am2")
        prog = self._amode_files(repo, max_corrections=1)
        reviewer_block = _make_result(
            role="reviewer", verdict="BLOCKER",
            findings=[{"severity": "HIGH", "text": "bug"}],
        )
        reviewer_pass = _make_result(role="reviewer", verdict="PASS")
        adjud_corr = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": True,
                "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                "accepted_refs": ["R1-F1"],
                "correction_brief": {"required_changes": ["fix"]},
                "stop_reason": None,
            },
        )

        def eff(**k):
            role, cycle = k.get("role"), k.get("cycle")
            if role == "architect":
                return (self._arch(), _make_record("architect"))
            if role == "worker" and cycle == 0:
                (Path(k.get("exec_repo")) / "src" / "allowed.txt").write_text(
                    "dirty0\n", encoding="utf-8")
                return (_make_result(role="worker"), _make_record("worker", 0))
            if role == "reviewer" and cycle == 0:
                return (reviewer_block, _make_record("reviewer", 0))
            if role == "adjudicator":
                return (adjud_corr, _make_record("adjudicator"))
            if role == "worker" and cycle == 1:
                _commit(Path(k.get("exec_repo")), "src/allowed.txt", "evil corr\n")
                return (_make_result(role="worker"), _make_record("worker", 1))
            return (reviewer_pass, _make_record("reviewer", 1))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(2, code)
        self.assertEqual("GIT_IDENTITY_MOVED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])

    def _bmode_files(self, name="bm"):
        task = {
            "task_id": "t1", "repo": str(self.source), "risk": "HIGH",
            "objective": "obj", "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": [],
            "expected_baseline": {},
            "isolation": {"enabled": True, "baseline_commit": self.source_head},
            "max_corrections": 0,
        }
        program = {
            "program_id": "pb1", "task": "task.json",
            "roles": {"architect": "a", "worker": "w", "reviewer": "r"},
            "max_corrections": 1, "max_subtasks": 1,
        }
        d = self.tmp / name
        d.mkdir(exist_ok=True)
        (d / "task.json").write_text(json.dumps(task), encoding="utf-8")
        (d / "program.json").write_text(json.dumps(program), encoding="utf-8")
        return d / "program.json"

    def _barch(self):
        plan = {
            "objective_interpretation": "o", "implementation_steps": ["s"],
            "invariants": [], "allowed_scope": ["src/"], "do_not_change": [],
            "validation_expectations": [], "known_risks": [],
            "subtasks": [{
                "subtask_id": "s1", "objective": "do s1",
                "allowed_paths": ["src/"], "invariants": ["i"],
                "expected_outputs": ["o"],
            }],
        }
        return _make_result(role="architect", verdict="PLAN_READY", architect_plan=plan)

    def test_bmode_subtask_worker_commit_stops_no_completed(self):
        prog = self._bmode_files("bm1")

        def eff(**k):
            if k.get("role") == "architect":
                return (self._barch(), _make_record("architect"))
            _commit(Path(k.get("exec_repo")), "src/allowed.txt", "evil bmode\n")
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(2, code)
        self.assertEqual("GIT_IDENTITY_MOVED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        subs = list((rd / "subtasks").glob("*/completed.json")) if (rd / "subtasks").exists() else []
        self.assertEqual([], subs)

    def test_bmode_correction_worker_commit_stops_no_correction_completed(self):
        prog = self._bmode_files("bm2")
        reviewer_block = _make_result(
            role="reviewer", verdict="BLOCKER",
            findings=[{"severity": "HIGH", "text": "bug"}],
        )

        def _adj(corr):
            return _make_result(
                role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
                adjudication={
                    "correction_required": corr,
                    "classifications": {"R1-F1": "ACTIONABLE_REQUIRED" if corr else "NON_ACTIONABLE"},
                    "accepted_refs": ["R1-F1"] if corr else [],
                    "correction_brief": {"required_changes": ["fix"]} if corr else None,
                    "stop_reason": None,
                },
            )

        state = {"n": 0}

        def eff(**k):
            role, cycle = k.get("role"), k.get("cycle")
            if role == "architect":
                return (self._barch(), _make_record("architect"))
            if role == "worker" and cycle == 0:
                (Path(k.get("exec_repo")) / "src" / "allowed.txt").write_text(
                    "dirty b\n", encoding="utf-8")
                return (_make_result(role="worker"), _make_record("worker", 0))
            if role == "reviewer" and cycle == 0:
                return (reviewer_block, _make_record("reviewer", 0))
            if role == "adjudicator" and cycle == 0:
                return (_adj(True), _make_record("adjudicator"))
            if role == "worker" and cycle == 1:
                _commit(Path(k.get("exec_repo")), "src/allowed.txt", "evil bcorr\n")
                return (_make_result(role="worker"), _make_record("worker", 1))
            state["n"] += 1
            return (_make_result(role="reviewer", verdict="PASS"), _make_record("reviewer", 1))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(2, code)
        self.assertEqual("GIT_IDENTITY_MOVED", final["verdict"])
        self.assertFalse((rd / "correction-completed.json").exists())

    def test_bmode_detached_happy_still_human_gate(self):
        prog = self._bmode_files("bmok")
        reviewer_pass = _make_result(
            role="reviewer", verdict="PASS",
            findings=[{"severity": "MEDIUM", "text": "note"}],
        )

        def _adj():
            return _make_result(
                role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
                adjudication={
                    "correction_required": False,
                    "classifications": {"R1-F1": "NON_ACTIONABLE"},
                    "accepted_refs": [], "correction_brief": None,
                    "stop_reason": None,
                },
            )

        def eff(**k):
            role = k.get("role")
            if role == "architect":
                return (self._barch(), _make_record("architect"))
            if role == "worker":
                (Path(k.get("exec_repo")) / "src" / "allowed.txt").write_text(
                    "dirty ok\n", encoding="utf-8")
                return (_make_result(role="worker"), _make_record("worker", k.get("cycle", 0)))
            if role == "reviewer":
                return (reviewer_pass, _make_record("reviewer", k.get("cycle", 0)))
            return (_adj(), _make_record("adjudicator"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual("SUCCESS", final["status"])

    def test_legitimate_baseline_setup_keeps_identity(self):
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source, baseline_commit=self.source_head,
            run_id="f03-legit", root=self.wt_root,
        )
        try:
            base = agentflow.capture_baseline(dest)
            self.assertEqual(canonical, base["head"])
            self.assertIsNone(base["branch"])
            self.assertEqual(canonical, _head(dest))
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(dest)],
                           cwd=self.source, capture_output=True)


class ValidatorBypassAndDiffTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.repo = _init_repo(self.tmp / "repo")
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()

    def test_validator_git_c_bypass_detected_at_frozen_assert(self):
        baseline = agentflow.capture_baseline(self.repo)
        before_worker = agentflow.capture_baseline(self.repo)
        # validator bypasses safe_validator_argv via git -c
        subprocess.run(
            ["git", "-c", "user.name=v", "-c", "user.email=v@v",
             "commit", "--allow-empty", "-m", "validator sneaky"],
            cwd=self.repo, check=True, capture_output=True,
        )
        after_validators = agentflow.capture_baseline(self.repo)
        with self.assertRaises(agentflow.AgentFlowError) as c:
            agentflow.assert_git_identity_unchanged(
                baseline, after_validators, context="validators frozen baseline"
            )
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)
        # scope delta is empty (empty commit, clean tree) yet identity moved
        self.assertEqual([], agentflow.changed_since(before_worker, after_validators))

    def test_anchored_diff_includes_committed_content(self):
        anchor = _head(self.repo)
        marker = "F03-COMMITTED-MARKER-xyz"
        _commit(self.repo, "src/allowed.txt", marker + "\n")
        out = agentflow._accumulated_diff_stdout(self.repo, ["src/"], anchor_sha=anchor)
        self.assertIn(marker, out)
        ctx = agentflow._build_bmode_integrated_review_context(
            task={"allowed_paths": ["src/"]},
            architect_plan={}, original_baseline={"branch": "main", "head": anchor},
            historical_completions=[], integrated_correction=None,
            current_baseline=agentflow.capture_baseline(self.repo),
            accumulated_changed=[], repo=self.repo, allowed_paths=["src/"],
        )
        self.assertIn(marker, ctx["accumulated_diff_from_program_baseline"])
        a = agentflow._build_initial_review_context(
            {"allowed_paths": ["src/"]}, {}, _make_result(),
            [], ["src/allowed.txt"], self.repo, ["src/"], anchor_sha=anchor,
        )
        self.assertIn(marker, a["git_diff"])


class QueueClassificationTests(unittest.TestCase):
    def test_git_identity_moved_is_queue_fatal(self):
        self.assertIn("GIT_IDENTITY_MOVED", agentflow._QUEUE_FATAL_VERDICTS)

    def test_durable_final_classifies_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prog = {"program_id": "p1"}
            task = {"task_id": "t1", "repo": str(root)}
            rid = agentflow.RunIdentity("r1", root / "r1")
            rid.run_dir.mkdir(parents=True, exist_ok=True)
            durable = {
                "program_id": "p1", "task_id": "t1", "run_id": "r1",
                "verdict": "GIT_IDENTITY_MOVED", "status": "STOPPED",
                "human_gate": False,
            }
            agentflow.atomic_json(rid.run_dir / "final.json", durable)
            out = agentflow._verified_program_outcome(
                program=prog, task=task, run_identity=rid,
                returned_final=dict(durable), execution_control=None,
            )
            self.assertEqual("QUEUE_FATAL_FAILURE", out.outcome_class)
            self.assertEqual("GIT_IDENTITY_MOVED", out.verdict)


if __name__ == "__main__":
    unittest.main()
