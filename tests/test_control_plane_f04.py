"""F-04: state-based control-plane integrity invariant.

Protected set is always rooted at the running AgentFlow ROOT, never
exec_repo. Any mutation fails closed as CONTROL_PLANE_MUTATED with no
retry, fallback, correction, reviewer progression, or HUMAN_GATE.
"""
import json
import os
import shutil
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
        "fb": {"backend": "opencode", "command": "/usr/bin/true", "provider": "p",
               "model": "p/fb-1", "variant": None, "agent": "agentflow-worker",
               "available": True, "eligible_roles": ["worker"]},
    },
    "routing": {"LOW": ["w"], "MEDIUM": ["w"], "HIGH": ["w"], "CRITICAL": ["w"]},
}


def _make_fake_root(base: Path) -> Path:
    """Create a minimal protected control-plane tree under base."""
    (base / "prompts").mkdir(parents=True, exist_ok=True)
    (base / "prompts" / "reviewer.md").write_text("# reviewer\n", encoding="utf-8")
    (base / "prompts" / "worker.md").write_text("# worker\n", encoding="utf-8")
    (base / "opencode" / "agents").mkdir(parents=True, exist_ok=True)
    (base / "opencode" / "agents" / "agentflow-reviewer.md").write_text("# reviewer agent\n", encoding="utf-8")
    (base / "config").mkdir(parents=True, exist_ok=True)
    (base / "config" / "models.json").write_text('{"profiles": {}}\n', encoding="utf-8")
    (base / "schemas").mkdir(parents=True, exist_ok=True)
    (base / "schemas" / "result.schema.json").write_text('{"type": "object"}\n', encoding="utf-8")
    (base / "agentflow.py").write_text("# agentflow\n", encoding="utf-8")
    (base / "opencode" / "node_modules").mkdir(parents=True, exist_ok=True)
    (base / "opencode" / "node_modules" / "skip.js").write_text("skip\n", encoding="utf-8")
    (base / "opencode" / "__pycache__").mkdir(parents=True, exist_ok=True)
    (base / "opencode" / "__pycache__" / "skip.pyc").write_text("skip\n", encoding="utf-8")
    return base


class _FakeRootMixin:
    def _setup_fake_root(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.fake_root = _make_fake_root(self.tmp / "cproot")
        self.repo = _init_repo(self.tmp / "repo")
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self._root_patch = mock.patch.object(agentflow, "ROOT", self.fake_root)
        self._root_patch.start()
        self.addCleanup(self._root_patch.stop)
        # Durable poison ledger is keyed off LOCKS_DIR; keep it inside the
        # temp workspace so tests never touch the real repository ledger.
        self._locks_patch = mock.patch.object(
            agentflow, "LOCKS_DIR", self.tmp / "locks")
        self._locks_patch.start()
        self.addCleanup(self._locks_patch.stop)
        agentflow._reset_control_plane_baselines()
        self.addCleanup(agentflow._reset_control_plane_baselines)
        try:
            agentflow._ACTIVE_EXECUTION_CONTROL.set(None)
        except Exception:
            pass
        self.task = {
            "task_id": "t1", "repo": str(self.repo), "risk": "LOW",
            "objective": "o", "allowed_paths": ["src/"],
            "validators": [], "invariants": [], "forbidden_actions": [],
            "expected_baseline": {}, "max_corrections": 0,
        }
        self.profile = dict(MODELS["profiles"]["w"])

    def _invoke(self, side_effect, **kw):
        with mock.patch("agentflow._invoke_model_once", side_effect=side_effect):
            return agentflow.invoke_model(
                role=kw.get("role", "worker"), profile_name="w",
                profile=self.profile, task=self.task,
                run_dir=self.run_dir, cycle=0, context=None,
                lease=None, exec_repo=self.repo,
            )


class OpenCodeRuntimeBoundaryTests(_FakeRootMixin, unittest.TestCase):
    def setUp(self):
        self._setup_fake_root()
        (self.fake_root / "prompts" / "architect.md").write_text(
            "Return a plan.\n", encoding="utf-8")
        (self.fake_root / "opencode" / "agents" / "agentflow-architect.md").write_text(
            "# architect agent\n", encoding="utf-8")
        self.profile = dict(MODELS["profiles"]["a"])
        self.provider = self.tmp / "fake-opencode"
        self.provider.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib\n"
            "config = pathlib.Path(os.environ['OPENCODE_CONFIG_DIR'])\n"
            "(config / '.gitignore').write_text('node_modules\\npackage.json\\n')\n"
            "(config / 'package.json').write_text('{}\\n')\n"
            "if os.environ.get('FAKE_MUTATE_SOURCE') == '1':\n"
            f"    pathlib.Path({str(self.fake_root / 'opencode' / 'agents' / 'agentflow-architect.md')!r}).write_text('mutated\\n')\n"
            "print(json.dumps({'verdict': 'PLAN_READY', 'findings': [], "
            "'files_changed': [], 'architect_plan': {"
            "'objective_interpretation': 'Inspect runtime isolation', "
            "'implementation_steps': ['Inspect runtime files'], "
            "'invariants': [], 'allowed_scope': ['src/'], "
            "'do_not_change': [], 'validation_expectations': [], "
            "'known_risks': []}}))\n",
            encoding="utf-8",
        )
        self.provider.chmod(0o700)
        self.profile["command"] = str(self.provider)

    def _invoke_architect(self):
        return agentflow.invoke_model(
            role="architect", profile_name="a", profile=self.profile,
            task=self.task, run_dir=self.run_dir, cycle=0, exec_repo=self.repo,
        )

    def test_runtime_artifacts_are_isolated_and_fresh(self):
        before = agentflow.capture_control_plane_manifest()
        repo_before = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=self.repo, check=True, capture_output=True, text=True,
        ).stdout
        paths = []
        for _ in range(2):
            result, record = self._invoke_architect()
            self.assertEqual("PLAN_READY", result["verdict"])
            runtime = Path(record["runtime_config_dir"])
            paths.append(runtime)
            self.assertEqual(self.run_dir / "runtime", runtime.parent.parent)
            self.assertTrue((runtime / ".gitignore").is_file())
            self.assertTrue((runtime / "package.json").is_file())
            self.assertTrue((runtime / "agents" / "agentflow-architect.md").is_file())
            self.assertFalse(runtime.is_relative_to(self.repo))
            self.assertFalse(runtime.is_relative_to(self.fake_root / "opencode"))
            self.assertEqual(
                str(runtime),
                json.loads((self.run_dir / "architect-cycle-0-invocation.json").read_text())[
                    "runtime_config_dir"],
            )
        self.assertNotEqual(paths[0], paths[1])
        self.assertFalse((self.fake_root / "opencode" / ".gitignore").exists())
        self.assertEqual(before["digest"], agentflow.capture_control_plane_manifest()["digest"])
        self.assertEqual(repo_before, subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=self.repo, check=True, capture_output=True, text=True,
        ).stdout)

    def test_direct_source_mutation_still_poisoned(self):
        with mock.patch.dict(os.environ, {"FAKE_MUTATE_SOURCE": "1"}):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                self._invoke_architect()
        self.assertEqual("CONTROL_PLANE_MUTATED", raised.exception.code)
        ledger = self.tmp / "locks" / "control-plane-poison.json"
        self.assertTrue(ledger.is_file())

    def test_invalid_architect_output_with_control_plane_mutation_never_retries(self):
        source = self.fake_root / "opencode" / "agents" / "agentflow-architect.md"
        def invalid_and_mutate(**_kwargs):
            source.write_text("mutated\n", encoding="utf-8")
            return subprocess.CompletedProcess(
                ["fake"], 0,
                json.dumps({"verdict": "PLAN_READY", "findings": [],
                            "files_changed": [], "architect_plan": {}}), "",
            )
        with mock.patch("agentflow._run_model_command", side_effect=invalid_and_mutate) as called:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                self._invoke_architect()
        self.assertEqual("CONTROL_PLANE_MUTATED", raised.exception.code)
        self.assertEqual(1, called.call_count)
        self.assertFalse(list(self.run_dir.glob("attempts/*/structural-retry")))

    def test_source_symlink_and_special_entries_fail_closed(self):
        source = self.fake_root / "opencode"
        link = source / "agents" / "redirect"
        link.symlink_to(self.fake_root / "prompts", target_is_directory=True)
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._stage_opencode_config(self.run_dir, self.repo)
        self.assertEqual("UNSAFE_OPENCODE_CONFIG", raised.exception.code)
        link.unlink()
        fifo = source / "agents" / "pipe"
        os.mkfifo(fifo)
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._stage_opencode_config(self.run_dir, self.repo)
        self.assertEqual("UNSAFE_OPENCODE_CONFIG", raised.exception.code)

    def test_runtime_parent_cannot_alias_source_or_target(self):
        (self.run_dir / "runtime").symlink_to(self.fake_root / "opencode", target_is_directory=True)
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._stage_opencode_config(self.run_dir, self.repo)
        self.assertEqual("UNSAFE_OPENCODE_CONFIG", raised.exception.code)
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._stage_opencode_config(self.repo / "inside-run", self.repo)
        self.assertEqual("UNSAFE_OPENCODE_CONFIG", raised.exception.code)


class DirectMutationTests(_FakeRootMixin, unittest.TestCase):
    def setUp(self):
        self._setup_fake_root()

    def test01_prompts_reviewer_mutation_fatal(self):
        def eff(**k):
            (self.fake_root / "prompts" / "reviewer.md").write_text("# POISONED\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
        self.assertTrue((self.run_dir / "control-plane-mutated.json").is_file())

    def test02_opencode_reviewer_mutation_fatal(self):
        def eff(**k):
            (self.fake_root / "opencode" / "agents" / "agentflow-reviewer.md").write_text(
                "# POISONED\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test03_agentflow_py_mutation_fatal(self):
        def eff(**k):
            (self.fake_root / "agentflow.py").write_text("# POISONED\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test04_models_json_mutation_fatal(self):
        def eff(**k):
            (self.fake_root / "config" / "models.json").write_text('{"poisoned": true}\n', encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test05_schema_mutation_fatal(self):
        def eff(**k):
            (self.fake_root / "schemas" / "result.schema.json").write_text('{"poisoned": true}\n', encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test06_success_after_mutation_still_fails_closed(self):
        calls = []

        def eff(**k):
            calls.append(1)
            (self.fake_root / "prompts" / "reviewer.md").write_text("# POISONED\n", encoding="utf-8")
            return (_make_result(role="worker", verdict="PASS"), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
        self.assertEqual(1, len(calls))
        payload = json.loads((self.run_dir / "control-plane-mutated.json").read_text(encoding="utf-8"))
        self.assertEqual("CONTROL_PLANE_MUTATED", payload["verdict"])
        self.assertTrue(payload["delta"])

    def test07_retryable_failure_plus_mutation_no_retry_fallback(self):
        ctrl_dir = self.tmp / "q"
        ctrl_dir.mkdir()
        item_dir = self.tmp / "item"
        item_dir.mkdir()
        models = dict(MODELS)
        control = agentflow.ExecutionControl(
            queue_id="q", queue_run_dir=ctrl_dir, item_dir=item_dir,
            budgets={"wall_clock_seconds": 60, "model_calls": 10, "retries": 2,
                      "fallbacks": 2, "corrections": 1},
            fallback_profiles={"worker": "fb"}, models=models,
        )
        control.start()
        token = agentflow._ACTIVE_EXECUTION_CONTROL.set(control)
        try:
            calls = []

            def eff(**k):
                calls.append(1)
                (self.fake_root / "prompts" / "reviewer.md").write_text("# POISONED\n", encoding="utf-8")
                raise agentflow.AgentFlowError("PROVIDER_TRANSIENT", "boom")

            with mock.patch("agentflow._invoke_model_once", side_effect=eff):
                with self.assertRaises(agentflow.AgentFlowError) as c:
                    agentflow.invoke_model(
                        role="worker", profile_name="w", profile=self.profile,
                        task=self.task, run_dir=self.run_dir, cycle=0,
                        context=None, lease=mock.Mock(), exec_repo=self.repo,
                    )
            self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
            self.assertEqual(1, len(calls))
            self.assertEqual(0, control.used["retries"])
            self.assertEqual(0, control.used["fallbacks"])
        finally:
            agentflow._ACTIVE_EXECUTION_CONTROL.reset(token)

    def test12_protected_deletion_detected(self):
        def eff(**k):
            (self.fake_root / "prompts" / "reviewer.md").unlink()
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test13_file_dir_replacement_detected(self):
        def eff(**k):
            target = self.fake_root / "prompts" / "reviewer.md"
            target.unlink()
            target.mkdir()
            (target / "child.txt").write_text("evil\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test14_symlink_substitution_and_target_change_detected(self):
        # file -> symlink substitution
        def eff(**k):
            target = self.fake_root / "prompts" / "reviewer.md"
            target.unlink()
            os.symlink("/tmp/evil-target", target)
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
        # symlink target change: fresh baseline with symlink present
        agentflow._reset_control_plane_baselines()
        run2 = self.tmp / "run2"
        run2.mkdir()
        link = self.fake_root / "prompts" / "link.md"
        if link.exists() or link.is_symlink():
            if link.is_symlink() or link.is_file():
                link.unlink()
            else:
                shutil.rmtree(link)
        os.symlink("/tmp/target-a", link)
        # re-baseline is captured lazily on next verify; mutate target after
        # baseline by changing the link inside the mocked model call.
        def eff2(**k):
            os.unlink(link)
            os.symlink("/tmp/target-b", link)
            return (_make_result(), _make_record())
        with mock.patch("agentflow._invoke_model_once", side_effect=eff2):
            with self.assertRaises(agentflow.AgentFlowError) as c2:
                agentflow.invoke_model(
                    role="worker", profile_name="w", profile=self.profile,
                    task=self.task, run_dir=run2, cycle=0, context=None,
                    lease=None, exec_repo=self.repo,
                )
        self.assertEqual("CONTROL_PLANE_MUTATED", c2.exception.code)

    def test15_exec_repo_only_edits_valid(self):
        def eff(**k):
            (self.repo / "src" / "allowed.txt").write_text("dirty ok\n", encoding="utf-8")
            return (_make_result(), _make_record())
        got, _rec = self._invoke(eff)
        self.assertIn("task_id", got)

    def test17_non_isolated_protected_root_edits_fatal(self):
        # task repo IS the running ROOT; allowed_paths permits prompts/ but
        # control-plane mutation is still fatal.
        task = dict(self.task)
        task["repo"] = str(self.fake_root)
        task["allowed_paths"] = ["prompts/"]

        def eff(**k):
            (self.fake_root / "prompts" / "reviewer.md").write_text("# POISONED\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with mock.patch("agentflow._invoke_model_once", side_effect=eff):
            with self.assertRaises(agentflow.AgentFlowError) as c:
                agentflow.invoke_model(
                    role="worker", profile_name="w", profile=self.profile,
                    task=task, run_dir=self.run_dir, cycle=0, context=None,
                    lease=None, exec_repo=self.fake_root,
                )
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test19_exclusions_no_false_positive(self):
        def eff(**k):
            (self.fake_root / "opencode" / "node_modules" / "evil.js").write_text("evil\n", encoding="utf-8")
            (self.fake_root / "opencode" / "__pycache__" / "evil.pyc").write_text("evil\n", encoding="utf-8")
            (self.repo / "src" / "allowed.txt").write_text("dirty ok\n", encoding="utf-8")
            return (_make_result(), _make_record())
        got, _rec = self._invoke(eff)
        self.assertIn("task_id", got)

    def test20_f03_coexistence(self):
        # F-03 file is untouched and git-identity still enforced when the
        # control plane is clean.
        f03 = Path(agentflow.ROOT if str(agentflow.ROOT) != str(self.fake_root) else self.tmp)  # noqa
        # When ROOT is patched, resolve the real repo location via this file.
        real_repo = Path(__file__).resolve().parent.parent
        f03_path = real_repo / "tests" / "test_git_identity_f03.py"
        self.assertTrue(f03_path.is_file())
        text = f03_path.read_text(encoding="utf-8")
        self.assertIn("GIT_IDENTITY_MOVED", text)

        def eff(**k):
            (self.repo / "src" / "allowed.txt").write_text("evil\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/allowed.txt"], cwd=self.repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "sneaky"], cwd=self.repo, check=True, capture_output=True)
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("GIT_IDENTITY_MOVED", c.exception.code)


class IsolatedCandidateTests(_FakeRootMixin, unittest.TestCase):
    def setUp(self):
        self._setup_fake_root()

    def test16_isolated_candidate_edits_valid(self):
        source = _init_repo(self.tmp / "source")
        head = _head(source)
        wt_root = self.tmp / "wts"
        wt_root.mkdir()
        with mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(wt_root)}):
            dest, canonical = agentflow.create_isolated_worktree(
                source=source, baseline_commit=head, run_id="f04-candidate", root=wt_root,
            )
            try:
                self.assertEqual(head, canonical)

                def eff(**k):
                    (dest / "src" / "allowed.txt").write_text("candidate edit\n", encoding="utf-8")
                    return (_make_result(), _make_record())
                with mock.patch("agentflow._invoke_model_once", side_effect=eff):
                    got, _rec = agentflow.invoke_model(
                        role="worker", profile_name="w", profile=self.profile,
                        task=self.task, run_dir=self.run_dir, cycle=0,
                        context=None, lease=None, exec_repo=dest,
                    )
                self.assertIn("task_id", got)
            finally:
                subprocess.run(["git", "worktree", "remove", "--force", str(dest)],
                               cwd=source, capture_output=True)


class QueueFatalTests(unittest.TestCase):
    def test18_queue_fatal_classification(self):
        self.assertIn("CONTROL_PLANE_MUTATED", agentflow._QUEUE_FATAL_VERDICTS)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prog = {"program_id": "p1"}
            task = {"task_id": "t1", "repo": str(root)}
            rid = agentflow.RunIdentity("r1", root / "r1")
            rid.run_dir.mkdir(parents=True, exist_ok=True)
            durable = {
                "program_id": "p1", "task_id": "t1", "run_id": "r1",
                "verdict": "CONTROL_PLANE_MUTATED", "status": "STOPPED",
                "human_gate": False,
            }
            agentflow.atomic_json(rid.run_dir / "final.json", durable)
            out = agentflow._verified_program_outcome(
                program=prog, task=task, run_identity=rid,
                returned_final=dict(durable), execution_control=None,
            )
            self.assertEqual("QUEUE_FATAL_FAILURE", out.outcome_class)
            self.assertEqual("CONTROL_PLANE_MUTATED", out.verdict)


class RunnerGateTestsF04(unittest.TestCase):
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
        # Patched ROOT carries a minimal protected tree for F-04.
        _make_fake_root(self.tmp)
        self._patches = []
        for attr, target in [("RUNS_DIR", self.runs), ("LOCKS_DIR", self.locks),
                             ("ROOT", self.tmp)]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)
        ep = mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(self.wt_root)})
        ep.start()
        self._patches.append(ep)
        agentflow._reset_control_plane_baselines()
        self.addCleanup(agentflow._reset_control_plane_baselines)
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

    def _poison_prompts(self):
        (self.tmp / "prompts" / "reviewer.md").write_text("# POISONED\n", encoding="utf-8")

    def test11_legacy_mutation_stops(self):
        repo = _init_repo(self.tmp / "leg")
        task_path = self._legacy_task_file(repo)

        def eff(**k):
            self._poison_prompts()
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, run_dir, final = agentflow.run_task(task_path)
        self.assertEqual(2, code)
        self.assertEqual("CONTROL_PLANE_MUTATED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertTrue(list(run_dir.rglob("control-plane-mutated.json")))

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

    def test08_amode_worker_mutation_stops_before_reviewer(self):
        repo = _init_repo(self.tmp / "am1")
        prog = self._amode_files(repo)
        calls = []

        def eff(**k):
            calls.append(k.get("role"))
            if k.get("role") == "architect":
                return (self._arch(), _make_record("architect"))
            self._poison_prompts()
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(2, code)
        self.assertEqual("CONTROL_PLANE_MUTATED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertNotIn("reviewer", calls)
        self.assertNotEqual("HUMAN_GATE", final["verdict"])

    def test10_correction_worker_mutation_stops(self):
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
                self._poison_prompts()
                return (_make_result(role="worker"), _make_record("worker", 1))
            return (reviewer_pass, _make_record("reviewer", 1))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(2, code)
        self.assertEqual("CONTROL_PLANE_MUTATED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])

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

    def test09_bmode_worker_mutation_stops_before_completion(self):
        prog = self._bmode_files("bm1")
        calls = []

        def eff(**k):
            calls.append(k.get("role"))
            if k.get("role") == "architect":
                return (self._barch(), _make_record("architect"))
            self._poison_prompts()
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, rd, final = agentflow.run_program(prog)
        self.assertEqual(2, code)
        self.assertEqual("CONTROL_PLANE_MUTATED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertNotIn("reviewer", calls)
        subs = list((rd / "subtasks").glob("*/completed.json")) if (rd / "subtasks").exists() else []
        self.assertEqual([], subs)


class DurablePoisonLedgerTestsF04(unittest.TestCase):
    """F-04 future-run invariant: a control-plane state that AgentFlow
    itself observed as mutated must never be silently accepted as the
    trusted baseline of a later logical run.

    Run/state 1: detect a protected mutation and durably record the
    poisoned manifest. Run/state 2 (poisoned state left in place): a
    fresh logical run must fail CONTROL_PLANE_MUTATED at the run-start
    poison gate, before any model launch, worktree creation, retry,
    fallback, or HUMAN_GATE.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.source = _init_repo(self.tmp / "source")
        self.runs = self.tmp / "runs"
        self.runs.mkdir()
        self.locks = self.tmp / "locks"
        self.locks.mkdir()
        self.wt_root = self.tmp / "wts"
        self.wt_root.mkdir()
        # Patched ROOT carries a minimal protected tree for F-04.
        _make_fake_root(self.tmp)
        self._patches = []
        for attr, target in [("RUNS_DIR", self.runs), ("LOCKS_DIR", self.locks),
                             ("ROOT", self.tmp)]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)
        ep = mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(self.wt_root)})
        ep.start()
        self._patches.append(ep)
        agentflow._reset_control_plane_baselines()
        self.addCleanup(agentflow._reset_control_plane_baselines)
        try:
            agentflow._ACTIVE_EXECUTION_CONTROL.set(None)
        except Exception:
            pass

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    # --- helpers -------------------------------------------------------

    @property
    def ledger_path(self) -> Path:
        return agentflow.LOCKS_DIR / "control-plane-poison.json"

    def _read_ledger(self):
        return json.loads(self.ledger_path.read_text(encoding="utf-8"))

    def _write_poison_ledger(self, entries):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        agentflow.atomic_json_fsync(self.ledger_path, {
            "version": 1,
            "updated_at": "2026-01-01T00:00:00+00:00",
            "entries": entries,
        })

    def _ledger_entry(self, files, phase="manual", digest=None):
        d = digest or agentflow.canonical_control_plane_digest({"files": dict(files)})
        return {
            "digest": d,
            "files": dict(files),
            "root": str(self.tmp),
            "recorded_at": "2026-01-01T00:00:00+00:00",
            "phase": phase,
            "baseline_digest": None,
        }

    def _legacy_task_file(self, repo: Path, task_id="t1"):
        task = {
            "task_id": task_id, "repo": str(repo), "risk": "LOW",
            "objective": "obj", "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": [],
            "expected_baseline": {}, "max_corrections": 0,
            "preferred_worker": "w",
        }
        p = self.tmp / f"task-{task_id}.json"
        p.write_text(json.dumps(task), encoding="utf-8")
        return p

    def _pass_validators(self):
        return [{
            "name": "lint", "command": "/usr/bin/true",
            "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
            "exit_code": 0, "status": "PASS", "stdout": "", "stderr": "",
        }]

    def _poison_prompts(self):
        (self.tmp / "prompts" / "reviewer.md").write_text("# POISONED\n", encoding="utf-8")

    def _run(self, task_path, model_calls, context_calls, fail_on_context=False):
        def eff(**k):
            model_calls.append((k.get("role"), k.get("cycle")))
            return (_make_result(role="worker"), _make_record("worker"))

        original_ctx = agentflow.build_execution_context

        def bctx(*a, **k):
            context_calls.append(1)
            if fail_on_context:
                raise AssertionError("execution context/worktree must not start")
            return original_ctx(*a, **k)

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff), \
             mock.patch("agentflow.build_execution_context", side_effect=bctx):
            return agentflow.run_task(task_path)

    # --- tests ---------------------------------------------------------

    def test21_run1_detection_writes_durable_poison(self):
        repo = _init_repo(self.tmp / "leg21")
        task_path = self._legacy_task_file(repo, "t21")

        def eff(**k):
            self._poison_prompts()
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            code, run_dir, final = agentflow.run_task(task_path)

        self.assertEqual(2, code)
        self.assertEqual("CONTROL_PLANE_MUTATED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final["human_gate"])
        # Durable, content-bound poison evidence was written under LOCKS_DIR.
        self.assertTrue(self.ledger_path.is_file())
        ledger = self._read_ledger()
        self.assertEqual(1, ledger["version"])
        self.assertEqual(1, len(ledger["entries"]))
        entry = ledger["entries"][0]
        poisoned = agentflow.capture_control_plane_manifest()
        self.assertEqual(entry["digest"], poisoned["digest"])
        self.assertEqual(entry["files"], poisoned["files"])
        self.assertEqual(
            entry["digest"],
            agentflow.canonical_control_plane_digest({"files": entry["files"]}),
        )

    def test22_future_run_fails_before_model_launch(self):
        repo = _init_repo(self.tmp / "leg22")
        # --- Run/state 1: clean control plane, mutate, detect, record. ---
        task_path = self._legacy_task_file(repo, "t22a")

        def eff1(**k):
            self._poison_prompts()
            return (_make_result(role="worker"), _make_record("worker"))

        with mock.patch("agentflow.load_models", return_value=dict(MODELS)), \
             mock.patch("agentflow.run_validators", return_value=self._pass_validators()), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff1):
            code1, run_dir1, final1 = agentflow.run_task(task_path)
        self.assertEqual(2, code1)
        self.assertEqual("CONTROL_PLANE_MUTATED", final1["verdict"])
        self.assertTrue(self.ledger_path.is_file())

        # --- Run/state 2: poisoned state NOT restored; fresh logical run. ---
        model_calls, context_calls = [], []
        task_path2 = self._legacy_task_file(repo, "t22b")
        code2, run_dir2, final2 = self._run(
            task_path2, model_calls, context_calls, fail_on_context=True)

        self.assertEqual(2, code2)
        self.assertEqual("CONTROL_PLANE_MUTATED", final2["verdict"])
        self.assertEqual("STOPPED", final2["status"])
        self.assertNotEqual("HUMAN_GATE", final2["verdict"])
        self.assertFalse(final2["human_gate"])
        # Failed BEFORE any model launch or worktree/context creation.
        self.assertEqual([], model_calls)
        self.assertEqual([], context_calls)
        # Durable stop evidence in the new run directory.
        durable = json.loads((run_dir2 / "final.json").read_text(encoding="utf-8"))
        self.assertEqual("CONTROL_PLANE_MUTATED", durable["verdict"])
        self.assertEqual("STOPPED", durable["status"])
        self.assertFalse(durable["human_gate"])
        evidence = json.loads(
            (run_dir2 / "control-plane-mutated.json").read_text(encoding="utf-8"))
        self.assertEqual("CONTROL_PLANE_MUTATED", evidence["verdict"])

    def test23_different_legit_manifest_not_in_ledger_allowed(self):
        repo = _init_repo(self.tmp / "leg23")
        # ROOT is a git repo whose committed control plane is the fake
        # baseline; prompts/worker.md is then legitimately modified, so
        # the manifest differs from git HEAD yet was never poisoned.
        subprocess.run(["git", "init"], cwd=self.tmp, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=self.tmp, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=self.tmp, check=True, capture_output=True)
        for rel in ("agentflow.py", "config/models.json", "schemas/result.schema.json"):
            subprocess.run(["git", "add", rel], cwd=self.tmp, check=True, capture_output=True)
        subprocess.run(["git", "add", "prompts", "opencode"], cwd=self.tmp, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "control plane"], cwd=self.tmp, check=True, capture_output=True)
        (self.tmp / "prompts" / "worker.md").write_text(
            "# worker v2 legit\n", encoding="utf-8")
        self.assertNotEqual(
            subprocess.run(["git", "status", "--porcelain"], cwd=self.tmp,
                           check=True, capture_output=True, text=True).stdout.strip(),
            "",
        )
        # The ledger holds an UNRELATED poisoned manifest.
        self._write_poison_ledger([
            self._ledger_entry({"prompts/reviewer.md": "sha256:" + "ab" * 32})
        ])
        model_calls, context_calls = [], []
        task_path = self._legacy_task_file(repo, "t23")
        code, run_dir, final = self._run(task_path, model_calls, context_calls)
        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertTrue(final["human_gate"])
        self.assertTrue(model_calls)
        self.assertTrue(context_calls)

    def test24_malformed_ledger_fails_closed(self):
        repo = _init_repo(self.tmp / "leg24")
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        # (a) unreadable garbage
        self.ledger_path.write_text("{{{not json at all", encoding="utf-8")
        model_calls, context_calls = [], []
        code, _rd, final = self._run(
            self._legacy_task_file(repo, "t24a"), model_calls, context_calls)
        self.assertEqual(2, code)
        self.assertEqual("CONTROL_PLANE_MUTATED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        self.assertFalse(final["human_gate"])
        self.assertEqual([], model_calls)
        # (b) valid JSON whose entry fails digest verification
        agentflow._reset_control_plane_baselines()
        self._write_poison_ledger([{
            "digest": "f" * 64,
            "files": {"prompts/reviewer.md": "sha256:" + "cd" * 32},
            "root": str(self.tmp),
            "recorded_at": "2026-01-01T00:00:00+00:00",
            "phase": "tampered", "baseline_digest": None,
        }])
        model_calls, context_calls = [], []
        code2, _rd2, final2 = self._run(
            self._legacy_task_file(repo, "t24b"), model_calls, context_calls)
        self.assertEqual(2, code2)
        self.assertEqual("CONTROL_PLANE_MUTATED", final2["verdict"])
        self.assertEqual([], model_calls)
        # (c) unsupported ledger shape/version
        agentflow._reset_control_plane_baselines()
        self._write_poison_ledger([])
        text = self.ledger_path.read_text(encoding="utf-8").replace(
            '"version": 1', '"version": 99')
        self.ledger_path.write_text(text, encoding="utf-8")
        model_calls, context_calls = [], []
        code3, _rd3, final3 = self._run(
            self._legacy_task_file(repo, "t24c"), model_calls, context_calls)
        self.assertEqual(2, code3)
        self.assertEqual("CONTROL_PLANE_MUTATED", final3["verdict"])
        self.assertEqual([], model_calls)

    def test25_ledger_bounded(self):
        first = {"prompts/p.md": f"sha256:{0:064x}"}
        agentflow._record_control_plane_poison(
            {"root": str(self.tmp), "files": dict(first)}, phase="p0")
        for i in range(1, 45):
            files = {"prompts/p.md": f"sha256:{i:064x}"}
            agentflow._record_control_plane_poison(
                {"root": str(self.tmp), "files": dict(files)}, phase=f"p{i}")
            # duplicate detection must not grow the ledger
            agentflow._record_control_plane_poison(
                {"root": str(self.tmp), "files": dict(files)}, phase=f"dup{i}")
        ledger = self._read_ledger()
        self.assertEqual(1, ledger["version"])
        self.assertEqual(
            agentflow._CONTROL_PLANE_POISON_MAX_ENTRIES, len(ledger["entries"]))
        digests = {e["digest"] for e in ledger["entries"]}
        self.assertNotIn(
            agentflow.canonical_control_plane_digest({"files": dict(first)}),
            digests)
        newest = {"prompts/p.md": f"sha256:{44:064x}"}
        self.assertIn(
            agentflow.canonical_control_plane_digest({"files": dict(newest)}),
            digests)
        for entry in ledger["entries"]:
            self.assertEqual(
                entry["digest"],
                agentflow.canonical_control_plane_digest({"files": entry["files"]}),
            )

    def test26_ledger_excluded_from_protected_manifest(self):
        before = agentflow.capture_control_plane_manifest()
        self._write_poison_ledger([
            self._ledger_entry({"prompts/reviewer.md": "sha256:" + "ef" * 32})
        ])
        after = agentflow.capture_control_plane_manifest()
        self.assertEqual(before["files"], after["files"])
        self.assertEqual(before["digest"], after["digest"])
        self.assertFalse(any(k.startswith(".locks") for k in after["files"]))


class LifecycleCleanupTests(_FakeRootMixin, unittest.TestCase):
    """F-04 lifecycle: ContextVar cleanup under BaseException propagation.

    Validates that _CONTROL_PLANE_BASELINE is always reset when
    KeyboardInterrupt or SystemExit propagates through run_task or
    run_program (A-mode and B-mode).
    """

    def setUp(self):
        self._setup_fake_root()
        self.runs = self.tmp / "runs"
        self.runs.mkdir()
        self._runs_patch = mock.patch.object(agentflow, "RUNS_DIR", self.runs)
        self._runs_patch.start()
        self.addCleanup(self._runs_patch.stop)

    def _task_file(self, repo=None, task_id="t1"):
        task = {
            "task_id": task_id, "repo": str(repo or self.repo), "risk": "LOW",
            "objective": "o", "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": [],
            "expected_baseline": {}, "max_corrections": 0,
        }
        p = self.tmp / f"task-{task_id}.json"
        p.write_text(json.dumps(task), encoding="utf-8")
        return p

    def _run_task_with_exception(self, exc_type):
        task_path = self._task_file()

        def eff(**k):
            raise exc_type()

        _pass_validators = [{
            "name": "lint", "command": "/usr/bin/true",
            "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
            "exit_code": 0, "status": "PASS", "stdout": "", "stderr": "",
        }]
        with mock.patch("agentflow.load_models", return_value=MODELS), \
             mock.patch("agentflow.run_validators", return_value=_pass_validators), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            with self.assertRaises(exc_type):
                agentflow.run_task(task_path)

    # --- Test 1: KeyboardInterrupt cleanup ---

    def test_keyboard_interrupt_cleanup_resets_baseline(self):
        """KeyboardInterrupt propagates unchanged; _CONTROL_PLANE_BASELINE is None afterward."""
        self._run_task_with_exception(KeyboardInterrupt)
        self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

    # --- Test 2: SystemExit cleanup ---

    def test_system_exit_cleanup_resets_baseline(self):
        """SystemExit propagates unchanged; _CONTROL_PLANE_BASELINE is None afterward."""
        self._run_task_with_exception(SystemExit)
        self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

    # --- Test 3: Exact minimal regression ---

    def test_no_stale_baseline_after_base_exception(self):
        """Same process: BaseException then different ROOT invocation, no CONTROL_PLANE_MUTATED."""
        # Step 1: Run BaseException scenario.
        self._run_task_with_exception(KeyboardInterrupt)
        self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

        # Step 2: Invocation under a legitimate different mocked ROOT.
        new_tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, new_tmp, ignore_errors=True)
        new_root = _make_fake_root(new_tmp / "cproot")
        new_repo = _init_repo(new_tmp / "repo")

        with mock.patch.object(agentflow, "ROOT", new_root):
            task_path = self._task_file(repo=new_repo, task_id="t2")

            def eff(**k):
                return (_make_result(), _make_record())

            _pass_validators = [{
                "name": "lint", "command": "/usr/bin/true",
                "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
                "exit_code": 0, "status": "PASS", "stdout": "", "stderr": "",
            }]
            with mock.patch("agentflow.load_models", return_value=MODELS), \
                 mock.patch("agentflow.run_validators", return_value=_pass_validators), \
                 mock.patch("agentflow._invoke_model_once", side_effect=eff):
                code, run_dir, final = agentflow.run_task(task_path)
        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])

    # --- Test 4: A-mode program cleanup under BaseException ---

    def test_amode_program_cleanup_under_base_exception(self):
        """A-mode program: KeyboardInterrupt propagates; baseline is None afterward."""
        repo = _init_repo(self.tmp / "amode")
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
            "max_corrections": 1,
        }
        d = self.tmp / "amode"
        d.mkdir(exist_ok=True)
        (d / "task.json").write_text(json.dumps(task), encoding="utf-8")
        (d / "program.json").write_text(json.dumps(program), encoding="utf-8")

        def eff(**k):
            raise KeyboardInterrupt()

        _pass_validators = [{
            "name": "lint", "command": "/usr/bin/true",
            "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
            "exit_code": 0, "status": "PASS", "stdout": "", "stderr": "",
        }]
        with mock.patch("agentflow.load_models", return_value=MODELS), \
             mock.patch("agentflow.run_validators", return_value=_pass_validators), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            with self.assertRaises(KeyboardInterrupt):
                agentflow.run_program(d / "program.json")
        self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

    # --- Test 5: B-mode program cleanup under BaseException ---

    def test_bmode_program_cleanup_under_base_exception(self):
        """B-mode program: KeyboardInterrupt propagates; baseline is None afterward."""
        source = _init_repo(self.tmp / "bmode_source")
        source_head = _head(source)
        wt_root = self.tmp / "wts"
        wt_root.mkdir()

        task = {
            "task_id": "t1", "repo": str(source), "risk": "HIGH",
            "objective": "obj", "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": [], "forbidden_actions": [],
            "expected_baseline": {},
            "isolation": {"enabled": True, "baseline_commit": source_head},
            "max_corrections": 0,
        }
        program = {
            "program_id": "pb1", "task": "task.json",
            "roles": {"architect": "a", "worker": "w", "reviewer": "r"},
            "max_corrections": 1, "max_subtasks": 1,
        }
        d = self.tmp / "bmode"
        d.mkdir(exist_ok=True)
        (d / "task.json").write_text(json.dumps(task), encoding="utf-8")
        (d / "program.json").write_text(json.dumps(program), encoding="utf-8")

        def eff(**k):
            raise KeyboardInterrupt()

        _pass_validators = [{
            "name": "lint", "command": "/usr/bin/true",
            "started_at": "2026-01-01T00:00:00", "finished_at": "2026-01-01T00:00:01",
            "exit_code": 0, "status": "PASS", "stdout": "", "stderr": "",
        }]
        with mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(wt_root)}), \
             mock.patch("agentflow.load_models", return_value=MODELS), \
             mock.patch("agentflow.run_validators", return_value=_pass_validators), \
             mock.patch("agentflow._invoke_model_once", side_effect=eff):
            with self.assertRaises(KeyboardInterrupt):
                agentflow.run_program(d / "program.json")
        self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

    # --- Test 6: Reentrant ownership ---

    def test_reentrant_owner_cannot_clear_parent_baseline(self):
        """Nested owner receiving token=None cannot clear parent's baseline."""
        token_outer = agentflow._control_plane_enter_run(self.run_dir)
        self.assertIsNotNone(token_outer)
        baseline_after_outer = agentflow._CONTROL_PLANE_BASELINE.get()
        self.assertIsNotNone(baseline_after_outer)

        # Reentrant enter returns None.
        token_inner = agentflow._control_plane_enter_run(self.run_dir)
        self.assertIsNone(token_inner)

        # Inner exit is a no-op; outer baseline survives.
        agentflow._control_plane_exit_run(token_inner)
        self.assertEqual(baseline_after_outer, agentflow._CONTROL_PLANE_BASELINE.get())

        # Outer exit cleans up.
        agentflow._control_plane_exit_run(token_outer)
        self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

    # --- Test 7: Real mutation still fatal ---

    def test_real_root_mutation_still_fatal(self):
        """Existing real control-plane root mutation is STILL fatal."""
        def eff(**k):
            (self.fake_root / "prompts" / "reviewer.md").write_text(
                "# POISONED\n", encoding="utf-8")
            return (_make_result(), _make_record())

        with self.assertRaises(agentflow.AgentFlowError) as ctx:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", ctx.exception.code)


class SitecustomizeInjectionTests(_FakeRootMixin, unittest.TestCase):
    """F-04 control-plane coverage: sitecustomize-style injection.

    A worker creating a .py file directly under ROOT (e.g.
    sitecustomize.py, which Python auto-imports) must be detected as a
    control-plane mutation before any trusted consumption.
    """

    def setUp(self):
        self._setup_fake_root()

    def test28_sitecustomize_creation_detected(self):
        """Creating sitecustomize.py under ROOT is CONTROL_PLANE_MUTATED."""
        def eff(**k):
            (self.fake_root / "sitecustomize.py").write_text(
                "import os; os.system('evil')\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
        self.assertTrue((self.run_dir / "control-plane-mutated.json").is_file())

    def test29_usercustomize_creation_detected(self):
        """Creating usercustomize.py under ROOT is CONTROL_PLANE_MUTATED."""
        def eff(**k):
            (self.fake_root / "usercustomize.py").write_text(
                "import sys; sys.path.insert(0, '/evil')\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test30_arbitrary_root_py_detected(self):
        """Any new .py file directly under ROOT is detected."""
        def eff(**k):
            (self.fake_root / "evil_runtime.py").write_text(
                "# injected\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test31_existing_root_py_in_manifest(self):
        """Pre-existing .py files under ROOT appear in the manifest."""
        # Create a pre-existing .py file (simulating telemetry.py etc.)
        (self.fake_root / "telemetry.py").write_text("# telemetry\n", encoding="utf-8")
        agentflow._reset_control_plane_baselines()
        manifest = agentflow.capture_control_plane_manifest(root=self.fake_root)
        self.assertIn("telemetry.py", manifest["files"])
        self.assertTrue(manifest["files"]["telemetry.py"].startswith("sha256:"))

    def test32_root_py_symlink_detected(self):
        """A symlink .py file under ROOT is detected."""
        def eff(**k):
            os.symlink("/tmp/evil.py", self.fake_root / "evil_link.py")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test33_root_py_subdirectory_not_scanned(self):
        """Only ROOT-level .py files are scanned; subdirs are not."""
        def eff(**k):
            # Create a .py file in a subdirectory (not at ROOT level)
            subdir = self.fake_root / "tools"
            subdir.mkdir(exist_ok=True)
            (subdir / "evil.py").write_text("# deep\n", encoding="utf-8")
            return (_make_result(), _make_record())
        # This should succeed: only ROOT-level .py files are protected
        got, _rec = self._invoke(eff)
        self.assertIn("task_id", got)

    def test34_root_py_dir_replacement_detected(self):
        """Replacing a .py file with a directory is detected."""
        (self.fake_root / "existing.py").write_text("# v1\n", encoding="utf-8")
        agentflow._reset_control_plane_baselines()
        # Baseline captured; now replace file with directory
        def eff(**k):
            target = self.fake_root / "existing.py"
            target.unlink()
            target.mkdir()
            (target / "child.txt").write_text("evil\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)


class StandalonePoisonGateTests(_FakeRootMixin, unittest.TestCase):
    """F-04 standalone invoke_model: durable poison gate.

    When invoke_model is called without an outer logical-run owner, it
    must execute the durable poison-ledger start gate before any untrusted
    execution, use a bounded ownership scope, and not inherit stale trust.
    """

    def setUp(self):
        self._setup_fake_root()

    @property
    def ledger_path(self) -> Path:
        return agentflow.LOCKS_DIR / "control-plane-poison.json"

    def _write_poison_ledger(self, entries):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        agentflow.atomic_json_fsync(self.ledger_path, {
            "version": 1,
            "updated_at": "2026-01-01T00:00:00+00:00",
            "entries": entries,
        })

    def _ledger_entry(self, files, phase="manual", digest=None):
        d = digest or agentflow.canonical_control_plane_digest({"files": dict(files)})
        return {
            "digest": d,
            "files": dict(files),
            "root": str(self.tmp),
            "recorded_at": "2026-01-01T00:00:00+00:00",
            "phase": phase,
            "baseline_digest": None,
        }

    def test35_standalone_poison_gate_blocks_before_model(self):
        """Standalone invoke_model fails at poison gate before model launch."""
        # Poison the ledger with the current (clean) manifest.
        clean_manifest = agentflow.capture_control_plane_manifest()
        self._write_poison_ledger([
            self._ledger_entry(clean_manifest["files"], phase="test-poison")
        ])
        model_calls = []
        def eff(**k):
            model_calls.append(1)
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
        self.assertEqual([], model_calls)  # No model was launched

    def test36_standalone_run_n_poison_then_fresh_invocation(self):
        """Run-N poison -> fresh standalone invocation fails at gate."""
        # Run N: detect mutation and record in poison ledger.
        def eff_poison(**k):
            (self.fake_root / "prompts" / "reviewer.md").write_text(
                "# POISONED\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff_poison)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
        self.assertTrue(self.ledger_path.is_file())

        # Fresh standalone invocation: fails at poison gate.
        model_calls = []
        def eff_clean(**k):
            model_calls.append(1)
            return (_make_result(), _make_record())
        agentflow._reset_control_plane_baselines()
        with self.assertRaises(agentflow.AgentFlowError) as c2:
            self._invoke(eff_clean)
        self.assertEqual("CONTROL_PLANE_MUTATED", c2.exception.code)
        self.assertEqual([], model_calls)

    def test37_standalone_repeated_run_dir_no_stale_trust(self):
        """Repeated standalone calls with same run_dir do not inherit stale trust."""
        # First call: clean, succeeds.
        def eff1(**k):
            return (_make_result(), _make_record())
        got1, _ = self._invoke(eff1)
        self.assertIn("task_id", got1)

        # Mutate and poison the ledger.
        (self.fake_root / "prompts" / "reviewer.md").write_text(
            "# POISONED\n", encoding="utf-8")
        agentflow._reset_control_plane_baselines()
        poisoned = agentflow.capture_control_plane_manifest()
        agentflow._record_control_plane_poison(poisoned, phase="test-poison")

        # Second call with same run_dir: must fail at poison gate.
        def eff2(**k):
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff2)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)

    def test38_standalone_scope_cleanup_no_leak(self):
        """Standalone scope is cleaned up; no stale baseline leaks."""
        def eff(**k):
            return (_make_result(), _make_record())
        self._invoke(eff)
        # After standalone call, ContextVar must be cleared.
        self.assertIsNone(agentflow._CONTROL_PLANE_BASELINE.get())

    def test39_standalone_mutation_during_invocation_detected(self):
        """Control-plane mutation during standalone invocation is detected."""
        def eff(**k):
            (self.fake_root / "prompts" / "reviewer.md").write_text(
                "# POISONED\n", encoding="utf-8")
            return (_make_result(), _make_record())
        with self.assertRaises(agentflow.AgentFlowError) as c:
            self._invoke(eff)
        self.assertEqual("CONTROL_PLANE_MUTATED", c.exception.code)
        # Poison ledger was written.
        self.assertTrue(self.ledger_path.is_file())


class PoisonLedgerConcurrencyTests(unittest.TestCase):
    """F-04 poison ledger concurrency: cross-process safe updates.

    Concurrent detections must not lose an entry.  The read-modify-write
    is protected by an OS advisory lock (fcntl.flock).
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.locks = self.tmp / "locks"
        self.locks.mkdir()
        self._locks_patch = mock.patch.object(
            agentflow, "LOCKS_DIR", self.locks)
        self._locks_patch.start()
        self.addCleanup(self._locks_patch.stop)
        self._make_fake_root(self.tmp)

    @staticmethod
    def _make_fake_root(base: Path) -> Path:
        (base / "prompts").mkdir(parents=True, exist_ok=True)
        (base / "prompts" / "reviewer.md").write_text("# reviewer\n", encoding="utf-8")
        (base / "prompts" / "worker.md").write_text("# worker\n", encoding="utf-8")
        (base / "opencode" / "agents").mkdir(parents=True, exist_ok=True)
        (base / "opencode" / "agents" / "agentflow-reviewer.md").write_text(
            "# reviewer agent\n", encoding="utf-8")
        (base / "config").mkdir(parents=True, exist_ok=True)
        (base / "config" / "models.json").write_text('{"profiles": {}}\n', encoding="utf-8")
        (base / "schemas").mkdir(parents=True, exist_ok=True)
        (base / "schemas" / "result.schema.json").write_text('{"type": "object"}\n', encoding="utf-8")
        (base / "agentflow.py").write_text("# agentflow\n", encoding="utf-8")
        return base

    @property
    def ledger_path(self) -> Path:
        return self.locks / "control-plane-poison.json"

    def _read_ledger(self):
        return json.loads(self.ledger_path.read_text(encoding="utf-8"))

    def test40_concurrent_writes_no_lost_entries(self):
        """Concurrent poison ledger writers do not lose entries."""
        import threading

        num_writers = 8
        errors: list[tuple[int, Exception]] = []
        barrier = threading.Barrier(num_writers)

        def writer(index: int) -> None:
            try:
                barrier.wait(timeout=10)
                files = {"prompts/p.md": f"sha256:{index:064x}"}
                current = {"root": str(self.tmp), "files": files}
                agentflow._record_control_plane_poison(
                    current, phase=f"concurrent-{index}", baseline_digest=None)
            except Exception as e:
                errors.append((index, e))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(num_writers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual([], errors, f"Writer errors: {errors}")

        ledger = self._read_ledger()
        self.assertEqual(1, ledger["version"])
        self.assertEqual(num_writers, len(ledger["entries"]))

        digests = {e["digest"] for e in ledger["entries"]}
        for i in range(num_writers):
            expected = agentflow.canonical_control_plane_digest(
                {"files": {"prompts/p.md": f"sha256:{i:064x}"}})
            self.assertIn(expected, digests)

    def test41_concurrent_dedup_under_contention(self):
        """Concurrent duplicate writes produce exactly one entry."""
        import threading

        files = {"prompts/dup.md": "sha256:" + "aa" * 32}
        current = {"root": str(self.tmp), "files": files}
        num_writers = 8
        barrier = threading.Barrier(num_writers)

        def writer(index: int) -> None:
            barrier.wait(timeout=10)
            agentflow._record_control_plane_poison(
                current, phase=f"dup-{index}", baseline_digest=None)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(num_writers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        ledger = self._read_ledger()
        self.assertEqual(1, len(ledger["entries"]))
        self.assertEqual(
            agentflow.canonical_control_plane_digest({"files": files}),
            ledger["entries"][0]["digest"],
        )


if __name__ == "__main__":
    unittest.main()
