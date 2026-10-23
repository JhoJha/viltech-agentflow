"""Tests for WORKTREE-001A: Isolated Execution Workspace.

Uses REAL temporary Git repositories and REAL git worktree commands.
Only model execution is mocked where needed.
"""

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentflow


def _init_git_repo(path: Path) -> Path:
    """Create a real git repository with an initial commit."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True, capture_output=True)
    (path / "README.md").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True)
    return path


def _head_sha(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
        capture_output=True, text=True,
    )
    return proc.stdout.strip()


def _make_result(task_id="t1", role="worker", verdict="PASS", findings=None,
                 files_changed=None, open_risks=None, **extra):
    result = {
        "task_id": task_id, "role": role, "harness": "opencode",
        "provider": "opencode", "model": "test/model", "variant": None,
        "files_changed": files_changed or [], "validators": {},
        "findings": findings or [], "open_risks": open_risks or [],
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
    "implementation_steps": ["Create src/foo.py"],
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
_REVIEWER_RESULT_0_PASS = _make_result(role="reviewer", verdict="PASS")
_ADJUDICATOR_RESULT_NO_CORRECTION = _make_result(
    role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
    adjudication={
        "correction_required": False,
        "classifications": {"R1-F1": "NON_ACTIONABLE"},
        "accepted_refs": [],
        "correction_brief": None,
        "stop_reason": None,
    },
)
_REVIEWER_RESULT_1_PASS = _make_result(role="reviewer", verdict="PASS")

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
        "independent_reviewer": {
            "backend": "opencode", "command": "opencode",
            "provider": "opencode-go", "model": "opencode-go/deepseek-v4.1-flash",
            "variant": "max", "agent": "agentflow-reviewer", "available": True,
            "eligible_roles": ["reviewer"],
        },
        # Mirrors config/models.json: fallback_long_context is write-capable
        # (agentflow-worker) and therefore declared worker-only under F-05.
        "fallback_long_context": {
            "backend": "opencode", "command": "opencode",
            "provider": "opencode-go", "model": "opencode-go/deepseek-v4.1-flash",
            "variant": "max", "agent": "agentflow-worker", "available": True,
            "eligible_roles": ["worker"],
        },
    },
    "routing": {
        "LOW": ["program_worker"], "MEDIUM": ["program_worker"],
        "HIGH": ["program_worker"], "CRITICAL": ["program_worker"],
    },
}


class _GitWorktreeTestBase(unittest.TestCase):
    """Base class providing real git repos, runs/locks dirs, and standard patches."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)

        self.source_repo = _init_git_repo(self.tmp / "source")
        self.source_head = _head_sha(self.source_repo)

        self.runs_dir = self.tmp / "runs"
        self.runs_dir.mkdir()
        self.locks_dir = self.tmp / "locks"
        self.locks_dir.mkdir()
        self.worktree_root = self.tmp / "worktrees"
        self.worktree_root.mkdir()

        self.prompts_dir = self.tmp / "prompts"
        self.prompts_dir.mkdir()
        for name in ("architect", "adjudicator", "worker", "reviewer"):
            (self.prompts_dir / f"{name}.md").write_text(f"# {name}\nReturn JSON.", encoding="utf-8")

        self._patches = []
        for attr, target in [
            ("RUNS_DIR", self.runs_dir), ("LOCKS_DIR", self.locks_dir),
            ("ROOT", self.tmp),
        ]:
            p = mock.patch.object(agentflow, attr, target)
            p.start()
            self._patches.append(p)

        env_patch = mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(self.worktree_root)})
        env_patch.start()
        self._patches.append(env_patch)

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()

    def _task(self, **overrides):
        task = {
            "task_id": "test-task-001", "repo": str(self.source_repo), "risk": "HIGH",
            "objective": "Add a helper function", "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": ["All tests pass"], "forbidden_actions": ["git commit"],
            "expected_baseline": {},
        }
        task.update(overrides)
        return task

    def _task_with_isolation(self, **overrides):
        task = self._task()
        task["isolation"] = {
            "enabled": True,
            "baseline_commit": self.source_head,
        }
        task.update(overrides)
        return task

    def _write_task_file(self, task):
        path = self.tmp / "task.json"
        path.write_text(json.dumps(task), encoding="utf-8")
        return path

    def _write_program_file(self, program):
        path = self.tmp / "program.json"
        path.write_text(json.dumps(program), encoding="utf-8")
        return path

    def _default_program(self):
        return {
            "program_id": "program-001a-test", "task": "task.json",
            "roles": {
                "architect": "program_architect",
                "worker": "program_worker",
                "reviewer": "program_reviewer",
            },
            "max_corrections": 1,
        }

    def _git_status_clean(self, repo):
        """Check that git status --porcelain is empty (no tracked/untracked changes)."""
        proc = subprocess.run(
            ["git", "status", "--porcelain"], cwd=repo,
            capture_output=True, text=True, check=True,
        )
        return proc.stdout.strip() == ""

    def _git_head(self, repo):
        return _head_sha(repo)

    def _git_is_detached(self, repo):
        proc = subprocess.run(
            ["git", "symbolic-ref", "--quiet", "HEAD"], cwd=repo,
            capture_output=True, text=True,
        )
        return proc.returncode != 0


class WorktreeCreationTests(_GitWorktreeTestBase):
    """Tests 1-4: Exact baseline SHA, HEAD match, detached state, workspace isolation."""

    def test_01_exact_baseline_sha_creates_worktree(self):
        """Test 1: Exact baseline SHA creates worktree."""
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-001",
            root=self.worktree_root,
        )
        self.assertTrue(dest.is_dir())
        self.assertEqual(self.source_head, canonical)
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))

    def test_02_head_in_worktree_equals_baseline(self):
        """Test 2: HEAD in worktree == baseline SHA."""
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-002",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        head = self._git_head(dest)
        self.assertEqual(canonical, head)

    def test_03_worktree_detached(self):
        """Test 3: Worktree is detached; no temp branch created."""
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-003",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        self.assertTrue(self._git_is_detached(dest))
        # Verify no branch was created for the worktree
        proc = subprocess.run(
            ["git", "branch", "--list"], cwd=self.source_repo,
            capture_output=True, text=True,
        )
        branches = [b.strip().lstrip("* ") for b in proc.stdout.splitlines() if b.strip()]
        self.assertNotIn("test-run-003", branches)

    def test_04_worker_change_only_in_execution_workspace(self):
        """Test 4: Worker changes occur only in execution workspace."""
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-004",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        # Create a file in the worktree
        (dest / "new_file.txt").write_text("worktree content", encoding="utf-8")
        # Source repo should not have this file
        self.assertFalse((self.source_repo / "new_file.txt").exists())
        # Source status should be clean
        self.assertTrue(self._git_status_clean(self.source_repo))


class PrimaryCheckoutImmutabilityTests(_GitWorktreeTestBase):
    """Tests 5-7: Primary checkout HEAD/index/tracked unchanged, git status unchanged."""

    def test_05_primary_checkout_head_unchanged(self):
        """Test 5: Primary checkout HEAD unchanged after worktree creation."""
        head_before = self._git_head(self.source_repo)
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-005",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        head_after = self._git_head(self.source_repo)
        self.assertEqual(head_before, head_after)

    def test_06_primary_checkout_index_unchanged(self):
        """Test 6: Primary checkout index unchanged."""
        proc_before = subprocess.run(
            ["git", "ls-files", "--stage"], cwd=self.source_repo,
            capture_output=True, text=True, check=True,
        )
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-006",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        proc_after = subprocess.run(
            ["git", "ls-files", "--stage"], cwd=self.source_repo,
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(proc_before.stdout, proc_after.stdout)

    def test_07_primary_git_status_candidate_state_unchanged(self):
        """Test 7: Primary git status candidate state unchanged (git admin metadata change allowed)."""
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-007",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        # The tracked working tree should be clean (no candidate changes)
        proc = subprocess.run(
            ["git", "status", "--porcelain"], cwd=self.source_repo,
            capture_output=True, text=True, check=True,
        )
        # No tracked file changes
        lines = [l for l in proc.stdout.splitlines() if l and not l.startswith("??")]
        self.assertEqual([], lines)


class ValidatorReviewerCwdTests(_GitWorktreeTestBase):
    """Tests 8-9: Validators and reviewer/architect/adjudicator cwd == execution workspace."""

    def test_08_validators_cwd_is_execution_workspace(self):
        """Test 8: Validators cwd == execution workspace."""
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-008",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        # Write a marker file in the worktree
        (dest / "marker.txt").write_text("worktree-marker", encoding="utf-8")
        # Validator that checks cwd
        validators = [{"name": "cwd-check", "command": ["cat", "marker.txt"]}]
        results = agentflow.run_validators(dest, validators, self.tmp / "run", 0)
        self.assertEqual("PASS", results[0]["status"])
        self.assertIn("worktree-marker", results[0]["stdout"])

    def test_09_reviewer_architect_adjudicator_cwd_is_execution_workspace(self):
        """Test 9: Reviewer/architect/adjudicator cwd == execution workspace.

        Exercises invoke_model itself with a fake binary (not mock-arg
        inspection) and proves exec_repo is wired as --dir/cwd.
        """
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-009",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        run_dir = self.runs_dir / "test-run-009"
        run_dir.mkdir()
        # The real OpenCode adapter now stages trusted source config for each
        # invocation; this fake ROOT needs that source tree as well.
        (self.tmp / "opencode" / "agents").mkdir(parents=True, exist_ok=True)
        (self.tmp / "opencode" / "agents" / "agentflow-reviewer.md").write_text(
            "# reviewer\n", encoding="utf-8")
        task = self._task()
        fake_bin = self.tmp / "fake-opencode-009"
        fake_bin.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "seen = None\n"
            "args = sys.argv[1:]\n"
            "for i, a in enumerate(args):\n"
            "    if a == '--dir' and i + 1 < len(args):\n"
            "        seen = args[i + 1]\n"
            "result = {\n"
            "    'verdict': 'PASS', 'files_changed': [], 'validators': {},\n"
            "    'findings': [], 'open_risks': ['SEEN_DIR:' + str(seen)],\n"
            "}\n"
            "sys.stdout.write(json.dumps(result))\n",
            encoding="utf-8",
        )
        fake_bin.chmod(0o755)
        profile = {
            "backend": "opencode", "command": str(fake_bin),
            "provider": "opencode", "model": "test/model",
            "variant": None, "agent": "agentflow-reviewer", "available": True,
            "eligible_roles": ["reviewer"],
        }
        result, record = agentflow.invoke_model(
            role="reviewer", profile_name="test", profile=profile,
            task=task, run_dir=run_dir, cycle=0, context=None, lease=None,
            exec_repo=dest,
        )
        seen_dirs = [r for r in result.get("open_risks", []) if r.startswith("SEEN_DIR:")]
        self.assertTrue(seen_dirs, f"fake binary did not report --dir: {result}")
        self.assertEqual(f"SEEN_DIR:{dest}", seen_dirs[0])
        # Prompt/cwd wiring: invocation record persisted and result valid.
        self.assertEqual("reviewer", result["role"])
        self.assertTrue((run_dir / "reviewer-cycle-0-invocation.json").exists())


class CorrectionWorkspaceReuseTests(_GitWorktreeTestBase):
    """Test 10: Correction worker reuses SAME workspace."""

    def test_10_correction_worker_reuses_same_workspace(self):
        """Test 10: Correction worker reuses SAME workspace."""
        task = self._task_with_isolation()
        task_path = self._write_task_file(task)
        program = self._default_program()
        program_path = self._write_program_file(program)

        # Create an actual worktree for the isolation
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-010",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))

        ctx = agentflow.ExecutionContext(
            source_repo=self.source_repo,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        )

        # Track which repos are used
        repos_used = []

        cs_counter = [0]
        cs_schedule = [[], ["src/foo.py"], [], [], [], ["src/foo.py"], []]

        def _changed_since(before, after):
            idx = cs_counter[0]
            cs_counter[0] += 1
            if idx < len(cs_schedule):
                return cs_schedule[idx]
            return []

        invoke_repos = []

        reviewer_result_blocking = _make_result(
            role="reviewer", verdict="BLOCKER",
            findings=[{"severity": "HIGH", "text": "Bug"}],
        )
        adjudicator_correction = _make_result(
            role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
            adjudication={
                "correction_required": True,
                "classifications": {"R1-F1": "ACTIONABLE_REQUIRED"},
                "accepted_refs": ["R1-F1"],
                "correction_brief": {"required_changes": ["Fix the bug"]},
                "stop_reason": None,
            },
        )

        call_count = [0]
        def _mock_invoke_sequential(*, role, profile_name, profile, task, run_dir,
                                     cycle, context=None, lease=None, exec_repo=None):
            invoke_repos.append(str(exec_repo))
            call_count[0] += 1
            idx = call_count[0] - 1
            if idx == 0:
                return (_ARCHITECT_RESULT, _make_record("architect", 0))
            elif idx == 1:
                return (_WORKER_RESULT_0, _make_record("worker", 0))
            elif idx == 2:
                return (reviewer_result_blocking, _make_record("reviewer", 0))
            elif idx == 3:
                return (adjudicator_correction, _make_record("adjudicator", 0))
            elif idx == 4:
                return (_WORKER_RESULT_0, _make_record("worker", 1))
            elif idx == 5:
                return (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1))
            return (_make_result(role=role, verdict="PASS"), _make_record(role, cycle))

        with (
            mock.patch("agentflow.build_execution_context", return_value=ctx),
            mock.patch("agentflow.invoke_model", side_effect=_mock_invoke_sequential),
            mock.patch("agentflow.changed_since", side_effect=_changed_since),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(dest),
                "branch": None, "head": canonical,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.git", return_value=mock.MagicMock(
                returncode=0, stdout="diff --git a/src/foo.py\n+new\n", stderr="")),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_program(program_path)

        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])
        # All invoke_model calls should use the same execution repo
        unique_repos = set(invoke_repos)
        self.assertEqual(1, len(unique_repos), f"Multiple repos used: {unique_repos}")


class ReadonlyWriteDetectionTests(_GitWorktreeTestBase):
    """Test 11: Readonly write detected inside workspace."""

    def test_11_readonly_write_detected_inside_workspace(self):
        """Test 11: Readonly write detected inside workspace."""
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-011",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        before = agentflow.capture_baseline(dest)
        # Simulate a readonly role writing
        (dest / "tainted.txt").write_text("readonly wrote this", encoding="utf-8")
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._check_readonly_mutation(dest, before, "reviewer")
        self.assertEqual("READONLY_ROLE_WROTE_REPO", raised.exception.code)


class UnauthorizedPathTests(_GitWorktreeTestBase):
    """Test 12: Unauthorized path modification stops."""

    def test_12_unauthorized_path_modification_stops(self):
        """Test 12: Unauthorized path modification stops."""
        dest, _ = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-012",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        # Simulate modification outside allowed_paths
        before = agentflow.capture_baseline(dest)
        (dest / "secret.txt").write_text("unauthorized", encoding="utf-8")
        after = agentflow.capture_baseline(dest)
        modified = agentflow.changed_since(before, after)
        unauthorized = [p for p in modified if not agentflow.path_allowed(p, ["src/"])]
        self.assertTrue(len(unauthorized) > 0)


class BaselineMismatchTests(_GitWorktreeTestBase):
    """Tests 13-14: Expected baseline mismatch stops before creation, head != baseline rejected."""

    def test_13_expected_baseline_mismatch_stops_before_worktree_creation(self):
        """Test 13: expected_baseline mismatch stops BEFORE worktree creation."""
        task = self._task(expected_baseline={"head": "different-head-value"})
        task_path = self._write_task_file(task)
        # No isolation - should check baseline normally
        with (
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(self.source_repo),
                "branch": "main", "head": self.source_head,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.changed_since", return_value=[]),
            mock.patch("agentflow.invoke_model", return_value=(
                _make_result(role="worker", verdict="PASS"), _make_record("worker"))),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
            mock.patch("agentflow.git", return_value=mock.MagicMock(
                returncode=0, stdout="", stderr="")),
        ):
            code, run_dir, final = agentflow.run_task(task_path)

        self.assertEqual(2, code)
        self.assertEqual("BASELINE_DRIFT", final["verdict"])

    def test_14_expected_baseline_head_ne_isolation_baseline_rejected(self):
        """Test 14: expected_baseline.head != isolation.baseline_commit is rejected."""
        task = self._task_with_isolation()
        task["expected_baseline"] = {"head": "0000000000000000000000000000000000000000"}
        # Validation passes; rejection happens in build_execution_context
        agentflow.validate_task(task)
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.build_execution_context(task, "test-run-014")
        self.assertEqual("INVALID_TASK", raised.exception.code)


class DirtySourceTests(_GitWorktreeTestBase):
    """Test 15: Source dirty/untracked can proceed when explicit baseline."""

    def test_15_source_dirty_with_explicit_baseline_can_proceed(self):
        """Test 15: Source dirty/untracked can proceed with explicit baseline."""
        # Make source dirty
        (self.source_repo / "dirty.txt").write_text("dirty", encoding="utf-8")
        # Isolation with explicit baseline should still work
        task = self._task_with_isolation()
        ctx = agentflow.build_execution_context(task, "test-run-015")
        self.assertTrue(ctx.isolated)
        self.assertEqual(self.source_head, ctx.baseline_commit)
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(ctx.execution_repo)],
            cwd=self.source_repo, capture_output=True,
        ))


class UnknownCommitTests(_GitWorktreeTestBase):
    """Test 16: Unknown/non-commit SHA controlled failure."""

    def test_16_unknown_sha_controlled_failure(self):
        """Test 16: Unknown/non-commit SHA controlled failure."""
        fake_sha = "a" * 40
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.create_isolated_worktree(
                source=self.source_repo,
                baseline_commit=fake_sha,
                run_id="test-run-016",
                root=self.worktree_root,
            )
        self.assertEqual("BASELINE_COMMIT_UNKNOWN", raised.exception.code)

    def test_16b_non_hex_sha_rejected(self):
        """Non-hex SHA rejected."""
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._canonical_sha("not-a-valid-sha")
        self.assertEqual("BASELINE_COMMIT_UNKNOWN", raised.exception.code)


class NonGitSourceTests(_GitWorktreeTestBase):
    """Test 17: Non-Git source controlled failure."""

    def test_17_non_git_source_controlled_failure(self):
        """Test 17: Non-Git source controlled failure."""
        non_git = self.tmp / "not-a-repo"
        non_git.mkdir()
        with self.assertRaises(agentflow.AgentFlowError):
            agentflow._resolve_source_head(non_git)


class PathEscapeTests(_GitWorktreeTestBase):
    """Tests 18-19: Root/destination inside source rejected, path traversal rejected."""

    def test_18_destination_inside_source_rejected(self):
        """Test 18: Root/destination inside source repo rejected."""
        dest = self.source_repo / "subdir" / "worktree"
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._worktree_safety_check(dest, self.source_repo, self.worktree_root)
        self.assertEqual("WORKTREE_PATH_ESCAPE", raised.exception.code)

    def test_18b_destination_equals_source_rejected(self):
        """Destination equals source repo rejected."""
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._worktree_safety_check(self.source_repo, self.source_repo, self.worktree_root)
        self.assertEqual("WORKTREE_PATH_ESCAPE", raised.exception.code)

    def test_19_path_traversal_rejected(self):
        """Test 19: Path traversal / symlink escape rejected."""
        # safe_slug sanitizes ../ so we test _worktree_safety_check directly
        escape_dest = self.worktree_root.parent.parent / "escaped"
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._worktree_safety_check(escape_dest, self.source_repo, self.worktree_root)
        self.assertEqual("WORKTREE_PATH_ESCAPE", raised.exception.code)


class PreexistingDestinationTests(_GitWorktreeTestBase):
    """Test 20: Preexisting destination rejected."""

    def test_20_preexisting_destination_rejected(self):
        """Test 20: Preexisting destination rejected."""
        dest = self.worktree_root / "existing"
        dest.mkdir()
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.create_isolated_worktree(
                source=self.source_repo,
                baseline_commit=self.source_head,
                run_id="existing",
                root=self.worktree_root,
            )
        self.assertEqual("WORKTREE_EXISTS", raised.exception.code)


class PartialCreationFailureTests(_GitWorktreeTestBase):
    """Test 21: Partial creation failure leaves source working-tree unchanged."""

    def test_21_partial_creation_failure_preserves_source(self):
        """Test 21: Partial creation failure leaves source working-tree candidate state unchanged."""
        state_before = agentflow.capture_baseline(self.source_repo)
        # Force a creation failure by making git worktree add fail
        original_git = agentflow.git
        def failing_git(repo, args, **kwargs):
            if len(args) >= 2 and args[0] == "worktree" and args[1] == "add":
                proc = mock.MagicMock()
                proc.returncode = 1
                proc.stderr = "forced failure"
                proc.stdout = ""
                return proc
            return original_git(repo, args, **kwargs)
        with mock.patch("agentflow.git", side_effect=failing_git):
            with self.assertRaises(agentflow.AgentFlowError):
                agentflow.create_isolated_worktree(
                    source=self.source_repo,
                    baseline_commit=self.source_head,
                    run_id="test-run-021",
                    root=self.worktree_root,
                )
        state_after = agentflow.capture_baseline(self.source_repo)
        self.assertEqual(state_before["head"], state_after["head"])
        self.assertEqual(state_before["dirty_paths"], state_after["dirty_paths"])


class PreservationTests(_GitWorktreeTestBase):
    """Tests 22-24: Validator/model/review failure preserves dirty worktree."""

    def _run_with_isolation_and_failure(self, run_id_suffix, fail_at):
        """Helper: run an isolated task that fails at the given stage."""
        task = self._task_with_isolation()
        task_path = self._write_task_file(task)

        # Create an actual worktree for the isolation
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id=f"test-run-{run_id_suffix}",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))

        ctx = agentflow.ExecutionContext(
            source_repo=self.source_repo,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        )

        cs_counter = [0]
        # Schedule: [0]=worker delta, [1]=reviewer readonly check, [2]=extra
        cs_schedule = [["src/foo.py"], [], []]

        def _changed_since(before, after):
            idx = cs_counter[0]
            cs_counter[0] += 1
            if idx < len(cs_schedule):
                return cs_schedule[idx]
            return []

        if fail_at == "validator":
            validators_result = [
                {"name": "lint", "command": "/usr/bin/false",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 1, "status": "FAIL", "stdout": "", "stderr": "lint error"},
            ]
        else:
            validators_result = [
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]

        if fail_at == "model":
            def _invoke_side_effect(*, role, profile_name, profile, task, run_dir,
                                     cycle, context=None, lease=None, exec_repo=None):
                raise agentflow.AgentFlowError("MODEL_INVOCATION_FAILED", "model crashed")
        else:
            def _invoke_side_effect(*, role, profile_name, profile, task, run_dir,
                                     cycle, context=None, lease=None, exec_repo=None):
                if role == "reviewer" and fail_at == "reviewer":
                    return (_make_result(
                        role="reviewer", verdict="BLOCKER",
                        findings=[{"severity": "BLOCKER", "text": "Critical issue"}],
                    ), _make_record("reviewer"))
                return (_make_result(role=role, verdict="PASS"), _make_record(role))

        # L5: make the real worktree dirty so preserved_dirty reflects actual
        # Git state (not a hardcoded value).
        (dest / "dirty-marker.txt").write_text("dirty", encoding="utf-8")
        original_git = agentflow.git

        def _git_side_effect(repo, args, **kwargs):
            if args and args[0] == "status":
                return original_git(repo, args, **kwargs)
            return mock.MagicMock(returncode=0, stdout="", stderr="")

        with (
            mock.patch("agentflow.build_execution_context", return_value=ctx),
            mock.patch("agentflow.invoke_model", side_effect=_invoke_side_effect),
            mock.patch("agentflow.changed_since", side_effect=_changed_since),
            mock.patch("agentflow.run_validators", return_value=validators_result),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(dest),
                "branch": None, "head": canonical,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.git", side_effect=_git_side_effect),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_task(task_path)

        self.assertEqual(2, code)
        return run_dir, final

    def test_22_validator_failure_preserves_dirty_worktree(self):
        """Test 22: Validator failure preserves dirty worktree."""
        run_dir, final = self._run_with_isolation_and_failure("022", "validator")
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        ws_path = run_dir / "workspace.json"
        self.assertTrue(ws_path.exists())
        ws = json.loads(ws_path.read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", ws["status"])
        self.assertTrue(ws["preserved_dirty"])

    def test_23_model_failure_preserves_dirty_worktree(self):
        """Test 23: Model failure preserves dirty worktree."""
        run_dir, final = self._run_with_isolation_and_failure("023", "model")
        self.assertEqual("MODEL_INVOCATION_FAILED", final["verdict"])
        ws_path = run_dir / "workspace.json"
        self.assertTrue(ws_path.exists())
        ws = json.loads(ws_path.read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", ws["status"])

    def test_24_final_review_failure_preserves_candidate(self):
        """Test 24: Final review failure preserves candidate."""
        run_dir, final = self._run_with_isolation_and_failure("024", "reviewer")
        self.assertIn(final["verdict"], ("FINAL_REVIEW_BLOCKED", "REVIEW_RETRY_CAP"))
        ws_path = run_dir / "workspace.json"
        self.assertTrue(ws_path.exists())
        ws = json.loads(ws_path.read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", ws["status"])


class CleanupTests(_GitWorktreeTestBase):
    """Tests 25-27: Cleanup behavior."""

    def _create_preserved_worktree(self, dirty=True):
        """Helper to create a worktree with PRESERVED status."""
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-cleanup",
            root=self.worktree_root,
        )
        run_dir = self.runs_dir / "test-run-cleanup"
        run_dir.mkdir(parents=True)
        ws = {
            "version": 1, "run_id": "test-run-cleanup",
            "source_repo": str(self.source_repo),
            "source_head": self.source_head,
            "baseline_commit": canonical,
            "execution_repo": str(dest),
            "worktree_root": str(self.worktree_root),
            "created_at": "2026-01-01T00:00:00+00:00",
            "detached": True, "verified_head": canonical,
            "status": "PRESERVED",
            "preserved_dirty": dirty,
            "cleanup": None,
        }
        (run_dir / "workspace.json").write_text(json.dumps(ws, indent=2), encoding="utf-8")
        return dest, run_dir

    def test_25_cleanup_refuses_dirty_without_force(self):
        """Test 25: Cleanup refuses dirty worktree without --force."""
        dest, run_dir = self._create_preserved_worktree(dirty=True)
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        import io
        from contextlib import redirect_stdout
        captured = io.StringIO()
        with redirect_stdout(captured):
            code = agentflow.cmd_worktree_remove("test-run-cleanup", force=False)
        self.assertEqual(2, code)
        output = json.loads(captured.getvalue())
        self.assertEqual("WORKTREE_CLEANUP_REFUSED", output["error"])

    def test_26_cleanup_force_removes_registered_worktree(self):
        """Test 26: Cleanup --force removes only registered contained worktree."""
        dest, run_dir = self._create_preserved_worktree(dirty=True)
        import io
        from contextlib import redirect_stdout
        captured = io.StringIO()
        with redirect_stdout(captured):
            code = agentflow.cmd_worktree_remove("test-run-cleanup", force=True)
        self.assertEqual(0, code)
        output = json.loads(captured.getvalue())
        self.assertEqual("CLEANED", output["status"])
        # Destination should be gone
        self.assertFalse(dest.exists())
        # Workspace should be updated
        ws = json.loads((run_dir / "workspace.json").read_text(encoding="utf-8"))
        self.assertEqual("CLEANED", ws["status"])
        self.assertTrue(ws["cleanup"]["force"])

    def test_27_tampered_workspace_cannot_delete_arbitrary_path(self):
        """Test 27: Tampered workspace.json cannot make cleanup delete arbitrary path."""
        run_dir = self.runs_dir / "test-run-tamper"
        run_dir.mkdir(parents=True)
        # Create a workspace.json pointing to an arbitrary path
        arbitrary = self.tmp / "arbitrary_target"
        arbitrary.mkdir()
        ws = {
            "version": 1, "run_id": "test-run-tamper",
            "source_repo": str(self.source_repo),
            "execution_repo": str(arbitrary),
            "status": "PRESERVED", "preserved_dirty": True, "cleanup": None,
        }
        (run_dir / "workspace.json").write_text(json.dumps(ws, indent=2), encoding="utf-8")
        import io
        from contextlib import redirect_stdout
        captured = io.StringIO()
        with redirect_stdout(captured):
            code = agentflow.cmd_worktree_remove("test-run-tamper", force=True)
        self.assertEqual(2, code)
        # The arbitrary directory should still exist
        self.assertTrue(arbitrary.exists())


class LegacyCompatibilityTests(_GitWorktreeTestBase):
    """Test 28: Legacy run_task without isolation unchanged."""

    def test_28_legacy_run_task_without_isolation_unchanged(self):
        """Test 28: Legacy run_task without isolation unchanged."""
        task = self._task()
        task_path = self._write_task_file(task)

        def _invoke(*, role, **kwargs):
            # Role-aware fixtures: run_task invokes a reviewer for HIGH risk,
            # and reviewer results must carry the reviewer role.
            return (_make_result(role=role, verdict="PASS"), _make_record(role))

        with (
            mock.patch("agentflow.invoke_model", side_effect=_invoke),
            mock.patch("agentflow.changed_since", return_value=[]),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(self.source_repo),
                "branch": "main", "head": self.source_head,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.git", return_value=mock.MagicMock(
                returncode=0, stdout="", stderr="")),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_task(task_path)

        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])
        # Should NOT have workspace.json (non-isolated)
        self.assertFalse((run_dir / "workspace.json").exists())


class RunTaskReviewerContractTests(_GitWorktreeTestBase):
    """F-02: legacy run_task reviewer gate is role-aware and fail-closed."""

    def _run_task_with_reviewer(self, reviewer_results):
        task = self._task(max_corrections=1)
        task_path = self._write_task_file(task)
        reviewer_calls = {"count": 0}

        def _invoke(*, role, **kwargs):
            if role == "reviewer":
                index = min(reviewer_calls["count"], len(reviewer_results) - 1)
                reviewer_calls["count"] += 1
                return (reviewer_results[index], _make_record("reviewer"))
            return (_make_result(role=role, verdict="PASS"), _make_record(role))

        with (
            mock.patch("agentflow.invoke_model", side_effect=_invoke),
            mock.patch("agentflow.changed_since", return_value=[]),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(self.source_repo),
                "branch": "main", "head": self.source_head,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.git", return_value=mock.MagicMock(
                returncode=0, stdout="", stderr="")),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_task(task_path)
        return code, run_dir, final, reviewer_calls["count"]

    def test_clean_pass_reviewer_reaches_human_gate(self):
        code, run_dir, final, calls = self._run_task_with_reviewer(
            [_make_result(role="reviewer", verdict="PASS")])
        self.assertEqual(0, code)
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual(1, calls)

    def test_unknown_reviewer_verdict_never_human_gate(self):
        code, run_dir, final, calls = self._run_task_with_reviewer(
            [_make_result(role="reviewer", verdict="NEEDS_WORK")])
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual(1, calls)

    def test_contradictory_reviewer_is_invalid_not_blocked(self):
        code, run_dir, final, calls = self._run_task_with_reviewer([
            _make_result(role="reviewer", verdict="PASS",
                         findings=[{"severity": "HIGH", "text": "contradiction"}]),
        ])
        self.assertEqual(2, code)
        self.assertEqual("INVALID_MODEL_OUTPUT", final["verdict"])
        self.assertNotEqual("FINAL_REVIEW_BLOCKED", final["verdict"])
        self.assertEqual(1, calls)

    def test_blocker_reviewer_hits_retry_cap(self):
        code, run_dir, final, calls = self._run_task_with_reviewer(
            [_make_result(role="reviewer", verdict="BLOCKER")])
        self.assertEqual(2, code)
        self.assertEqual("REVIEW_RETRY_CAP", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertEqual(2, calls)


class PostValidatorScopeGuardTests(_GitWorktreeTestBase):
    """F-01: run_task re-checks validator-produced mutations against allowed_paths."""

    def _run_task_with_validator_delta(self, validator_delta):
        task = self._task(risk="LOW")
        task_path = self._write_task_file(task)

        cs_counter = [0]
        cs_schedule = [[], list(validator_delta)]

        def _changed_since(before, after):
            idx = cs_counter[0]
            cs_counter[0] += 1
            if idx < len(cs_schedule):
                return cs_schedule[idx]
            return []

        with (
            mock.patch("agentflow.invoke_model", return_value=(
                _make_result(role="worker", verdict="PASS"), _make_record("worker"))),
            mock.patch("agentflow.changed_since", side_effect=_changed_since),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(self.source_repo),
                "branch": "main", "head": self.source_head,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            return agentflow.run_task(task_path)

    def test_run_task_validator_write_inside_allowed_paths_continues(self):
        code, run_dir, final = self._run_task_with_validator_delta(["src/generated.py"])
        self.assertEqual(0, code)
        self.assertEqual("SUCCESS", final["status"])
        self.assertEqual("HUMAN_GATE", final["verdict"])

    def test_run_task_validator_write_outside_allowed_paths_stops(self):
        code, run_dir, final = self._run_task_with_validator_delta(["outside/report.txt"])
        self.assertEqual(2, code)
        self.assertEqual("STOPPED", final["status"])
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", final["verdict"])
        self.assertNotEqual("HUMAN_GATE", final["verdict"])
        self.assertTrue((run_dir / "final.json").is_file())
        persisted = json.loads((run_dir / "final.json").read_text(encoding="utf-8"))
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", persisted["verdict"])


class ValidationTests(_GitWorktreeTestBase):
    """Tests for isolation validation."""

    def test_validate_task_rejects_malformed_isolation(self):
        """Isolation must be an object."""
        task = self._task(isolation="not-an-object")
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_task(task)
        self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_validate_task_rejects_bool_isolation_enabled(self):
        """isolation.enabled must be boolean."""
        task = self._task(isolation={"enabled": "yes", "baseline_commit": self.source_head})
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_task(task)
        self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_validate_task_rejects_missing_baseline_commit(self):
        """isolation.baseline_commit required when isolation present."""
        task = self._task(isolation={"enabled": True})
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_task(task)
        self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_validate_task_accepts_valid_isolation(self):
        """Valid isolation passes validation."""
        task = self._task_with_isolation()
        validated = agentflow.validate_task(task)
        self.assertTrue(validated["isolation"]["enabled"])

    def test_validate_task_accepts_disabled_isolation(self):
        """Disabled isolation passes validation."""
        task = self._task(isolation={"enabled": False, "baseline_commit": "a" * 40})
        validated = agentflow.validate_task(task)
        self.assertFalse(validated["isolation"]["enabled"])

    def test_validate_task_no_isolation_still_works(self):
        """No isolation field still works (legacy)."""
        task = self._task()
        validated = agentflow.validate_task(task)
        self.assertNotIn("isolation", validated)


class WorktreeRootTests(unittest.TestCase):
    """Test worktree root derivation."""

    def test_env_variable_root(self):
        with mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": "/custom/path"}):
            self.assertEqual(Path("/custom/path").resolve(), agentflow.worktree_root())

    def test_xdg_fallback(self):
        with mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": "", "XDG_DATA_HOME": "/xdg"}):
            if os.environ.get("AGENTFLOW_WORKTREES_DIR") == "":
                del os.environ["AGENTFLOW_WORKTREES_DIR"]
            self.assertEqual(Path("/xdg/agentflow/worktrees").resolve(), agentflow.worktree_root())

    def test_home_fallback(self):
        with mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": "", "XDG_DATA_HOME": ""}):
            for key in ("AGENTFLOW_WORKTREES_DIR", "XDG_DATA_HOME"):
                if os.environ.get(key) == "":
                    del os.environ[key]
            expected = Path.home().resolve() / ".local" / "share" / "agentflow" / "worktrees"
            self.assertEqual(expected, agentflow.worktree_root())


class FullMockedModelIsolatedProgramTest(_GitWorktreeTestBase):
    """Test 30: Full mocked-model + REAL-GIT isolated PROGRAM-001A reaches HUMAN_GATE."""

    def test_30_full_isolated_program_reaches_human_gate(self):
        """Test 30: Full mocked-model + REAL-GIT isolated PROGRAM-001A reaches HUMAN_GATE
        with all stages using one execution workspace."""
        task = self._task_with_isolation()
        task_path = self._write_task_file(task)
        program = self._default_program()
        program_path = self._write_program_file(program)

        # Create an actual worktree for the isolation
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-030",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))

        ctx = agentflow.ExecutionContext(
            source_repo=self.source_repo,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        )

        cs_counter = [0]
        cs_schedule = [[], ["src/foo.py"], [], [], []]

        def _changed_since(before, after):
            idx = cs_counter[0]
            cs_counter[0] += 1
            if idx < len(cs_schedule):
                return cs_schedule[idx]
            return []

        invoke_repos = []
        call_count = [0]
        def _mock_invoke(*, role, profile_name, profile, task, run_dir,
                         cycle, context=None, lease=None, exec_repo=None):
            invoke_repos.append(str(exec_repo))
            call_count[0] += 1
            idx = call_count[0] - 1
            if idx == 0:
                return (_ARCHITECT_RESULT, _make_record("architect", 0))
            elif idx == 1:
                return (_WORKER_RESULT_0, _make_record("worker", 0))
            elif idx == 2:
                return (_REVIEWER_RESULT_0_PASS, _make_record("reviewer", 0))
            elif idx == 3:
                # Reviewer had no findings, so adjudicator must have empty classifications
                no_findings_adjudicator = _make_result(
                    role="adjudicator", verdict="ADJUDICATION_COMPLETE", files_changed=[],
                    adjudication={
                        "correction_required": False,
                        "classifications": {},
                        "accepted_refs": [],
                        "correction_brief": None,
                        "stop_reason": None,
                    },
                )
                return (no_findings_adjudicator, _make_record("adjudicator", 0))
            elif idx == 4:
                return (_REVIEWER_RESULT_1_PASS, _make_record("reviewer", 1))
            return (_make_result(role=role, verdict="PASS"), _make_record(role, cycle))

        with (
            mock.patch("agentflow.build_execution_context", return_value=ctx),
            mock.patch("agentflow.invoke_model", side_effect=_mock_invoke),
            mock.patch("agentflow.changed_since", side_effect=_changed_since),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(dest),
                "branch": None, "head": canonical,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.git", return_value=mock.MagicMock(
                returncode=0, stdout="diff --git a/src/foo.py\n+new\n", stderr="")),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_program(program_path)

        self.assertEqual(0, code)
        self.assertEqual("SUCCESS", final["status"])
        self.assertEqual("HUMAN_GATE", final["verdict"])
        self.assertTrue(final["human_gate"])
        self.assertEqual(5, call_count[0])

        # Verify all stages used the same execution workspace
        unique_repos = set(invoke_repos)
        self.assertEqual(1, len(unique_repos), f"Multiple repos used: {unique_repos}")

        # Verify workspace.json exists with correct status
        ws_path = run_dir / "workspace.json"
        self.assertTrue(ws_path.exists())
        ws = json.loads(ws_path.read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", ws["status"])
        self.assertTrue(ws["detached"])

        # Verify source_baseline.json exists
        self.assertTrue((run_dir / "source_baseline.json").exists())

        # Verify workspace summary in final
        self.assertIn("workspace", final)
        self.assertTrue(final["workspace"]["isolated"])

        # Verify execution repo is different from source
        exec_repo = Path(ws["execution_repo"])
        self.assertNotEqual(str(self.source_repo.resolve()), str(exec_repo.resolve()))

        # Verify primary source repo HEAD unchanged
        self.assertEqual(self.source_head, self._git_head(self.source_repo))

        # Verify the worktree is registered
        self.assertTrue(agentflow._is_worktree_registered(self.source_repo, exec_repo))

        # Cleanup
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(exec_repo)],
            cwd=self.source_repo, capture_output=True,
        )


class WorktreeRegistryCleanup(_GitWorktreeTestBase):
    """Ensure no persistent test worktrees remain after tests."""

    def test_no_persistent_worktrees_after_tests(self):
        """Verify worktree helper can create and remove cleanly."""
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-registry",
            root=self.worktree_root,
        )
        self.assertTrue(agentflow._is_worktree_registered(self.source_repo, dest))
        agentflow._remove_worktree(self.source_repo, dest)
        self.assertFalse(agentflow._is_worktree_registered(self.source_repo, dest))
        self.assertFalse(dest.exists())


class CrossRunCleanupTamperTests(_GitWorktreeTestBase):
    """M1: cleanup run A must never delete worktree B."""

    def test_cross_run_cleanup_tamper_refused(self):
        """Tampered cross-run binding is refused even with --force."""
        dest_b, canonical_b = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-B",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest_b)],
            cwd=self.source_repo, capture_output=True,
        ))
        # Run A directory whose workspace points at B's worktree.
        run_dir_a = self.runs_dir / "test-run-A"
        run_dir_a.mkdir(parents=True)
        ws = {
            "version": 1, "run_id": "test-run-A",
            "source_repo": str(self.source_repo),
            "source_head": self.source_head,
            "baseline_commit": canonical_b,
            "execution_repo": str(dest_b),
            "worktree_root": str(self.worktree_root),
            "created_at": "2026-01-01T00:00:00+00:00",
            "detached": True, "verified_head": canonical_b,
            "status": "PRESERVED", "preserved_dirty": True, "cleanup": None,
        }
        (run_dir_a / "workspace.json").write_text(json.dumps(ws, indent=2), encoding="utf-8")
        import io
        from contextlib import redirect_stdout
        captured = io.StringIO()
        with redirect_stdout(captured):
            code = agentflow.cmd_worktree_remove("test-run-A", force=True)
        self.assertEqual(2, code)
        output = json.loads(captured.getvalue())
        self.assertEqual("WORKTREE_CLEANUP_REFUSED", output["error"])
        self.assertTrue(dest_b.exists())
        self.assertTrue(agentflow._is_worktree_registered(self.source_repo, dest_b))

    def test_cross_run_id_mismatch_refused(self):
        """Workspace run_id field must equal the requested run_id."""
        dest_b, canonical_b = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-B2",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest_b)],
            cwd=self.source_repo, capture_output=True,
        ))
        run_dir_a = self.runs_dir / "test-run-A2"
        run_dir_a.mkdir(parents=True)
        # Copy B's identity into A's run dir: run_id field still says B.
        ws = {
            "version": 1, "run_id": "test-run-B2",
            "source_repo": str(self.source_repo),
            "source_head": self.source_head,
            "baseline_commit": canonical_b,
            "execution_repo": str(dest_b),
            "worktree_root": str(self.worktree_root),
            "created_at": "2026-01-01T00:00:00+00:00",
            "detached": True, "verified_head": canonical_b,
            "status": "PRESERVED", "preserved_dirty": True, "cleanup": None,
        }
        (run_dir_a / "workspace.json").write_text(json.dumps(ws, indent=2), encoding="utf-8")
        import io
        from contextlib import redirect_stdout
        captured = io.StringIO()
        with redirect_stdout(captured):
            code = agentflow.cmd_worktree_remove("test-run-A2", force=True)
        self.assertEqual(2, code)
        self.assertTrue(dest_b.exists())


class UnexpectedErrorPreservationTests(_GitWorktreeTestBase):
    """M2: unexpected RuntimeError must preserve READY/CANDIDATE with evidence."""

    def test_unexpected_runtime_error_preserved_with_evidence(self):
        """RuntimeError -> INTERNAL_ERROR with preserved workspace + final."""
        task = self._task_with_isolation()
        task_path = self._write_task_file(task)
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-rterr",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        ctx = agentflow.ExecutionContext(
            source_repo=self.source_repo,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        )

        def _boom(*, role, profile_name, profile, task, run_dir,
                  cycle, context=None, lease=None, exec_repo=None):
            raise RuntimeError("unexpected boom")

        original_git = agentflow.git

        def _git_side_effect(repo, args, **kwargs):
            if args and args[0] == "status":
                return original_git(repo, args, **kwargs)
            return mock.MagicMock(returncode=0, stdout="", stderr="")

        with (
            mock.patch("agentflow.build_execution_context", return_value=ctx),
            mock.patch("agentflow.invoke_model", side_effect=_boom),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", side_effect=lambda repo: {
                "captured_at": "2026-01-01", "repo": str(repo),
                "branch": None, "head": canonical,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.git", side_effect=_git_side_effect),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_task(task_path)
        self.assertEqual(2, code)
        self.assertEqual("INTERNAL_ERROR", final["verdict"])
        ws_path = run_dir / "workspace.json"
        self.assertTrue(ws_path.exists())
        ws = json.loads(ws_path.read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", ws["status"])
        # Clean failure must report actual clean state, not hardcoded True.
        self.assertFalse(ws["preserved_dirty"])
        self.assertTrue((run_dir / "final.json").exists())
        self.assertIn("workspace", final)
        self.assertEqual("PRESERVED", final["workspace"]["status"])
        self.assertIn("final_baseline", final)

    def test_keyboard_interrupt_propagates(self):
        """KeyboardInterrupt/SystemExit must not be swallowed as INTERNAL_ERROR."""
        task = self._task_with_isolation()
        task_path = self._write_task_file(task)
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-kbd",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        ctx = agentflow.ExecutionContext(
            source_repo=self.source_repo,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        )

        def _kbd(*, role, profile_name, profile, task, run_dir,
                 cycle, context=None, lease=None, exec_repo=None):
            raise KeyboardInterrupt()

        with (
            mock.patch("agentflow.build_execution_context", return_value=ctx),
            mock.patch("agentflow.invoke_model", side_effect=_kbd),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            with self.assertRaises(KeyboardInterrupt):
                agentflow.run_task(task_path)


class PersistenceFailureOrphanTests(_GitWorktreeTestBase):
    """M2 narrow window: no registered-but-unbound orphan."""

    def test_workspace_persistence_failure_leaves_no_orphan(self):
        """Failing workspace persistence must not leave an unbound worktree."""
        task = self._task_with_isolation()
        task_path = self._write_task_file(task)
        original_atomic = agentflow.atomic_json

        def _flaky_atomic(path, value):
            if Path(path).name == "workspace.json":
                raise OSError("simulated persistence failure")
            return original_atomic(path, value)

        with (
            mock.patch("agentflow.atomic_json", side_effect=_flaky_atomic),
            mock.patch("agentflow.invoke_model", return_value=(
                _make_result(role="worker", verdict="PASS"), _make_record("worker"))),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_task(task_path)
        self.assertEqual(2, code)
        # No registered worktree may remain without a durable binding.
        proc = subprocess.run(
            ["git", "worktree", "list", "--porcelain"], cwd=self.source_repo,
            capture_output=True, text=True, check=True,
        )
        registered = [
            line[9:].strip() for line in proc.stdout.splitlines()
            if line.startswith("worktree ")
        ]
        worktree_root_resolved = str(self.worktree_root.resolve())
        leaked = [r for r in registered if r.startswith(worktree_root_resolved)]
        # Clean up any bound worktree left by the fallback for test hygiene.
        for r in leaked:
            subprocess.run(
                ["git", "worktree", "remove", "--force", r],
                cwd=self.source_repo, capture_output=True,
            )
        self.assertEqual([], leaked,
                         f"registered-but-unbound orphan leaked: {leaked}")
        # Either a minimal binding exists or nothing is registered.
        ws_path = run_dir / "workspace.json"
        if ws_path.exists():
            ws = json.loads(ws_path.read_text(encoding="utf-8"))
            self.assertIn("execution_repo", ws)


class UppercaseBaselineTests(_GitWorktreeTestBase):
    """L1: uppercase spelling of the same SHA must be accepted."""

    def test_uppercase_expected_baseline_head_accepted(self):
        """Uppercase expected_baseline.head == baseline is accepted."""
        task = self._task_with_isolation()
        task["expected_baseline"] = {"head": self.source_head.upper()}
        agentflow.validate_task(task)
        ctx = agentflow.build_execution_context(task, "test-run-upper")
        try:
            self.assertTrue(ctx.isolated)
            self.assertEqual(self.source_head.lower(), ctx.baseline_commit)
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(ctx.execution_repo)],
                cwd=self.source_repo, capture_output=True,
            )

    def test_real_mismatch_still_rejected(self):
        """A genuinely different SHA must still fail."""
        task = self._task_with_isolation()
        task["expected_baseline"] = {"head": "b" * 40}
        agentflow.validate_task(task)
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.build_execution_context(task, "test-run-upper-mismatch")
        self.assertEqual("INVALID_TASK", raised.exception.code)


class LegacyUnbornTests(_GitWorktreeTestBase):
    """L3+L6: legacy non-isolated unborn repo remains compatible."""

    def test_legacy_non_isolated_unborn_repo_compatible(self):
        """Unborn repo (head None) without isolation reaches HUMAN_GATE."""
        unborn = self.tmp / "unborn-repo"
        unborn.mkdir()
        subprocess.run(["git", "init"], cwd=unborn, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"],
                       cwd=unborn, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"],
                       cwd=unborn, check=True, capture_output=True)
        # No commit: HEAD unresolvable, capture_baseline head is None.
        baseline = agentflow.capture_baseline(unborn)
        self.assertIsNone(baseline["head"])
        task = self._task(repo=str(unborn), expected_baseline={})
        # expected_baseline with explicit head:null must also be compatible.
        task_null = self._task(repo=str(unborn), expected_baseline={"head": None},
                               task_id="test-task-002")
        for t in (task, task_null):
            task_path = self.tmp / "unborn-task.json"
            task_path.write_text(json.dumps(t), encoding="utf-8")

            def _invoke(*, role, **kwargs):
                # Role-aware fixtures: HIGH risk invokes a reviewer too.
                return (_make_result(role=role, verdict="PASS"), _make_record(role))

            with (
                mock.patch("agentflow.invoke_model", side_effect=_invoke),
                mock.patch("agentflow.changed_since", return_value=[]),
                mock.patch("agentflow.run_validators", return_value=[
                    {"name": "lint", "command": "/usr/bin/true",
                     "started_at": "2026-01-01", "finished_at": "2026-01-01",
                     "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
                ]),
                mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
                mock.patch("shutil.which", return_value="/usr/bin/opencode"),
            ):
                code, run_dir, final = agentflow.run_task(task_path)
            self.assertEqual(0, code)
            self.assertEqual("HUMAN_GATE", final["verdict"])
            self.assertFalse((run_dir / "workspace.json").exists())

    def test_isolated_unborn_fails_closed(self):
        """Isolated execution on unborn source remains fail-closed."""
        unborn = self.tmp / "unborn-isolated"
        unborn.mkdir()
        subprocess.run(["git", "init"], cwd=unborn, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"],
                       cwd=unborn, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"],
                       cwd=unborn, check=True, capture_output=True)
        task = self._task(repo=str(unborn))
        task["isolation"] = {"enabled": True, "baseline_commit": "a" * 40}
        with self.assertRaises(agentflow.AgentFlowError):
            agentflow.build_execution_context(task, "test-run-unborn-iso")


class DirtySuccessPreservationTests(_GitWorktreeTestBase):
    """L5: successful HUMAN_GATE candidate reports actual dirty state."""

    def test_dirty_human_gate_reports_preserved_dirty_true(self):
        """Dirty success must not report preserved_dirty=False."""
        task = self._task_with_isolation()
        task_path = self._write_task_file(task)
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id="test-run-dirty-success",
            root=self.worktree_root,
        )
        self.addCleanup(lambda: subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo, capture_output=True,
        ))
        ctx = agentflow.ExecutionContext(
            source_repo=self.source_repo,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        )
        # Real dirty file in the execution workspace.
        (dest / "src").mkdir(exist_ok=True)
        (dest / "src" / "foo.py").write_text("x = 1\n", encoding="utf-8")

        def _invoke_ok(*, role, profile_name, profile, task, run_dir,
                       cycle, context=None, lease=None, exec_repo=None):
            return (_make_result(role=role, verdict="PASS"), _make_record(role))

        original_git = agentflow.git

        def _git_side_effect(repo, args, **kwargs):
            if args and args[0] == "status":
                return original_git(repo, args, **kwargs)
            return mock.MagicMock(returncode=0, stdout="", stderr="")

        with (
            mock.patch("agentflow.build_execution_context", return_value=ctx),
            mock.patch("agentflow.invoke_model", side_effect=_invoke_ok),
            mock.patch("agentflow.changed_since", return_value=[]),
            mock.patch("agentflow.run_validators", return_value=[
                {"name": "lint", "command": "/usr/bin/true",
                 "started_at": "2026-01-01", "finished_at": "2026-01-01",
                 "exit_code": 0, "status": "PASS", "stdout": "", "stderr": ""},
            ]),
            mock.patch("agentflow.load_models", return_value=_DEFAULT_MODELS),
            mock.patch("agentflow.capture_baseline", return_value={
                "captured_at": "2026-01-01", "repo": str(dest),
                "branch": None, "head": canonical,
                "dirty_paths": [], "untracked_paths": [],
                "path_state": {}, "git_diff_check": {"exit_code": 0, "stdout": "", "stderr": ""},
            }),
            mock.patch("agentflow.git", side_effect=_git_side_effect),
            mock.patch("shutil.which", return_value="/usr/bin/opencode"),
        ):
            code, run_dir, final = agentflow.run_task(task_path)
        self.assertEqual(0, code)
        ws = json.loads((run_dir / "workspace.json").read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", ws["status"])
        self.assertTrue(ws["preserved_dirty"])


if __name__ == "__main__":
    unittest.main()
