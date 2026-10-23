"""Characterization tests for OPT-002 preservation behavior.

These tests intentionally exercise both public execution entry points against
real temporary Git repositories and real Git worktrees. Model/provider work is
mocked; no external model process is invoked.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentflow


def _init_git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    (path / "README.md").write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    return path


def _head_sha(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _result(task_id: str, role: str, verdict: str = "PASS", **extra):
    value = {
        "task_id": task_id,
        "role": role,
        "harness": "opencode",
        "provider": "opencode",
        "model": "test/model",
        "variant": None,
        "files_changed": [],
        "validators": {},
        "findings": [],
        "open_risks": [],
        "verdict": verdict,
    }
    value.update(extra)
    return value


def _record(role: str, cycle: int = 0):
    return {
        "profile": "test_profile",
        "role": role,
        "harness": "opencode",
        "provider": "opencode",
        "model": "test/model",
        "variant": None,
        "agent": "test-agent",
        "cycle": cycle,
        "invoked_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:01:00+00:00",
        "exit_code": 0,
    }


_MODELS = {
    "profiles": {
        "program_architect": {
            "backend": "opencode",
            "command": "opencode",
            "provider": "opencode",
            "model": "opencode/muse-spark-1.2",
            "variant": "high",
            "agent": "agentflow-architect",
            "available": True,
            "eligible_roles": ["architect", "adjudicator"],
        },
        "program_worker": {
            "backend": "opencode",
            "command": "opencode",
            "provider": "opencode",
            "model": "opencode/nemotron-3-ultra-free",
            "variant": None,
            "agent": "agentflow-worker",
            "available": True,
            "eligible_roles": ["worker"],
        },
        "program_reviewer": {
            "backend": "opencode",
            "command": "opencode",
            "provider": "opencode-go",
            "model": "opencode-go/deepseek-v4.1-flash",
            "variant": "max",
            "agent": "agentflow-reviewer",
            "available": True,
            "eligible_roles": ["reviewer"],
        },
    },
    "routing": {
        "LOW": ["program_worker"],
        "MEDIUM": ["program_worker"],
        "HIGH": ["program_worker"],
        "CRITICAL": ["program_worker"],
    },
}


class Opt002PreservationCharacterizationTests(unittest.TestCase):
    """Current behavior matrix for isolated preservation and its boundaries."""

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

        self._patches = []
        for attr, target in (
            ("RUNS_DIR", self.runs_dir),
            ("LOCKS_DIR", self.locks_dir),
        ):
            patcher = mock.patch.object(agentflow, attr, target)
            patcher.start()
            self._patches.append(patcher)
        env_patcher = mock.patch.dict(
            os.environ,
            {"AGENTFLOW_WORKTREES_DIR": str(self.worktree_root)},
        )
        env_patcher.start()
        self._patches.append(env_patcher)

    def tearDown(self):
        for patcher in reversed(self._patches):
            patcher.stop()

    def _task(self, label: str, *, isolated: bool) -> dict:
        task = {
            "task_id": f"opt002-task-{label}",
            "repo": str(self.source_repo),
            "risk": "LOW",
            "objective": "Characterize preservation",
            "allowed_paths": ["src/"],
            "validators": [{"name": "lint", "command": ["/usr/bin/true"]}],
            "invariants": ["Preservation remains behaviorally equivalent"],
            "forbidden_actions": ["git commit"],
            "expected_baseline": {},
        }
        if isolated:
            task["isolation"] = {
                "enabled": True,
                "baseline_commit": self.source_head,
            }
        return task

    def _program(self, label: str, task_path: Path) -> dict:
        return {
            "program_id": f"opt002-program-{label}",
            "task": task_path.name,
            "roles": {
                "architect": "program_architect",
                "worker": "program_worker",
                "reviewer": "program_reviewer",
            },
            "max_corrections": 1,
        }

    def _source_checkout_state(self) -> tuple[bytes, bytes, bytes, bytes]:
        def run(args: list[str]) -> bytes:
            return subprocess.run(
                ["git", *args],
                cwd=self.source_repo,
                check=True,
                capture_output=True,
            ).stdout

        return (
            run(["rev-parse", "HEAD"]),
            run(["status", "--porcelain=v1", "-z", "--untracked-files=all"]),
            run(["ls-files", "--stage", "-z"]),
            run(["ls-files", "-z"]),
        )

    def _assert_source_unchanged(self, before):
        self.assertEqual(before, self._source_checkout_state())

    def _create_execution_context(self, label: str):
        dest, canonical = agentflow.create_isolated_worktree(
            source=self.source_repo,
            baseline_commit=self.source_head,
            run_id=f"opt002-{label}",
            root=self.worktree_root,
        )
        self.addCleanup(
            lambda: subprocess.run(
                ["git", "worktree", "remove", "--force", str(dest)],
                cwd=self.source_repo,
                capture_output=True,
            )
        )
        return agentflow.ExecutionContext(
            source_repo=self.source_repo,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        ), dest, canonical

    def _remove_worktree_now(self, dest: Path):
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(dest)],
            cwd=self.source_repo,
            capture_output=True,
        )

    def _prepare_case(self, kind: str, label: str, *, isolated: bool, dirty: bool):
        source_before = self._source_checkout_state()
        task = self._task(label, isolated=isolated)
        task_path = self.tmp / f"{label}-task.json"
        task_path.write_text(json.dumps(task), encoding="utf-8")

        ctx = None
        dest = None
        canonical = None
        if isolated:
            ctx, dest, canonical = self._create_execution_context(label)
            if dirty:
                (dest / "dirty-marker.txt").write_text("dirty\n", encoding="utf-8")

        program_path = None
        if kind == "program":
            program_path = self.tmp / f"{label}-program.json"
            program_path.write_text(
                json.dumps(self._program(label, task_path)),
                encoding="utf-8",
            )
        return {
            "task_path": task_path,
            "program_path": program_path,
            "ctx": ctx,
            "dest": dest,
            "canonical": canonical,
            "source_before": source_before,
            "task_id": task["task_id"],
        }

    def _runtime_patches(
        self,
        case: dict,
        *,
        kind: str,
        action: str,
        dirty_inspection_failure: bool,
        persistence_failure: bool,
        corrupt_execution_repo: object | None = None,
    ):
        stack = contextlib.ExitStack()
        if case["ctx"] is not None:
            stack.enter_context(
                mock.patch.object(
                    agentflow,
                    "build_execution_context",
                    return_value=case["ctx"],
                )
            )
        stack.enter_context(mock.patch.object(agentflow, "load_models", return_value=_MODELS))
        stack.enter_context(mock.patch("shutil.which", return_value="/usr/bin/opencode"))
        stack.enter_context(
            mock.patch.object(
                agentflow,
                "run_validators",
                return_value=[
                    {
                        "name": "lint",
                        "command": "/usr/bin/true",
                        "started_at": "2026-01-01",
                        "finished_at": "2026-01-01",
                        "exit_code": 0,
                        "status": "PASS",
                        "stdout": "",
                        "stderr": "",
                    }
                ],
            )
        )
        stack.enter_context(mock.patch.object(agentflow, "changed_since", return_value=[]))

        def invoke(*, role, **kwargs):
            if role == "worker":
                if action == "agent_error":
                    raise agentflow.AgentFlowError(
                        "MODEL_INVOCATION_FAILED", "characterized model failure"
                    )
                if action == "runtime_error":
                    raise RuntimeError("characterized unexpected failure")
                if action == "keyboard_interrupt":
                    raise KeyboardInterrupt()
                if action == "system_exit":
                    raise SystemExit("characterized system exit")
            task_id = case["task_id"]
            if kind == "task":
                return _result(task_id, role), _record(role)
            if role == "architect":
                return (
                    _result(
                        task_id,
                        "architect",
                        verdict="PLAN_READY",
                        architect_plan={
                            "objective_interpretation": "Characterize preservation",
                            "implementation_steps": ["Observe behavior"],
                            "invariants": ["No behavior change"],
                            "allowed_scope": ["src/"],
                            "do_not_change": ["README.md"],
                            "validation_expectations": ["All tests pass"],
                            "known_risks": ["None"],
                        },
                    ),
                    _record("architect"),
                )
            if role == "adjudicator":
                return (
                    _result(
                        task_id,
                        "adjudicator",
                        verdict="ADJUDICATION_COMPLETE",
                        adjudication={
                            "correction_required": False,
                            "classifications": {},
                            "accepted_refs": [],
                            "correction_brief": None,
                            "stop_reason": None,
                        },
                    ),
                    _record("adjudicator"),
                )
            return _result(task_id, role), _record(role, 1)

        stack.enter_context(mock.patch.object(agentflow, "invoke_model", side_effect=invoke))

        if dirty_inspection_failure:
            original_git = agentflow.git

            def failing_status(repo, args, **kwargs):
                if args == ["status", "--porcelain"]:
                    return subprocess.CompletedProcess(
                        ["git", *args], 1, "", "simulated status inspection failure"
                    )
                return original_git(repo, args, **kwargs)

            stack.enter_context(mock.patch.object(agentflow, "git", side_effect=failing_status))

        if persistence_failure:
            original_atomic = agentflow.atomic_json

            def failing_workspace_persistence(path, value):
                if Path(path).name == "workspace.json":
                    raise OSError("simulated workspace persistence failure")
                return original_atomic(path, value)

            stack.enter_context(
                mock.patch.object(
                    agentflow,
                    "atomic_json",
                    side_effect=failing_workspace_persistence,
                )
            )
        if corrupt_execution_repo is not None:
            original_atomic = agentflow.atomic_json

            def corrupt_workspace_execution_repo(path, value):
                result = original_atomic(path, value)
                if (
                    Path(path).name == "workspace.json"
                    and isinstance(value, dict)
                    and value.get("status") == "CANDIDATE"
                ):
                    value["execution_repo"] = corrupt_execution_repo
                return result

            stack.enter_context(
                mock.patch.object(
                    agentflow,
                    "atomic_json",
                    side_effect=corrupt_workspace_execution_repo,
                )
            )
        return stack

    def _invoke_case(self, kind: str, case: dict):
        if kind == "task":
            return agentflow.run_task(case["task_path"])
        return agentflow.run_program(case["program_path"])

    def _run_case(
        self,
        kind: str,
        label: str,
        *,
        action: str,
        isolated: bool = True,
        dirty: bool = False,
        dirty_inspection_failure: bool = False,
        persistence_failure: bool = False,
        corrupt_execution_repo: object | None = None,
        expected_exception: type[BaseException] | None = None,
    ):
        case = self._prepare_case(kind, label, isolated=isolated, dirty=dirty)
        before_runs = set(self.runs_dir.iterdir())
        with self._runtime_patches(
            case,
            kind=kind,
            action=action,
            dirty_inspection_failure=dirty_inspection_failure,
            persistence_failure=persistence_failure,
            corrupt_execution_repo=corrupt_execution_repo,
        ):
            if expected_exception is None:
                result = self._invoke_case(kind, case)
            else:
                with self.assertRaises(expected_exception):
                    self._invoke_case(kind, case)
                result = (None, None, None)
        new_run_dirs = sorted(set(self.runs_dir.iterdir()) - before_runs)
        self.assertEqual(1, len(new_run_dirs), new_run_dirs)
        run_dir = result[1] if result[1] is not None else new_run_dirs[0]
        self._assert_source_unchanged(case["source_before"])
        return {
            "code": result[0],
            "run_dir": run_dir,
            "final": result[2],
            "dest": case["dest"],
            "canonical": case["canonical"],
            "task_id": case["task_id"],
        }

    def _assert_preserved(self, outcome: dict, *, dirty: bool, verdict: str):
        self.assertEqual(0 if verdict == "HUMAN_GATE" else 2, outcome["code"])
        final = outcome["final"]
        self.assertEqual(verdict, final["verdict"])
        if verdict == "HUMAN_GATE":
            self.assertEqual("SUCCESS", final["status"])
        else:
            self.assertEqual("STOPPED", final["status"])
        run_dir = outcome["run_dir"]
        workspace = json.loads((run_dir / "workspace.json").read_text(encoding="utf-8"))
        self.assertEqual("PRESERVED", workspace["status"])
        self.assertIs(dirty, workspace["preserved_dirty"])
        self.assertEqual("PRESERVED", final["workspace"]["status"])
        self.assertEqual(workspace["execution_repo"], final["workspace"]["execution_repo"])
        self.assertEqual(workspace["baseline_commit"], final["workspace"]["baseline_commit"])
        self.assertEqual(str(outcome["dest"]), workspace["execution_repo"])
        self.assertTrue((run_dir / "final.json").exists())
        self.assertEqual(final, json.loads((run_dir / "final.json").read_text(encoding="utf-8")))
        self.assertIn("final_baseline", final)
        self.assertEqual(str(outcome["dest"]), final["final_baseline"]["repo"])
        self.assertTrue(agentflow._is_worktree_registered(self.source_repo, outcome["dest"]))

    def _assert_no_registered_worktree_under_root(self):
        proc = subprocess.run(
            ["git", "worktree", "list", "--porcelain"],
            cwd=self.source_repo,
            check=True,
            capture_output=True,
            text=True,
        )
        root = str(self.worktree_root.resolve())
        registered = [
            line[9:].strip()
            for line in proc.stdout.splitlines()
            if line.startswith("worktree ")
        ]
        self.assertEqual([], [path for path in registered if path.startswith(root)])

    def test_clean_failure_preservation_matrix(self):
        for kind in ("task", "program"):
            with self.subTest(entrypoint=kind):
                outcome = self._run_case(
                    kind,
                    f"clean-failure-{kind}",
                    action="agent_error",
                )
                self._assert_preserved(
                    outcome,
                    dirty=False,
                    verdict="MODEL_INVOCATION_FAILED",
                )

    def test_dirty_failure_preservation_matrix(self):
        for kind in ("task", "program"):
            with self.subTest(entrypoint=kind):
                outcome = self._run_case(
                    kind,
                    f"dirty-failure-{kind}",
                    action="agent_error",
                    dirty=True,
                )
                self._assert_preserved(
                    outcome,
                    dirty=True,
                    verdict="MODEL_INVOCATION_FAILED",
                )

    def test_successful_dirty_human_gate_preservation_matrix(self):
        for kind in ("task", "program"):
            with self.subTest(entrypoint=kind):
                outcome = self._run_case(
                    kind,
                    f"dirty-success-{kind}",
                    action="success",
                    dirty=True,
                )
                self._assert_preserved(
                    outcome,
                    dirty=True,
                    verdict="HUMAN_GATE",
                )

    def test_workspace_persistence_failure_preserves_or_reconciles_registration(self):
        for kind in ("task", "program"):
            for dirty in (False, True):
                label = f"persistence-{kind}-{'dirty' if dirty else 'clean'}"
                with self.subTest(entrypoint=kind, dirty=dirty):
                    outcome = self._run_case(
                        kind,
                        label,
                        action="success",
                        dirty=dirty,
                        persistence_failure=True,
                    )
                    self.assertEqual(2, outcome["code"])
                    self.assertEqual("INTERNAL_ERROR", outcome["final"]["verdict"])
                    workspace = json.loads(
                        (outcome["run_dir"] / "workspace.json").read_text(encoding="utf-8")
                    )
                    if dirty:
                        self.assertEqual("PRESERVED", workspace["status"])
                        self.assertTrue(workspace["preserved_dirty"])
                        self.assertTrue(
                            agentflow._is_worktree_registered(
                                self.source_repo, outcome["dest"]
                            )
                        )
                        self.assertEqual(
                            "PRESERVED", outcome["final"]["workspace"]["status"]
                        )
                    else:
                        self.assertEqual("CLEANED", workspace["status"])
                        self.assertFalse(workspace["preserved_dirty"])
                        self.assertFalse(outcome["dest"].exists())
                        self._assert_no_registered_worktree_under_root()
                        self.assertEqual(
                            "CLEANED", outcome["final"]["workspace"]["status"]
                        )
                    self._remove_worktree_now(outcome["dest"])

    def test_dirty_state_inspection_failure_fails_closed(self):
        for kind in ("task", "program"):
            with self.subTest(entrypoint=kind):
                outcome = self._run_case(
                    kind,
                    f"inspection-failure-{kind}",
                    action="success",
                    dirty_inspection_failure=True,
                )
                self._assert_preserved(
                    outcome,
                    dirty=True,
                    verdict="HUMAN_GATE",
                )

    def test_unexpected_runtime_error_preserves_coherent_evidence(self):
        for kind in ("task", "program"):
            with self.subTest(entrypoint=kind):
                outcome = self._run_case(
                    kind,
                    f"runtime-error-{kind}",
                    action="runtime_error",
                )
                self._assert_preserved(
                    outcome,
                    dirty=False,
                    verdict="INTERNAL_ERROR",
                )

    def test_corrupt_execution_repo_failure_fails_closed(self):
        for kind in ("task", "program"):
            for corrupt_value in (123, {"bad": "value"}):
                with self.subTest(entrypoint=kind, corrupt_value=corrupt_value):
                    outcome = self._run_case(
                        kind,
                        f"corrupt-execution-repo-{kind}-{type(corrupt_value).__name__}",
                        action="agent_error",
                        corrupt_execution_repo=corrupt_value,
                    )
                    self.assertEqual(2, outcome["code"])
                    self.assertEqual(
                        "MODEL_INVOCATION_FAILED", outcome["final"]["verdict"]
                    )
                    workspace = json.loads(
                        (outcome["run_dir"] / "workspace.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    self.assertEqual(corrupt_value, workspace["execution_repo"])
                    self.assertEqual("PRESERVED", workspace["status"])
                    self.assertTrue(workspace["preserved_dirty"])
                    self.assertTrue((outcome["run_dir"] / "workspace.json").exists())
                    self.assertTrue((outcome["run_dir"] / "final.json").exists())
                    self.assertEqual(
                        "PRESERVED", outcome["final"]["workspace"]["status"]
                    )
                    self.assertEqual(
                        corrupt_value,
                        outcome["final"]["workspace"]["execution_repo"],
                    )
                    self.assertIn("final_baseline", outcome["final"])
                    self.assertEqual(
                        str(outcome["dest"]), outcome["final"]["final_baseline"]["repo"]
                    )
                    self.assertTrue(outcome["dest"].exists())
                    self.assertTrue(
                        agentflow._is_worktree_registered(
                            self.source_repo, outcome["dest"]
                        )
                    )

    def test_preservation_helper_inspects_dirty_state_before_status(self):
        for exc_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=exc_type.__name__):
                workspace = {
                    "status": "CANDIDATE",
                    "preserved_dirty": False,
                }
                with mock.patch.object(
                    agentflow,
                    "_execution_dirty_state",
                    side_effect=exc_type(),
                ):
                    with self.assertRaises(exc_type):
                        agentflow._mark_workspace_preserved(workspace, self.source_repo)
                self.assertEqual("CANDIDATE", workspace["status"])
                self.assertFalse(workspace["preserved_dirty"])

    def test_keyboard_interrupt_and_system_exit_propagate(self):
        for kind in ("task", "program"):
            for action, exc_type in (
                ("keyboard_interrupt", KeyboardInterrupt),
                ("system_exit", SystemExit),
            ):
                with self.subTest(entrypoint=kind, exception=exc_type.__name__):
                    outcome = self._run_case(
                        kind,
                        f"{action}-{kind}",
                        action=action,
                        expected_exception=exc_type,
                    )
                    workspace = json.loads(
                        (outcome["run_dir"] / "workspace.json").read_text(encoding="utf-8")
                    )
                    self.assertEqual("CANDIDATE", workspace["status"])
                    self.assertTrue(
                        agentflow._is_worktree_registered(
                            self.source_repo, outcome["dest"]
                        )
                    )
                    self.assertFalse((outcome["run_dir"] / "final.json").exists())

    def test_non_isolated_execution_creates_no_workspace_json(self):
        for kind in ("task", "program"):
            with self.subTest(entrypoint=kind):
                outcome = self._run_case(
                    kind,
                    f"non-isolated-{kind}",
                    action="success",
                    isolated=False,
                )
                self.assertEqual(0, outcome["code"])
                self.assertEqual("HUMAN_GATE", outcome["final"]["verdict"])
                self.assertNotIn("workspace", outcome["final"])
                self.assertFalse((outcome["run_dir"] / "workspace.json").exists())


if __name__ == "__main__":
    unittest.main()
