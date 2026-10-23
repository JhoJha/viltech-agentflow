"""WATCHDOG-001A opt-in model output-inactivity tests.

All children are synthetic local Python subprocesses or fake provider
executables. No network, no real model providers.

Coverage map to the required areas:
 1. silent live process -> STALL_DETECTED before absolute timeout
 2. sparse stdout below threshold repeatedly prevents stall
 3. sparse stderr prevents stall
 4. stdout-only activity works
 5. stderr-only activity works
 6. multibyte output counts raw bytes
 7. continuous activity does NOT extend absolute timeout
 8. silent process exits before threshold -> not stall
 9. quick nonzero process exit -> MODEL_INVOCATION_FAILED, not stall
 10. user on_activity raises Exception -> accounting still works
 11. user on_activity raises custom BaseException -> same
 12. user on_activity raises KeyboardInterrupt -> isolated as observer failure
 13. stall kills controlled descendants
 14. dead leader + live controlled descendant is NOT stall
 15. worker real synthetic adapter detects stall
 16. readonly real synthetic adapter detects stall
 17. worker registration/GO delay does not consume watchdog budget
 18. WriteLease safe release after proven stall cleanup
 19. WriteLease remains fail closed on uncertain group
 20. Git and validators remain outside model supervision/watchdog
 21. exact policy boundary: below continue, at threshold abort
 22. activity committed before abort check wins
 23. activity after completed abort decision does not reverse decision
 24. leader exits around abort boundary: re-poll prevents misclassification
 25. simultaneous absolute + stall due: PROCESS_TIMEOUT wins
 26. task schema validation for the inactivity threshold
 27. end-to-end task failure: final.json STALL_DETECTED, preservation correct
 28. end-to-end program failure: same
 29. stall evidence includes partial stdout/stderr and byte counts
 30. absolute timeout evidence remains distinct from stall
"""

from __future__ import annotations

import contextlib
import inspect
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import agentflow


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _write_child(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _write_exe(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _wait_pid_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            # Exists but not signalable: provably alive.
            return False
        except OSError:
            # Any other kill(2) failure cannot prove death; treat as alive
            # so callers fail on quiescence instead of crashing.
            return False
        time.sleep(0.02)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except (PermissionError, OSError):
        return False
    return False


def _group_quiet(pgid: int, session_id: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if agentflow.WriteLease._group_status(pgid, session_id) == "inactive":
            return True
        time.sleep(0.02)
    return agentflow.WriteLease._group_status(pgid, session_id) == "inactive"


def _recording_observer():
    events = []
    lock = threading.Lock()

    def _callback(stream: str, nbytes: int) -> None:
        with lock:
            events.append((stream, nbytes))

    return _callback, events


class _WatchdogTestBase(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.locks = self.tmp / "locks"
        self.locks.mkdir()
        patcher = mock.patch.object(agentflow, "LOCKS_DIR", self.locks)
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_lease(self, task_id="wd-task", run_id="wd-run"):
        lease = agentflow.WriteLease(self.repo, task_id, run_id)
        lease.acquire()
        self.addCleanup(lambda: self._release_quietly(lease))
        return lease

    @staticmethod
    def _release_quietly(lease):
        with contextlib.suppress(Exception):
            lease.release()

    def child(self, name: str, body: str) -> Path:
        return _write_child(self.tmp / name, body)

    def assert_no_supervisor_threads(self):
        leftovers = [
            thread.name
            for thread in threading.enumerate()
            if thread.name.startswith("agentflow-model-")
        ]
        self.assertEqual([], leftovers)

    def base_task(self, **overrides):
        task = {
            "task_id": "wd-task",
            "repo": str(self.repo),
            "risk": "LOW",
            "objective": "watchdog probe",
            "allowed_paths": [],
            "forbidden_actions": [],
            "invariants": [],
            "validators": [{"name": "v", "command": ["/usr/bin/true"]}],
            "model_timeout_seconds": 12,
        }
        task.update(overrides)
        return task


# ---------------------------------------------------------------------------
# Policy unit tests: exact boundary, commit ordering (areas 21, 22, 23)
# ---------------------------------------------------------------------------


class InactivityPolicyBoundaryTests(_WatchdogTestBase):
    """Area 21/22/23: exact threshold boundary and activity/check ordering."""

    def test_below_threshold_continues_at_threshold_aborts(self):
        # Area 21: inactive_duration < threshold -> continue,
        # inactive_duration >= threshold -> STALL_DETECTED request.
        policy = agentflow._ModelInactivityPolicy(10.0)
        with policy._lock:
            anchored = policy._last_activity
        self.assertIsNone(policy.abort_check(anchored + 9.999))
        request = policy.abort_check(anchored + 10.0)
        self.assertIsNotNone(request)
        self.assertEqual("STALL_DETECTED", request.code)
        self.assertIsInstance(request.message, str)
        self.assertIn("threshold_seconds", request.details)
        self.assertIn("inactive_seconds", request.details)

    def test_zero_bytes_do_not_refresh(self):
        policy = agentflow._ModelInactivityPolicy(10.0)
        with policy._lock:
            anchored = policy._last_activity
        policy.note_activity("stdout", 0)
        policy.note_activity("stderr", 0)
        # Empty chunks must not move the activity instant.
        self.assertIsNotNone(policy.abort_check(anchored + 10.0))

    def test_either_stream_refreshes(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                policy = agentflow._ModelInactivityPolicy(100.0)
                with policy._lock:
                    anchored = policy._last_activity
                policy.note_activity(stream, 7)
                # A check far past the old anchor must observe the refresh.
                self.assertIsNone(policy.abort_check(time.monotonic()))

    def test_activity_committed_before_abort_check_wins(self):
        # Area 22: once note_activity has committed under the lock, a later
        # abort_check must observe it.
        policy = agentflow._ModelInactivityPolicy(5.0)
        with policy._lock:
            anchored = policy._last_activity
        # Without activity the old anchor is actionable past the threshold.
        self.assertIsNotNone(policy.abort_check(anchored + 5.5))
        policy.note_activity("stdout", 4)
        self.assertIsNone(policy.abort_check(time.monotonic()))

    def test_completed_abort_decision_is_not_reversed(self):
        # Area 23: a returned request is a point-in-time decision; later
        # activity cannot un-return it.
        policy = agentflow._ModelInactivityPolicy(5.0)
        with policy._lock:
            anchored = policy._last_activity
        decision = policy.abort_check(anchored + 6.0)
        self.assertIsNotNone(decision)
        self.assertEqual("STALL_DETECTED", decision.code)
        policy.note_activity("stderr", 9)
        # The already-taken decision still stands as a request object, while
        # a fresh check observes the new activity.
        self.assertIsNotNone(decision)
        self.assertEqual("STALL_DETECTED", decision.code)
        self.assertIsNone(policy.abort_check(time.monotonic()))

    def test_uses_monotonic_clock(self):
        source = inspect.getsource(agentflow._ModelInactivityPolicy)
        self.assertIn("time.monotonic()", source)
        self.assertNotIn("time.time()", source)


# ---------------------------------------------------------------------------
# Generic supervisor abort seam (areas 24, 25 + seam failure semantics)
# ---------------------------------------------------------------------------


class _ScriptedBoundaryProc:
    """Fake leader that is alive at the loop check but gone at re-poll."""

    def __init__(self):
        rout, wout = os.pipe()
        rerr, werr = os.pipe()
        os.close(wout)
        os.close(werr)
        self.stdout = os.fdopen(rout, "rb")
        self.stderr = os.fdopen(rerr, "rb")
        self.args = ["fake", "argv"]
        self.returncode: int | None = None
        self._polls = 0

    def poll(self):
        self._polls += 1
        if self._polls == 1:
            return None
        self.returncode = 0
        return 0

    def wait(self, timeout=None):
        return self.returncode if self.returncode is not None else 0


class SupervisorAbortSeamTests(_WatchdogTestBase):
    """Areas 24/25: re-poll safety and absolute-timeout precedence."""

    def test_leader_exit_at_boundary_is_not_misclassified(self):
        # Area 24: the hook fires while the leader looks alive, but the
        # mandatory re-poll finds it gone -> normal completion, no abort.
        proc = _ScriptedBoundaryProc()
        terminated = []

        def _terminate(target):
            terminated.append(target)

        def _hook(now):
            return agentflow.AbortRequest(
                code="STALL_DETECTED", message="scripted", details={}
            )

        try:
            completed = agentflow._supervise_model_process(
                proc,  # type: ignore[arg-type]
                result_args=["fake", "argv"],
                timeout=10,
                terminate=_terminate,
                decode_output=agentflow._decode_process_output,
                abort_check=_hook,
            )
        finally:
            with contextlib.suppress(Exception):
                proc.stdout.close()
            with contextlib.suppress(Exception):
                proc.stderr.close()
        self.assertEqual(0, completed.returncode)
        self.assertEqual([], terminated)
        self.assert_no_supervisor_threads()

    def test_simultaneous_absolute_and_stall_due_timeout_wins(self):
        # Area 25 (deterministic, no real-clock race): timeout=0 makes
        # remaining <= 0 provably true on the very first controller
        # iteration (deadline = T0, now = T1 >= T0 on a monotonic clock),
        # while the hook unconditionally returns a valid AbortRequest, so
        # BOTH conditions are due in the exact same iteration. Correct
        # ordering (deadline before abort_check) must raise TimeoutExpired
        # / PROCESS_TIMEOUT without letting the abort override it -- the
        # hook is not even consulted once the deadline has passed.
        # No sleep, no microsecond scheduling luck. Repeated inline so a
        # single run already proves the absence of a race window.
        for iteration in range(50):
            with self.subTest(iteration=iteration):
                rout, wout = os.pipe()
                rerr, werr = os.pipe()
                os.close(wout)
                os.close(werr)
                stdout_pipe = os.fdopen(rout, "rb")
                stderr_pipe = os.fdopen(rerr, "rb")

                class _AlwaysAliveProc:
                    def __init__(self):
                        self.stdout = stdout_pipe
                        self.stderr = stderr_pipe
                        self.args = ["fake", "argv"]
                        self.returncode = None

                    def poll(self):
                        return None

                    def wait(self, timeout=None):
                        raise subprocess.TimeoutExpired(
                            self.args, timeout
                        )

                proc = _AlwaysAliveProc()
                terminated = []
                hook_calls: list[float] = []

                def _terminate(target):
                    terminated.append(target)

                def _hook(now: float):
                    hook_calls.append(now)
                    return agentflow.AbortRequest(
                        code="STALL_DETECTED",
                        message="simultaneous abort request",
                        details={},
                    )

                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        agentflow._supervise_model_process(
                            proc,  # type: ignore[arg-type]
                            result_args=["fake", "argv"],
                            timeout=0,
                            terminate=_terminate,
                            decode_output=agentflow._decode_process_output,
                            abort_check=_hook,
                        )
                finally:
                    with contextlib.suppress(Exception):
                        stdout_pipe.close()
                    with contextlib.suppress(Exception):
                        stderr_pipe.close()
                # Timeout path must have terminated the leader...
                self.assertEqual([proc], terminated)
                # ...and must not have consulted the abort hook to override
                # it once remaining <= 0 was already due.
                self.assertEqual(
                    [],
                    hook_calls,
                    "abort_check must not override an already-due deadline",
                )
                self.assert_no_supervisor_threads()

    def test_invalid_hook_return_is_internal_error(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._supervise_model_process(
                    proc,
                    result_args=["fake", "argv"],
                    timeout=10,
                    terminate=agentflow._terminate_readonly_group,
                    decode_output=agentflow._decode_process_output,
                    abort_check=lambda now: "not-a-request",  # type: ignore[return-value]
                )
            self.assertEqual("INTERNAL_ERROR", raised.exception.code)
        finally:
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=5)
            with contextlib.suppress(Exception):
                proc.stdout.close()
            with contextlib.suppress(Exception):
                proc.stderr.close()
        self.assert_no_supervisor_threads()

    def test_hook_exception_is_internal_error(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        def _boom(now):
            raise RuntimeError("hook blew up")

        try:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._supervise_model_process(
                    proc,
                    result_args=["fake", "argv"],
                    timeout=10,
                    terminate=agentflow._terminate_readonly_group,
                    decode_output=agentflow._decode_process_output,
                    abort_check=_boom,
                )
            self.assertEqual("INTERNAL_ERROR", raised.exception.code)
        finally:
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=5)
            with contextlib.suppress(Exception):
                proc.stdout.close()
            with contextlib.suppress(Exception):
                proc.stderr.close()
        self.assert_no_supervisor_threads()

    def test_hook_keyboard_interrupt_propagates(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        def _kbd(now):
            raise KeyboardInterrupt()

        try:
            with self.assertRaises(KeyboardInterrupt):
                agentflow._supervise_model_process(
                    proc,
                    result_args=["fake", "argv"],
                    timeout=10,
                    terminate=agentflow._terminate_readonly_group,
                    decode_output=agentflow._decode_process_output,
                    abort_check=_kbd,
                )
        finally:
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=5)
            with contextlib.suppress(Exception):
                proc.stdout.close()
            with contextlib.suppress(Exception):
                proc.stderr.close()
        self.assert_no_supervisor_threads()


# ---------------------------------------------------------------------------
# Readonly adapter watchdog behavior (areas 1-8, 13, 14, 16)
# ---------------------------------------------------------------------------


class ReadonlyWatchdogTests(_WatchdogTestBase):
    """Areas 1-8, 13, 14, 16 through the readonly adapter."""

    def _run_reader(self, argv, timeout, **kwargs):
        return agentflow._run_model_command(
            role="reviewer", argv=argv, cwd=self.repo,
            timeout=timeout, env=None, **kwargs,
        )

    def test_silent_live_process_reports_stall_before_absolute_timeout(self):
        # Area 1: silent process, threshold 1s, absolute 10s.
        script = self.child(
            "wd_silent.py",
            "import time\ntime.sleep(30)\n",
        )
        started = time.monotonic()
        with self.assertRaises(agentflow.AbortedProcessError) as raised:
            self._run_reader(
                [sys.executable, str(script)], 10,
                inactivity_timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        self.assertLess(elapsed, 8, f"stall not prompt: {elapsed:.2f}s")
        self.assert_no_supervisor_threads()

    def test_sparse_stdout_prevents_stall(self):
        # Area 2: stdout every 0.4s stays far below the 2s threshold.
        script = self.child(
            "wd_sparse_out.py",
            "import sys, time\n"
            "for _ in range(6):\n"
            "    sys.stdout.write('tick\\n')\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.4)\n",
        )
        proc = self._run_reader(
            [sys.executable, str(script)], 15,
            inactivity_timeout_seconds=2,
        )
        self.assertEqual(0, proc.returncode)
        self.assertEqual("tick\n" * 6, proc.stdout)
        self.assert_no_supervisor_threads()

    def test_sparse_stderr_prevents_stall(self):
        # Area 3: same protection from the stderr pipe.
        script = self.child(
            "wd_sparse_err.py",
            "import sys, time\n"
            "for _ in range(6):\n"
            "    sys.stderr.write('tick\\n')\n"
            "    sys.stderr.flush()\n"
            "    time.sleep(0.4)\n",
        )
        proc = self._run_reader(
            [sys.executable, str(script)], 15,
            inactivity_timeout_seconds=2,
        )
        self.assertEqual(0, proc.returncode)
        self.assertEqual("tick\n" * 6, proc.stderr)
        self.assert_no_supervisor_threads()

    def test_stdout_only_activity_works(self):
        # Area 4: stderr stays completely quiet; stdout alone sustains.
        script = self.child(
            "wd_out_only.py",
            "import sys, time\n"
            "for _ in range(5):\n"
            "    sys.stdout.write('o')\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.4)\n",
        )
        proc = self._run_reader(
            [sys.executable, str(script)], 15,
            inactivity_timeout_seconds=2,
        )
        self.assertEqual("o" * 5, proc.stdout)
        self.assertEqual("", proc.stderr)
        self.assert_no_supervisor_threads()

    def test_stderr_only_activity_works(self):
        # Area 5: stdout stays completely quiet; stderr alone sustains.
        script = self.child(
            "wd_err_only.py",
            "import sys, time\n"
            "for _ in range(5):\n"
            "    sys.stderr.write('e')\n"
            "    sys.stderr.flush()\n"
            "    time.sleep(0.4)\n",
        )
        proc = self._run_reader(
            [sys.executable, str(script)], 15,
            inactivity_timeout_seconds=2,
        )
        self.assertEqual("", proc.stdout)
        self.assertEqual("e" * 5, proc.stderr)
        self.assert_no_supervisor_threads()

    def test_multibyte_output_counts_raw_bytes(self):
        # Area 6: observer totals equal UTF-8 raw-byte length, not chars.
        text = "héllo→世界" * 20
        script = self.child(
            "wd_multi.py",
            "import sys, time\n"
            f"s = {text!r}\n"
            "for _ in range(4):\n"
            "    sys.stdout.write(s)\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.3)\n",
        )
        totals: dict[str, int] = {}
        lock = threading.Lock()

        def _count(stream: str, nbytes: int) -> None:
            with lock:
                totals[stream] = totals.get(stream, 0) + nbytes

        proc = self._run_reader(
            [sys.executable, str(script)], 15,
            inactivity_timeout_seconds=2,
            on_activity=_count,
        )
        self.assertEqual(text * 4, proc.stdout)
        self.assertEqual(len((text * 4).encode("utf-8")), totals.get("stdout", 0))
        self.assert_no_supervisor_threads()

    def test_continuous_activity_does_not_extend_absolute_timeout(self):
        # Area 7: constant output, threshold larger than the absolute
        # deadline -> absolute timeout still fires on time.
        script = self.child(
            "wd_busy.py",
            "import sys, time\n"
            "end = time.monotonic() + 30\n"
            "while time.monotonic() < end:\n"
            "    sys.stdout.write('x' * 500)\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.01)\n",
        )
        callback, events = _recording_observer()
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            self._run_reader(
                [sys.executable, str(script)], 2,
                inactivity_timeout_seconds=1,
                on_activity=callback,
            )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 10)
        self.assertTrue(events, "expected activity before the deadline")
        self.assert_no_supervisor_threads()

    def test_silent_exit_before_threshold_is_not_stall(self):
        # Area 8: quiet process that exits on its own is normal completion.
        script = self.child(
            "wd_quick_quiet.py",
            "import time\ntime.sleep(0.5)\n",
        )
        proc = self._run_reader(
            [sys.executable, str(script)], 10,
            inactivity_timeout_seconds=3,
        )
        self.assertEqual(0, proc.returncode)
        self.assert_no_supervisor_threads()

    def test_readonly_adapter_detects_stall(self):
        # Area 16: direct readonly adapter entry point.
        script = self.child(
            "wd_ro_direct.py",
            "import time\ntime.sleep(30)\n",
        )
        started = time.monotonic()
        with self.assertRaises(agentflow.AbortedProcessError) as raised:
            agentflow._run_readonly_model_process(
                [sys.executable, str(script)],
                cwd=self.repo,
                timeout=10,
                env=None,
                inactivity_timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        self.assertLess(elapsed, 8)
        self.assert_no_supervisor_threads()

    def test_stall_kills_controlled_descendants(self):
        # Area 13: leader alive + descendant in the controlled group; the
        # stall termination must leave neither behind.
        pidfile = self.tmp / "wd_gc.pid"
        grandchild = self.child(
            "wd_gc.py",
            "import time\ntime.sleep(60)\n",
        )
        parent = self.child(
            "wd_parent.py",
            "import subprocess, sys, time\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdout=sys.stdout, stderr=sys.stderr)\n"
            f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
            "time.sleep(30)\n",
        )
        started = time.monotonic()
        with self.assertRaises(agentflow.AbortedProcessError) as raised:
            self._run_reader(
                [sys.executable, str(parent)], 15,
                inactivity_timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        self.assertLess(elapsed, 10, f"descendant kill not prompt: {elapsed:.2f}s")
        grandchild_pid = int(pidfile.read_text(encoding="ascii").strip())
        self.addCleanup(lambda: _wait_pid_dead(grandchild_pid, timeout=1.0))
        self.assertTrue(
            _wait_pid_dead(grandchild_pid),
            "controlled descendant survivor still alive after stall",
        )
        self.assert_no_supervisor_threads()

    def test_stall_kills_detached_descendant_independently_of_pipes(self):
        # LOW 1 (focused descendant-quiescence): the controlled descendant
        # does NOT inherit the supervisor stdout/stderr pipes, so
        # reader-join latency cannot mask survival. Stall termination must
        # still leave neither the leader nor the descendant behind; death
        # is asserted directly via PID + group quiescence, independently of
        # any elapsed-time promptness bound.
        gc_pidfile = self.tmp / "wd_gc_detached.pid"
        leader_pidfile = self.tmp / "wd_leader_detached.pid"
        grandchild = self.child(
            "wd_gc_detached.py",
            "import time\ntime.sleep(60)\n",
        )
        parent = self.child(
            "wd_parent_detached.py",
            "import os, subprocess, sys, time\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdin=subprocess.DEVNULL,\n"
            "    stdout=subprocess.DEVNULL,\n"
            "    stderr=subprocess.DEVNULL,\n"
            "    close_fds=True)\n"
            f"open({str(gc_pidfile)!r}, 'w').write(str(child.pid))\n"
            f"open({str(leader_pidfile)!r}, 'w').write(str(os.getpid()))\n"
            "time.sleep(30)\n",
        )
        with self.assertRaises(agentflow.AbortedProcessError) as raised:
            self._run_reader(
                [sys.executable, str(parent)], 15,
                inactivity_timeout_seconds=1,
            )
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        grandchild_pid = int(gc_pidfile.read_text(encoding="ascii").strip())
        leader_pid = int(leader_pidfile.read_text(encoding="ascii").strip())

        def _kill_leftover():
            with contextlib.suppress(Exception):
                os.kill(grandchild_pid, signal.SIGKILL)
            with contextlib.suppress(Exception):
                os.kill(leader_pid, signal.SIGKILL)
            _wait_pid_dead(grandchild_pid, timeout=1.0)
            _wait_pid_dead(leader_pid, timeout=1.0)

        self.addCleanup(_kill_leftover)
        # Direct descendant-death assertion: no inherited-pipe blocking can
        # delay this, so a leader-only kill mutation fails HERE, not on an
        # elapsed-time or reader-thread timeout.
        self.assertTrue(
            _wait_pid_dead(grandchild_pid),
            "detached controlled descendant survivor still alive after stall",
        )
        self.assertTrue(
            _wait_pid_dead(leader_pid),
            "stalled leader still alive after stall",
        )
        # The controlled session/process group rooted at the leader must be
        # provably inactive as well.
        self.assertTrue(
            _group_quiet(leader_pid, leader_pid),
            "controlled process group still active after stall",
        )
        self.assert_no_supervisor_threads()

    def test_dead_leader_with_live_descendant_is_not_stall(self):
        # Area 14: leader exits at once, descendant holds the pipes open.
        # The hook is skipped for a dead leader -> absolute timeout, and the
        # exception must be TimeoutExpired, never an abort failure.
        pidfile = self.tmp / "wd_closed.pid"
        grandchild = self.child(
            "wd_gc_closed.py",
            "import time\ntime.sleep(30)\n",
        )
        parent = self.child(
            "wd_parent_closed.py",
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdout=sys.stdout, stderr=sys.stderr)\n"
            f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n",
        )
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self._run_reader(
                [sys.executable, str(parent)], 3,
                inactivity_timeout_seconds=1,
            )
        self.assertNotIsInstance(
            raised.exception, agentflow.AbortedProcessError
        )
        grandchild_pid = int(pidfile.read_text(encoding="ascii").strip())
        self.addCleanup(lambda: _wait_pid_dead(grandchild_pid, timeout=1.0))
        self.assertTrue(_wait_pid_dead(grandchild_pid))
        self.assert_no_supervisor_threads()


# ---------------------------------------------------------------------------
# Worker adapter watchdog behavior (areas 15, 17, 18, 19)
# ---------------------------------------------------------------------------


class WorkerWatchdogTests(_WatchdogTestBase):
    """Areas 15/17/18/19 through the lease/GO worker adapter."""

    def test_worker_adapter_detects_stall(self):
        # Area 15: silent worker, threshold 1s, absolute 10s.
        lease = self.make_lease()
        script = self.child(
            "wdw_silent.py",
            "import time\ntime.sleep(30)\n",
        )
        started = time.monotonic()
        with self.assertRaises(agentflow.AbortedProcessError) as raised:
            agentflow.run_lifecycle_process(
                [sys.executable, str(script)],
                cwd=self.repo, timeout=10, env=None, lease=lease,
                inactivity_timeout_seconds=1,
            )
        elapsed = time.monotonic() - started
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        self.assertLess(elapsed, 8, f"worker stall not prompt: {elapsed:.2f}s")
        self.assert_no_supervisor_threads()

    def test_registration_go_delay_does_not_consume_budget(self):
        # Area 17: a 2s registration/GO delay with a 2s threshold must fire
        # ~4s after start, proving setup latency is outside both budgets.
        lease = self.make_lease()
        original_register = agentflow.WriteLease.register_writer

        def _delayed(pid, **kwargs):
            time.sleep(2.0)
            return original_register(lease, pid, **kwargs)

        script = self.child(
            "wdw_origin.py",
            "import time\ntime.sleep(30)\n",
        )
        started = time.monotonic()
        with mock.patch.object(lease, "register_writer", side_effect=_delayed):
            with self.assertRaises(agentflow.AbortedProcessError) as raised:
                agentflow.run_lifecycle_process(
                    [sys.executable, str(script)],
                    cwd=self.repo, timeout=12, env=None, lease=lease,
                    inactivity_timeout_seconds=2,
                )
        elapsed = time.monotonic() - started
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        self.assertGreaterEqual(
            elapsed, 3.2,
            f"registration/GO latency consumed watchdog budget: {elapsed:.2f}s",
        )
        self.assertLess(elapsed, 10)
        self.assert_no_supervisor_threads()

    def test_safe_release_after_proven_stall_cleanup(self):
        # Area 18: after a stall with provably-quiet group, the lease
        # records quiescence and releases cleanly.
        lease = self.make_lease()
        script = self.child(
            "wdw_release.py",
            "import time\ntime.sleep(30)\n",
        )
        with self.assertRaises(agentflow.AbortedProcessError):
            agentflow.run_lifecycle_process(
                [sys.executable, str(script)],
                cwd=self.repo, timeout=10, env=None, lease=lease,
                inactivity_timeout_seconds=1,
            )
        lease.mark_writer_quiescent()
        lease.release()
        self.assertFalse(lease.path.exists())
        self.assert_no_supervisor_threads()

    def test_uncertain_group_remains_fail_closed(self):
        # Area 19: when group state cannot be proven, release must refuse.
        lease = self.make_lease()
        script = self.child(
            "wdw_uncertain.py",
            "import time\ntime.sleep(30)\n",
        )
        with self.assertRaises(agentflow.AbortedProcessError):
            agentflow.run_lifecycle_process(
                [sys.executable, str(script)],
                cwd=self.repo, timeout=10, env=None, lease=lease,
                inactivity_timeout_seconds=1,
            )
        with mock.patch.object(
            agentflow.WriteLease, "_group_status", return_value="unknown"
        ):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                lease.release()
        self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)
        self.assert_no_supervisor_threads()


# ---------------------------------------------------------------------------
# Observer isolation: policy accounting before user observer (10, 11, 12)
# ---------------------------------------------------------------------------


class ObserverIsolationTests(_WatchdogTestBase):
    """Areas 10/11/12: user observer failures cannot defeat accounting."""

    def _sparse_stdout_script(self, name: str) -> Path:
        return self.child(
            name,
            "import sys, time\n"
            "for _ in range(6):\n"
            "    sys.stdout.write('k')\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.4)\n",
        )

    def test_exception_observer_still_accounts(self):
        # Area 10: every user callback raises Exception, yet sparse stdout
        # below the threshold prevents any stall and output is preserved.
        script = self._sparse_stdout_script("wd_obs_exc.py")
        calls = []

        def _boom(stream: str, nbytes: int) -> None:
            calls.append((stream, nbytes))
            raise RuntimeError("instrumentation failure")

        proc = agentflow._run_model_command(
            role="reviewer", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=15, env=None, on_activity=_boom,
            inactivity_timeout_seconds=2,
        )
        self.assertTrue(calls)
        self.assertEqual("k" * 6, proc.stdout)
        self.assert_no_supervisor_threads()

    def test_custom_base_exception_observer_still_accounts(self):
        # Area 11: same with a custom BaseException (not KI/SystemExit).
        class Sentinel(BaseException):
            pass

        script = self._sparse_stdout_script("wd_obs_base.py")

        def _sentinel(stream: str, nbytes: int) -> None:
            raise Sentinel()

        proc = agentflow._run_model_command(
            role="reviewer", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=15, env=None, on_activity=_sentinel,
            inactivity_timeout_seconds=2,
        )
        self.assertEqual("k" * 6, proc.stdout)
        self.assert_no_supervisor_threads()

    def test_keyboard_interrupt_observer_isolated(self):
        # Area 12: KeyboardInterrupt from the user observer is isolated as an
        # observer failure, matching OPT-001 observer semantics.
        script = self._sparse_stdout_script("wd_obs_kbd.py")

        def _kbd(stream: str, nbytes: int) -> None:
            raise KeyboardInterrupt()

        proc = agentflow._run_model_command(
            role="reviewer", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=15, env=None, on_activity=_kbd,
            inactivity_timeout_seconds=2,
        )
        self.assertEqual("k" * 6, proc.stdout)
        self.assert_no_supervisor_threads()


# ---------------------------------------------------------------------------
# invoke_model wiring: failure codes + evidence (areas 9, 29, 30)
# ---------------------------------------------------------------------------


class InvokeModelWatchdogTests(_WatchdogTestBase):
    """Areas 9/29/30: invoke_model failure mapping and evidence artifacts."""

    def _fake_backend(self, name: str, body: str) -> str:
        return str(_write_exe(self.tmp / name, body))

    def _profile(self, command: str) -> dict:
        return {
            "backend": "opencode", "command": command,
            "provider": "p", "model": "m", "variant": None,
            "agent": "agentflow-reviewer",
            "eligible_roles": ["reviewer"],
        }

    def test_quick_nonzero_exit_is_model_invocation_failed(self):
        # Area 9: fast nonzero exit beats the threshold -> not a stall.
        fake = self._fake_backend("fake_exit3", "import sys\nsys.exit(3)\n")
        task = self.base_task(model_inactivity_timeout_seconds=1)
        run_dir = self.tmp / "rundir9"
        run_dir.mkdir()
        started = time.monotonic()
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.invoke_model(
                role="reviewer", profile_name="fake",
                profile=self._profile(fake),
                task=task, run_dir=run_dir, cycle=0, context=None,
            )
        elapsed = time.monotonic() - started
        self.assertEqual("MODEL_INVOCATION_FAILED", raised.exception.code)
        self.assertLess(elapsed, 5)
        self.assert_no_supervisor_threads()

    def test_stall_evidence_has_partials_and_counts(self):
        # Area 29: partial stdout/stderr plus byte counts are persisted.
        fake = self._fake_backend(
            "fake_partial",
            "import sys, time\n"
            "sys.stdout.write('PARTIAL-OUT')\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write('PARTIAL-ERR')\n"
            "sys.stderr.flush()\n"
            "time.sleep(30)\n",
        )
        task = self.base_task(model_inactivity_timeout_seconds=1)
        run_dir = self.tmp / "rundir29"
        run_dir.mkdir()
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.invoke_model(
                role="reviewer", profile_name="fake",
                profile=self._profile(fake),
                task=task, run_dir=run_dir, cycle=0, context=None,
            )
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        evidence = json.loads(
            (run_dir / "reviewer-cycle-0-failure.json").read_text(encoding="utf-8")
        )
        self.assertEqual("STALL_DETECTED", evidence["failure_code"])
        self.assertEqual(12, evidence["absolute_timeout_seconds"])
        self.assertEqual(1, evidence["inactivity_threshold_seconds"])
        self.assertIsNotNone(evidence["inactive_seconds"])
        self.assertGreaterEqual(evidence["inactive_seconds"], 1.0)
        self.assertEqual(len(b"PARTIAL-OUT"), evidence["stdout_byte_count"])
        self.assertEqual(len(b"PARTIAL-ERR"), evidence["stderr_byte_count"])
        self.assertIn("PARTIAL-OUT", evidence["partial_stdout"])
        self.assertIn("PARTIAL-ERR", evidence["partial_stderr"])
        self.assert_no_supervisor_threads()

    def test_stall_evidence_survives_invalid_bytes(self):
        # Area 29b: invalid model bytes use lossy decoding for evidence only.
        fake = self._fake_backend(
            "fake_invalid",
            "import sys, time\n"
            "sys.stdout.buffer.write(bytes([65, 255, 66]))\n"
            "sys.stdout.buffer.flush()\n"
            "time.sleep(30)\n",
        )
        task = self.base_task(model_inactivity_timeout_seconds=1)
        run_dir = self.tmp / "rundir29b"
        run_dir.mkdir()
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.invoke_model(
                role="reviewer", profile_name="fake",
                profile=self._profile(fake),
                task=task, run_dir=run_dir, cycle=0, context=None,
            )
        self.assertEqual("STALL_DETECTED", raised.exception.code)
        evidence = json.loads(
            (run_dir / "reviewer-cycle-0-failure.json").read_text(encoding="utf-8")
        )
        self.assertEqual(3, evidence["stdout_byte_count"])
        self.assertIn("A", evidence["partial_stdout"])
        self.assertIn("B", evidence["partial_stdout"])
        self.assert_no_supervisor_threads()

    def test_absolute_timeout_evidence_is_distinct(self):
        # Area 30: absolute-timeout evidence carries PROCESS_TIMEOUT with no
        # inactivity attribution, distinct from stall evidence.
        fake = self._fake_backend(
            "fake_busy_quiet",
            "import sys, time\n"
            "sys.stdout.write('EARLY')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n",
        )
        task = self.base_task()
        task["model_timeout_seconds"] = 2
        run_dir = self.tmp / "rundir30"
        run_dir.mkdir()
        with self.assertRaises(subprocess.TimeoutExpired):
            agentflow.invoke_model(
                role="reviewer", profile_name="fake",
                profile=self._profile(fake),
                task=task, run_dir=run_dir, cycle=0, context=None,
            )
        evidence = json.loads(
            (run_dir / "reviewer-cycle-0-failure.json").read_text(encoding="utf-8")
        )
        self.assertEqual("PROCESS_TIMEOUT", evidence["failure_code"])
        self.assertEqual(2, evidence["absolute_timeout_seconds"])
        self.assertIsNone(evidence["inactivity_threshold_seconds"])
        self.assertIsNone(evidence["inactive_seconds"])
        self.assertEqual(len(b"EARLY"), evidence["stdout_byte_count"])
        self.assertIn("EARLY", evidence["partial_stdout"])
        self.assert_no_supervisor_threads()


# ---------------------------------------------------------------------------
# Task schema validation (area 26)
# ---------------------------------------------------------------------------


class InactivitySchemaTests(_WatchdogTestBase):
    """Area 26: model_inactivity_timeout_seconds validation."""

    def _task(self, **overrides):
        task = {
            "task_id": "schema-task", "repo": str(self.repo), "risk": "LOW",
            "objective": "schema probe", "allowed_paths": [],
            "validators": [{"name": "v", "command": ["/usr/bin/true"]}],
        }
        task.update(overrides)
        return task

    def test_absent_is_accepted(self):
        validated = agentflow.validate_task(self._task())
        self.assertNotIn("model_inactivity_timeout_seconds", validated)

    def test_positive_integer_accepted(self):
        for value in (1, 60, 3599):
            with self.subTest(value=value):
                task = self._task(
                    model_inactivity_timeout_seconds=value,
                    model_timeout_seconds=3600,
                )
                agentflow.validate_task(task)

    def test_zero_rejected(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_task(
                self._task(model_inactivity_timeout_seconds=0)
            )
        self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_negative_rejected(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_task(
                self._task(model_inactivity_timeout_seconds=-5)
            )
        self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_bool_rejected(self):
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_task(
                        self._task(model_inactivity_timeout_seconds=value)
                    )
                self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_non_integer_rejected(self):
        for value in (2.5, "30", None, [30]):
            with self.subTest(value=value):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_task(
                        self._task(model_inactivity_timeout_seconds=value)
                    )
                self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_at_or_above_effective_timeout_rejected(self):
        for value in (3600, 3601, 100000):
            with self.subTest(value=value):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow.validate_task(
                        self._task(
                            model_inactivity_timeout_seconds=value,
                            model_timeout_seconds=3600,
                        )
                    )
                self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_compared_against_effective_model_timeout(self):
        # Custom effective timeout governs the strict-less-than rule.
        agentflow.validate_task(
            self._task(
                model_inactivity_timeout_seconds=9,
                model_timeout_seconds=10,
            )
        )
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow.validate_task(
                self._task(
                    model_inactivity_timeout_seconds=10,
                    model_timeout_seconds=10,
                )
            )
        self.assertEqual("INVALID_TASK", raised.exception.code)

    def test_schema_file_documents_threshold(self):
        schema = json.loads(
            (Path(agentflow.__file__).resolve().parent
             / "schemas" / "task.schema.json").read_text(encoding="utf-8")
        )
        prop = schema["properties"]["model_inactivity_timeout_seconds"]
        self.assertEqual("integer", prop["type"])
        self.assertGreaterEqual(prop.get("minimum", 1), 1)


# ---------------------------------------------------------------------------
# Git / validators stay outside supervision (area 20)
# ---------------------------------------------------------------------------


class GitValidatorPreservationTests(_WatchdogTestBase):
    """Area 20: Git and validators never enter model supervision."""

    def test_git_and_validators_bypass_supervision(self):
        for name in ("run_process", "git", "run_validators"):
            source = inspect.getsource(getattr(agentflow, name))
            self.assertIn("run_process", source)
            self.assertNotIn("_supervise_model_process", source)
            self.assertNotIn("_run_readonly_model_process", source)
            self.assertNotIn("_run_model_command", source)
            self.assertNotIn("abort_check", source)
            self.assertNotIn("inactivity", source)

    def test_git_and_validators_functional(self):
        subprocess.run(
            ["git", "init"], cwd=self.repo, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "wd@example.com"],
            cwd=self.repo, check=True, capture_output=True,
        )
        proc = agentflow.git(self.repo, ["status", "--porcelain"])
        self.assertEqual(0, proc.returncode)
        results = agentflow.run_validators(
            self.repo,
            [{"name": "echo-check", "command": ["echo", "validator-ok"]}],
            self.tmp / "rundir20",
            0,
        )
        self.assertEqual("PASS", results[0]["status"])
        self.assertIn("validator-ok", results[0]["stdout"])


# ---------------------------------------------------------------------------
# End-to-end task + program failures (areas 27, 28)
# ---------------------------------------------------------------------------


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "wd@example.com"],
        cwd=path, check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "wd"],
        cwd=path, check=True, capture_output=True,
    )
    (path / "work").mkdir(exist_ok=True)
    (path / "work" / "keep.txt").write_text("keep\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"], cwd=path, check=True, capture_output=True
    )


class EndToEndTaskStallTests(_WatchdogTestBase):
    """Area 27: run_task surfaces STALL_DETECTED with preservation intact."""

    def test_task_failure_final_json_and_preservation(self):
        _init_git_repo(self.repo)
        fake_worker = _write_exe(
            self.tmp / "fake_worker_sleep",
            "import time\ntime.sleep(30)\n",
        )
        models = {
            "profiles": {
                "fake-worker": {
                    "backend": "opencode", "command": str(fake_worker),
                    "provider": "p", "model": "worker-1", "variant": None,
                    "agent": "agentflow-worker", "available": True,
                    "eligible_roles": ["worker"],
                }
            },
            "routing": {"LOW": ["fake-worker"]},
        }
        task = {
            "task_id": "wd-e2e", "repo": str(self.repo), "risk": "LOW",
            "objective": "e2e stall probe", "allowed_paths": ["work/"],
            "validators": [{"name": "v", "command": ["/usr/bin/true"]}],
            "model_timeout_seconds": 12,
            "model_inactivity_timeout_seconds": 2,
        }
        task_path = self.tmp / "task.json"
        task_path.write_text(json.dumps(task), encoding="utf-8")
        runs_dir = self.tmp / "runs"
        runs_dir.mkdir()
        started = time.monotonic()
        with (
            mock.patch.object(agentflow, "load_models", return_value=models),
            mock.patch.object(agentflow, "RUNS_DIR", runs_dir),
        ):
            code, run_dir, final = agentflow.run_task(task_path)
        elapsed = time.monotonic() - started
        self.assertEqual(2, code)
        self.assertEqual("STALL_DETECTED", final["verdict"])
        self.assertEqual("STOPPED", final["status"])
        # Stall fires long before the 12s absolute deadline.
        self.assertLess(elapsed, 10, f"e2e stall not prompt: {elapsed:.2f}s")
        # final.json is authoritative for the run outcome.
        persisted = json.loads(
            (run_dir / "final.json").read_text(encoding="utf-8")
        )
        self.assertEqual("STALL_DETECTED", persisted["verdict"])
        # Stall evidence was persisted before propagation.
        evidence = json.loads(
            (run_dir / "worker-cycle-0-failure.json").read_text(encoding="utf-8")
        )
        self.assertEqual("STALL_DETECTED", evidence["failure_code"])
        # Repository state preservation: no stray files, baseline captured.
        self.assertIn("final_baseline", final)
        status = agentflow.git(self.repo, ["status", "--porcelain"])
        self.assertEqual("", status.stdout.strip())
        self.assertTrue((self.repo / "work" / "keep.txt").is_file())


class EndToEndProgramStallTests(_WatchdogTestBase):
    """Area 28: run_program surfaces STALL_DETECTED the same way."""

    def test_program_failure_final_json(self):
        _init_git_repo(self.repo)
        architect_result = {
            "task_id": "wd-prog", "role": "architect", "harness": "opencode",
            "provider": "p", "model": "m", "variant": None,
            "files_changed": [], "validators": {}, "findings": [],
            "open_risks": [], "verdict": "PLAN_READY",
            "architect_plan": {
                "objective_interpretation": "probe",
                "implementation_steps": ["observe"],
                "invariants": [], "allowed_scope": [],
                "do_not_change": [], "validation_expectations": [],
                "known_risks": [],
            },
        }
        fake_architect = _write_exe(
            self.tmp / "fake_architect",
            "import json, sys\n"
            f"sys.stdout.write({json.dumps(architect_result)!r})\n"
            "sys.stdout.flush()\n",
        )
        fake_worker = _write_exe(
            self.tmp / "fake_worker_sleep",
            "import time\ntime.sleep(30)\n",
        )
        fake_reviewer = _write_exe(
            self.tmp / "fake_reviewer",
            "import json, sys\n"
            "sys.stdout.write(json.dumps({"
            "'task_id': 'wd-prog', 'role': 'reviewer', 'harness': 'opencode',"
            "'provider': 'p', 'model': 'm', 'variant': None,"
            "'files_changed': [], 'validators': {}, 'findings': [],"
            "'open_risks': [], 'verdict': 'PASS'}))\n"
            "sys.stdout.flush()\n",
        )

        def _profile(command: str, role: str) -> dict:
            if role == "architect":
                return {
                    "backend": "opencode", "command": str(command),
                    "provider": "p", "model": "architect-1",
                    "variant": None,
                    "agent": "agentflow-architect",
                    "available": True,
                    "eligible_roles": ["architect", "adjudicator"],
                }
            if role == "worker":
                return {
                    "backend": "opencode", "command": str(command),
                    "provider": "p", "model": "worker-1",
                    "variant": None,
                    "agent": "agentflow-worker",
                    "available": True,
                    "eligible_roles": ["worker"],
                }
            if role == "reviewer":
                return {
                    "backend": "opencode", "command": str(command),
                    "provider": "p", "model": "reviewer-1",
                    "variant": None,
                    "agent": "agentflow-reviewer",
                    "available": True,
                    "eligible_roles": ["reviewer"],
                }
            raise AssertionError(role)

        models = {
            "profiles": {
                "fake-architect": _profile(fake_architect, "architect"),
                "fake-worker": _profile(fake_worker, "worker"),
                "fake-reviewer": _profile(fake_reviewer, "reviewer"),
            },
            "routing": {"LOW": ["fake-worker"]},
        }
        spec_dir = self.tmp / "spec"
        spec_dir.mkdir()
        task = {
            "task_id": "wd-prog", "repo": str(self.repo), "risk": "LOW",
            "objective": "program stall probe", "allowed_paths": ["work/"],
            "validators": [{"name": "v", "command": ["/usr/bin/true"]}],
            "model_timeout_seconds": 12,
            "model_inactivity_timeout_seconds": 2,
        }
        (spec_dir / "task.json").write_text(json.dumps(task), encoding="utf-8")
        program = {
            "program_id": "wd-prog",
            "task": "task.json",
            "roles": {
                "architect": "fake-architect",
                "worker": "fake-worker",
                "reviewer": "fake-reviewer",
            },
            "max_corrections": 0,
        }
        program_path = spec_dir / "program.json"
        program_path.write_text(json.dumps(program), encoding="utf-8")
        runs_dir = self.tmp / "runs"
        runs_dir.mkdir()
        started = time.monotonic()
        with (
            mock.patch.object(agentflow, "load_models", return_value=models),
            mock.patch.object(agentflow, "RUNS_DIR", runs_dir),
        ):
            code, run_dir, final = agentflow.run_program(program_path)
        elapsed = time.monotonic() - started
        self.assertEqual(2, code)
        self.assertEqual("STALL_DETECTED", final["verdict"])
        self.assertLess(elapsed, 11, f"program stall not prompt: {elapsed:.2f}s")
        persisted = json.loads(
            (run_dir / "final.json").read_text(encoding="utf-8")
        )
        self.assertEqual("STALL_DETECTED", persisted["verdict"])
        evidence = json.loads(
            (run_dir / "worker-cycle-0-failure.json").read_text(encoding="utf-8")
        )
        self.assertEqual("STALL_DETECTED", evidence["failure_code"])
        self.assertIn("final_baseline", final)


if __name__ == "__main__":
    unittest.main()
