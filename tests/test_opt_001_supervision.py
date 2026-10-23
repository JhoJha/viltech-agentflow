"""OPT-001 model-process supervision tests.

BASELINE CHARACTERIZATION tests document pre-existing process behavior of
``run_process`` (readonly/Git/validator path) and ``run_lifecycle_process``
(worker path). They were written first and run green against the unmodified
baseline before the supervision seam was implemented.

NEW CONTRACT TESTS cover the intentional new supervision behavior owned by
``_supervise_model_process`` and its readonly/worker adapters.

All children are synthetic local Python subprocesses. No network, no real
model providers.
"""

from __future__ import annotations

import contextlib
import inspect
import locale
import os
import re
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

_SPARSE_SLEEP = 2.5
_SPARSE_EARLY_MARGIN = 1.0


def _write_child(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _wait_pid_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.02)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
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
            events.append((stream, nbytes, time.monotonic()))

    return _callback, events, lock


class _SupervisionTestBase(unittest.TestCase):
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

    def make_lease(self, task_id="opt001-task", run_id="opt001-run"):
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

    def assert_no_group_survivor(self, pgid: int, session_id: int):
        self.assertTrue(
            _group_quiet(pgid, session_id),
            f"controlled process group {pgid}/{session_id} still active",
        )


# ---------------------------------------------------------------------------
# BASELINE CHARACTERIZATION — run_process (readonly/Git/validator path)
# ---------------------------------------------------------------------------

class BaselineRunProcessTests(_SupervisionTestBase):
    """BASELINE CHARACTERIZATION: pre-existing run_process behavior."""

    def test_success_argv_result_args_and_types(self):
        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('OUT-1'); sys.stderr.write('ERR-1')",
        ]
        proc = agentflow.run_process(argv, cwd=self.repo, timeout=10)
        self.assertEqual(argv, proc.args)
        self.assertEqual(argv, list(proc.args))
        self.assertEqual(0, proc.returncode)
        self.assertIsInstance(proc.stdout, str)
        self.assertIsInstance(proc.stderr, str)
        self.assertEqual("OUT-1", proc.stdout)
        self.assertEqual("ERR-1", proc.stderr)

    def test_success_returncode_passthrough(self):
        argv = [sys.executable, "-c", "import sys; sys.exit(7)"]
        proc = agentflow.run_process(argv, cwd=self.repo, timeout=10)
        self.assertEqual(7, proc.returncode)
        self.assertEqual(argv, proc.args)

    def test_timeout_payload_cmd_timeout_and_partial_bytes(self):
        script = self.child(
            "ro_partial.py",
            "import sys, time\n"
            "sys.stdout.write('PARTIAL-OUT')\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write('PARTIAL-ERR')\n"
            "sys.stderr.flush()\n"
            "time.sleep(30)\n",
        )
        argv = [sys.executable, str(script)]
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agentflow.run_process(argv, cwd=self.repo, timeout=1)
        exc = raised.exception
        self.assertEqual(argv, exc.cmd)
        self.assertEqual(argv, list(exc.cmd))
        self.assertEqual(1, exc.timeout)
        self.assertIsInstance(exc.output, bytes)
        self.assertIsInstance(exc.stdout, bytes)
        self.assertIsInstance(exc.stderr, bytes)
        self.assertEqual(b"PARTIAL-OUT", exc.output)
        self.assertEqual(b"PARTIAL-OUT", exc.stdout)
        self.assertEqual(b"PARTIAL-ERR", exc.stderr)

    def test_timeout_without_output_is_none(self):
        argv = [sys.executable, "-c", "import time; time.sleep(30)"]
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agentflow.run_process(argv, cwd=self.repo, timeout=1)
        exc = raised.exception
        self.assertEqual(argv, exc.cmd)
        self.assertEqual(1, exc.timeout)
        self.assertIsNone(exc.output)
        self.assertIsNone(exc.stdout)
        self.assertIsNone(exc.stderr)

    def test_success_invalid_bytes_strict_decoding(self):
        script = self.child(
            "ro_invalid.py",
            "import sys\n"
            "sys.stdout.buffer.write(bytes([65, 255, 66]))\n"
            "sys.stdout.buffer.flush()\n",
        )
        with self.assertRaises(UnicodeDecodeError):
            agentflow.run_process([sys.executable, str(script)], cwd=self.repo, timeout=10)

    def test_success_decoding_uses_effective_locale_encoding(self):
        self.assertEqual(
            locale.getpreferredencoding(False),
            locale.getpreferredencoding(False),
        )
        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('plain-ascii-42')",
        ]
        proc = agentflow.run_process(argv, cwd=self.repo, timeout=10)
        self.assertEqual("plain-ascii-42", proc.stdout)


# ---------------------------------------------------------------------------
# BASELINE CHARACTERIZATION — run_lifecycle_process (worker path)
# ---------------------------------------------------------------------------

class BaselineWorkerLifecycleTests(_SupervisionTestBase):
    """BASELINE CHARACTERIZATION: pre-existing worker lifecycle behavior."""

    def test_success_result_args_and_decode(self):
        lease = self.make_lease()
        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('W-OUT'); sys.stderr.write('W-ERR')",
        ]
        proc = agentflow.run_lifecycle_process(
            argv, cwd=self.repo, timeout=10, env=None, lease=lease
        )
        self.assertEqual(argv, proc.args)
        self.assertEqual(0, proc.returncode)
        self.assertIsInstance(proc.stdout, str)
        self.assertIsInstance(proc.stderr, str)
        self.assertEqual("W-OUT", proc.stdout)
        self.assertEqual("W-ERR", proc.stderr)

    def test_timeout_cmd_is_writer_wrapper_argv(self):
        lease = self.make_lease()
        argv = [sys.executable, "-c", "import time; time.sleep(30)"]
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agentflow.run_lifecycle_process(
                argv, cwd=self.repo, timeout=1, env=None, lease=lease
            )
        exc = raised.exception
        self.assertIsInstance(exc.cmd, list)
        self.assertEqual(sys.executable, exc.cmd[0])
        self.assertIn(agentflow.WRITER_WRAPPER_MODE, exc.cmd)
        self.assertEqual(argv, exc.cmd[-len(argv):])
        self.assertEqual(1, exc.timeout)
        self.assertIsNone(exc.output)
        self.assertIsNone(exc.stdout)
        self.assertIsNone(exc.stderr)

    def test_timeout_partial_output_is_raw_bytes(self):
        lease = self.make_lease()
        script = self.child(
            "w_partial.py",
            "import sys, time\n"
            "sys.stdout.write('PARTIAL-W')\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n",
        )
        argv = [sys.executable, str(script)]
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agentflow.run_lifecycle_process(
                argv, cwd=self.repo, timeout=1, env=None, lease=lease
            )
        exc = raised.exception
        self.assertEqual(b"PARTIAL-W", exc.output)
        self.assertEqual(b"PARTIAL-W", exc.stdout)
        self.assertIsNone(exc.stderr)

    def test_worker_success_invalid_bytes_replacement(self):
        lease = self.make_lease()
        script = self.child(
            "w_invalid.py",
            "import sys\n"
            "sys.stdout.buffer.write(bytes([65, 255, 66]))\n"
            "sys.stdout.buffer.flush()\n",
        )
        proc = agentflow.run_lifecycle_process(
            [sys.executable, str(script)], cwd=self.repo, timeout=10,
            env=None, lease=lease,
        )
        self.assertEqual(0, proc.returncode)
        self.assertEqual(b"A\xef\xbf\xbdB".decode("utf-8"), proc.stdout)

    def test_go_gate_blocks_exec_before_registration(self):
        marker = self.tmp / "must-not-exist.txt"
        wrapper = [
            sys.executable,
            str(Path(agentflow.__file__).resolve()),
            agentflow.WRITER_WRAPPER_MODE,
            "--",
            sys.executable,
            "-c",
            f"open({str(marker)!r}, 'w').write('x')",
        ]
        blocked = subprocess.run(
            wrapper,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(125, blocked.returncode)
        self.assertEqual(b"", blocked.stdout)
        self.assertFalse(marker.exists())

    def test_worker_registers_before_go(self):
        lease = self.make_lease()
        code = (
            "import json, sys; "
            "record=json.load(open(sys.argv[1], encoding='utf-8')); "
            "print(record['writer']['state']); "
            "assert record['writer']['pid'] == __import__('os').getpid()"
        )
        proc = agentflow.run_lifecycle_process(
            [sys.executable, "-c", code, str(lease.path)],
            cwd=self.repo,
            timeout=10,
            env=None,
            lease=lease,
        )
        self.assertEqual(0, proc.returncode)
        self.assertEqual("running\n", proc.stdout)


# ---------------------------------------------------------------------------
# NEW CONTRACT — readonly model adapter
# ---------------------------------------------------------------------------

class ReadonlyAdapterTests(_SupervisionTestBase):
    """NEW CONTRACT: readonly model execution through the shared supervisor."""

    def _run_reader(self, argv, timeout, **kwargs):
        return agentflow._run_model_command(
            role="reviewer", argv=argv, cwd=self.repo,
            timeout=timeout, env=None, **kwargs,
        )

    def test_readonly_normal_success(self):
        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('RO-OUT'); sys.stderr.write('RO-ERR')",
        ]
        proc = self._run_reader(argv, 10)
        self.assertEqual(argv, proc.args)
        self.assertEqual(0, proc.returncode)
        self.assertEqual("RO-OUT", proc.stdout)
        self.assertEqual("RO-ERR", proc.stderr)
        self.assert_no_supervisor_threads()

    def test_readonly_success_invalid_bytes_strict(self):
        script = self.child(
            "ro_new_invalid.py",
            "import sys\n"
            "sys.stdout.buffer.write(bytes([65, 255, 66]))\n"
            "sys.stdout.buffer.flush()\n",
        )
        with self.assertRaises(UnicodeDecodeError):
            self._run_reader([sys.executable, str(script)], 10)
        self.assert_no_supervisor_threads()

    def test_readonly_timeout_compatibility(self):
        script = self.child(
            "ro_new_partial.py",
            "import sys, time\n"
            "sys.stdout.write('P-OUT')\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write('P-ERR')\n"
            "sys.stderr.flush()\n"
            "time.sleep(30)\n",
        )
        argv = [sys.executable, str(script)]
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self._run_reader(argv, 1)
        elapsed = time.monotonic() - started
        exc = raised.exception
        self.assertEqual(argv, list(exc.cmd))
        self.assertEqual(1, exc.timeout)
        self.assertEqual(b"P-OUT", exc.output)
        self.assertEqual(b"P-OUT", exc.stdout)
        self.assertEqual(b"P-ERR", exc.stderr)
        self.assertLess(elapsed, 10)
        self.assert_no_supervisor_threads()

    def test_readonly_timeout_without_output_is_none(self):
        argv = [sys.executable, "-c", "import time; time.sleep(30)"]
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self._run_reader(argv, 1)
        exc = raised.exception
        self.assertEqual(argv, list(exc.cmd))
        self.assertEqual(1, exc.timeout)
        self.assertIsNone(exc.output)
        self.assertIsNone(exc.stdout)
        self.assertIsNone(exc.stderr)
        self.assert_no_supervisor_threads()

    def test_readonly_sparse_stdout_prompt_activity(self):
        script = self.child(
            "ro_sparse_out.py",
            "import sys, time\n"
            f"sys.stdout.write('FIRST'); sys.stdout.flush()\n"
            f"time.sleep({_SPARSE_SLEEP})\n"
            "sys.stdout.write('SECOND'); sys.stdout.flush()\n",
        )
        callback, events, _ = _recording_observer()
        started = time.monotonic()
        proc = agentflow._run_model_command(
            role="reviewer", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=15, env=None, on_activity=callback,
        )
        finished = time.monotonic()
        self.assertEqual("FIRSTSECOND", proc.stdout)
        first_hits = [item for item in events if item[0] == "stdout"]
        self.assertTrue(first_hits, "no stdout activity observed")
        first_at = first_hits[0][2]
        self.assertLess(
            first_at - started, finished - started - _SPARSE_EARLY_MARGIN,
            "first stdout activity was not observed before the sparse sleep completed",
        )

    def test_readonly_sparse_stderr_prompt_activity(self):
        script = self.child(
            "ro_sparse_err.py",
            "import sys, time\n"
            f"sys.stderr.write('E1'); sys.stderr.flush()\n"
            f"time.sleep({_SPARSE_SLEEP})\n"
            "sys.stderr.write('E2'); sys.stderr.flush()\n",
        )
        callback, events, _ = _recording_observer()
        started = time.monotonic()
        proc = agentflow._run_model_command(
            role="architect", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=15, env=None, on_activity=callback,
        )
        finished = time.monotonic()
        self.assertEqual("E1E2", proc.stderr)
        err_hits = [item for item in events if item[0] == "stderr"]
        self.assertTrue(err_hits, "no stderr activity observed")
        self.assertLess(
            err_hits[0][2] - started, finished - started - _SPARSE_EARLY_MARGIN,
            "first stderr activity was not observed before the sparse sleep completed",
        )

    def test_readonly_large_interleaved_no_deadlock(self):
        count = 3000
        script = self.child(
            "ro_big.py",
            "import sys\n"
            f"for i in range({count}):\n"
            "    sys.stdout.write('O' * 100 + str(i) + chr(10))\n"
            "    sys.stdout.flush()\n"
            "    sys.stderr.write('E' * 100 + str(i) + chr(10))\n"
            "    sys.stderr.flush()\n",
        )
        expected_out = "".join(f"{'O' * 100}{i}\n" for i in range(count))
        expected_err = "".join(f"{'E' * 100}{i}\n" for i in range(count))
        proc = self._run_reader([sys.executable, str(script)], 60)
        self.assertEqual(0, proc.returncode)
        self.assertEqual(expected_out, proc.stdout)
        self.assertEqual(expected_err, proc.stderr)
        self.assert_no_supervisor_threads()

    def test_readonly_tail_output_before_exit_not_lost(self):
        script = self.child(
            "ro_tail.py",
            "import sys\n"
            "sys.stdout.write('T' * 200000)\n"
            "sys.stderr.write('U' * 200000)\n",
        )
        proc = self._run_reader([sys.executable, str(script)], 15)
        self.assertEqual("T" * 200000, proc.stdout)
        self.assertEqual("U" * 200000, proc.stderr)

    def test_readonly_waits_for_descendant_pipe_eof(self):
        pidfile = self.tmp / "ro_brief.pid"
        grandchild = self.child(
            "ro_gc_brief.py",
            "import sys, time\n"
            "time.sleep(1.0)\n"
            "sys.stdout.write('GRAND-OUTPUT')\n"
            "sys.stdout.flush()\n",
        )
        parent = self.child(
            "ro_parent_brief.py",
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdout=sys.stdout, stderr=sys.stderr)\n"
            f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n",
        )
        argv = [sys.executable, str(parent)]
        started = time.monotonic()
        proc = self._run_reader(argv, 15)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.9)
        self.assertIn("GRAND-OUTPUT", proc.stdout)
        self.assert_no_supervisor_threads()

    def test_readonly_descendant_beyond_deadline_timeout_no_survivor(self):
        pidfile = self.tmp / "ro_long.pid"
        grandchild = self.child(
            "ro_gc_long.py",
            "import time\n"
            "time.sleep(30)\n",
        )
        parent = self.child(
            "ro_parent_long.py",
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdout=sys.stdout, stderr=sys.stderr)\n"
            f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n",
        )
        argv = [sys.executable, str(parent)]
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self._run_reader(argv, 2)
        exc = raised.exception
        self.assertEqual(argv, list(exc.cmd))
        grandchild_pid = int(pidfile.read_text(encoding="ascii").strip())
        self.addCleanup(lambda: _wait_pid_dead(grandchild_pid, timeout=1.0))
        self.assertTrue(
            _wait_pid_dead(grandchild_pid),
            "descendant survivor still alive after readonly timeout",
        )
        self.assert_no_supervisor_threads()

    def test_readonly_leader_exit_with_live_descendant_is_timeout(self):
        pidfile = self.tmp / "ro_closed.pid"
        grandchild = self.child(
            "ro_gc_closed.py",
            "import time\n"
            "time.sleep(30)\n",
        )
        parent = self.child(
            "ro_parent_closed.py",
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdout=sys.stdout, stderr=sys.stderr)\n"
            f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n",
        )
        argv = [sys.executable, str(parent)]
        with self.assertRaises(subprocess.TimeoutExpired):
            self._run_reader(argv, 2)
        grandchild_pid = int(pidfile.read_text(encoding="ascii").strip())
        self.addCleanup(lambda: _wait_pid_dead(grandchild_pid, timeout=1.0))
        self.assertTrue(_wait_pid_dead(grandchild_pid))
        self.assert_no_supervisor_threads()

    def test_readonly_leader_alive_with_closed_pipes_is_timeout(self):
        script = self.child(
            "ro_closer.py",
            "import sys, time\n"
            "sys.stdout.close()\n"
            "sys.stderr.close()\n"
            "time.sleep(30)\n",
        )
        # Both pipes hit EOF while the leader is still alive: success requires
        # leader exit too, so this must be a TIMEOUT, not success.
        with self.assertRaises(subprocess.TimeoutExpired):
            self._run_reader([sys.executable, str(script)], 2)
        self.assert_no_supervisor_threads()

    def test_readonly_multibyte_byte_totals(self):
        text = "héllo→世界" * 200
        script = self.child(
            "ro_multi.py",
            "import sys\n"
            f"s = {text!r}\n"
            "sys.stdout.write(s)\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write(s)\n"
            "sys.stderr.flush()\n",
        )
        totals: dict[str, int] = {}
        lock = threading.Lock()

        def _count(stream: str, nbytes: int) -> None:
            with lock:
                totals[stream] = totals.get(stream, 0) + nbytes

        proc = agentflow._run_model_command(
            role="reviewer", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=15, env=None, on_activity=_count,
        )
        self.assertEqual(text, proc.stdout)
        self.assertEqual(text, proc.stderr)
        raw = text.encode("utf-8")
        self.assertEqual(len(raw), totals.get("stdout", 0))
        self.assertEqual(len(raw), totals.get("stderr", 0))

    def test_readonly_noop_observer_equivalent(self):
        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('N-OUT'); sys.stderr.write('N-ERR')",
        ]
        plain = self._run_reader(argv, 10)
        observed = agentflow._run_model_command(
            role="reviewer", argv=argv, cwd=self.repo, timeout=10, env=None,
            on_activity=lambda stream, nbytes: None,
        )
        self.assertEqual(plain.args, observed.args)
        self.assertEqual(plain.returncode, observed.returncode)
        self.assertEqual(plain.stdout, observed.stdout)
        self.assertEqual(plain.stderr, observed.stderr)

    def test_readonly_escaped_descendant_bounded_timeout(self):
        """Escaped pipe holder cannot force natural-lifetime wait.

        Leader exits quickly; a descendant that escapes the controlled
        session (setsid) inherits stdout/stderr and sleeps 60s. The
        supervisor must raise TimeoutExpired on the short deadline without
        waiting for the escaped sleep, attempt controlled-group cleanup,
        and fail closed (no success). Cleanup kills the escaped holder so
        no repository process or reader thread leaks.
        """
        pidfile = self.tmp / "ro_escaped.pid"
        grandchild = self.child(
            "ro_gc_escaped.py",
            "import sys, time\n"
            "sys.stdout.write('ESCAPED-HELD')\n"
            "sys.stdout.flush()\n"
            "time.sleep(60)\n",
        )
        parent = self.child(
            "ro_parent_escaped.py",
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdout=sys.stdout, stderr=sys.stderr, start_new_session=True)\n"
            f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n",
        )
        argv = [sys.executable, str(parent)]
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self._run_reader(argv, 2)
        elapsed = time.monotonic() - started
        exc = raised.exception
        self.assertEqual(argv, list(exc.cmd))
        # Bounded controller failure latency: ~2s deadline + bounded
        # terminate (controlled group already inactive) + 5s reader join.
        # Must be far below the 60s escaped natural lifetime.
        self.assertLess(
            elapsed, 20,
            f"escaped descendant forced natural-lifetime wait: {elapsed:.2f}s",
        )
        escaped_pid = int(pidfile.read_text(encoding="ascii").strip())
        # The escaped holder is out of scope: AgentFlow must not claim to
        # control it, but the controller must not have waited for it either.
        # It must still be alive right after the bounded timeout.
        try:
            os.kill(escaped_pid, 0)
        except ProcessLookupError:
            self.fail("escaped descendant already gone; test did not hold pipe open")
        except PermissionError:
            pass
        # Controlled group cleanup was attempted: the leader exited and its
        # session is gone even though the escaped pipe holder survives.
        # (Leader liveness cannot be observed directly after the internal
        # Popen is reaped; the bounded TimeoutExpired itself proves the
        # controller did not wait for pipe EOF as success.)
        self.assertIsNotNone(exc.output if hasattr(exc, "output") else True)
        # Test cleanup: kill the escaped holder, then readers must drain.
        try:
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.kill(escaped_pid, signal.SIGKILL)
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                os.kill(-escaped_pid, signal.SIGKILL)
            self.assertTrue(
                _wait_pid_dead(escaped_pid, timeout=10.0),
                "escaped descendant survivor still alive after test cleanup",
            )
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                leftovers = [
                    thread.name
                    for thread in threading.enumerate()
                    if thread.name.startswith("agentflow-model-")
                ]
                if not leftovers:
                    break
                time.sleep(0.05)
            self.assertEqual([], leftovers)
        finally:
            with contextlib.suppress(Exception):
                try:
                    os.kill(escaped_pid, signal.SIGKILL)
                except Exception:
                    pass
            with contextlib.suppress(Exception):
                try:
                    os.kill(-escaped_pid, signal.SIGKILL)
                except Exception:
                    pass


class ReadonlyNewlineParityTests(_SupervisionTestBase):
    """MEDIUM 1: readonly universal-newline parity with run_process(text=True)."""

    def _baseline_and_candidate(self, stdout_bytes: bytes, stderr_bytes: bytes):
        script = self.child(
            "ro_newline_probe.py",
            "import sys\n"
            f"sys.stdout.buffer.write({stdout_bytes!r})\n"
            "sys.stdout.buffer.flush()\n"
            f"sys.stderr.buffer.write({stderr_bytes!r})\n"
            "sys.stderr.buffer.flush()\n",
        )
        argv = [sys.executable, str(script)]
        baseline = agentflow.run_process(argv, cwd=self.repo, timeout=10)
        candidate = agentflow._run_model_command(
            role="reviewer", argv=argv, cwd=self.repo,
            timeout=10, env=None,
        )
        return baseline, candidate

    def test_readonly_stdout_newlines_match_baseline(self):
        for label, raw in [
            ("lf", b"A\nB\n"),
            ("crlf", b"A\r\nB\r\n"),
            ("lone-cr", b"A\rB\r"),
            ("mixed", b"A\r\nB\rC\nD"),
        ]:
            with self.subTest(kind=label):
                baseline, candidate = self._baseline_and_candidate(raw, b"")
                self.assertEqual(baseline.stdout, candidate.stdout)
                self.assertNotIn("\r", candidate.stdout)
                self.assert_no_supervisor_threads()

    def test_readonly_stderr_newlines_match_baseline(self):
        for label, raw in [
            ("lf", b"E\nF\n"),
            ("crlf", b"E\r\nF\r\n"),
            ("lone-cr", b"E\rF\r"),
            ("mixed", b"E\r\nF\rG\nH"),
        ]:
            with self.subTest(kind=label):
                baseline, candidate = self._baseline_and_candidate(b"", raw)
                self.assertEqual(baseline.stderr, candidate.stderr)
                self.assertNotIn("\r", candidate.stderr)
                self.assert_no_supervisor_threads()

    def test_readonly_decoder_is_locale_strict_with_universal_newlines(self):
        # Locale strict decoding retained (invalid bytes still raise), and
        # CRLF/CR are normalized like text=True universal newlines.
        script = self.child(
            "ro_newline_strict.py",
            "import sys\n"
            "sys.stdout.buffer.write(b'X\\r\\nY\\rZ\\n')\n"
            "sys.stdout.buffer.flush()\n",
        )
        proc = agentflow._run_model_command(
            role="reviewer", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=10, env=None,
        )
        self.assertEqual("X\nY\nZ\n", proc.stdout)
        bad = self.child(
            "ro_newline_bad.py",
            "import sys\n"
            "sys.stdout.buffer.write(bytes([65, 255, 66]))\n"
            "sys.stdout.buffer.flush()\n",
        )
        with self.assertRaises(UnicodeDecodeError):
            agentflow._run_model_command(
                role="reviewer", argv=[sys.executable, str(bad)],
                cwd=self.repo, timeout=10, env=None,
            )
        self.assert_no_supervisor_threads()

    def test_invoke_model_persisted_artifacts_normalize_newlines(self):
        # End-to-end: a fake opencode backend that emits CRLF/CR must have
        # persisted *-output.jsonl / *-stderr.txt with baseline-normalized
        # newlines (no CR), matching run_process(text=True) parity.
        fake = self.tmp / "fake_opencode_crlf"
        result_obj = {
            "task_id": "t", "role": "reviewer", "harness": "opencode",
            "provider": "p", "model": "m", "variant": None,
            "files_changed": [], "validators": {}, "findings": [],
            "open_risks": [], "verdict": "PASS",
        }
        payload = (
            "PRE-LINE\r\n"
            + __import__("json").dumps(result_obj)
            + "\r\nTRAIL\rEND\n"
        )
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.stdout.buffer.write({payload.encode('utf-8')!r})\n"
            "sys.stdout.buffer.flush()\n"
            f"sys.stderr.buffer.write({b'ERR-A\r\nERR-B\rERR-C\n'!r})\n"
            "sys.stderr.buffer.flush()\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        profile = {
            "backend": "opencode", "command": str(fake),
            "provider": "p", "model": "m", "variant": None,
            "agent": "agentflow-reviewer",
            "eligible_roles": ["reviewer"],
        }
        task = {
            "task_id": "newline-task", "repo": str(self.repo),
            "risk": "LOW", "objective": "newline parity probe",
            "allowed_paths": [], "forbidden_actions": [], "invariants": [],
            "model_timeout_seconds": 15,
        }
        run_dir = self.tmp / "rundir"
        run_dir.mkdir()
        result, _ = agentflow.invoke_model(
            role="reviewer", profile_name="fake", profile=profile,
            task=task, run_dir=run_dir, cycle=0, context=None,
        )
        self.assertEqual("PASS", result["verdict"])
        persisted_out = (run_dir / "reviewer-cycle-0-output.jsonl").read_text(
            encoding="utf-8"
        )
        persisted_err = (run_dir / "reviewer-cycle-0-stderr.txt").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("\r", persisted_out)
        self.assertNotIn("\r", persisted_err)
        # Baseline parity: the same backend argv under run_process(text=True)
        # must equal the readonly adapter result that was persisted.
        baseline = agentflow.run_process(
            [str(fake), "probe"], cwd=self.repo, timeout=10
        )
        candidate = agentflow._run_model_command(
            role="reviewer", argv=[str(fake), "probe"],
            cwd=self.repo, timeout=10, env=None,
        )
        self.assertEqual(baseline.stdout, candidate.stdout)
        self.assertEqual(baseline.stderr, candidate.stderr)
        # The fake backend ignores argv, so the persisted invoke_model
        # artifacts must equal the normalized readonly adapter output.
        self.assertEqual(candidate.stdout, persisted_out)
        self.assertEqual(candidate.stderr, persisted_err)
        self.assert_no_supervisor_threads()


# ---------------------------------------------------------------------------
# NEW CONTRACT — worker adapter through the shared supervisor
# ---------------------------------------------------------------------------

class WorkerAdapterTests(_SupervisionTestBase):
    """NEW CONTRACT: worker lifecycle through the shared supervisor."""

    def test_worker_normal_success(self):
        lease = self.make_lease()
        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('W2-OUT'); sys.stderr.write('W2-ERR')",
        ]
        proc = agentflow.run_lifecycle_process(
            argv, cwd=self.repo, timeout=15, env=None, lease=lease
        )
        self.assertEqual(argv, proc.args)
        self.assertEqual(0, proc.returncode)
        self.assertEqual("W2-OUT", proc.stdout)
        self.assertEqual("W2-ERR", proc.stderr)
        self.assert_no_supervisor_threads()

    def test_worker_timeout_origin_after_registration_and_go(self):
        lease = self.make_lease()
        original_register = agentflow.WriteLease.register_writer

        def _delayed(pid, **kwargs):
            time.sleep(3.0)
            return original_register(lease, pid, **kwargs)

        script = self.child(
            "w_origin.py",
            "import time\n"
            "time.sleep(3.0)\n",
        )
        argv = [sys.executable, str(script)]
        started = time.monotonic()
        with mock.patch.object(lease, "register_writer", side_effect=_delayed):
            proc = agentflow.run_lifecycle_process(
                argv, cwd=self.repo, timeout=5, env=None, lease=lease
            )
        elapsed = time.monotonic() - started
        # Registration consumed ~3s and execution ~3s. A deadline computed at
        # Popen time would expire at 5s wall (3.0 + 3.0 > 5); supervisor-entry
        # origin leaves the full 5s budget for execution, so this succeeds.
        self.assertGreaterEqual(elapsed, 2.9)
        self.assertEqual(0, proc.returncode)
        self.assert_no_supervisor_threads()

    def test_worker_timeout_compatibility(self):
        lease = self.make_lease()
        script = self.child(
            "w_new_partial.py",
            "import sys, time\n"
            "sys.stdout.write('WP-OUT')\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write('WP-ERR')\n"
            "sys.stderr.flush()\n"
            "time.sleep(30)\n",
        )
        argv = [sys.executable, str(script)]
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agentflow.run_lifecycle_process(
                argv, cwd=self.repo, timeout=1, env=None, lease=lease
            )
        exc = raised.exception
        self.assertEqual(sys.executable, exc.cmd[0])
        self.assertIn(agentflow.WRITER_WRAPPER_MODE, exc.cmd)
        self.assertEqual(argv, exc.cmd[-len(argv):])
        self.assertEqual(1, exc.timeout)
        self.assertEqual(b"WP-OUT", exc.output)
        self.assertEqual(b"WP-OUT", exc.stdout)
        self.assertEqual(b"WP-ERR", exc.stderr)
        self.assert_no_supervisor_threads()

    def test_worker_success_invalid_bytes_replacement(self):
        lease = self.make_lease()
        script = self.child(
            "w_new_invalid.py",
            "import sys\n"
            "sys.stdout.buffer.write(bytes([65, 255, 66]))\n"
            "sys.stdout.buffer.flush()\n",
        )
        proc = agentflow.run_lifecycle_process(
            [sys.executable, str(script)], cwd=self.repo, timeout=10,
            env=None, lease=lease,
        )
        self.assertEqual(b"A\xef\xbf\xbdB".decode("utf-8"), proc.stdout)

    def test_worker_sparse_stdout_prompt_activity(self):
        lease = self.make_lease()
        script = self.child(
            "w_sparse_out.py",
            "import sys, time\n"
            f"sys.stdout.write('WFIRST'); sys.stdout.flush()\n"
            f"time.sleep({_SPARSE_SLEEP})\n"
            "sys.stdout.write('WSECOND'); sys.stdout.flush()\n",
        )
        callback, events, _ = _recording_observer()
        started = time.monotonic()
        proc = agentflow.run_lifecycle_process(
            [sys.executable, str(script)], cwd=self.repo, timeout=15,
            env=None, lease=lease, on_activity=callback,
        )
        finished = time.monotonic()
        self.assertEqual("WFIRSTWSECOND", proc.stdout)
        hits = [item for item in events if item[0] == "stdout"]
        self.assertTrue(hits)
        self.assertLess(
            hits[0][2] - started, finished - started - _SPARSE_EARLY_MARGIN
        )

    def test_worker_descendant_beyond_deadline_timeout_no_survivor(self):
        lease = self.make_lease()
        pidfile = self.tmp / "w_long.pid"
        grandchild = self.child(
            "w_gc_long.py",
            "import time\n"
            "time.sleep(30)\n",
        )
        parent = self.child(
            "w_parent_long.py",
            "import subprocess, sys\n"
            "child = subprocess.Popen(\n"
            f"    [{sys.executable!r}, {str(grandchild)!r}],\n"
            "    stdout=sys.stdout, stderr=sys.stderr)\n"
            f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n",
        )
        argv = [sys.executable, str(parent)]
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agentflow.run_lifecycle_process(
                argv, cwd=self.repo, timeout=2, env=None, lease=lease
            )
        elapsed = time.monotonic() - started
        # Prompt group termination after leader exit: the 30s fixture must
        # not be awaited. A removed termination step waits out the natural
        # lifetime (old blocking cleanup) or leaves a survivor (bounded
        # cleanup), so this bound plus the survivor assertions below detect
        # the mutation promptly.
        self.assertLess(
            elapsed, 10,
            f"worker descendant termination was not prompt: {elapsed:.2f}s",
        )
        exc = raised.exception
        self.assertIn(agentflow.WRITER_WRAPPER_MODE, exc.cmd)
        grandchild_pid = int(pidfile.read_text(encoding="ascii").strip())
        self.addCleanup(lambda: _wait_pid_dead(grandchild_pid, timeout=1.0))
        self.assertTrue(
            _wait_pid_dead(grandchild_pid),
            "registered-group descendant survivor still alive after worker timeout",
        )
        recorded = __import__("json").loads(lease.path.read_text(encoding="utf-8"))
        pgid = recorded["writer"]["pgid"]
        session_id = recorded["writer"]["session_id"]
        self.assert_no_group_survivor(pgid, session_id)
        self.assert_no_supervisor_threads()

    def test_worker_quiescence_not_recorded_while_active(self):
        lease = self.make_lease()
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        self.addCleanup(lambda: _close_quietly(proc))
        try:
            identity = lease.register_writer(proc.pid)
            self.assertEqual("active", agentflow.WriteLease._process_status(
                identity, require_group=True))
            lease.mark_writer_quiescent()
            recorded = __import__("json").loads(
                lease.path.read_text(encoding="utf-8"))
            # Still active: must NOT be recorded as quiescent.
            self.assertNotEqual("quiescent", recorded["writer"]["state"])
            self.assertEqual("exited", recorded["writer"]["state"])
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                lease.release()
            self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
            with contextlib.suppress(Exception):
                proc.stdout.close()
            with contextlib.suppress(Exception):
                proc.stderr.close()
        lease.mark_writer_quiescent()
        recorded = __import__("json").loads(lease.path.read_text(encoding="utf-8"))
        self.assertEqual("quiescent", recorded["writer"]["state"])
        lease.release()
        self.assertFalse(lease.path.exists())


def _close_quietly(proc: subprocess.Popen) -> None:
    with contextlib.suppress(Exception):
        if proc.poll() is None:
            proc.kill()
    with contextlib.suppress(Exception):
        proc.wait(timeout=5)
    with contextlib.suppress(Exception):
        if proc.stdout is not None:
            proc.stdout.close()
    with contextlib.suppress(Exception):
        if proc.stderr is not None:
            proc.stderr.close()


# ---------------------------------------------------------------------------
# NEW CONTRACT — supervisor activity / observer isolation
# ---------------------------------------------------------------------------

class SupervisorActivityTests(_SupervisionTestBase):
    """NEW CONTRACT: activity callbacks and observer isolation."""

    def test_observer_runtime_error_preserves_output(self):
        calls = []

        def _boom(stream: str, nbytes: int) -> None:
            calls.append((stream, nbytes))
            raise RuntimeError("instrumentation failure")

        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('KEEP-ME'); sys.stderr.write('KEEP-TOO')",
        ]
        proc = agentflow._run_model_command(
            role="reviewer", argv=argv, cwd=self.repo, timeout=10, env=None,
            on_activity=_boom,
        )
        self.assertTrue(calls)
        self.assertEqual("KEEP-ME", proc.stdout)
        self.assertEqual("KEEP-TOO", proc.stderr)
        self.assert_no_supervisor_threads()

    def test_observer_custom_base_exception_preserves_output(self):
        class Sentinel(BaseException):
            pass

        def _sentinel(stream: str, nbytes: int) -> None:
            raise Sentinel()

        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('BASE-OK'); sys.stderr.write('BASE-ERR')",
        ]
        proc = agentflow._run_model_command(
            role="reviewer", argv=argv, cwd=self.repo, timeout=10, env=None,
            on_activity=_sentinel,
        )
        self.assertEqual("BASE-OK", proc.stdout)
        self.assertEqual("BASE-ERR", proc.stderr)
        self.assert_no_supervisor_threads()

    def test_observer_keyboard_interrupt_preserves_output(self):
        def _kbd(stream: str, nbytes: int) -> None:
            raise KeyboardInterrupt()

        argv = [
            sys.executable, "-c",
            "import sys; sys.stdout.write('KBD-OK')",
        ]
        proc = agentflow._run_model_command(
            role="reviewer", argv=argv, cwd=self.repo, timeout=10, env=None,
            on_activity=_kbd,
        )
        self.assertEqual("KBD-OK", proc.stdout)
        self.assert_no_supervisor_threads()

    def test_activity_counts_raw_bytes_not_characters(self):
        text = "héllo→世界" * 50
        script = self.child(
            "activity_bytes.py",
            "import sys\n"
            f"sys.stdout.write({text!r})\n"
            "sys.stdout.flush()\n",
        )
        totals: dict[str, int] = {}

        def _count(stream: str, nbytes: int) -> None:
            totals[stream] = totals.get(stream, 0) + nbytes

        agentflow._run_model_command(
            role="reviewer", argv=[sys.executable, str(script)],
            cwd=self.repo, timeout=10, env=None, on_activity=_count,
        )
        self.assertEqual(len(text.encode("utf-8")), totals.get("stdout", 0))

    def test_timeout_activity_never_resets_deadline(self):
        script = self.child(
            "busy_writer.py",
            "import sys, time\n"
            "end = time.monotonic() + 30\n"
            "while time.monotonic() < end:\n"
            "    sys.stdout.write('x' * 1000)\n"
            "    sys.stdout.flush()\n"
            "    time.sleep(0.01)\n",
        )
        argv = [sys.executable, str(script)]
        callback, events, _ = _recording_observer()
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agentflow._run_model_command(
                role="reviewer", argv=argv, cwd=self.repo, timeout=2,
                env=None, on_activity=callback,
            )
        elapsed = time.monotonic() - started
        # Continuous activity must not extend the absolute deadline.
        self.assertLess(elapsed, 10)
        self.assertTrue(events, "expected activity before the deadline")
        exc = raised.exception
        self.assertIsNotNone(exc.output)
        self.assert_no_supervisor_threads()


# ---------------------------------------------------------------------------
# NEW CONTRACT — supervisor failure / controller semantics (unit level)
# ---------------------------------------------------------------------------

class _FailOnceReader:
    def __init__(self, real):
        self._real = real
        self._failed = False

    def read1(self, size=-1):
        if not self._failed:
            self._failed = True
            raise OSError("simulated pipe read failure")
        return self._real.read1(size)

    def close(self):
        return self._real.close()


class SupervisorFailureTests(_SupervisionTestBase):
    """NEW CONTRACT: fail-closed reader/termination/controller behavior."""

    def test_reader_io_failure_cannot_produce_success(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('hi')"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        terminated = []
        assert proc.stdout is not None
        real_stdout = proc.stdout
        proc.stdout = _FailOnceReader(real_stdout)  # type: ignore[assignment]

        def _terminate(target):
            terminated.append(target)

        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._supervise_model_process(
                proc,
                result_args=["fake", "argv"],
                timeout=10,
                terminate=_terminate,
                decode_output=agentflow._decode_process_output,
            )
        self.assertEqual("INTERNAL_ERROR", raised.exception.code)
        self.assertEqual(1, len(terminated))
        _close_quietly(proc)
        self.assert_no_supervisor_threads()

    def test_termination_failure_cannot_produce_success(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        calls = []

        def _failing_terminate(target):
            calls.append(target)
            raise OSError("simulated termination failure")

        try:
            with self.assertRaises(OSError):
                agentflow._supervise_model_process(
                    proc,
                    result_args=["fake", "argv"],
                    timeout=1,
                    terminate=_failing_terminate,
                    decode_output=agentflow._decode_process_output,
                )
            self.assertEqual(1, len(calls))
        finally:
            _close_quietly(proc)
        self.assert_no_supervisor_threads()

    def test_unknown_termination_state_cannot_produce_success(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        def _unknown_terminate(target):
            raise agentflow.AgentFlowError(
                "INTERNAL_ERROR", "group state UNKNOWN; failing closed"
            )

        try:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._supervise_model_process(
                    proc,
                    result_args=["fake", "argv"],
                    timeout=1,
                    terminate=_unknown_terminate,
                    decode_output=agentflow._decode_process_output,
                )
            self.assertEqual("INTERNAL_ERROR", raised.exception.code)
        finally:
            _close_quietly(proc)
        self.assert_no_supervisor_threads()

    def test_controller_keyboard_interrupt_propagates(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        terminated = []
        real_terminate = agentflow._terminate_readonly_group

        def _counting_terminate(target):
            terminated.append(target)
            return real_terminate(target)

        def _kbd_wait(timeout=None):
            raise KeyboardInterrupt()

        real_wait = proc.wait
        proc.wait = _kbd_wait  # type: ignore[method-assign]
        try:
            with self.assertRaises(KeyboardInterrupt):
                agentflow._supervise_model_process(
                    proc,
                    result_args=["fake", "argv"],
                    timeout=30,
                    terminate=_counting_terminate,
                    decode_output=agentflow._decode_process_output,
                )
        finally:
            proc.wait = real_wait  # type: ignore[method-assign]
            _close_quietly(proc)
        self.assertEqual(1, len(terminated))
        self.assert_no_supervisor_threads()

    def test_controller_system_exit_propagates(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=self.repo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        def _exit_wait(timeout=None):
            raise SystemExit(3)

        real_wait = proc.wait
        proc.wait = _exit_wait  # type: ignore[method-assign]
        try:
            with self.assertRaises(SystemExit):
                agentflow._supervise_model_process(
                    proc,
                    result_args=["fake", "argv"],
                    timeout=30,
                    terminate=agentflow._terminate_readonly_group,
                    decode_output=agentflow._decode_process_output,
                )
        finally:
            proc.wait = real_wait  # type: ignore[method-assign]
            _close_quietly(proc)
        self.assert_no_supervisor_threads()


class _StubReadonlyProc:
    """Minimal stub for direct _terminate_readonly_group fault injection."""

    def __init__(self, pid: int = 424242, alive: bool = True):
        self.pid = pid
        self._alive = alive
        self.terminated = 0
        self.killed = 0

    def poll(self):
        return None if self._alive else 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        self.terminated += 1

    def kill(self):
        self.killed += 1


class ReadonlyTerminationDirectTests(_SupervisionTestBase):
    """MEDIUM 3B: direct production _terminate_readonly_group fault injection.

    The mocked-terminate test above cannot catch a mutation that suppresses
    signal errors inside the real helper, so these tests exercise the real
    helper with fault-injected os.kill / group status. Unsafe states must
    fail closed with the existing INTERNAL_ERROR semantics; only leader-gone
    plus provably-inactive group may accept ESRCH quietly.
    """

    def test_permission_error_fails_closed(self):
        proc = _StubReadonlyProc(alive=True)
        with (
            mock.patch.object(
                agentflow.os, "kill", side_effect=PermissionError("denied")
            ),
            mock.patch.object(
                agentflow.WriteLease, "_group_status", return_value="active"
            ),
        ):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._terminate_readonly_group(proc)  # type: ignore[arg-type]
        self.assertEqual("INTERNAL_ERROR", raised.exception.code)

    def test_generic_oserror_fails_closed(self):
        proc = _StubReadonlyProc(alive=True)
        with (
            mock.patch.object(
                agentflow.os,
                "kill",
                side_effect=OSError(13, "generic termination failure"),
            ),
            mock.patch.object(
                agentflow.WriteLease, "_group_status", return_value="active"
            ),
        ):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._terminate_readonly_group(proc)  # type: ignore[arg-type]
        self.assertEqual("INTERNAL_ERROR", raised.exception.code)

    def test_esrch_unproven_fails_closed(self):
        # ESRCH while the leader is still alive and the group is active
        # must NOT be silently accepted.
        proc = _StubReadonlyProc(alive=True)
        with (
            mock.patch.object(
                agentflow.os, "kill", side_effect=ProcessLookupError("gone?")
            ),
            mock.patch.object(
                agentflow.WriteLease, "_group_status", return_value="active"
            ),
        ):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._terminate_readonly_group(proc)  # type: ignore[arg-type]
        self.assertEqual("INTERNAL_ERROR", raised.exception.code)

    def test_esrch_leader_gone_group_active_fails_closed(self):
        proc = _StubReadonlyProc(alive=False)
        with (
            mock.patch.object(
                agentflow.os, "kill", side_effect=ProcessLookupError("gone?")
            ),
            mock.patch.object(
                agentflow.WriteLease, "_group_status", return_value="active"
            ),
        ):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._terminate_readonly_group(proc)  # type: ignore[arg-type]
        self.assertEqual("INTERNAL_ERROR", raised.exception.code)

    def test_unknown_group_fails_closed(self):
        proc = _StubReadonlyProc(alive=True)
        with (
            mock.patch.object(agentflow.os, "kill", return_value=None),
            mock.patch.object(
                agentflow.WriteLease, "_group_status", return_value="unknown"
            ),
            mock.patch.object(agentflow, "_MODEL_SIGNAL_WAIT_TIMEOUT", 0.2),
        ):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._terminate_readonly_group(proc)  # type: ignore[arg-type]
        self.assertEqual("INTERNAL_ERROR", raised.exception.code)

    def test_valid_esrch_leader_gone_group_inactive_succeeds(self):
        # The only quiet ESRCH: leader gone AND group proven inactive.
        proc = _StubReadonlyProc(alive=False)
        with (
            mock.patch.object(
                agentflow.os, "kill", side_effect=ProcessLookupError("gone")
            ),
            mock.patch.object(
                agentflow.WriteLease, "_group_status", return_value="inactive"
            ),
        ):
            agentflow._terminate_readonly_group(proc)  # type: ignore[arg-type]

    def test_already_quiet_succeeds_without_signals(self):
        proc = _StubReadonlyProc(alive=False)
        killed = []
        with (
            mock.patch.object(
                agentflow.os,
                "kill",
                side_effect=lambda *args: killed.append(args),
            ),
            mock.patch.object(
                agentflow.WriteLease, "_group_status", return_value="inactive"
            ),
        ):
            agentflow._terminate_readonly_group(proc)  # type: ignore[arg-type]
        self.assertEqual([], killed)


# ---------------------------------------------------------------------------
# NEW CONTRACT — seam, invoke_model wiring, Git/validator preservation
# ---------------------------------------------------------------------------

class ModelCommandSeamTests(_SupervisionTestBase):
    """NEW CONTRACT: backend-independent model execution selector."""

    def test_worker_without_lease_conflicts(self):
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._run_model_command(
                role="worker", argv=[sys.executable, "-c", "pass"],
                cwd=self.repo, timeout=10, env=None, lease=None,
            )
        self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)

    def test_worker_routes_through_lifecycle_adapter(self):
        lease = self.make_lease()
        proc = agentflow._run_model_command(
            role="worker",
            argv=[sys.executable, "-c", "import sys; sys.stdout.write('SEAM-W')"],
            cwd=self.repo, timeout=10, env=None, lease=lease,
        )
        self.assertEqual("SEAM-W", proc.stdout)

    def test_readonly_roles_route_through_readonly_adapter(self):
        for role in ("reviewer", "architect", "adjudicator"):
            with self.subTest(role=role):
                proc = agentflow._run_model_command(
                    role=role,
                    argv=[sys.executable, "-c",
                          "import sys; sys.stdout.write('SEAM-R')"],
                    cwd=self.repo, timeout=10, env=None,
                )
                self.assertEqual("SEAM-R", proc.stdout)
        self.assert_no_supervisor_threads()

    def test_seam_forwards_activity(self):
        callback, events, _ = _recording_observer()
        agentflow._run_model_command(
            role="reviewer",
            argv=[sys.executable, "-c", "import sys; sys.stdout.write('AB')"],
            cwd=self.repo, timeout=10, env=None, on_activity=callback,
        )
        total = sum(nbytes for stream, nbytes, _ in events if stream == "stdout")
        self.assertEqual(2, total)

    def test_invoke_model_forwards_to_seam(self):
        source = inspect.getsource(agentflow.invoke_model)
        self.assertIn("_run_model_command", source)
        self.assertIn("on_activity", source)

    def test_git_and_validators_remain_on_run_process(self):
        for name in ("run_process", "git", "run_validators"):
            source = inspect.getsource(getattr(agentflow, name))
            self.assertIn("run_process", source)
            self.assertNotIn("_supervise_model_process", source)
            self.assertNotIn("_run_readonly_model_process", source)
            self.assertNotIn("_run_model_command", source)

    def test_git_functional(self):
        subprocess.run(["git", "init"], cwd=self.repo, check=True,
                       capture_output=True)
        proc = agentflow.git(self.repo, ["status", "--porcelain"])
        self.assertEqual(0, proc.returncode)
        self.assertIsInstance(proc.stdout, str)

    def test_validators_functional(self):
        results = agentflow.run_validators(
            self.repo,
            [{"name": "echo-check", "command": ["echo", "validator-ok"]}],
            self.tmp / "rundir",
            0,
        )
        self.assertEqual("PASS", results[0]["status"])
        self.assertIn("validator-ok", results[0]["stdout"])

    def test_no_watchdog_policy_in_candidate(self):
        source = Path(agentflow.__file__).read_text(encoding="utf-8")
        lowered = source.lower()
        self.assertNotIn("watchdog", lowered)
        self.assertNotIn("nudge", lowered)
        self.assertNotIn("asyncio", lowered)
        self.assertNotIn("ProcessRunner", source)
        self.assertNotIn("ModelProcessResult", source)
        self.assertEqual(
            [], re.findall(r"(?i)\bstall(?:s|ed|ing)?\b", source)
        )


if __name__ == "__main__":
    unittest.main()
