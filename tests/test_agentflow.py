import contextlib
import io
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


DEAD_PID = 2**31 - 1  # above Linux pid_max, so /proc has no entry for it


class AgentFlowTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.repo = Path(self._temp.name) / "repo"
        self.repo.mkdir()
        self.locks = Path(self._temp.name) / "locks"
        patch = mock.patch.object(agentflow, "LOCKS_DIR", self.locks)
        patch.start()
        self.addCleanup(patch.stop)

    def lease_path(self) -> Path:
        return agentflow.WriteLease(self.repo, "probe", "probe").path

    def write_lease(self, payload) -> Path:
        path = self.lease_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def own_identity(self, **overrides) -> dict:
        identity = {
            "pid": os.getpid(),
            "boot_id": agentflow.read_boot_id(),
            "process_start_time": agentflow.process_start_time(os.getpid()),
        }
        identity.update(overrides)
        return identity

    def stale_payload(self, **overrides) -> dict:
        controller = self.own_identity()
        controller.update({key: overrides[key] for key in ("pid", "boot_id", "process_start_time") if key in overrides})
        payload = {
            "format": agentflow.WriteLease.FORMAT,
            "task_id": "stale",
            "run_id": "stale-run",
            "token": "stale-token",
            "acquired_at": "2026-01-01T00:00:00+00:00",
            "repo": str(self.repo),
            "controller": controller,
            "controller_pid": controller["pid"],
            "controller_boot_id": controller["boot_id"],
            "controller_process_start_time": controller["process_start_time"],
            "controller_start_time": controller["process_start_time"],
            "pid": controller["pid"],
            "boot_id": controller["boot_id"],
            "process_start_time": controller["process_start_time"],
        }
        agentflow.WriteLease._set_writer_payload(payload, agentflow.WriteLease._writer_payload("not_started"))
        payload.update({key: value for key, value in overrides.items() if key not in {"pid", "boot_id", "process_start_time"}})
        return payload

    def assert_fails_closed(self, path: Path, lease: agentflow.WriteLease) -> None:
        before = path.read_bytes()
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            lease.acquire()
        self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)
        self.assertFalse(lease.acquired)
        self.assertEqual(before, path.read_bytes())
        self.assertEqual([], list(self.locks.glob("*.stale-*.json")))

    # --- baseline/validator helpers ---------------------------------------

    def test_baseline_drift_detected(self):
        actual = {
            "branch": "main",
            "head": "abc",
            "dirty_paths": ["a.py"],
            "untracked_paths": [],
            "git_diff_check": {"exit_code": 0},
        }
        mismatch = agentflow.baseline_mismatches(actual, {"head": "different"})
        self.assertEqual(1, len(mismatch))
        self.assertIn("head", mismatch[0])

    def test_failed_validator_is_observed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            results = agentflow.run_validators(
                root,
                [{"name": "intentional-failure", "command": ["/usr/bin/false"]}],
                root,
                0,
            )
            self.assertEqual("FAIL", results[0]["status"])
            self.assertNotEqual(0, results[0]["exit_code"])

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

    # --- lease basics ------------------------------------------------------

    def test_write_lease_excludes_second_writer(self):
        first = agentflow.WriteLease(self.repo, "one", "run-one")
        second = agentflow.WriteLease(self.repo, "two", "run-two")
        first.acquire()
        try:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                second.acquire()
            self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)
            self.assertFalse(second.acquired)
        finally:
            first.release()

    def test_acquired_lease_records_verifiable_identity(self):
        lease = agentflow.WriteLease(self.repo, "one", "run-one")
        lease.acquire()
        try:
            recorded = json.loads(lease.path.read_text(encoding="utf-8"))
            self.assertEqual(agentflow.WriteLease.FORMAT, recorded["format"])
            self.assertEqual(os.getpid(), recorded["pid"])
            self.assertEqual(agentflow.read_boot_id(), recorded["boot_id"])
            self.assertEqual(agentflow.process_start_time(os.getpid()), recorded["process_start_time"])
            self.assertTrue(recorded["token"])
            self.assertEqual("not_started", recorded["writer"]["state"])
            self.assertIsNone(recorded["writer"]["pid"])
        finally:
            lease.release()
        self.assertFalse(lease.path.exists())

    def test_legacy_format_two_lease_fails_closed(self):
        path = self.write_lease({
            "format": 2,
            "pid": os.getpid(),
            "boot_id": agentflow.read_boot_id(),
            "process_start_time": agentflow.process_start_time(os.getpid()),
            "token": "legacy-token",
        })
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_pipe_wrapper_requires_go_before_exec(self):
        wrapper = [
            sys.executable,
            str(Path(agentflow.__file__).resolve()),
            agentflow.WRITER_WRAPPER_MODE,
            "--",
            sys.executable,
            "-c",
            "print('fake-worker-ran')",
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
        allowed = subprocess.run(
            wrapper,
            input=agentflow.WRITER_GO,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(0, allowed.returncode)
        self.assertEqual("fake-worker-ran\n", allowed.stdout.decode())

    def test_worker_lifecycle_registers_before_go_and_releases(self):
        lease = agentflow.WriteLease(self.repo, "one", "run-one")
        lease.acquire()
        try:
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
            recorded = json.loads(lease.path.read_text(encoding="utf-8"))
            self.assertEqual("quiescent", recorded["writer"]["state"])
            self.assertEqual(recorded["writer"]["pid"], recorded["writer"]["pgid"])
            self.assertEqual(recorded["writer"]["pid"], recorded["writer"]["session_id"])
        finally:
            lease.release()

    def _start_fake_writer(self, lease: agentflow.WriteLease):
        lease.prepare_writer()
        proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(agentflow.__file__).resolve()),
                agentflow.WRITER_WRAPPER_MODE,
                "--",
                sys.executable,
                "-c",
                "import time; time.sleep(30)",
            ],
            cwd=self.repo,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        identity = lease.register_writer(proc.pid)
        self.assertIsNotNone(proc.stdin)
        proc.stdin.write(agentflow.WRITER_GO)
        proc.stdin.flush()
        proc.stdin.close()
        proc.stdin = None
        return proc, identity

    def test_release_retains_lease_while_writer_group_is_active(self):
        lease = agentflow.WriteLease(self.repo, "one", "run-one")
        lease.acquire()
        proc, identity = self._start_fake_writer(lease)
        try:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                lease.release()
            self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)
            self.assertTrue(lease.path.exists())
            self.assertTrue(lease.acquired)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            proc.communicate()
            lease.mark_writer_quiescent()
            lease.release()
        self.assertFalse(lease.path.exists())

    def test_dead_controller_and_active_writer_block_recovery(self):
        original = agentflow.WriteLease(self.repo, "old", "old-run")
        original.acquire()
        proc, _ = self._start_fake_writer(original)
        payload = json.loads(original.path.read_text(encoding="utf-8"))
        dead_controller = {
            "pid": DEAD_PID,
            "boot_id": payload["controller"]["boot_id"],
            "process_start_time": 1,
        }
        payload["controller"] = dead_controller
        payload["controller_pid"] = DEAD_PID
        payload["controller_process_start_time"] = 1
        payload["controller_start_time"] = 1
        payload["pid"] = DEAD_PID
        payload["process_start_time"] = 1
        original.path.write_text(json.dumps(payload), encoding="utf-8")
        contender = agentflow.WriteLease(self.repo, "new", "new-run")
        try:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                contender.acquire()
            self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)
            self.assertEqual([], list(self.locks.glob("*.stale-*.json")))
            proc.terminate()
            proc.wait(timeout=10)
            proc.communicate()
            contender.acquire()
            self.assertEqual(1, len(list(self.locks.glob("*.stale-*.json"))))
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)
                proc.communicate()
            if contender.acquired:
                contender.release()

    def test_dead_writer_leader_with_live_descendant_blocks_recovery(self):
        original = agentflow.WriteLease(self.repo, "old", "old-run")
        original.acquire()
        marker = self.repo / "descendant.pid"
        stop_marker = self.repo / "descendant.stop"
        child_pid = None
        proc = None
        identity = None
        contender = agentflow.WriteLease(self.repo, "new", "new-run")
        try:
            original.prepare_writer()
            descendant_code = (
                "import pathlib, sys, time; "
                "stop=pathlib.Path(sys.argv[1]); "
                "while not stop.exists(): time.sleep(0.01)"
            )
            worker_code = (
                "import pathlib, subprocess, sys; "
                f"child=subprocess.Popen([sys.executable, '-c', {descendant_code!r}, sys.argv[2]]); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')"
            )
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(agentflow.__file__).resolve()),
                    agentflow.WRITER_WRAPPER_MODE,
                    "--",
                    sys.executable,
                    "-c",
                    worker_code,
                    str(marker),
                    str(stop_marker),
                ],
                cwd=self.repo,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            identity = original.register_writer(proc.pid)
            self.assertIsNotNone(proc.stdin)
            proc.stdin.write(agentflow.WRITER_GO)
            proc.stdin.flush()
            proc.stdin.close()
            proc.stdin = None

            deadline = time.monotonic() + 10
            child_pid = None
            last_content: str = "<missing>"
            while time.monotonic() < deadline:
                try:
                    last_content = marker.read_text(encoding="ascii").strip()
                except FileNotFoundError:
                    last_content = "<missing>"
                except OSError:
                    last_content = "<unreadable>"
                else:
                    if last_content.isdigit() and int(last_content) > 0:
                        child_pid = int(last_content)
                        break
                time.sleep(0.01)
            self.assertIsNotNone(
                child_pid,
                f"descendant marker never held a valid pid within 10s (last={last_content!r})",
            )
            child_pgid, child_session = agentflow.process_group_identity(child_pid)
            self.assertEqual(identity["pgid"], child_pgid)
            self.assertEqual(identity["session_id"], child_session)
            proc.wait(timeout=10)
            self.assertEqual("inactive", agentflow.WriteLease._process_status(identity, require_group=True))
            self.assertEqual("active", agentflow.WriteLease._group_status(
                identity["pgid"], identity["session_id"]
            ))

            payload = json.loads(original.path.read_text(encoding="utf-8"))
            dead_controller = {
                "pid": DEAD_PID,
                "boot_id": payload["controller"]["boot_id"],
                "process_start_time": 1,
            }
            payload["controller"] = dead_controller
            payload["controller_pid"] = DEAD_PID
            payload["controller_process_start_time"] = 1
            payload["controller_start_time"] = 1
            payload["pid"] = DEAD_PID
            payload["process_start_time"] = 1
            original.path.write_text(json.dumps(payload), encoding="utf-8")
            stale_bytes = original.path.read_bytes()

            with self.assertRaises(agentflow.AgentFlowError) as raised:
                contender.acquire()
            self.assertEqual("WRITE_LEASE_CONFLICT", raised.exception.code)
            self.assertFalse(contender.acquired)
            self.assertEqual(stale_bytes, original.path.read_bytes())
            self.assertEqual([], list(self.locks.glob("*.stale-*.json")))

            stop_marker.write_text("stop", encoding="ascii")
            deadline = time.monotonic() + 15
            stable_inactive = 0
            while time.monotonic() < deadline:
                state = agentflow.WriteLease._group_status(identity["pgid"], identity["session_id"])
                if state == "inactive":
                    stable_inactive += 1
                    if stable_inactive >= 2:
                        break
                else:
                    # "active" means the group is still alive; "unknown" is a
                    # transient fail-closed observation that discards any prior
                    # single confirmation. Neither ever counts as quiescence.
                    stable_inactive = 0
                time.sleep(0.02)
            self.assertEqual(
                2,
                stable_inactive,
                f"writer group never reached stable quiescence within 15s "
                f"for pgid={identity['pgid']}",
            )
            contender.acquire()
            self.assertTrue(contender.acquired)
            self.assertEqual(1, len(list(self.locks.glob("*.stale-*.json"))))
        finally:
            stop_marker.write_text("stop", encoding="ascii")
            if identity is not None and child_pid is not None:
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    if agentflow.pid_exists(child_pid):
                        os.kill(-identity["pgid"], signal.SIGTERM)
            if proc is not None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=10)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.communicate(timeout=10)
            if contender.acquired:
                contender.release()

    def test_unverifiable_writer_group_blocks_recovery(self):
        original = agentflow.WriteLease(self.repo, "old", "old-run")
        original.acquire()
        proc, _ = self._start_fake_writer(original)
        try:
            proc.terminate()
            proc.wait(timeout=10)
            proc.communicate()
            payload = json.loads(original.path.read_text(encoding="utf-8"))
            payload["controller"] = {
                "pid": DEAD_PID,
                "boot_id": payload["controller"]["boot_id"],
                "process_start_time": 1,
            }
            payload["controller_pid"] = DEAD_PID
            payload["controller_process_start_time"] = 1
            payload["controller_start_time"] = 1
            payload["pid"] = DEAD_PID
            payload["process_start_time"] = 1
            original.path.write_text(json.dumps(payload), encoding="utf-8")

            contender = agentflow.WriteLease(self.repo, "new", "new-run")
            with mock.patch.object(agentflow.WriteLease, "_group_status", return_value="unknown"):
                self.assert_fails_closed(original.path, contender)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)
                proc.communicate()

    # --- fail-closed leases ------------------------------------------------

    def test_legacy_identity_free_lease_fails_closed(self):
        payload = {"task_id": "legacy", "run_id": "legacy", "pid": os.getpid(), "token": "legacy-token"}
        path = self.write_lease(payload)
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_malformed_json_lease_fails_closed(self):
        path = self.lease_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not-json", encoding="utf-8")
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_deeply_nested_lease_fails_closed(self):
        path = self.lease_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        depth = 10_000
        path.write_text('{"token":' + "[" * depth + "]" * depth + "}", encoding="utf-8")
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_non_object_lease_fails_closed(self):
        path = self.write_lease([1, 2, 3])
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_missing_pid_fails_closed(self):
        payload = self.stale_payload()
        payload.pop("pid")
        path = self.write_lease(payload)
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_non_integer_pid_fails_closed(self):
        path = self.write_lease(self.stale_payload(pid="not-a-pid"))
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_boolean_pid_fails_closed(self):
        path = self.write_lease(self.stale_payload(pid=True))
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_out_of_range_pid_fails_closed(self):
        path = self.write_lease(self.stale_payload(pid=agentflow.MAX_LINUX_PID + 1))
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_pid_beyond_kernel_range_is_unverifiable(self):
        self.assertIsNone(agentflow.pid_exists(agentflow.MAX_LINUX_PID + 1))
        self.assertIsNone(agentflow.pid_exists(10**30))

    def test_missing_start_time_fails_closed(self):
        payload = self.stale_payload()
        payload.pop("process_start_time")
        path = self.write_lease(payload)
        self.assert_fails_closed(path, agentflow.WriteLease(self.repo, "new", "run"))

    def test_unreadable_boot_id_fails_closed(self):
        path = self.write_lease(self.stale_payload())
        lease = agentflow.WriteLease(self.repo, "new", "run")
        with mock.patch.object(agentflow, "read_boot_id", side_effect=OSError("missing")):
            self.assert_fails_closed(path, lease)

    def test_unreadable_process_identity_fails_closed(self):
        path = self.write_lease(self.stale_payload())
        lease = agentflow.WriteLease(self.repo, "new", "run")
        with mock.patch.object(agentflow, "process_start_time", side_effect=PermissionError("denied")):
            self.assert_fails_closed(path, lease)

    def test_unreadable_lease_fails_closed(self):
        path = self.write_lease(self.stale_payload())
        lease = agentflow.WriteLease(self.repo, "new", "run")
        with mock.patch.object(agentflow.WriteLease, "_read_lease", side_effect=PermissionError("denied")):
            self.assert_fails_closed(path, lease)

    def test_pid_alive_without_stat_fails_closed(self):
        path = self.write_lease(self.stale_payload())
        lease = agentflow.WriteLease(self.repo, "new", "run")
        with mock.patch.object(agentflow, "process_start_time", side_effect=FileNotFoundError):
            with mock.patch.object(agentflow, "pid_exists", return_value=True):
                self.assert_fails_closed(path, lease)

    # --- provably stale recovery ------------------------------------------

    def test_dead_pid_lease_is_archived_and_recovered(self):
        path = self.write_lease(self.stale_payload(pid=DEAD_PID, process_start_time=1))
        original = path.read_bytes()
        lease = agentflow.WriteLease(self.repo, "new", "run")
        lease.acquire()
        try:
            archives = sorted(self.locks.glob("*.stale-*.json"))
            self.assertEqual(1, len(archives))
            self.assertEqual(original, archives[0].read_bytes())
            recorded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(os.getpid(), recorded["pid"])
            self.assertNotEqual("stale-token", recorded["token"])
        finally:
            lease.release()
        self.assertFalse(path.exists())

    def test_start_time_mismatch_is_archived_and_recovered(self):
        live_start = agentflow.process_start_time(os.getpid())
        path = self.write_lease(self.stale_payload(process_start_time=live_start + 1))
        original = path.read_bytes()
        lease = agentflow.WriteLease(self.repo, "new", "run")
        lease.acquire()
        try:
            archives = sorted(self.locks.glob("*.stale-*.json"))
            self.assertEqual(1, len(archives))
            self.assertEqual(original, archives[0].read_bytes())
            self.assertNotEqual("stale-token", json.loads(path.read_text(encoding="utf-8"))["token"])
        finally:
            lease.release()

    def test_boot_id_mismatch_is_archived_and_recovered(self):
        stale_boot = "stale-" + agentflow.read_boot_id()
        path = self.write_lease(self.stale_payload(boot_id=stale_boot))
        original = path.read_bytes()
        lease = agentflow.WriteLease(self.repo, "new", "run")
        lease.acquire()
        try:
            archives = sorted(self.locks.glob("*.stale-*.json"))
            self.assertEqual(1, len(archives))
            self.assertEqual(original, archives[0].read_bytes())
            self.assertNotEqual("stale-token", json.loads(path.read_text(encoding="utf-8"))["token"])
        finally:
            lease.release()

    def test_archive_creation_never_overwrites_prior_archive(self):
        path = self.write_lease(self.stale_payload(pid=DEAD_PID, process_start_time=1))
        original = path.read_bytes()
        self.locks.mkdir(parents=True, exist_ok=True)
        first_archive = self.locks / "fixed.stale-1.json"
        first_archive.write_bytes(b"prior archive")
        second_archive = self.locks / "fixed.stale-2.json"
        lease = agentflow.WriteLease(self.repo, "new", "run")
        candidates = iter([first_archive, second_archive])
        with mock.patch.object(lease, "_archive_path", lambda: next(candidates)):
            lease.acquire()
        try:
            self.assertEqual(b"prior archive", first_archive.read_bytes())
            self.assertEqual(original, second_archive.read_bytes())
            self.assertNotEqual("stale-token", json.loads(path.read_text(encoding="utf-8"))["token"])
        finally:
            lease.release()

    def test_two_threads_cannot_both_recover_a_stale_lease(self):
        path = self.write_lease(self.stale_payload(pid=DEAD_PID, process_start_time=1))
        original = path.read_bytes()
        barrier = threading.Barrier(2)
        acquired: list[agentflow.WriteLease] = []
        conflicts: list[str] = []
        failures: list[Exception] = []

        def contender() -> None:
            lease = agentflow.WriteLease(self.repo, "thread", "run")
            barrier.wait(timeout=10)
            try:
                lease.acquire()
            except agentflow.AgentFlowError as exc:
                conflicts.append(exc.code)
            except Exception as exc:  # pragma: no cover - defensive
                failures.append(exc)
            else:
                acquired.append(lease)

        threads = [threading.Thread(target=contender) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        try:
            self.assertEqual([], failures)
            self.assertEqual(1, len(acquired))
            self.assertEqual(["WRITE_LEASE_CONFLICT"], conflicts)
            archives = sorted(self.locks.glob("*.stale-*.json"))
            self.assertEqual(1, len(archives))
            self.assertEqual(original, archives[0].read_bytes())
            self.assertTrue(path.exists())
        finally:
            for lease in acquired:
                lease.release()

    # --- token-safe release ------------------------------------------------

    def test_release_rejects_foreign_token(self):
        lease = agentflow.WriteLease(self.repo, "one", "run")
        lease.acquire()
        payload = json.loads(lease.path.read_text(encoding="utf-8"))
        payload["token"] = "foreign-token"
        lease.path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            lease.release()
        self.assertEqual("WRITE_LEASE_OWNERSHIP_LOST", raised.exception.code)
        self.assertEqual("foreign-token", json.loads(lease.path.read_text(encoding="utf-8"))["token"])
        self.assertTrue(lease.path.exists())

    def test_release_after_external_removal_reports_ownership_lost(self):
        lease = agentflow.WriteLease(self.repo, "one", "run")
        lease.acquire()
        lease.path.unlink()
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            lease.release()
        self.assertEqual("WRITE_LEASE_OWNERSHIP_LOST", raised.exception.code)
        self.assertFalse(lease.acquired)

    def test_release_without_acquire_is_a_noop(self):
        lease = agentflow.WriteLease(self.repo, "one", "run")
        lease.release()
        self.assertFalse(lease.path.exists())


class StatusDiagnosticsTests(unittest.TestCase):
    """Read-only AF-001 lease/run diagnostics. No sleeps, no real children."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.repo = Path(self._temp.name) / "repo"
        self.repo.mkdir()
        self.locks = Path(self._temp.name) / "locks"
        self.runs = Path(self._temp.name) / "runs"
        self.runs.mkdir()
        locks_patch = mock.patch.object(agentflow, "LOCKS_DIR", self.locks)
        locks_patch.start()
        self.addCleanup(locks_patch.stop)
        runs_patch = mock.patch.object(agentflow, "RUNS_DIR", self.runs)
        runs_patch.start()
        self.addCleanup(runs_patch.stop)

    def lease_path(self) -> Path:
        return agentflow.WriteLease(self.repo, "probe", "probe").path

    def snapshot(self) -> dict[str, bytes]:
        found: dict[str, bytes] = {}
        for base in (self.locks, self.runs):
            if not base.exists():
                continue
            for item in sorted(base.rglob("*")):
                if item.is_file():
                    found[str(item.relative_to(Path(self._temp.name)))] = item.read_bytes()
        return found

    def assert_read_only(self, before: dict[str, bytes]) -> None:
        self.assertEqual(before, self.snapshot())
        self.assertEqual([], list(self.locks.glob("*.stale-*.json")))
        self.assertEqual([], list(self.locks.glob("*.breakglass-*.json")))

    def stale_payload(self, **overrides) -> dict:
        controller = {
            "pid": os.getpid(),
            "boot_id": agentflow.read_boot_id(),
            "process_start_time": agentflow.process_start_time(os.getpid()),
        }
        controller.update({k: overrides[k] for k in ("pid", "boot_id", "process_start_time") if k in overrides})
        payload = {
            "format": agentflow.WriteLease.FORMAT,
            "task_id": "stale",
            "run_id": "stale-run",
            "token": "stale-token",
            "acquired_at": "2026-01-01T00:00:00+00:00",
            "repo": str(self.repo),
            "controller": controller,
            "controller_pid": controller["pid"],
            "controller_boot_id": controller["boot_id"],
            "controller_process_start_time": controller["process_start_time"],
            "controller_start_time": controller["process_start_time"],
            "pid": controller["pid"],
            "boot_id": controller["boot_id"],
            "process_start_time": controller["process_start_time"],
        }
        agentflow.WriteLease._set_writer_payload(payload, agentflow.WriteLease._writer_payload("not_started"))
        payload.update({k: v for k, v in overrides.items() if k not in {"pid", "boot_id", "process_start_time"}})
        return payload

    def write_lease(self, payload) -> Path:
        path = self.lease_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def make_run(self, run_id: str, *, task=True, invocation=False, result=False,
                 validators=False, final=None) -> Path:
        run_dir = self.runs / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        if task:
            (run_dir / "task.json").write_text(
                json.dumps({"task_id": "stale", "repo": str(self.repo.resolve())}), encoding="utf-8")
        if invocation:
            (run_dir / "worker-cycle-0-invocation.json").write_text(
                json.dumps({"profile": "primary_worker", "role": "worker"}), encoding="utf-8")
        if result:
            (run_dir / "worker-cycle-0-result.json").write_text(
                json.dumps({"verdict": "PASS"}), encoding="utf-8")
        if validators:
            (run_dir / "validators-cycle-0.json").write_text(json.dumps([]), encoding="utf-8")
        if final is not None:
            (run_dir / "final.json").write_text(json.dumps(final), encoding="utf-8")
        return run_dir

    def test_status_no_lease(self):
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("NO_LEASE", report["lease"]["classification"])
        self.assertEqual("NO_RUN", report["run"]["phase"])
        self.assertIn("No lease", report["recommendation"])
        self.assert_read_only(before)

    def test_status_active_live_owner(self):
        lease = agentflow.WriteLease(self.repo, "one", "run-one")
        lease.acquire()
        try:
            before = self.snapshot()
            report = agentflow.diagnose_repo(self.repo)
            self.assertEqual("ACTIVE", report["lease"]["classification"])
            self.assertIn("DO NOT launch", report["recommendation"])
            self.assertNotIn("token", report["lease"]["owner"].keys())
            self.assertTrue(report["lease"]["owner"]["token_present"])
            self.assert_read_only(before)
        finally:
            lease.release()

    def test_status_stale_dead_owner(self):
        self.write_lease(self.stale_payload(pid=DEAD_PID, process_start_time=1))
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("STALE", report["lease"]["classification"])
        self.assertIn("never recovers automatically", report["recommendation"])
        self.assert_read_only(before)

    def test_status_malformed_lease(self):
        path = self.lease_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not-json", encoding="utf-8")
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("MALFORMED", report["lease"]["classification"])
        self.assert_read_only(before)
        legacy = self.stale_payload()
        legacy["format"] = 2
        self.write_lease(legacy)
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("MALFORMED", report["lease"]["classification"])
        self.assert_read_only(self.snapshot())

    def test_status_unknown_unverifiable_group(self):
        # Dead controller, but the recorded writer group identity cannot be
        # verified: the recorded pgid matches no live group member while the
        # leader pid is alive under a different group, so _process_status
        # reports unknown and _group_status reports inactive -> UNKNOWN.
        # Fully deterministic: no mocks, no sleeps, no real children.
        payload = self.stale_payload(pid=DEAD_PID, process_start_time=1)
        me = {
            "pid": os.getpid(),
            "boot_id": agentflow.read_boot_id(),
            "process_start_time": agentflow.process_start_time(os.getpid()),
        }
        _, sid = agentflow.process_group_identity(os.getpid())
        identity = dict(me, pgid=DEAD_PID, session_id=sid)
        agentflow.WriteLease._set_writer_payload(
            payload, agentflow.WriteLease._writer_payload("running", identity))
        self.write_lease(payload)
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("UNKNOWN", report["lease"]["classification"])
        self.assertIn("FAIL CLOSED", report["recommendation"])
        self.assert_read_only(before)

    def test_status_run_invocation_without_final(self):
        self.write_lease(self.stale_payload(pid=DEAD_PID, process_start_time=1))
        self.make_run("stale-run", invocation=True)
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("STALE", report["lease"]["classification"])
        self.assertEqual("exact", report["run"]["association"])
        self.assertEqual("IN_PROGRESS", report["run"]["phase"])
        self.assert_read_only(before)

    def test_status_run_finalized(self):
        self.make_run("stale-run", invocation=True, result=True, validators=True,
                      final={"task_id": "stale", "verdict": "HUMAN_GATE", "status": "SUCCESS"})
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("NO_LEASE", report["lease"]["classification"])
        self.assertEqual("heuristic-latest", report["run"]["association"])
        self.assertEqual("FINALIZED", report["run"]["phase"])
        self.assertEqual("HUMAN_GATE", report["run"]["artifacts"]["final_verdict"])
        self.assert_read_only(before)

    def test_status_run_artifacts_inconsistent_fails_closed(self):
        run_dir = self.runs / "odd-run"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "baseline.json").write_text(json.dumps({"repo": "x"}), encoding="utf-8")
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("hinted", report["run"]["association"])
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assert_read_only(before)

    def test_status_cli_is_read_only(self):
        self.write_lease(self.stale_payload(pid=DEAD_PID, process_start_time=1))
        self.make_run("stale-run", invocation=True)
        before = self.snapshot()
        with mock.patch.object(sys, "argv", ["agentflow.py", "status", "--repo", str(self.repo)]):
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                code = agentflow.main()
        self.assertEqual(0, code)
        self.assertIn('"classification": "STALE"', captured.getvalue())
        self.assert_read_only(before)

    def test_status_diagnose_alias_is_read_only(self):
        self.write_lease(self.stale_payload(pid=DEAD_PID, process_start_time=1))
        before = self.snapshot()
        with mock.patch.object(sys, "argv", ["agentflow.py", "diagnose", "--repo", str(self.repo)]):
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                code = agentflow.main()
        self.assertEqual(0, code)
        self.assertIn('"classification": "STALE"', captured.getvalue())
        self.assert_read_only(before)

    def test_status_lease_unreadable_is_unknown(self):
        path = self.lease_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir()
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo)
        self.assertEqual("UNKNOWN", report["lease"]["classification"])
        self.assertIn("FAIL CLOSED", report["recommendation"])
        self.assert_read_only(before)

    def test_status_final_malformed_is_unknown(self):
        run_dir = self.make_run("odd-run", invocation=True)
        (run_dir / "final.json").write_text("{not-json", encoding="utf-8")
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertTrue(report["run"]["run_hint_found"])
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assert_read_only(before)

    def test_status_final_unreadable_is_unknown(self):
        run_dir = self.make_run("odd-run", invocation=True)
        (run_dir / "final.json").write_text(json.dumps({"verdict": "HUMAN_GATE"}), encoding="utf-8")
        (run_dir / "final.json").unlink()
        (run_dir / "final.json").mkdir()
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assert_read_only(before)

    def test_status_final_missing_verdict_is_unknown(self):
        self.make_run("odd-run", invocation=True, final={"task_id": "stale", "status": "STOPPED"})
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assert_read_only(before)

    def test_status_final_null_verdict_is_unknown(self):
        self.make_run("odd-run", invocation=True, final={"task_id": "stale", "verdict": None})
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assert_read_only(self.snapshot())

    def test_status_final_invalid_verdict_is_unknown(self):
        self.make_run("odd-run", invocation=True, final={"task_id": "stale", "verdict": 123})
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.make_run("odd-run", invocation=True, final={"task_id": "stale", "verdict": "   "})
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.make_run("odd-run", invocation=True, final=["not", "an", "object"])
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assert_read_only(self.snapshot())

    def test_status_final_running_is_in_progress(self):
        self.make_run("odd-run", invocation=True, final={"task_id": "stale", "verdict": "RUNNING"})
        report = agentflow.diagnose_repo(self.repo, run_hint="odd-run")
        self.assertEqual("IN_PROGRESS", report["run"]["phase"])
        self.assert_read_only(self.snapshot())

    def test_status_run_hint_missing_has_no_fallback(self):
        self.make_run("real-run", invocation=True,
                      final={"task_id": "stale", "verdict": "HUMAN_GATE", "status": "SUCCESS"})
        before = self.snapshot()
        report = agentflow.diagnose_repo(self.repo, run_hint="ghost-run")
        self.assertFalse(report["run"]["run_hint_found"])
        self.assertEqual("ghost-run", report["run"]["run_hint"])
        self.assertEqual("none", report["run"]["association"])
        self.assertIsNone(report["run"]["run_dir"])
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assertNotIn("real-run", json.dumps(report["run"]))
        self.assertTrue(any("hint" in conflict for conflict in report["conflicts"]))
        self.assert_read_only(before)

    def test_status_run_hint_traversal_rejected(self):
        self.make_run("real-run", invocation=True)
        report = agentflow.diagnose_repo(self.repo, run_hint="../evil")
        self.assertFalse(report["run"]["run_hint_found"])
        self.assertIsNone(report["run"]["run_dir"])
        self.assertEqual("UNKNOWN", report["run"]["phase"])
        self.assert_read_only(self.snapshot())

    def test_status_token_redaction_all_states(self):
        secret = "tok-SECRET-abc123"

        def diagnose_unchanged(**kwargs):
            before = self.snapshot()
            report = agentflow.diagnose_repo(self.repo, **kwargs)
            self.assertEqual(before, self.snapshot())
            self.assertNotIn(secret, json.dumps(report))
            return report

        payload = self.stale_payload(pid=DEAD_PID, process_start_time=1)
        payload["token"] = secret
        self.write_lease(payload)
        report = diagnose_unchanged()
        self.assertEqual("STALE", report["lease"]["classification"])
        self.assertNotIn("token", report["lease"]["owner"].keys())
        self.assertTrue(report["lease"]["owner"]["token_present"])
        self.assertEqual([], list(self.locks.glob("*.stale-*.json")))

        live = agentflow.WriteLease(self.repo, "one", "run-one")
        live.acquire()  # legitimately archives the planted stale lease above
        try:
            live_token = json.loads(live.path.read_bytes().decode("utf-8"))["token"]
            report = diagnose_unchanged()
            self.assertEqual("ACTIVE", report["lease"]["classification"])
            self.assertNotIn("token", report["lease"]["owner"].keys())
            self.assertNotIn(live_token, json.dumps(report))
        finally:
            live.release()

        path = self.lease_path()
        path.write_text("{token: " + secret + "!!!", encoding="utf-8")
        report = diagnose_unchanged()
        self.assertEqual("MALFORMED", report["lease"]["classification"])

    def test_lease_key_parity_with_write_lease(self):
        # Finding 7 guard WITHOUT touching runtime: the status helper must
        # derive byte-for-byte the same lease file name WriteLease uses.
        expected = agentflow.WriteLease(self.repo, "parity", "parity").path
        self.assertEqual(str(expected), str(agentflow.lease_path_for_repo(self.repo)))
        self.assertEqual(
            str(expected), str(agentflow.lease_path_for_repo(str(self.repo.resolve()))))

    def test_status_classifications_vocabulary(self):
        self.assertEqual(
            ("NO_LEASE", "ACTIVE", "STALE", "UNKNOWN", "MALFORMED"),
            agentflow.STATUS_CLASSIFICATIONS)
        report = agentflow.diagnose_repo(self.repo)
        self.assertIn(report["lease"]["classification"], agentflow.STATUS_CLASSIFICATIONS)


class F05RolePolicyTests(unittest.TestCase):
    """F-05 centralized role eligibility, permission containment, independence."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.tmp = Path(self._temp.name)
        self.repo = self.tmp / "repo"
        (self.repo / "src").mkdir(parents=True)
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self.task = {
            "task_id": "t-f05", "repo": str(self.repo), "risk": "LOW",
            "objective": "obj", "allowed_paths": ["src/"],
            "validators": [], "invariants": [], "forbidden_actions": [],
            "expected_baseline": {},
        }

    @staticmethod
    def _profile(model="p/alpha-1", agent="agentflow-worker",
                 roles=("worker",), backend="opencode"):
        return {
            "backend": backend, "command": "/usr/bin/true", "provider": "p",
            "model": model, "variant": None, "agent": agent,
            "available": True, "eligible_roles": list(roles),
        }

    def _control(self, models, fallback_profiles):
        return agentflow.ExecutionControl(
            queue_id="q", queue_run_dir=self.tmp / "queue",
            item_dir=self.tmp / "item",
            budgets={"wall_clock_seconds": 10, "model_calls": 1,
                     "retries": 0, "fallbacks": 0, "corrections": 0},
            fallback_profiles=fallback_profiles, models=models,
        )

    # -- role eligibility -------------------------------------------------

    def test_role_permission_class_is_centralized(self):
        self.assertEqual("write", agentflow._role_permission_class("worker"))
        for role in ("reviewer", "architect", "adjudicator"):
            with self.subTest(role=role):
                self.assertEqual("read_only", agentflow._role_permission_class(role))
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._role_permission_class("planner")
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_worker_only_profile_rejected_for_every_readonly_role(self):
        profile = self._profile(roles=("worker",))
        for role in ("reviewer", "architect", "adjudicator"):
            with self.subTest(role=role):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._check_role_eligible(profile, role)
                self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_readonly_agent_cannot_fill_worker_role(self):
        profile = self._profile(agent="agentflow-reviewer", roles=("reviewer",))
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._check_role_eligible(profile, "worker")
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_write_capable_agent_rejected_without_declaration(self):
        # Missing role metadata fails closed: a write-capable OpenCode agent
        # can never fill a read-only role even without any declaration.
        profile = {
            "backend": "opencode", "command": "opencode", "provider": "p",
            "model": "p/qwen-1", "variant": None,
            "agent": "agentflow-worker", "available": True,
        }
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._check_role_eligible(profile, "reviewer")
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_missing_eligible_roles_fails_closed(self):
        # No undeclared-profile exception exists: every role resolution path
        # requires valid semantic eligibility metadata.
        profile = self._profile()
        del profile["eligible_roles"]
        for role in ("worker", "reviewer", "architect", "adjudicator"):
            with self.subTest(role=role):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._check_role_eligible(profile, role)
                self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_malformed_eligible_roles_fails_closed(self):
        for bad in ("worker", {"worker": True}, 7, True):
            profile = self._profile()
            profile["eligible_roles"] = bad
            for role in ("worker", "reviewer"):
                with self.subTest(bad=bad, role=role):
                    with self.assertRaises(agentflow.AgentFlowError) as raised:
                        agentflow._check_role_eligible(profile, role)
                    self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_undeclared_arbitrary_opencode_agent_cannot_be_reviewer(self):
        # Reproduction of F05-FINDING-01: a custom write-capable agent must
        # not be accepted merely because it is not a known write agent.
        profile = {
            "backend": "opencode", "command": "opencode", "provider": "custom",
            "model": "custom/model-1", "agent": "developer", "available": True,
        }
        for role in ("reviewer", "architect", "adjudicator"):
            with self.subTest(role=role):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._check_role_eligible(profile, role)
                self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_declared_custom_opencode_agent_cannot_be_readonly_role(self):
        # Declaring read-only intent does not launder an arbitrary agent.
        profile = self._profile(
            model="custom/model-1", agent="developer", roles=("reviewer",))
        for role in ("reviewer", "architect", "adjudicator"):
            with self.subTest(role=role):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._check_role_eligible(profile, role)
                self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_worker_role_rejects_custom_and_readonly_agents(self):
        # Write roles require an explicitly approved write-capable agent.
        for profile in (
            self._profile(agent="agentflow-reviewer", roles=("worker",)),
            self._profile(agent="developer", roles=("worker",)),
            self._profile(agent="agentflow-architect", roles=("worker",)),
        ):
            with self.subTest(agent=profile["agent"]):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._check_role_eligible(profile, "worker")
                self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_declared_codex_worker_remains_eligible_without_agent(self):
        profile = {
            "backend": "codex", "command": "codex", "provider": "openai",
            "model": "gpt-5.6-terra", "variant": "high", "agent": None,
            "available": True, "eligible_roles": ["worker"],
        }
        agentflow._check_role_eligible(profile, "worker")
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._check_role_eligible(profile, "reviewer")
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_codex_architect_profile_rejected_for_reviewer(self):
        profile = {
            "backend": "codex", "command": "codex", "provider": "openai",
            "model": "gpt-5.6-sol", "variant": "high", "agent": None,
            "available": True, "eligible_roles": ["architect", "adjudicator"],
        }
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            agentflow._check_role_eligible(profile, "reviewer")
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_choose_profile_rejects_worker_only_reviewer(self):
        models = {"profiles": {
            "fallback_long_context": self._profile(model="p/qwen-1"),
        }}
        task = {"risk": "LOW", "preferred_reviewer": "fallback_long_context"}
        with mock.patch("agentflow._run_model_command") as run:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow.choose_profile(task, "reviewer", models)
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)
        run.assert_not_called()

    def test_choose_profile_skips_ineligible_preference(self):
        models = {"profiles": {
            "fallback_long_context": self._profile(model="p/qwen-1"),
            "independent_reviewer": self._profile(
                model="p/glm-1", agent="agentflow-reviewer", roles=("reviewer",)),
        }}
        task = {"risk": "LOW", "preferred_reviewer": "fallback_long_context"}
        name, _ = agentflow.choose_profile(task, "reviewer", models)
        self.assertEqual("independent_reviewer", name)

    def test_invoke_model_once_rejects_before_process_spawn(self):
        profile = self._profile(model="p/qwen-1")
        with mock.patch("agentflow.render_prompt", return_value="prompt"), \
             mock.patch("agentflow._run_model_command") as run:
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._invoke_model_once(
                    role="reviewer", profile_name="fb", profile=profile,
                    task=self.task, run_dir=self.run_dir, cycle=0,
                )
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)
        run.assert_not_called()
        self.assertEqual([], list(self.run_dir.iterdir()))

    def test_fallback_for_role_rejects_ineligible_reviewer_fallback(self):
        models = {"profiles": {
            "fallback_long_context": self._profile(model="p/qwen-1"),
        }}
        control = self._control(
            models, {"reviewer": "fallback_long_context"})
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            control.fallback_for_role("reviewer")
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    def test_fallback_for_adjudicator_requires_adjudicator_eligibility(self):
        models = {"profiles": {
            "arch_fb": self._profile(
                model="p/muse-1", agent="agentflow-architect",
                roles=("architect",)),
        }}
        control = self._control(models, {"architect": "arch_fb"})
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            control.fallback_for_role("adjudicator")
        self.assertEqual("ROLE_NOT_ELIGIBLE", raised.exception.code)

    # -- preventive read-only containment ---------------------------------

    def _capture_codex_sandbox(self, role):
        roles = {
            "worker": ["worker"],
            "reviewer": ["reviewer"],
            "architect": ["architect", "adjudicator"],
            "adjudicator": ["architect", "adjudicator"],
        }[role]
        profile = {
            "backend": "codex", "command": "/usr/bin/true", "provider": "openai",
            "model": "gpt-5.6-sol", "variant": "high", "agent": None,
            "available": True, "eligible_roles": roles,
        }
        captured = {}

        def fake_run(**kwargs):
            captured["argv"] = kwargs["argv"]
            raise agentflow.AgentFlowError("TEST_STOP", "captured before spawn")

        with mock.patch("agentflow.render_prompt", return_value="prompt"), \
             mock.patch("agentflow._run_model_command", side_effect=fake_run):
            with self.assertRaises(agentflow.AgentFlowError) as raised:
                agentflow._invoke_model_once(
                    role=role, profile_name="codex-x", profile=profile,
                    task=self.task, run_dir=self.run_dir, cycle=0,
                )
        self.assertEqual("TEST_STOP", raised.exception.code)
        argv = captured["argv"]
        self.assertIn("-s", argv)
        return argv[argv.index("-s") + 1]

    def test_codex_readonly_roles_are_sandboxed_read_only(self):
        for role in ("reviewer", "architect", "adjudicator"):
            with self.subTest(role=role):
                self.assertEqual("read-only", self._capture_codex_sandbox(role))

    def test_codex_worker_keeps_workspace_write_sandbox(self):
        self.assertEqual("workspace-write", self._capture_codex_sandbox("worker"))

    # -- adjudicator independence helper ----------------------------------

    def test_adjudicator_independence_rejects_matching_families(self):
        worker = self._profile(model="p/alpha-1")
        reviewer = self._profile(
            model="p/beta-1", agent="agentflow-reviewer", roles=("reviewer",))
        same_as_worker = self._profile(
            model="p/alpha-2", agent="agentflow-architect",
            roles=("architect", "adjudicator"))
        same_as_reviewer = self._profile(
            model="p/beta-2", agent="agentflow-architect",
            roles=("architect", "adjudicator"))
        for adjudicator in (same_as_worker, same_as_reviewer):
            with self.subTest(model=adjudicator["model"]):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._check_adjudicator_independence(
                        worker, reviewer, adjudicator)
                self.assertEqual("ADJUDICATOR_NOT_INDEPENDENT", raised.exception.code)
        independent = self._profile(
            model="p/muse-1", agent="agentflow-architect",
            roles=("architect", "adjudicator"))
        agentflow._check_adjudicator_independence(worker, reviewer, independent)

    def test_adjudicator_independence_is_unconditional_on_declaration(self):
        # Reproduction of F05-FINDING-02: omission of eligible_roles must not
        # disable the invariant.
        def undeclared(model):
            return {
                "backend": "opencode", "command": "/usr/bin/true",
                "provider": "p", "model": model, "variant": None,
                "agent": "a", "available": True,
            }

        worker = undeclared("p/alpha-1")
        reviewer = undeclared("p/beta-1")
        for adjudicator in (undeclared("p/alpha-2"), undeclared("p/beta-2")):
            with self.subTest(model=adjudicator["model"]):
                with self.assertRaises(agentflow.AgentFlowError) as raised:
                    agentflow._check_adjudicator_independence(
                        worker, reviewer, adjudicator)
                self.assertEqual(
                    "ADJUDICATOR_NOT_INDEPENDENT", raised.exception.code)
        agentflow._check_adjudicator_independence(
            worker, reviewer, undeclared("p/muse-1"))
        self.assertFalse(hasattr(agentflow, "_adjudicator_independence_applies"))

    # -- default routing --------------------------------------------------

    def test_default_routing_contains_only_worker_eligible_profiles(self):
        models = json.loads(agentflow.MODELS_FILE.read_text(encoding="utf-8"))
        routing = models["routing"]
        self.assertEqual(
            {"LOW", "MEDIUM", "HIGH", "CRITICAL"}, set(routing))
        for risk, names in routing.items():
            with self.subTest(risk=risk):
                self.assertTrue(names)
                for name in names:
                    profile = models["profiles"][name]
                    agentflow._check_role_eligible(profile, "worker")

    def test_default_routing_resolves_first_profile_without_ineligible_fallback(self):
        models = json.loads(agentflow.MODELS_FILE.read_text(encoding="utf-8"))
        for risk, names in models["routing"].items():
            with self.subTest(risk=risk):
                with mock.patch(
                    "agentflow.shutil.which", return_value="/usr/bin/true"
                ):
                    name, profile = agentflow.choose_profile(
                        {"risk": risk}, "worker", models)
                self.assertEqual(names[0], name)
                agentflow._check_role_eligible(profile, "worker")


if __name__ == "__main__":
    unittest.main()
