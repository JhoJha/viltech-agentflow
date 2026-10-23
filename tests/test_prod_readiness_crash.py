"""Self-tests for the deterministic PROD-READINESS crash driver."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tests.prod_readiness_support import (
    ContainmentPolicy,
    CrashDriver,
    HarnessSafetyError,
    authoritative_json,
    process_identity,
    sha256_path,
    terminate_owned_process_group,
)


CANONICAL_REPO = Path(__file__).resolve().parents[1]


class CrashHarnessTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="agentflow-prod-ready-crash-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.policy = ContainmentPolicy.create(self.root, CANONICAL_REPO)
        self.driver = CrashDriver(self.policy)

    def test_ch01_kill_before_write_cannot_claim_completion(self):
        result = self.driver.run("ch01", "before_authoritative_write", seed=11)
        authoritative = self.root / "scenarios/ch01/authoritative.json"
        diagnostic = self.root / "scenarios/ch01/diagnostic.json"
        self.assertEqual(signal.SIGKILL, result.signal)
        self.assertFalse(result.durability_acknowledged)
        self.assertFalse(authoritative.exists())
        self.assertIsNone(authoritative_json(authoritative))
        self.assertTrue(diagnostic.is_file())

    def test_atomic_json_after_replace_is_observable_but_not_durable(self):
        result = self.driver.run(
            "atomic-json-observable",
            "after_write_before_durability",
            seed=12,
            writer="atomic_json",
        )
        authoritative = self.root / "scenarios/atomic-json-observable/authoritative.json"
        self.assertTrue(authoritative.is_file())
        self.assertIsNotNone(authoritative_json(authoritative))
        self.assertFalse(result.durability_acknowledged)

    def test_after_replace_before_directory_fsync_is_not_acknowledged(self):
        result = self.driver.run("replace-window", "after_write_before_durability", seed=13)
        self.assertEqual(signal.SIGKILL, result.signal)
        self.assertFalse(result.durability_acknowledged)
        self.assertTrue((self.root / "scenarios/replace-window/authoritative.json").is_file())

    def test_ch02_kill_after_durable_boundary_preserves_artifact(self):
        result = self.driver.run("ch02", "after_durable_completion", seed=14)
        artifact = self.root / "scenarios/ch02/authoritative.json"
        self.assertEqual(signal.SIGKILL, result.signal)
        self.assertTrue(result.durability_acknowledged)
        self.assertEqual("COMPLETED", authoritative_json(artifact)["status"])
        self.assertEqual(sha256_path(artifact), result.hashes[str(artifact)])

    def test_after_durable_artifact_before_next_boundary(self):
        result = self.driver.run(
            "between-logical-boundaries",
            "after_durable_artifact_before_next_boundary",
            seed=15,
        )
        artifact = self.root / "scenarios/between-logical-boundaries/authoritative.json"
        self.assertTrue(result.durability_acknowledged)
        self.assertEqual(15, authoritative_json(artifact)["seed"])

    def test_ch03_diagnostic_cannot_be_mistaken_for_authority(self):
        self.driver.run("ch03", "before_authoritative_write")
        diagnostic = self.root / "scenarios/ch03/diagnostic.json"
        self.assertEqual("COMPLETED", json.loads(diagnostic.read_text())["status"])
        self.assertIsNone(authoritative_json(diagnostic))

    def test_ch04_malformed_and_truncated_authority_rejected(self):
        malformed = self.root / "malformed.json"
        malformed.write_text('{"authority":"AUTHORITATIVE", bad}', encoding="utf-8")
        truncated = self.root / "truncated.json"
        truncated.write_text('{"authority":"AUTHORITATIVE","status":"COMP', encoding="utf-8")
        self.assertIsNone(authoritative_json(malformed))
        self.assertIsNone(authoritative_json(truncated))

    def test_ch05_sigkill_accounts_for_owned_descendant(self):
        result = self.driver.run(
            "ch05", "before_authoritative_write", spawn_descendant=True
        )
        self.assertEqual(signal.SIGKILL, result.signal)
        self.assertEqual((), result.active_descendants_after_wait)

    def test_ch05_current_descendant_topology_cannot_silently_daemonize(self):
        result = self.driver.run(
            "ch05-topology", "before_authoritative_write", spawn_descendant=True
        )
        self.assertTrue(result.descendant_identities_before_kill)
        leader = result.child_identity
        for descendant in result.descendant_identities_before_kill:
            self.assertEqual(result.child_pid, descendant["ppid"])
            self.assertEqual(leader["pgid"], descendant["pgid"])
            self.assertEqual(leader["sid"], descendant["sid"])
            self.assertIsNotNone(descendant["start_time"])
            self.assertTrue(descendant["boot_id"])

    def test_ch06_wrong_recorded_identity_cannot_be_targeted(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            start_new_session=True,
        )
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
        self.addCleanup(cleanup)
        identity = process_identity(proc.pid)
        forged = replace(identity, start_time=identity.start_time + 1)
        with self.assertRaisesRegex(HarnessSafetyError, "PROCESS_IDENTITY_CHANGED"):
            terminate_owned_process_group(proc, forged)
        self.assertIsNone(proc.poll())
        proc.kill()
        proc.wait(timeout=5)

    def test_ch07_replay_has_same_logical_result(self):
        first = self.driver.run("replay-a", "after_durable_completion", seed=777)
        with tempfile.TemporaryDirectory(prefix="agentflow-prod-ready-replay-") as other:
            other_root = Path(other).resolve()
            other_driver = CrashDriver(ContainmentPolicy.create(other_root, CANONICAL_REPO))
            second = other_driver.run("replay-a", "after_durable_completion", seed=777)
        self.assertNotEqual(first.child_pid, second.child_pid)
        self.assertEqual(first.logical_result(), second.logical_result())

    def test_result_record_contains_required_identity_and_hash_fields(self):
        result = self.driver.run("record", "after_durable_completion", seed=9)
        path = self.root / "scenarios/record/crash-result.json"
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(result.scenario_id, record["scenario_id"])
        self.assertEqual(result.child_pid, record["child_pid"])
        self.assertEqual("after_durable_completion", record["selected_boundary"])
        self.assertEqual(signal.SIGKILL, record["signal"])
        self.assertIn("start_time", record["child_identity"])
        self.assertTrue(any(record["hashes"].values()))


if __name__ == "__main__":
    unittest.main()
