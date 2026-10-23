"""TEL-001 tests: append-only human + external evidence capture.

All fixtures live in temp dirs. Nothing is ever written to the real repo:
RUNS/EVENTS/MODELS/AGENTFLOW globals are patched per test. No sleeps,
no network, no real children.
"""

import ast
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import telemetry
from telemetry import TelemetryError


class TelemetryTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # Hermetic fixture workspace (auto-cleaned).
        self.root = Path(self._tmp.name) / "ws"
        (self.root / "config").mkdir(parents=True)
        (self.root / "config" / "models.json").write_text(json.dumps({"profiles": {}}), encoding="utf-8")
        (self.root / "agentflow.py").write_text("# fixture harness\n", encoding="utf-8")
        self.runs = self.root / "runs"
        self.events = self.root / "telemetry" / "v1" / "events"
        self.run_dir = self.runs / "run-abc"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "task.json").write_text(json.dumps({"task_id": "t"}), encoding="utf-8")
        (self.run_dir / "final.json").write_text(
            json.dumps({"verdict": "HUMAN_GATE", "status": "STOPPED"}), encoding="utf-8")
        self._patches = [
            mock.patch.object(telemetry, "ROOT", self.root),
            mock.patch.object(telemetry, "RUNS_DIR", self.runs),
            mock.patch.object(telemetry, "EVENTS_DIR", self.events),
            mock.patch.object(telemetry, "MODELS_FILE", self.root / "config" / "models.json"),
            mock.patch.object(telemetry, "AGENTFLOW_FILE", self.root / "agentflow.py"),
        ]
        for patch in self._patches:
            patch.start()
            self.addCleanup(patch.stop)

    def snapshot(self) -> dict[str, bytes]:
        found: dict[str, bytes] = {}
        for base in (self.runs, self.events):
            if not base.exists():
                continue
            for item in sorted(base.rglob("*")):
                if item.is_file():
                    found[str(item.relative_to(self.root))] = item.read_bytes()
        return found

    def gate_args(self, **overrides):
        base = {
            "task": "task-1", "run": "run-abc", "actor": "human-operator",
            "decision": "accepted_as_is", "decided_at": None, "supersedes": None,
            "note": None, "artifact": ["run-abc:final.json"],
        }
        base.update(overrides)
        return argparse_namespace(base)

    def external_args(self, **overrides):
        base = {
            "task": "task-1", "run": None, "actor": "human-operator", "actor_kind": "model",
            "roles": "architect,worker", "provider": "opencode", "model": "muse-spark",
            "variant": None, "session_type": "unknown", "timing_source": "unknown",
            "started_at": None, "finished_at": None, "verdict": "PASS", "summary": "did work",
            "token_source": "unavailable", "tokens_in": None, "tokens_out": None,
            "tokens_reasoning": None, "tokens_cached": None,
            "cost_source": "unavailable", "cost_value": None, "currency": None,
            "note": None, "artifact": [],
        }
        base.update(overrides)
        return argparse_namespace(base)


def argparse_namespace(values: dict) -> object:
    namespace = type("Args", (), {})()
    for key, value in values.items():
        setattr(namespace, key, value)
    return namespace


class GateTests(TelemetryTestBase):
    def test_gate_round_trip(self):  # 1
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        path = telemetry.publish_event(validated, self.events)
        self.assertEqual(path.name, validated["event_id"] + ".json")
        reloaded = json.loads(path.read_bytes().decode("utf-8"))
        self.assertEqual(validated, reloaded)
        self.assertEqual("accepted_as_is", reloaded["decision"])

    def test_gate_run_id_null(self):  # 3 (gate over external work)
        raw = telemetry.build_gate_event(self.gate_args(run=None, artifact=[]), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        self.assertIsNone(validated["run_id"])
        self.assertEqual([], validated["artifact_refs"])

    def test_actor_required(self):  # 11
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(self.gate_args(actor="  "), root=self.root)
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(self.gate_args(actor=None), root=self.root)

    def test_decision_required_and_sourced(self):  # 13, 14
        with self.assertRaises(TelemetryError):
            telemetry.validate_gate_event(
                telemetry.build_gate_event(self.gate_args(decision=None), root=self.root),
                self.runs, self.events)
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        self.assertEqual("human", raw["decision_source"])
        raw["decision_source"] = "agentflow"
        with self.assertRaises(TelemetryError):
            telemetry.validate_gate_event(raw, self.runs, self.events)

    def test_decided_at_null(self):  # 18
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        self.assertIsNone(raw["decided_at"])

    def test_decided_at_valid_utc(self):  # 19
        raw = telemetry.build_gate_event(
            self.gate_args(decided_at="2026-09-17T03:14:00Z"), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        self.assertEqual("2026-09-17T03:14:00Z", validated["decided_at"])

    def test_decided_at_after_recorded_fails(self):  # 20
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        raw["decided_at"] = "2999-01-01T00:00:00Z"
        with self.assertRaises(TelemetryError):
            telemetry.validate_gate_event(raw, self.runs, self.events)

    def test_non_utc_timestamps_fail(self):  # 21
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        raw["recorded_at"] = "2026-09-17 03:15:00"
        with self.assertRaises(TelemetryError):
            telemetry.validate_gate_event(raw, self.runs, self.events)
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(
                self.gate_args(decided_at="2026-09-17T03:14:00+00:00"), root=self.root)

    def test_supersede_flow(self):  # 27
        first = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root), self.runs, self.events)
        telemetry.publish_event(first, self.events)
        second_raw = telemetry.build_gate_event(
            self.gate_args(decision="accepted_with_changes", supersedes=first["event_id"],
                           note="correction"), root=self.root)
        second = telemetry.validate_gate_event(second_raw, self.runs, self.events)
        self.assertEqual(first["event_id"], second["supersedes_event_id"])
        self.assertEqual(first, telemetry.load_event(self.events, first["event_id"]))

    def test_supersede_missing_fails(self):  # 28
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(
                self.gate_args(supersedes="20260917T000000Z-abcdef"), root=self.root)

    def test_supersede_other_task_fails(self):  # 29
        first = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root), self.runs, self.events)
        telemetry.publish_event(first, self.events)
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(
                self.gate_args(task="other-task", supersedes=first["event_id"]), root=self.root)

    def test_supersede_wrong_type_fails(self):  # 30
        ext = telemetry.validate_external_event(
            telemetry.build_external_event(self.external_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(ext, self.events)
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(
                self.gate_args(supersedes=ext["event_id"]), root=self.root)

    def test_superseded_without_pointer_fails(self):  # 31
        with self.assertRaises(TelemetryError):
            telemetry.validate_gate_event(
                telemetry.build_gate_event(self.gate_args(decision="superseded"), root=self.root),
                self.runs, self.events)

    def test_note_limit(self):  # 32
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(self.gate_args(note="x" * 2001), root=self.root)

    def test_note_secret_rejected(self):  # 34
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(
                self.gate_args(note="key: -----BEGIN RSA PRIVATE KEY-----\nabc"), root=self.root)

    def test_environment_hashes(self):  # 40
        env = telemetry.environment_hashes(self.root)
        self.assertEqual(hashlib.sha256(b'{"profiles": {}}').hexdigest(), env["models_sha256"])
        self.assertEqual(hashlib.sha256(b"# fixture harness\n").hexdigest(), env["agentflow_sha256"])
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        self.assertEqual(env, raw["environment"])


class ExternalTests(TelemetryTestBase):
    def test_external_round_trip(self):  # 2
        raw = telemetry.build_external_event(self.external_args(), root=self.root)
        validated = telemetry.validate_external_event(raw, self.runs, self.events)
        path = telemetry.publish_event(validated, self.events)
        self.assertEqual(path.name, validated["event_id"] + ".json")
        self.assertEqual(validated, json.loads(path.read_bytes().decode("utf-8")))

    def test_run_id_null(self):  # 3
        raw = telemetry.build_external_event(self.external_args(), root=self.root)
        self.assertIsNone(raw["run_id"])

    def test_multiple_roles(self):  # 4
        raw = telemetry.build_external_event(self.external_args(roles="architect,worker,reviewer"),
                                             root=self.root)
        self.assertEqual(["architect", "worker", "reviewer"], raw["roles"])

    def test_session_unknown_default(self):  # 5
        raw = telemetry.build_external_event(self.external_args(), root=self.root)
        self.assertEqual("unknown", raw["session_type"])

    def test_usage_unavailable_default(self):  # 6
        raw = telemetry.build_external_event(self.external_args(), root=self.root)
        validated = telemetry.validate_external_event(raw, self.runs, self.events)
        self.assertEqual("unavailable", validated["usage"]["token_source"])
        self.assertEqual({"in": None, "out": None, "reasoning": None, "cached": None},
                         validated["usage"]["tokens"])
        self.assertEqual("unavailable", validated["usage"]["cost"]["source"])

    def test_token_source_partial(self):  # 7
        raw = telemetry.build_external_event(
            self.external_args(token_source="partial", tokens_in=100, tokens_out=None),
            root=self.root)
        validated = telemetry.validate_external_event(raw, self.runs, self.events)
        self.assertEqual(100, validated["usage"]["tokens"]["in"])
        self.assertIsNone(validated["usage"]["tokens"]["out"])

    def test_cost_harness_estimated(self):  # 8
        raw = telemetry.build_external_event(
            self.external_args(cost_source="harness_estimated", cost_value=0.004, currency="USD"),
            root=self.root)
        validated = telemetry.validate_external_event(raw, self.runs, self.events)
        self.assertEqual("harness_estimated", validated["usage"]["cost"]["source"])

    def test_currency_required_with_value(self):  # 9
        raw = telemetry.build_external_event(
            self.external_args(cost_source="harness_estimated", cost_value=0.004, currency=None),
            root=self.root)
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(raw, self.runs, self.events)

    def test_nan_infinity_rejected(self):  # 10
        raw = telemetry.build_external_event(
            self.external_args(cost_source="harness_estimated", cost_value=float("nan"),
                               currency="USD"), root=self.root)
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(raw, self.runs, self.events)
        raw = telemetry.build_external_event(
            self.external_args(cost_source="harness_estimated", cost_value=float("inf"),
                               currency="USD"), root=self.root)
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(raw, self.runs, self.events)

    def test_attestation_source_human(self):  # 15
        raw = telemetry.build_external_event(self.external_args(), root=self.root)
        self.assertEqual("human", raw["attestation_source"])
        raw["attestation_source"] = "agent"
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(raw, self.runs, self.events)
        raw2 = dict(telemetry.build_external_event(self.external_args(), root=self.root))
        raw2["decision_source"] = "human"
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(raw2, self.runs, self.events)

    def test_summary_limit(self):  # 33
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(
                telemetry.build_external_event(self.external_args(summary="y" * 501),
                                               root=self.root),
                self.runs, self.events)

    def test_summary_secret_rejected(self):  # 35
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(
                telemetry.build_external_event(
                    self.external_args(summary="key AKIAIOSFODNN7EXAMPLE here"), root=self.root),
                self.runs, self.events)

    def test_timing_order_validated(self):
        with self.assertRaises(TelemetryError):
            telemetry.validate_external_event(
                telemetry.build_external_event(
                    self.external_args(started_at="2026-09-17T04:00:00Z",
                                       finished_at="2026-09-17T03:00:00Z",
                                       timing_source="observed"), root=self.root),
                self.runs, self.events)


class ArtifactTests(TelemetryTestBase):
    def gate_with_artifact(self, spec):
        return telemetry.build_gate_event(self.gate_args(artifact=[spec]), root=self.root)

    def test_valid_regular_artifact(self):  # 22, 26
        raw = self.gate_with_artifact("run-abc:final.json")
        self.assertEqual(
            hashlib.sha256((self.run_dir / "final.json").read_bytes()).hexdigest(),
            raw["artifact_refs"][0]["sha256"])
        self.assertEqual({"run_id": "run-abc", "relpath": "final.json",
                          "sha256": raw["artifact_refs"][0]["sha256"]},
                         raw["artifact_refs"][0])

    def test_absolute_rejected(self):  # 23
        with self.assertRaises(TelemetryError):
            self.gate_with_artifact("run-abc:/etc/passwd")

    def test_dotdot_rejected(self):  # 24
        with self.assertRaises(TelemetryError):
            self.gate_with_artifact("run-abc:../agentflow.py")

    def test_symlink_rejected(self):  # 25
        link = self.run_dir / "link.json"
        try:
            link.symlink_to(self.run_dir / "final.json")
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        with self.assertRaises(TelemetryError):
            self.gate_with_artifact("run-abc:link.json")

    def test_missing_artifact_fails_loudly(self):
        with self.assertRaises(TelemetryError):
            self.gate_with_artifact("run-abc:nope.json")
        with self.assertRaises(TelemetryError):
            self.gate_with_artifact("ghost-run:final.json")


class ProvenanceDegradationTests(TelemetryTestBase):
    """TEL-001-R1 M1: degraded environment provenance must warn loudly.

    The event is still recorded (never lose an irreplaceable human
    decision), the unavailable hash stays null, and nothing is invented.
    """

    def test_missing_models_file_warns_and_records_null(self):
        (self.root / "config" / "models.json").unlink()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            env = telemetry.environment_hashes(self.root)
        self.assertIsNone(env["models_sha256"])
        self.assertIsNotNone(env["agentflow_sha256"])
        warning = err.getvalue()
        self.assertIn("warning", warning)
        self.assertIn("models_sha256", warning)
        self.assertIn("null", warning)

    def test_unhashable_base_file_warns_and_records_null(self):
        (self.root / "config" / "models.json").unlink()
        (self.root / "config" / "models.json").mkdir()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            env = telemetry.environment_hashes(self.root)
        self.assertIsNone(env["models_sha256"])
        self.assertIsNotNone(env["agentflow_sha256"])
        self.assertIn("warning", err.getvalue())

    def test_fully_missing_provenance_still_records_event(self):
        (self.root / "config" / "models.json").unlink()
        (self.root / "agentflow.py").unlink()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            raw = telemetry.build_gate_event(
                self.gate_args(run=None, artifact=[]), root=self.root)
        self.assertIsNone(raw["environment"]["models_sha256"])
        self.assertIsNone(raw["environment"]["agentflow_sha256"])
        warning = err.getvalue()
        self.assertIn("warning", warning)
        self.assertIn("models_sha256", warning)
        self.assertIn("agentflow_sha256", warning)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        path = telemetry.publish_event(validated, self.events)
        stored = json.loads(path.read_bytes().decode("utf-8"))
        self.assertIsNone(stored["environment"]["models_sha256"])
        self.assertIsNone(stored["environment"]["agentflow_sha256"])

    def test_healthy_provenance_is_silent(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            env = telemetry.environment_hashes(self.root)
        self.assertEqual("", err.getvalue())
        self.assertIsNotNone(env["models_sha256"])
        self.assertIsNotNone(env["agentflow_sha256"])


class SymlinkHardeningTests(TelemetryTestBase):
    """TEL-001-R1 M2/M3: symlinked run roots and prior events are rejected.

    Both go through cmd_gate so the assertions are CLI-literal: non-zero
    exit and zero new events.
    """

    def test_symlinked_run_root_rejected_with_no_new_event(self):  # M2
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        (outside / "evil.json").write_text(json.dumps({"pwned": True}), encoding="utf-8")
        link = self.runs / "run-link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        args = self.gate_args(run="run-link", artifact=["run-link:evil.json"])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = telemetry.cmd_gate(args)
        self.assertEqual(2, code)
        self.assertIn("symlink", err.getvalue())
        self.assertEqual(
            [], list(self.events.rglob("*.json")) if self.events.exists() else [])

    def test_symlinked_prior_event_rejected_with_no_new_event(self):  # M3
        first = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(first, self.events)
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        evil = outside / "evil.json"
        evil.write_text(json.dumps(dict(first)), encoding="utf-8")
        link_id = "20260917T000000Z-abcdef"
        link = self.events / f"{link_id}.json"
        try:
            link.symlink_to(evil)
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        before = sorted(p.name for p in self.events.glob("*.json"))
        args = self.gate_args(decision="accepted_with_changes",
                              supersedes=link_id, note="correction")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = telemetry.cmd_gate(args)
        self.assertEqual(2, code)
        self.assertIn("symlink", err.getvalue())
        after = sorted(p.name for p in self.events.glob("*.json"))
        # Only the planted link plus the original event: no new event file.
        self.assertEqual(before, after)
        self.assertEqual(sorted([first["event_id"] + ".json", link.name]), after)


class AppendOnlyTests(TelemetryTestBase):
    def test_no_overwrite_on_republish(self):  # 36
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        first = telemetry.publish_event(validated, self.events)
        before = first.read_bytes()
        with self.assertRaises(TelemetryError):
            telemetry.publish_event(validated, self.events)
        self.assertEqual(before, first.read_bytes())

    def test_failed_validation_writes_nothing(self):  # 37a
        before = {p.name for p in self.events.rglob("*")} if self.events.exists() else set()
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(self.gate_args(actor=""), root=self.root)
        after = {p.name for p in self.events.rglob("*")} if self.events.exists() else set()
        self.assertEqual(before, after)

    def test_collision_leaves_no_tmp_and_keeps_final(self):  # 37b, 38
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        path = telemetry.publish_event(validated, self.events)
        before = path.read_bytes()
        with self.assertRaises(TelemetryError):
            telemetry.publish_event(validated, self.events)
        self.assertEqual(before, path.read_bytes())
        leftovers = [p for p in self.events.iterdir() if ".tmp" in p.name or p.suffix == ".tmp"]
        self.assertEqual([], leftovers)

    def test_filename_equals_event_id(self):  # 39
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        path = telemetry.publish_event(validated, self.events)
        self.assertEqual(validated["event_id"] + ".json", path.name)


class CLITests(TelemetryTestBase):
    def run_cli(self, argv):
        with mock.patch.object(sys, "argv", ["telemetry.py", *argv]):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    try:
                        code = telemetry.main()
                    except SystemExit as exited:
                        code = exited.code if isinstance(exited.code, int) else 2
        return code, out.getvalue(), err.getvalue()

    def test_cli_gate_missing_decision_fails(self):  # 17 (+13 CLI)
        code, _, _ = self.run_cli(["gate", "--task", "t", "--actor", "human-operator"])
        self.assertEqual(2, code)

    def test_cli_gate_human_gate_final_still_needs_decision(self):
        code, _, _ = self.run_cli([
            "gate", "--task", "t", "--run", "run-abc", "--actor", "human-operator",
            "--artifact", "run-abc:final.json"])
        self.assertEqual(2, code)
        self.assertEqual([], list(self.events.rglob("*.json")) if self.events.exists() else [])

    def test_cli_gate_success_writes_event(self):
        code, out, _ = self.run_cli([
            "gate", "--task", "t", "--run", "run-abc", "--actor", "human-operator",
            "--decision", "accepted_as_is", "--artifact", "run-abc:final.json"])
        self.assertEqual(0, code)
        written = list(self.events.glob("*.json"))
        self.assertEqual(1, len(written))
        stored = json.loads(written[0].read_bytes().decode("utf-8"))
        self.assertEqual("accepted_as_is", stored["decision"])
        self.assertIn(stored["event_id"], out)

    def test_cli_external_nan_cost_fails(self):  # 10 CLI
        code, _, _ = self.run_cli([
            "external", "--actor", "human-operator", "--roles", "worker",
            "--cost-source", "harness_estimated", "--cost-value", "nan", "--currency", "USD"])
        self.assertEqual(2, code)

    def test_cli_runs_do_not_touch_fixtures(self):  # 42 (CLI flavor)
        before = self.snapshot()
        self.run_cli(["gate", "--task", "t", "--run", "run-abc", "--actor", "human-operator",
                      "--decision", "rejected", "--artifact", "run-abc:final.json"])
        self.run_cli(["external", "--actor", "human-operator", "--roles", "reviewer"])
        after_full = self.snapshot()
        added = set(after_full) - set(before)
        self.assertTrue(all(name.startswith("telemetry/v1/events/") for name in added))
        for name in set(before):
            if name.startswith("runs/"):
                self.assertEqual(before[name], after_full[name])


class StaticAndContractTests(TelemetryTestBase):
    def test_no_agentflow_import(self):  # 41
        tree = ast.parse(Path(telemetry.__file__).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertFalse(alias.name == "agentflow" or alias.name.startswith("agentflow."))
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual("agentflow", node.module)

    def test_no_verdict_to_decision_mapping(self):  # 16
        source = Path(telemetry.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from-final", source)
        self.assertNotIn("from_final", source)
        self.assertNotIn("HUMAN_GATE", source)

    def test_no_autodetection(self):  # 12
        source = Path(telemetry.__file__).read_text(encoding="utf-8")
        for marker in ("getlogin", "LOGNAME", "os.getuid", "getpass.getuser", "os.environ[\"USER\"",
                       'os.environ["USER"', "os.getenv(\"USER\"", "getuid"):
            self.assertNotIn(marker, source)

    def test_no_lock_writes(self):  # 42 static
        # Boundary declarations in prose are fine; no CODE may reference locks.
        source = Path(telemetry.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        prose = {node.value.value for node in ast.walk(tree) if isinstance(node, ast.Expr)
                 and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}
        code_only = source
        for blob in prose:
            code_only = code_only.replace(blob, "")
        self.assertNotIn(".locks", code_only)

    def test_schema_files_readable(self):  # 44
        root = Path(telemetry.__file__).resolve().parent
        for name in ("gate.schema.json", "external.schema.json"):
            data = json.loads((root / "telemetry" / "v1" / "schemas" / name).read_text(encoding="utf-8"))
            self.assertIn("properties", data)

    def test_unknown_fields_preserved(self):  # 45
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        raw["future_field"] = "keep-me"
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        self.assertEqual("keep-me", validated["future_field"])

    def test_runs_fixture_untouched(self):  # 42 functional
        before = self.snapshot()
        telemetry.build_gate_event(self.gate_args(), root=self.root)
        telemetry.build_external_event(self.external_args(), root=self.root)
        self.assertEqual(before, self.snapshot())


class VerifyTests(TelemetryTestBase):
    """TEL-001-R2: read-only event store verification. All hermetic."""

    def write_raw(self, event, filename=None):
        self.events.mkdir(parents=True, exist_ok=True)
        name = filename or (event["event_id"] + ".json")
        path = self.events / name
        path.write_text(json.dumps(event, indent=2) + "\n", encoding="utf-8")
        return path

    def valid_gate(self, **overrides):
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        validated.update(overrides)
        return validated

    def valid_external(self, **overrides):
        raw = telemetry.build_external_event(self.external_args(), root=self.root)
        validated = telemetry.validate_external_event(raw, self.runs, self.events)
        validated.update(overrides)
        return validated

    def run_verify(self):
        return telemetry.verify_event_store(self.events, self.runs)

    def run_cli_verify(self):
        with mock.patch.object(sys, "argv", ["telemetry.py", "verify"]):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    try:
                        code = telemetry.main()
                    except SystemExit as exited:
                        code = exited.code if isinstance(exited.code, int) else 2
        return code, out.getvalue(), err.getvalue()

    def codes(self, report, code=None, severity=None):
        out = report["findings"]
        if code is not None:
            out = [item for item in out if item["code"] == code]
        if severity is not None:
            out = [item for item in out if item["severity"] == severity]
        return out

    def test_verify_healthy_store_exit_0(self):
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(gate, self.events)
        ext = telemetry.validate_external_event(
            telemetry.build_external_event(self.external_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(ext, self.events)
        report = self.run_verify()
        self.assertTrue(report["ok"])
        self.assertEqual(0, report["errors"])
        self.assertEqual(2, report["events_parsed"])
        self.assertEqual(1, report["human_gate"])
        self.assertEqual(1, report["external_execution"])
        code, out, _ = self.run_cli_verify()
        self.assertEqual(0, code)
        self.assertIn("VERIFY OK", out)

    def test_verify_empty_store_exit_0(self):
        report = self.run_verify()
        self.assertTrue(report["ok"])
        self.assertEqual(0, report["files_scanned"])
        self.assertEqual(0, report["events_parsed"])
        code, out, _ = self.run_cli_verify()
        self.assertEqual(0, code)
        self.assertIn("VERIFY OK", out)

    def test_verify_gitkeep_ignored(self):
        self.events.mkdir(parents=True, exist_ok=True)
        (self.events / ".gitkeep").write_text("", encoding="utf-8")
        report = self.run_verify()
        self.assertTrue(report["ok"])
        self.assertEqual(0, report["files_scanned"])
        self.assertEqual(0, report["events_parsed"])
        code, _, _ = self.run_cli_verify()
        self.assertEqual(0, code)

    def test_verify_invalid_json(self):
        self.events.mkdir(parents=True, exist_ok=True)
        (self.events / "20260917T000000Z-aaaaaa.json").write_text("{broken", encoding="utf-8")
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertEqual(1, len(self.codes(report, "JSON_INVALID", "ERROR")))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_event_symlink(self):
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(gate, self.events)
        link = self.events / "20260917T000000Z-bbbbbc.json"
        try:
            link.symlink_to(self.events / (gate["event_id"] + ".json"))
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertEqual(1, len(self.codes(report, "EVENT_SYMLINK", "ERROR")))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_filename_mismatch(self):
        gate = self.valid_gate()
        self.write_raw(gate, "20260917T000000Z-cccccd.json")
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertEqual(
            1, len(self.codes(report, "EVENT_ID_FILENAME_MISMATCH", "ERROR")))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_unsupported_version(self):
        gate = self.valid_gate()
        gate["telemetry_version"] = 999
        self.write_raw(gate)
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertEqual(
            1, len(self.codes(report, "UNSUPPORTED_VERSION", "ERROR")))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_invalid_human_gate(self):
        gate = self.valid_gate()
        gate["decision"] = "bogus"
        self.write_raw(gate)
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertTrue(self.codes(report, "EVENT_INVALID", "ERROR"))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_invalid_external(self):
        ext = self.valid_external()
        ext["attestation_source"] = "agent"
        self.write_raw(ext)
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertTrue(self.codes(report, "EVENT_INVALID", "ERROR"))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_broken_supersession(self):
        gate = self.valid_gate(
            supersedes_event_id="20260917T000000Z-dddddd")
        self.write_raw(gate)
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertEqual(
            1, len(self.codes(report, "SUPERSESSION_INVALID", "ERROR")))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_null_provenance_warning(self):
        gate = self.valid_gate(
            environment={"models_sha256": None, "agentflow_sha256": None})
        self.write_raw(gate)
        report = self.run_verify()
        self.assertTrue(report["ok"])
        self.assertEqual(
            1, len(self.codes(report, "DEGRADED_PROVENANCE", "WARNING")))
        code, _, _ = self.run_cli_verify()
        self.assertEqual(0, code)

    def test_verify_exact_duplicate(self):
        first = telemetry.validate_external_event(
            telemetry.build_external_event(self.external_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(first, self.events)
        second = telemetry.validate_external_event(
            telemetry.build_external_event(self.external_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(second, self.events)
        self.assertNotEqual(first["event_id"], second["event_id"])
        report = self.run_verify()
        self.assertTrue(report["ok"])
        dups = self.codes(report, "EXACT_SEMANTIC_DUPLICATE", "WARNING")
        self.assertEqual(1, len(dups))
        self.assertIn(first["event_id"], dups[0]["detail"])
        self.assertIn(second["event_id"], dups[0]["detail"])
        code, _, _ = self.run_cli_verify()
        self.assertEqual(0, code)

    def test_verify_similar_not_duplicate(self):
        first = telemetry.validate_external_event(
            telemetry.build_external_event(self.external_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(first, self.events)
        second = telemetry.validate_external_event(
            telemetry.build_external_event(
                self.external_args(summary="a different honest summary"),
                root=self.root),
            self.runs, self.events)
        telemetry.publish_event(second, self.events)
        report = self.run_verify()
        self.assertTrue(report["ok"])
        self.assertEqual(
            [], self.codes(report, "EXACT_SEMANTIC_DUPLICATE", "WARNING"))

    def test_verify_invalid_artifact_ref(self):
        gate = self.valid_gate()
        gate["artifact_refs"] = [{
            "run_id": "run-abc", "relpath": "/etc/passwd",
            "sha256": "0" * 64}]
        self.write_raw(gate)
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertEqual(
            1, len(self.codes(report, "ARTIFACT_INVALID", "ERROR")))
        code, _, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)

    def test_verify_missing_artifact_warning(self):
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(gate, self.events)
        (self.run_dir / "final.json").unlink()
        report = self.run_verify()
        self.assertTrue(report["ok"])
        missing = self.codes(report, "ARTIFACT_UNAVAILABLE", "WARNING")
        self.assertEqual(1, len(missing))
        self.assertEqual([], self.codes(report, "ERROR"))
        code, _, _ = self.run_cli_verify()
        self.assertEqual(0, code)

    def test_verify_never_writes(self):
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(gate, self.events)
        ext = telemetry.validate_external_event(
            telemetry.build_external_event(self.external_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(ext, self.events)
        before_files = sorted(
            (item.relative_to(self.root), item.read_bytes())
            for item in list(self.runs.rglob("*")) + list(self.events.rglob("*"))
            if item.is_file() and not item.is_symlink())
        before_names = sorted(
            item.name for item in list(self.runs.rglob("*")) + list(self.events.rglob("*")))
        report = self.run_verify()
        code, _, _ = self.run_cli_verify()
        after_files = sorted(
            (item.relative_to(self.root), item.read_bytes())
            for item in list(self.runs.rglob("*")) + list(self.events.rglob("*"))
            if item.is_file() and not item.is_symlink())
        after_names = sorted(
            item.name for item in list(self.runs.rglob("*")) + list(self.events.rglob("*")))
        self.assertEqual(before_files, after_files)
        self.assertEqual(before_names, after_names)
        self.assertTrue(report["ok"])
        self.assertEqual(0, code)

    def test_verify_continues_past_bad_event(self):
        self.events.mkdir(parents=True, exist_ok=True)
        (self.events / "20260917T000000Z-eeeeee.json").write_text(
            "{nope", encoding="utf-8")
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(gate, self.events)
        report = self.run_verify()
        self.assertFalse(report["ok"])
        self.assertEqual(1, len(self.codes(report, "JSON_INVALID", "ERROR")))
        self.assertEqual(1, report["events_parsed"])
        self.assertEqual(1, report["human_gate"])
        code, out, _ = self.run_cli_verify()
        self.assertNotEqual(0, code)
        self.assertIn("JSON_INVALID", out)
        self.assertIn("VERIFY FAIL", out)


    def test_verify_rework_unhashable_list_task_id_continues(self):
        # HIGH-1: list task_id must be EVENT_INVALID, never abort scan.
        bad = self.valid_gate()
        bad["task_id"] = []
        bad["event_id"] = "20260917T000001Z-aaaaaa"
        self.write_raw(bad)
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertTrue(self.codes(report, "EVENT_INVALID", "ERROR"))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("EVENT_INVALID", out)
        self.assertIn("VERIFY FAIL", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_rework_unhashable_dict_task_id_continues(self):
        # HIGH-1: dict task_id must be EVENT_INVALID, never abort scan.
        bad = self.valid_gate()
        bad["task_id"] = {}
        bad["event_id"] = "20260917T000002Z-bbbbbb"
        self.write_raw(bad)
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertTrue(self.codes(report, "EVENT_INVALID", "ERROR"))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("EVENT_INVALID", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_rework_unreadable_artifact_continues(self):
        # MEDIUM-1: PermissionError/OSError on artifact must be
        # ARTIFACT_UNAVAILABLE, never abort scan.
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        self.write_raw(gate)
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(
                self.gate_args(run=None, artifact=[]), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)

        def _boom(path):
            raise PermissionError(13, "Permission denied", str(path))

        with mock.patch.object(telemetry, "sha256_file", side_effect=_boom):
            report = self.run_verify()
        self.assertEqual(2, report["events_parsed"])
        missing = self.codes(report, "ARTIFACT_UNAVAILABLE", "WARNING")
        self.assertEqual(1, len(missing))
        with mock.patch.object(telemetry, "sha256_file", side_effect=_boom):
            code, out, err = self.run_cli_verify()
        self.assertEqual(0, code)
        self.assertIn("ARTIFACT_UNAVAILABLE", out)
        self.assertIn("VERIFY OK", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_rework_huge_numeric_cost_continues(self):
        # MEDIUM-2: 10**400 must be EVENT_INVALID, never OverflowError abort.
        ext = self.valid_external()
        ext["usage"]["cost"] = {
            "source": "harness_estimated", "value": 10 ** 400,
            "currency": "USD",
        }
        ext["event_id"] = "20260917T000003Z-cccccc"
        self.write_raw(ext)
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertTrue(self.codes(report, "EVENT_INVALID", "ERROR"))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("EVENT_INVALID", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_rework_artifact_hash_match_no_finding(self):
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(gate, self.events)
        report = self.run_verify()
        self.assertEqual(
            [], self.codes(report, "ARTIFACT_HASH_MISMATCH", "ERROR"))
        self.assertTrue(report["ok"])

    def test_verify_rework_artifact_hash_mismatch(self):
        gate = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        stored_sha = gate["artifact_refs"][0]["sha256"]
        self.write_raw(gate)
        (self.run_dir / "final.json").write_text(
            "tampered-content", encoding="utf-8")
        report = self.run_verify()
        mismatches = self.codes(report, "ARTIFACT_HASH_MISMATCH", "ERROR")
        self.assertEqual(1, len(mismatches))
        self.assertFalse(report["ok"])
        self.assertIn(stored_sha, mismatches[0]["detail"])
        self.assertNotIn("tampered-content", mismatches[0]["detail"])
        # Read-only: stored event still carries the original hash.
        stored = json.loads(
            (self.events / (gate["event_id"] + ".json")).read_bytes().decode(
                "utf-8"))
        self.assertEqual(stored_sha, stored["artifact_refs"][0]["sha256"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("ARTIFACT_HASH_MISMATCH", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_rework_telemetry_version_bool_rejected(self):
        gate = self.valid_gate()
        gate["telemetry_version"] = True
        self.write_raw(gate)
        report = self.run_verify()
        self.assertEqual(
            1, len(self.codes(report, "UNSUPPORTED_VERSION", "ERROR")))
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_rework_telemetry_version_float_rejected(self):
        gate = self.valid_gate()
        gate["telemetry_version"] = 1.0
        self.write_raw(gate)
        report = self.run_verify()
        self.assertEqual(
            1, len(self.codes(report, "UNSUPPORTED_VERSION", "ERROR")))
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)


    def test_verify_r22_nul_in_run_id_is_invalid_not_crash(self):
        # HIGH-1: NUL in run_id is JSON-legal but never a filesystem path.
        bad = self.valid_gate()
        bad["artifact_refs"] = [
            {"run_id": "run\x00abc", "relpath": "final.json",
             "sha256": "0" * 64}]
        bad["event_id"] = "20260917T000011Z-aaaaaa"
        self.write_raw(bad)
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        before = self.snapshot()
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertEqual(
            1, len(self.codes(report, "ARTIFACT_INVALID", "ERROR")))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("ARTIFACT_INVALID", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)
        self.assertEqual(before, self.snapshot())

    def test_verify_r22_nul_in_relpath_is_invalid_not_crash(self):
        # HIGH-1: NUL in relpath must be ARTIFACT_INVALID, scan continues.
        bad = self.valid_gate()
        bad["artifact_refs"] = [
            {"run_id": "run-abc", "relpath": "a\x00b.json",
             "sha256": "0" * 64}]
        bad["event_id"] = "20260917T000012Z-bbbbbb"
        self.write_raw(bad)
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertEqual(
            1, len(self.codes(report, "ARTIFACT_INVALID", "ERROR")))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("ARTIFACT_INVALID", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_r22_lone_surrogate_ref_is_invalid_not_crash(self):
        # HIGH-1: lone surrogates are legal JSON strings but unencodable
        # paths (UnicodeEncodeError, a ValueError subclass).
        bad = self.valid_gate()
        bad["artifact_refs"] = [
            {"run_id": "run-abc", "relpath": "x\ud800y.json",
             "sha256": "0" * 64}]
        bad["event_id"] = "20260917T000013Z-cccccc"
        path = self.events / (bad["event_id"] + ".json")
        self.events.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(bad, ensure_ascii=True) + "\n", encoding="utf-8")
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertEqual(
            1, len(self.codes(report, "ARTIFACT_INVALID", "ERROR")))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("ARTIFACT_INVALID", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_r22_valid_first_nul_second_ref(self):
        # HIGH-1 second crash path: the bad ref sits behind a valid one, so
        # the failure surfaces inside the _artifact_status loop, not the
        # first validate_artifact_ref call.
        gate = self.valid_gate()
        first_sha = gate["artifact_refs"][0]["sha256"]
        gate["artifact_refs"] = [
            {"run_id": "run-abc", "relpath": "final.json",
             "sha256": first_sha},
            {"run_id": "run-abc", "relpath": "x\x00y.json",
             "sha256": "0" * 64},
        ]
        gate["event_id"] = "20260917T000014Z-dddddd"
        self.write_raw(gate)
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(
                self.gate_args(run=None, artifact=[]), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertTrue(self.codes(report, "ARTIFACT_INVALID", "ERROR"))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_r22_deep_json_is_invalid_not_crash(self):
        # HIGH-2: a RecursionError inside json.loads must become
        # JSON_INVALID and the scan must continue. The RecursionError is
        # injected deterministically (no CPython nesting-threshold
        # assumption, portable across 3.12+): the mock raises only for
        # the exact malformed fixture and delegates everything else to
        # the real json.loads so the later valid event parses normally.
        # Capture the real function before patching so the mock cannot
        # recurse into itself.
        self.events.mkdir(parents=True, exist_ok=True)
        payload = '["deep-fixture recursion probe" ' + "[" * 16 + "{invalid-json"
        try:
            json.loads(payload)
            self.fail("fixture must be invalid JSON under the real parser")
        except ValueError:
            pass
        real_loads = json.loads
        injected = {"count": 0}

        def controlled_loads(value, *args, **kwargs):
            if value == payload:
                injected["count"] += 1
                raise RecursionError("synthetic recursion boundary")
            return real_loads(value, *args, **kwargs)

        (self.events / "20260917T000015Z-eeeeee.json").write_text(
            payload, encoding="utf-8")
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        telemetry.publish_event(good, self.events)
        before = self.snapshot()
        with mock.patch.object(json, "loads", side_effect=controlled_loads):
            report = self.run_verify()
            code, out, err = self.run_cli_verify()
        self.assertGreaterEqual(
            injected["count"], 1,
            "the RecursionError path must actually be exercised")
        self.assertGreaterEqual(report["errors"], 1)
        self.assertEqual(
            1, len(self.codes(report, "JSON_INVALID", "ERROR")))
        self.assertEqual(1, report["events_parsed"])
        self.assertEqual(1, report["human_gate"])
        self.assertEqual(2, code)
        self.assertIn("JSON_INVALID", out)
        self.assertIn("VERIFY FAIL", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)
        self.assertEqual(before, self.snapshot())


class _StrictUTF8Stdout(io.StringIO):
    """Simulate a real UTF-8 terminal: encoding surrogates raises.

    contextlib.redirect_stdout(StringIO) never raises on surrogates, so
    a rendering crash would be invisible to the plain CLI helper. This
    writer encodes strictly exactly like a UTF-8 terminal would.
    """

    def write(self, text):
        text.encode("utf-8")
        return super().write(text)


class VerifyR23RobustnessTests(TelemetryTestBase):
    """TEL-001-R2.3: symlink loops + surrogate-safe rendering. Hermetic."""

    def write_raw(self, event, filename=None):
        self.events.mkdir(parents=True, exist_ok=True)
        name = filename or (event["event_id"] + ".json")
        path = self.events / name
        path.write_text(json.dumps(event, indent=2) + "\n", encoding="utf-8")
        return path

    def valid_gate(self, **overrides):
        raw = telemetry.build_gate_event(self.gate_args(), root=self.root)
        validated = telemetry.validate_gate_event(raw, self.runs, self.events)
        validated.update(overrides)
        return validated

    def publish_good_gate(self, **overrides):
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        good.update(overrides)
        telemetry.publish_event(good, self.events)
        return good

    def run_verify(self):
        return telemetry.verify_event_store(self.events, self.runs)

    def run_cli_verify(self):
        with mock.patch.object(sys, "argv", ["telemetry.py", "verify"]):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    try:
                        code = telemetry.main()
                    except SystemExit as exited:
                        code = exited.code if isinstance(exited.code, int) else 2
        return code, out.getvalue(), err.getvalue()

    def codes(self, report, code=None, severity=None):
        out = report["findings"]
        if code is not None:
            out = [item for item in out if item["code"] == code]
        if severity is not None:
            out = [item for item in out if item["severity"] == severity]
        return out

    def test_verify_r23_self_symlink_loop_is_invalid_not_crash(self):
        # HIGH-1: runs/<run>/loop -> loop cited as loop/final.json must be
        # ARTIFACT_INVALID ERROR; the scan must reach the later good event.
        loop_run = self.runs / "run-loop"
        loop_run.mkdir(parents=True)
        try:
            (loop_run / "loop").symlink_to("loop")
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        # Writer path fails cleanly too (controlled TelemetryError).
        with self.assertRaises(TelemetryError):
            telemetry.build_gate_event(
                self.gate_args(run="run-loop", artifact=["run-loop:loop/final.json"]),
                root=self.root)
        bad = self.valid_gate()
        bad["artifact_refs"] = [
            {"run_id": "run-loop", "relpath": "loop/final.json",
             "sha256": "0" * 64}]
        bad["event_id"] = "20260917T000017Z-aaaaab"
        self.write_raw(bad)
        self.publish_good_gate()
        before = self.snapshot()
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertEqual(
            1, len(self.codes(report, "ARTIFACT_INVALID", "ERROR")))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("ARTIFACT_INVALID", out)
        self.assertIn("VERIFY FAIL", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)
        self.assertEqual(before, self.snapshot())

    def test_verify_r23_two_node_symlink_cycle_is_invalid_not_crash(self):
        # HIGH-1 multi-node cycle: a -> b -> a cited as a/final.json.
        cyc_run = self.runs / "run-cyc"
        cyc_run.mkdir(parents=True)
        try:
            (cyc_run / "a").symlink_to("b")
            (cyc_run / "b").symlink_to("a")
        except OSError as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        bad = self.valid_gate()
        bad["artifact_refs"] = [
            {"run_id": "run-cyc", "relpath": "a/final.json",
             "sha256": "0" * 64}]
        bad["event_id"] = "20260917T000018Z-a1b2c3"
        self.write_raw(bad)
        self.publish_good_gate()
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertEqual(
            1, len(self.codes(report, "ARTIFACT_INVALID", "ERROR")))
        self.assertEqual(2, report["events_parsed"])
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("ARTIFACT_INVALID", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)

    def test_verify_r23_runtime_error_from_resolve_is_invalid_not_crash(self):
        # HIGH-1 narrow boundary: some versions raise RuntimeError
        # ("Symlink loop") from Path.resolve() instead of OSError. It must
        # become ARTIFACT_INVALID, never a traceback/scan abort. Only
        # resolves under run-rt raise; everything else delegates so the
        # later good event stays fully valid.
        bad = self.valid_gate()
        bad["artifact_refs"] = [
            {"run_id": "run-rt", "relpath": "loop/final.json",
             "sha256": "0" * 64}]
        bad["event_id"] = "20260917T000019Z-d4e5f6"
        self.write_raw(bad)
        self.publish_good_gate()
        before = self.snapshot()
        real_resolve = Path.resolve

        def flaky_resolve(self, *args, **kwargs):
            if "run-rt" in self.parts:
                raise RuntimeError("Symlink loop from 'run-rt/loop'")
            return real_resolve(self, *args, **kwargs)

        with mock.patch.object(Path, "resolve", flaky_resolve):
            report = self.run_verify()
            code, out, err = self.run_cli_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertEqual(
            1, len(self.codes(report, "ARTIFACT_INVALID", "ERROR")))
        self.assertEqual(2, report["events_parsed"])
        self.assertEqual(2, code)
        self.assertIn("ARTIFACT_INVALID", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)
        self.assertEqual(before, self.snapshot())

    def test_verify_r23_surrogate_event_id_renders_without_crash(self):
        # HIGH-2: a JSON-legal lone surrogate in event_id survives parsing
        # and reaches findings. The API report must stay usable and the CLI
        # must render it on a strict UTF-8 stdout with exit 2, no
        # traceback, and the later finding still represented.
        self.events.mkdir(parents=True, exist_ok=True)
        bad = self.valid_gate()
        bad["event_id"] = "20260917T000016Z-fffff\ud800"
        (self.events / "20260917T000016Z-ffffff.json").write_text(
            json.dumps(bad, ensure_ascii=True) + "\n", encoding="utf-8")
        good = self.publish_good_gate(
            environment={"models_sha256": None, "agentflow_sha256": None})
        before = self.snapshot()
        report = self.run_verify()
        self.assertGreaterEqual(report["errors"], 1)
        self.assertTrue(self.codes(report, "EVENT_INVALID", "ERROR"))
        self.assertEqual(2, report["events_parsed"])
        surrogate_hits = [
            item for item in report["findings"]
            if item["event_id"] is not None and "\ud800" in item["event_id"]]
        self.assertTrue(
            surrogate_hits,
            "the surrogate must reach the structured report findings")
        text = telemetry.format_verify_report(report)
        text.encode("utf-8")  # must not raise
        self.assertNotIn("\ud800", text)
        self.assertIn("EVENT_INVALID", text)
        self.assertIn("DEGRADED_PROVENANCE", text)
        self.assertIn(good["event_id"], text)
        code, out, err = self.run_cli_verify()
        self.assertEqual(2, code)
        self.assertIn("EVENT_INVALID", out)
        self.assertIn("VERIFY FAIL", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("Traceback", err)
        strict = _StrictUTF8Stdout()
        with mock.patch.object(sys, "stdout", strict):
            with mock.patch.object(sys, "argv", ["telemetry.py", "verify"]):
                with contextlib.redirect_stderr(io.StringIO()) as strict_err:
                    strict_code = telemetry.main()
        self.assertEqual(2, strict_code)
        self.assertIn("EVENT_INVALID", strict.getvalue())
        self.assertIn("VERIFY FAIL", strict.getvalue())
        self.assertNotIn("\ud800", strict.getvalue())
        self.assertNotIn("Traceback", strict_err.getvalue())
        self.assertEqual(before, self.snapshot())


class WriterSurrogateTests(TelemetryTestBase):
    """TEL-001-R2.3 MEDIUM-1: undecodable writer text fails cleanly."""

    def test_writer_r23_note_surrogate_fails_cleanly(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = telemetry.cmd_gate(
                self.gate_args(note="operator note \ud800 here"))
        self.assertEqual(2, code)
        self.assertIn("UTF-8", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        self.assertEqual(
            [], list(self.events.rglob("*.json")) if self.events.exists() else [])

    def test_writer_r23_actor_surrogate_fails_cleanly(self):
        # Second user-controlled writer string, via the external CLI path.
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = telemetry.cmd_external(
                self.external_args(actor="field-agent-\ud800"))
        self.assertEqual(2, code)
        self.assertIn("UTF-8", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        self.assertEqual(
            [], list(self.events.rglob("*.json")) if self.events.exists() else [])

    def test_writer_r23_publish_surrogate_writes_nothing(self):
        # Safety net: content that bypasses validation is still refused
        # atomically — TelemetryError, no event file, no tmp leftovers,
        # not even an events directory created.
        self.assertFalse(self.events.exists())
        good = telemetry.validate_gate_event(
            telemetry.build_gate_event(self.gate_args(), root=self.root),
            self.runs, self.events)
        good["note"] = "bypassed validation \ud800"
        with self.assertRaises(TelemetryError):
            telemetry.publish_event(good, self.events)
        self.assertFalse(self.events.exists())


class TaskClassPassthroughTests(unittest.TestCase):
    def test_task_class_survives_validate_and_redact(self):  # 43
        import agentflow
        task = {
            "task_id": "demo", "repo": "/tmp/x", "risk": "LOW",
            "objective": "demo objective", "allowed_paths": ["a.py"],
            "validators": [{"name": "v", "command": ["true"]}],
            "task_class": "lease-fix",
        }
        validated = agentflow.validate_task(dict(task))
        self.assertEqual("lease-fix", validated["task_class"])
        redacted = agentflow.redact_config(validated)
        self.assertEqual("lease-fix", redacted["task_class"])


if __name__ == "__main__":
    unittest.main()
