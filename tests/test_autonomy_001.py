import contextlib
import errno
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import fields
from pathlib import Path
from unittest import mock

import agentflow


SHA = "a" * 40


def models():
    def p(model, agent, roles):
        return {"backend": "opencode", "command": "true", "provider": "fake",
                "model": f"fake/{model}", "variant": None, "agent": agent,
                "available": True, "eligible_roles": list(roles)}
    arch_roles = ("architect", "adjudicator")
    return {"profiles": {
        "arch": p("sol-one", "agentflow-architect", arch_roles),
        "worker": p("alpha-one", "agentflow-worker", ("worker",)),
        "reviewer": p("beta-one", "agentflow-reviewer", ("reviewer",)),
        "arch_fb": p("delta-one", "agentflow-architect", arch_roles),
        "worker_fb": p("gamma-one", "agentflow-worker", ("worker",)),
        "reviewer_fb": p("epsilon-one", "agentflow-reviewer", ("reviewer",)),
        # Same model family as "worker" but validly declared as a read-only
        # reviewer profile: independence must still fail closed.
        "same_worker": p("alpha-two", "agentflow-reviewer", ("reviewer",)),
    }}


def program(pid="p"):
    return {"program_id": pid, "task": "task.json",
            "roles": {"architect": "arch", "worker": "worker", "reviewer": "reviewer"},
            "max_corrections": 1}


def task(root):
    return {"task_id": "t", "repo": str(root), "risk": "HIGH", "objective": "x",
            "allowed_paths": ["src/"], "validators": [{"command": ["true"]}],
            "isolation": {"enabled": True, "baseline_commit": SHA}}


def queue_doc(items=1):
    return {"queue_id": "q", "items": [
        {"item_id": f"i{n}", "program": f"p{n}.json"} for n in range(1, items + 1)],
        "budgets": {"wall_clock_seconds": 60, "model_calls": 20, "retries": 2,
                    "fallbacks": 2, "corrections": 1},
        "recovery": {"fallback_profiles": {
            "architect": "arch_fb", "worker": "worker_fb", "reviewer": "reviewer_fb"}},
    }


class QueueSchemaTests(unittest.TestCase):
    def test_schema_is_strict_and_bounded(self):
        schema = json.loads(agentflow.QUEUE_SCHEMA.read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(1, schema["properties"]["items"]["minItems"])
        self.assertEqual(8, schema["properties"]["items"]["maxItems"])
        self.assertFalse(schema["properties"]["items"]["items"]["additionalProperties"])

    def test_program_outcome_exact_required_fields(self):
        self.assertEqual({
            "run_id", "run_dir", "final_path", "final_sha256", "program_id", "task_id",
            "verdict", "status", "human_gate", "outcome_class", "primary_failure",
            "secondary_failures", "budget_dimension", "execution_repo", "baseline_commit",
            "preservation_status", "preservation_evidence_path", "process_quiescence", "final",
        }, {field.name for field in fields(agentflow.ProgramOutcome)})


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.queue_path = self.root / "queue.json"

    def run_preflight(self, doc, *, loaded_task=None, loaded_program=None,
                      loaded_models=None):
        self.queue_path.write_text(json.dumps(doc), encoding="utf-8")
        loaded_task = loaded_task or task(self.root)
        loaded_program = loaded_program or program()
        with mock.patch("agentflow._load_program_and_task", return_value=(loaded_program, loaded_task, self.root / "task.json")), \
             mock.patch("agentflow.load_models", return_value=loaded_models or models()), \
             mock.patch("agentflow.shutil.which", return_value="/bin/true"), \
             mock.patch("agentflow._resolve_commit_object", return_value=SHA):
            return agentflow.preflight_queue(self.queue_path)

    def test_one_and_eight_items_allowed(self):
        self.assertEqual(1, len(self.run_preflight(queue_doc(1))[1]))
        self.assertEqual(8, len(self.run_preflight(queue_doc(8))[1]))

    def test_ninth_item_rejected(self):
        with self.assertRaisesRegex(agentflow.AgentFlowError, "1..8"):
            self.run_preflight(queue_doc(9))

    def test_duplicate_item_id_rejected(self):
        doc = queue_doc(2); doc["items"][1]["item_id"] = "i1"
        with self.assertRaisesRegex(agentflow.AgentFlowError, "duplicate"):
            self.run_preflight(doc)

    def test_unknown_queue_field_rejected(self):
        doc = queue_doc(); doc["priority"] = 1
        with self.assertRaises(agentflow.AgentFlowError):
            self.run_preflight(doc)

    def test_bool_budget_rejected(self):
        doc = queue_doc(); doc["budgets"]["model_calls"] = True
        with self.assertRaises(agentflow.AgentFlowError):
            self.run_preflight(doc)

    def test_isolation_is_required(self):
        bad = task(self.root); bad["isolation"]["enabled"] = False
        with self.assertRaisesRegex(agentflow.AgentFlowError, "isolation"):
            self.run_preflight(queue_doc(), loaded_task=bad)

    def test_unsafe_validator_rejected_before_execution(self):
        bad = task(self.root); bad["validators"] = [{"command": "bash -c true"}]
        with self.assertRaisesRegex(agentflow.AgentFlowError, "validator"):
            self.run_preflight(queue_doc(), loaded_task=bad)

    def test_fallback_must_differ(self):
        doc = queue_doc(); doc["recovery"]["fallback_profiles"]["worker"] = "worker"
        with self.assertRaisesRegex(agentflow.AgentFlowError, "equals primary"):
            self.run_preflight(doc)

    def test_every_worker_reviewer_pair_is_independent(self):
        doc = queue_doc(); doc["recovery"]["fallback_profiles"]["reviewer"] = "same_worker"
        with self.assertRaisesRegex(agentflow.AgentFlowError, "independence"):
            self.run_preflight(doc)

    # ------------------------------------------------------------------
    # F-05: queue role eligibility and adjudicator independence
    # ------------------------------------------------------------------
    def test_worker_only_reviewer_profile_rejected(self):
        broken = models()
        broken["profiles"]["fallback_long_context"] = {
            "backend": "opencode", "command": "true", "provider": "fake",
            "model": "fake/qwen-3", "variant": None,
            "agent": "agentflow-worker", "available": True,
            "eligible_roles": ["worker"],
        }
        prog = program()
        prog["roles"]["reviewer"] = "fallback_long_context"
        with self.assertRaises(agentflow.AgentFlowError) as raised:
            self.run_preflight(queue_doc(), loaded_program=prog,
                               loaded_models=broken)
        self.assertEqual("INVALID_QUEUE", raised.exception.code)

    def test_adjudicator_primary_same_family_as_worker_rejected(self):
        broken = models()
        broken["profiles"]["arch"]["model"] = "fake/alpha-two"
        with self.assertRaisesRegex(agentflow.AgentFlowError, "adjudicator independence"):
            self.run_preflight(queue_doc(), loaded_models=broken)

    def test_adjudicator_architect_fallback_same_family_as_reviewer_rejected(self):
        broken = models()
        broken["profiles"]["arch_fb"]["model"] = "fake/beta-two"
        with self.assertRaisesRegex(agentflow.AgentFlowError, "adjudicator independence"):
            self.run_preflight(queue_doc(), loaded_models=broken)

    def test_adjudicator_reviewer_fallback_same_family_as_architect_rejected(self):
        broken = models()
        broken["profiles"]["reviewer_fb"]["model"] = "fake/sol-two"
        with self.assertRaisesRegex(agentflow.AgentFlowError, "adjudicator independence"):
            self.run_preflight(queue_doc(), loaded_models=broken)

    def test_inputs_and_hashes_are_frozen(self):
        _queue, frozen, _models = self.run_preflight(queue_doc())
        item = frozen[0]
        self.assertEqual(SHA, item.baseline_commit)
        self.assertEqual(64, len(item.hashes["program_sha256"]))
        self.assertIn("primary_worker", item.profiles)

    def test_unusable_backend_rejected(self):
        broken = models(); broken["profiles"]["worker"]["backend"] = "mystery"
        self.queue_path.write_text(json.dumps(queue_doc()), encoding="utf-8")
        with mock.patch("agentflow._load_program_and_task", return_value=(program(), task(self.root), self.root / "task.json")), \
             mock.patch("agentflow.load_models", return_value=broken), \
             mock.patch("agentflow.shutil.which", return_value="/bin/true"), \
             mock.patch("agentflow._resolve_commit_object", return_value=SHA):
            with self.assertRaisesRegex(agentflow.AgentFlowError, "unusable backend"):
                agentflow.preflight_queue(self.queue_path)

    def test_invalid_later_item_prevents_any_artifact(self):
        doc = queue_doc(2)
        calls = []
        def load(path):
            calls.append(path)
            if len(calls) == 2:
                bad = task(self.root); bad["isolation"]["enabled"] = False
                return program("p2"), bad, self.root / "task2.json"
            return program("p1"), task(self.root), self.root / "task1.json"
        self.queue_path.write_text(json.dumps(doc), encoding="utf-8")
        with mock.patch("agentflow._load_program_and_task", side_effect=load), \
             mock.patch("agentflow.load_models", return_value=models()), \
             mock.patch("agentflow.shutil.which", return_value="/bin/true"), \
             mock.patch("agentflow._resolve_commit_object", return_value=SHA):
            code, run_dir, final = agentflow.run_queue(self.queue_path)
        self.assertEqual(2, code); self.assertIsNone(run_dir)
        self.assertEqual("INVALID_QUEUE", final["verdict"])


class ProviderClassificationTests(unittest.TestCase):
    def test_every_structured_class(self):
        cases = {
            "NETWORK_ERROR": agentflow.ProviderFailureClass.TRANSIENT_NETWORK,
            "RATE_LIMITED": agentflow.ProviderFailureClass.RATE_LIMITED,
            "SERVICE_UNAVAILABLE": agentflow.ProviderFailureClass.TEMPORARILY_UNAVAILABLE,
            "INSUFFICIENT_QUOTA": agentflow.ProviderFailureClass.QUOTA_EXHAUSTED,
            "INVALID_API_KEY": agentflow.ProviderFailureClass.AUTH_OR_CONFIGURATION,
            "MODEL_DISABLED": agentflow.ProviderFailureClass.MODEL_NOT_FOUND_OR_DISABLED,
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                self.assertEqual(expected, agentflow.classify_provider_failure(
                    "", json.dumps({"error": {"code": code}})))

    def test_structured_stdout_is_accepted(self):
        self.assertEqual(agentflow.ProviderFailureClass.RATE_LIMITED,
                         agentflow.classify_provider_failure('{"error_code":"RATE_LIMIT"}', ""))

    def test_arbitrary_prose_is_unknown(self):
        self.assertEqual(agentflow.ProviderFailureClass.PROCESS_NONZERO_UNKNOWN,
                         agentflow.classify_provider_failure("quota exhausted rate limited", ""))

    def test_malformed_event_is_unknown(self):
        self.assertEqual(agentflow.ProviderFailureClass.PROCESS_NONZERO_UNKNOWN,
                         agentflow.classify_provider_failure('{"error":', ""))

    def test_typed_network_condition_is_secondary_evidence(self):
        condition = OSError(errno.ECONNRESET, "reset")
        self.assertEqual(agentflow.ProviderFailureClass.TRANSIENT_NETWORK,
                         agentflow.classify_provider_failure("", "", condition))


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value


class ExecutionControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); (self.root / "item").mkdir()
        self.clock = Clock()
        self.control = agentflow.ExecutionControl(
            queue_id="q", queue_run_dir=self.root, item_dir=self.root / "item",
            budgets={"wall_clock_seconds": 10, "model_calls": 3, "retries": 1,
                     "fallbacks": 1, "corrections": 1},
            fallback_profiles={"worker": "worker_fb", "reviewer": "reviewer_fb"},
            models=models(), monotonic=self.clock,
        ); self.control.start()

    def test_model_call_reserved_durably(self):
        self.control.reserve_attempt(logical_id="x", attempt="PRIMARY")
        state = json.loads((self.root / "budget-state.json").read_text())
        self.assertEqual(1, state["used"]["model_calls"])
        self.assertEqual("PRIMARY", state["reservations"][0]["attempt"])

    def test_failed_spawn_reservation_still_consumed(self):
        self.control.reserve_attempt(logical_id="x", attempt="PRIMARY")
        self.assertEqual(1, self.control.used["model_calls"])

    def test_retry_and_fallback_counters(self):
        self.control.reserve_attempt(logical_id="x", attempt="RETRY")
        self.control.reserve_attempt(logical_id="y", attempt="FALLBACK")
        self.assertEqual((2, 1, 1), (self.control.used["model_calls"],
                         self.control.used["retries"], self.control.used["fallbacks"]))

    def test_denied_retry_does_not_consume(self):
        self.control.reserve_attempt(logical_id="x", attempt="RETRY")
        with self.assertRaises(agentflow.BudgetExhausted):
            self.control.reserve_attempt(logical_id="y", attempt="RETRY")
        self.assertEqual(1, self.control.used["retries"])

    def test_correction_and_model_reserved_together(self):
        self.control.reserve_attempt(logical_id="x", attempt="PRIMARY", correction_start=True)
        self.assertEqual(1, self.control.used["corrections"])
        self.assertEqual(1, self.control.used["model_calls"])

    def test_wall_clock_never_resets(self):
        origin = self.control.deadline
        self.clock.value = 11
        with self.assertRaises(agentflow.BudgetExhausted): self.control.check_deadline()
        self.assertEqual(origin, self.control.deadline)

    def test_model_abort_hook_reports_wall_budget(self):
        self.control.deadline = 1.0
        request = self.control.abort_check(1.0)
        self.assertEqual("BUDGET_EXHAUSTED", request.code)
        self.assertEqual("WALL_CLOCK", request.details["budget_dimension"])

    def test_inactivity_policy_precedes_queue_abort(self):
        policy = agentflow._ModelInactivityPolicy(0.01)
        combined = agentflow._combined_model_abort_check(policy, self.control.abort_check)
        request = combined(time.monotonic() + 1)
        self.assertEqual("STALL_DETECTED", request.code)

    def test_model_call_limit_is_queue_stopping(self):
        for n in range(3):
            self.control.reserve_attempt(logical_id=str(n), attempt="PRIMARY")
        with self.assertRaises(agentflow.BudgetExhausted) as caught:
            self.control.reserve_attempt(logical_id="overflow", attempt="PRIMARY")
        self.assertEqual("MODEL_CALLS", caught.exception.dimension)

    def test_fallback_role_mapping_covers_adjudicator(self):
        self.control.fallback_profiles["architect"] = "arch_fb"
        self.assertEqual("arch_fb", self.control.fallback_for_role("adjudicator")[0])

    def test_queue_deadline_terminates_plain_process(self):
        self.control.monotonic = time.monotonic
        self.control.deadline = time.monotonic() + 0.03
        with self.assertRaises(agentflow.BudgetExhausted):
            agentflow._run_queue_process(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                cwd=self.root, local_timeout=2, control=self.control)

    def test_local_plain_timeout_keeps_native_semantics(self):
        self.control.monotonic = time.monotonic
        self.control.deadline = time.monotonic() + 5
        with self.assertRaises(subprocess.TimeoutExpired):
            agentflow._run_queue_process(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                cwd=self.root, local_timeout=0.03, control=self.control)

    def test_local_failure_survives_transient_scanner_churn(self):
        uncertain = (agentflow._QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ())
        quiet = (agentflow._QUEUE_GROUP_ORIGINAL_QUIESCENT, ())
        with mock.patch(
            "agentflow._scan_queue_process_group",
            side_effect=[uncertain, uncertain, quiet],
        ):
            result = agentflow._run_queue_process(
                [sys.executable, "-c", "raise SystemExit(7)"],
                cwd=self.root, local_timeout=2, control=self.control,
            )
        self.assertEqual(7, result.returncode)
        self.assertEqual("PROVEN", self.control.process_quiescence())

    def test_validator_failure_remains_local_under_scanner_churn(self):
        run_dir = self.root / "validator-run"; run_dir.mkdir()
        uncertain = (agentflow._QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ())
        quiet = (agentflow._QUEUE_GROUP_ORIGINAL_QUIESCENT, ())
        token = agentflow._ACTIVE_EXECUTION_CONTROL.set(self.control)
        try:
            with mock.patch(
                "agentflow._scan_queue_process_group",
                side_effect=[uncertain, quiet],
            ):
                results = agentflow.run_validators(
                    self.root, [{"name": "local", "command": ["/usr/bin/false"]}],
                    run_dir, 0,
                )
        finally:
            agentflow._ACTIVE_EXECUTION_CONTROL.reset(token)
        self.assertEqual("FAIL", results[0]["status"])
        self.assertEqual("PROVEN", self.control.process_quiescence())


class QueueProcessIdentityTests(unittest.TestCase):
    def setUp(self):
        self.identity = agentflow.QueueProcessIdentity("boot", 100, 10, 100, 100)
        self.member = agentflow.QueueProcessMember(100, 10)

    def scan(self, values, entries=(Path("/proc/100"),)):
        def read(pid):
            value = values[pid]
            if isinstance(value, BaseException):
                raise value
            return value
        proc_root = mock.Mock()
        proc_root.iterdir.return_value = list(entries)
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.multiple(
            agentflow,
            read_boot_id=mock.Mock(return_value="boot"),
            _queue_proc_identity=mock.Mock(side_effect=read),
            PROC_ROOT=proc_root,
        ))
        stack.enter_context(mock.patch("agentflow.os.kill", side_effect=ProcessLookupError))
        return stack

    def test_original_active_group_identified(self):
        with self.scan({100: (10, 100, 100, "S")}):
            status, members = agentflow._scan_queue_process_group(self.identity)
        self.assertEqual(agentflow._QUEUE_GROUP_ORIGINAL_ACTIVE, status)
        self.assertEqual((self.member,), members)

    def test_original_group_completely_gone_is_quiescent(self):
        with self.scan({100: FileNotFoundError()}, entries=()):
            status, members = agentflow._scan_queue_process_group(self.identity)
        self.assertEqual(agentflow._QUEUE_GROUP_ORIGINAL_QUIESCENT, status)
        self.assertEqual((), members)

    def test_numeric_group_existence_alone_is_only_uncertainty(self):
        with self.scan({100: FileNotFoundError()}, entries=()), \
             mock.patch("agentflow.os.kill", return_value=None):
            status, members = agentflow._scan_queue_process_group(self.identity)
        self.assertEqual(agentflow._QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, status)
        self.assertEqual((), members)

    def test_leader_gone_original_descendant_remains_active(self):
        descendant = agentflow.QueueProcessMember(101, 11)
        with self.scan(
            {100: FileNotFoundError(), 101: (11, 100, 100, "S")},
            entries=(Path("/proc/101"),),
        ):
            status, members = agentflow._scan_queue_process_group(self.identity)
        self.assertEqual(agentflow._QUEUE_GROUP_ORIGINAL_ACTIVE, status)
        self.assertEqual((descendant,), members)

    def test_reused_leader_starttime_is_identity_mismatch(self):
        with self.scan({100: (99, 100, 100, "S")}):
            status, members = agentflow._scan_queue_process_group(self.identity)
        self.assertEqual(agentflow._QUEUE_GROUP_IDENTITY_MISMATCH, status)
        self.assertEqual((), members)

    def test_transient_ambiguity_is_bounded_then_recovers(self):
        scanner = mock.Mock(side_effect=[
            (agentflow._QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()),
            (agentflow._QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()),
            (agentflow._QUEUE_GROUP_ORIGINAL_QUIESCENT, ()),
        ])
        status, _members = agentflow._queue_group_status(
            self.identity, scanner=scanner
        )
        self.assertEqual(agentflow._QUEUE_GROUP_ORIGINAL_QUIESCENT, status)
        self.assertEqual(3, scanner.call_count)

    def test_persistent_ambiguity_fails_closed_without_signal(self):
        proc = mock.Mock()
        with mock.patch("agentflow._queue_group_status", return_value=(
            agentflow._QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ())), \
             mock.patch("agentflow._signal_queue_members") as send:
            with self.assertRaisesRegex(agentflow.AgentFlowError, "Cannot prove") as caught:
                agentflow._terminate_plain_process_group(proc, self.identity)
        self.assertEqual("INTERNAL_ERROR", caught.exception.code)
        send.assert_not_called()

    def test_identity_mismatch_before_term_never_signals(self):
        proc = mock.Mock()
        with mock.patch("agentflow._queue_group_status", return_value=(
            agentflow._QUEUE_GROUP_IDENTITY_MISMATCH, ())), \
             mock.patch("agentflow._signal_queue_members") as send:
            agentflow._terminate_plain_process_group(proc, self.identity)
        send.assert_not_called()

    def test_identity_mismatch_before_kill_never_sends_kill(self):
        proc = mock.Mock()
        states = [
            (agentflow._QUEUE_GROUP_ORIGINAL_ACTIVE, (self.member,)),
            (agentflow._QUEUE_GROUP_ORIGINAL_ACTIVE, (self.member,)),
            (agentflow._QUEUE_GROUP_IDENTITY_MISMATCH, ()),
        ]
        with mock.patch("agentflow._queue_group_status", side_effect=states), \
             mock.patch("agentflow._signal_queue_members") as send:
            agentflow._terminate_plain_process_group(proc, self.identity)
        send.assert_called_once_with(self.identity, (self.member,), signal.SIGTERM)

    def test_descendant_member_is_included_in_termination(self):
        proc = mock.Mock()
        descendant = agentflow.QueueProcessMember(101, 11)
        states = [
            (agentflow._QUEUE_GROUP_ORIGINAL_ACTIVE, (descendant,)),
            (agentflow._QUEUE_GROUP_ORIGINAL_QUIESCENT, ()),
        ]
        with mock.patch("agentflow._queue_group_status", side_effect=states), \
             mock.patch("agentflow._signal_queue_members") as send:
            agentflow._terminate_plain_process_group(proc, self.identity)
        send.assert_called_once_with(self.identity, (descendant,), signal.SIGTERM)

    def test_pidfd_revalidation_skips_recycled_member(self):
        recycled = agentflow.QueueProcessMember(101, 11)
        with mock.patch("agentflow.os.pidfd_open", return_value=9), \
             mock.patch("agentflow.os.close"), \
             mock.patch("agentflow.read_boot_id", return_value="boot"), \
             mock.patch("agentflow._queue_proc_identity", return_value=(12, 100, 100, "S")), \
             mock.patch("agentflow.signal.pidfd_send_signal") as send:
            agentflow._signal_queue_members(self.identity, (recycled,), signal.SIGTERM)
        send.assert_not_called()


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.run_dir = self.root / "run"; self.run_dir.mkdir()
        self.item = self.root / "item"; self.item.mkdir()
        self.control = agentflow.ExecutionControl(
            queue_id="q", queue_run_dir=self.root, item_dir=self.item,
            budgets={"wall_clock_seconds": 60, "model_calls": 10, "retries": 2,
                     "fallbacks": 2, "corrections": 1},
            fallback_profiles={"worker": "worker_fb", "reviewer": "reviewer_fb"},
            models=models(),
        ); self.control.start()
        self.task = task(self.root)

    def invoke(self, effects, *, role="reviewer", changed=None):
        token = agentflow._ACTIVE_EXECUTION_CONTROL.set(self.control)
        try:
            with mock.patch("agentflow._invoke_model_once", side_effect=effects) as called, \
                 mock.patch("agentflow.capture_baseline", return_value={}), \
                 mock.patch("agentflow.changed_since", side_effect=(changed or (lambda a, b: []))):
                try:
                    result = agentflow.invoke_model(
                        role=role, profile_name="arch" if role in {"architect", "adjudicator"} else role,
                        profile=models()["profiles"]["arch" if role in {"architect", "adjudicator"} else role],
                        task=self.task, run_dir=self.run_dir, cycle=0, context={},
                        lease=mock.Mock() if role == "worker" else None, exec_repo=self.root,
                    )
                    return result, called
                except Exception as exc:
                    exc.called = called
                    raise
        finally:
            agentflow._ACTIVE_EXECUTION_CONTROL.reset(token)

    def invoke_raw(self, role, outputs, *, context=None, changed=None):
        role_profile = "arch" if role in {"architect", "adjudicator"} else role
        profile = models()["profiles"][role_profile]
        raw_task = dict(self.task, forbidden_actions=[], invariants=[])
        responses = [subprocess.CompletedProcess(["fake"], 0, json.dumps(output), "")
                     for output in outputs]
        token = agentflow._ACTIVE_EXECUTION_CONTROL.set(self.control)
        try:
            with mock.patch("agentflow._run_model_command", side_effect=responses) as called, \
                 mock.patch("agentflow._stage_opencode_config", return_value=self.root), \
                 mock.patch("agentflow.capture_baseline", return_value={}), \
                 mock.patch("agentflow.changed_since", side_effect=(changed or (lambda a, b: []))):
                try:
                    result = agentflow.invoke_model(
                        role=role, profile_name=role_profile, profile=profile,
                        task=raw_task, run_dir=self.run_dir, cycle=0,
                        context=context, exec_repo=self.root,
                    )
                    return result, called
                except Exception as exc:
                    exc.called = called
                    raise
        finally:
            agentflow._ACTIVE_EXECUTION_CONTROL.reset(token)

    def test_transient_retries_exactly_once_and_succeeds(self):
        result = ({"ok": True}, {"profile": "reviewer"})
        got, called = self.invoke([agentflow.AgentFlowError("PROVIDER_TRANSIENT", "x"), result])
        self.assertEqual(result, got); self.assertEqual(2, called.call_count)
        self.assertEqual(1, self.control.used["retries"])

    def test_retry_failure_falls_back(self):
        result = ({"ok": True}, {})
        got, called = self.invoke([agentflow.AgentFlowError("PROCESS_TIMEOUT", "x"),
                                   agentflow.AgentFlowError("PROCESS_TIMEOUT", "x"), result])
        self.assertEqual(result, got); self.assertEqual(3, called.call_count)
        self.assertEqual((1, 1), (self.control.used["retries"], self.control.used["fallbacks"]))

    def test_retry_receives_original_global_deadline(self):
        clock = Clock()
        self.control.monotonic = clock
        self.control.started_monotonic = None
        self.control.deadline = None
        self.control.start()
        seen = []
        def dispatch(**_kwargs):
            seen.append(self.control.deadline)
            if len(seen) == 1:
                clock.value = 5
                raise agentflow.AgentFlowError("PROVIDER_TRANSIENT", "retry")
            return ({"ok": True}, {})
        self.invoke(dispatch)
        self.assertEqual([60.0, 60.0], seen)

    def test_fallback_receives_original_global_deadline(self):
        clock = Clock()
        self.control.monotonic = clock
        self.control.started_monotonic = None
        self.control.deadline = None
        self.control.start()
        seen = []
        def dispatch(**_kwargs):
            seen.append(self.control.deadline)
            if len(seen) == 1:
                clock.value = 7
                raise agentflow.AgentFlowError("PROVIDER_QUOTA_EXHAUSTED", "fallback")
            return ({"ok": True}, {})
        self.invoke(dispatch)
        self.assertEqual([60.0, 60.0], seen)

    def test_quota_goes_directly_to_fallback(self):
        result = ({"ok": True}, {})
        got, called = self.invoke([agentflow.AgentFlowError("PROVIDER_QUOTA_EXHAUSTED", "x"), result])
        self.assertEqual(result, got); self.assertEqual(2, called.call_count)
        self.assertEqual(0, self.control.used["retries"])

    def test_model_unavailable_goes_directly_to_fallback(self):
        result = ({"ok": True}, {})
        got, _ = self.invoke([agentflow.AgentFlowError("MODEL_UNAVAILABLE", "x"), result])
        self.assertEqual(result, got)

    def test_auth_has_no_recovery(self):
        with self.assertRaisesRegex(agentflow.AgentFlowError, "auth") as caught:
            self.invoke([agentflow.AgentFlowError("PROVIDER_AUTH_OR_CONFIGURATION", "auth")])
        self.assertEqual(1, caught.exception.called.call_count)

    def test_unknown_nonzero_has_no_recovery(self):
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("MODEL_INVOCATION_FAILED", "x")])
        self.assertEqual(1, caught.exception.called.call_count)

    def test_invalid_readonly_output_gets_one_contract_retry(self):
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("INVALID_MODEL_OUTPUT", "x"),
                         agentflow.AgentFlowError("INVALID_MODEL_OUTPUT", "x again")])
        self.assertEqual("INVALID_MODEL_OUTPUT", caught.exception.code)
        self.assertEqual(2, caught.exception.called.call_count)
        self.assertEqual((2, 1), (self.control.used["model_calls"], self.control.used["retries"]))
        calls = caught.exception.called.call_args_list
        self.assertEqual(["reviewer", "reviewer"], [c.kwargs["role"] for c in calls])
        self.assertEqual(["reviewer", "reviewer"], [c.kwargs["profile_name"] for c in calls])
        self.assertEqual(calls[0].kwargs["profile"], calls[1].kwargs["profile"])
        self.assertEqual("x", calls[1].kwargs["context"]["structural_retry_feedback"]["error"])

    def test_worker_invalid_output_has_no_contract_retry(self):
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("INVALID_MODEL_OUTPUT", "worker bad")], role="worker")
        self.assertEqual(1, caught.exception.called.call_count)
        self.assertEqual(0, self.control.used["retries"])

    def test_contract_retry_budget_denial_is_fail_closed(self):
        self.control.budgets["retries"] = 0
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("INVALID_MODEL_OUTPUT", "bad")])
        self.assertEqual("INVALID_MODEL_OUTPUT", caught.exception.code)
        self.assertEqual(1, caught.exception.called.call_count)
        self.assertEqual((1, 0), (self.control.used["model_calls"], self.control.used["retries"]))

    def test_contract_retry_model_call_budget_denial_is_fail_closed(self):
        self.control.budgets["model_calls"] = 1
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("INVALID_MODEL_OUTPUT", "bad")])
        self.assertEqual("INVALID_MODEL_OUTPUT", caught.exception.code)
        self.assertEqual(1, caught.exception.called.call_count)
        self.assertEqual((1, 0), (self.control.used["model_calls"], self.control.used["retries"]))

    def test_provider_retry_then_contract_retry_are_distinct_transitions(self):
        result = ({"ok": True}, {})
        got, called = self.invoke([
            agentflow.AgentFlowError("PROVIDER_TRANSIENT", "network"),
            agentflow.AgentFlowError("INVALID_MODEL_OUTPUT", "contract"), result,
        ])
        self.assertEqual(result, got)
        self.assertEqual(3, called.call_count)
        self.assertEqual((3, 2, 0), (self.control.used["model_calls"],
                                     self.control.used["retries"], self.control.used["fallbacks"]))
        transitions = {p.name for p in (self.item / "transitions").iterdir()}
        self.assertTrue(any("primary-to-retry" in name for name in transitions))
        self.assertTrue(any("retry-to-structural_retry" in name for name in transitions))

    def test_contract_retry_preserves_original_deadline(self):
        clock = Clock()
        self.control.monotonic = clock
        self.control.started_monotonic = None
        self.control.deadline = None
        self.control.start()
        seen = []
        def dispatch(**kwargs):
            seen.append(self.control.deadline)
            if len(seen) == 1:
                clock.value = 5
                raise agentflow.AgentFlowError("INVALID_MODEL_OUTPUT", "bad")
            return ({"ok": True}, {})
        self.invoke(dispatch)
        self.assertEqual([60.0, 60.0], seen)

    def test_adjudicator_missing_stop_reason_repaired_with_distinct_evidence(self):
        invalid = {"verdict": "ADJUDICATION_COMPLETE", "findings": [],
                   "adjudication": {"correction_required": False, "classifications": {},
                                    "accepted_refs": [], "correction_brief": None}}
        valid = json.loads(json.dumps(invalid))
        valid["adjudication"]["stop_reason"] = None
        (result, _record), called = self.invoke_raw(
            "adjudicator", [invalid, valid], context={"initial_review_findings": []})
        self.assertIsNone(result["adjudication"]["stop_reason"])
        self.assertEqual(2, called.call_count)
        self.assertEqual((2, 1, 0), (self.control.used["model_calls"],
                                     self.control.used["retries"], self.control.used["fallbacks"]))
        self.assertEqual(called.call_args_list[0].kwargs["argv"][5],
                         called.call_args_list[1].kwargs["argv"][5])
        first = json.loads((self.run_dir / "adjudicator-cycle-0-invalid-output.json").read_text())
        self.assertIn("adjudication missing fields: ['stop_reason']", first["error"])
        self.assertEqual(invalid["adjudication"], json.loads(first["raw_output"])["adjudication"])
        retry_dir = next(self.run_dir.glob("attempts/*/structural_retry"))
        feedback = json.loads((retry_dir / "structural-retry-feedback.json").read_text())
        self.assertEqual(first["error"], feedback["error"])
        self.assertTrue((retry_dir / "adjudicator-cycle-0-result.json").is_file())
        self.assertTrue((retry_dir / "adjudicator-cycle-0-output.jsonl").is_file())
        self.assertNotEqual((self.run_dir / "adjudicator-cycle-0-output.jsonl").read_text(),
                            (retry_dir / "adjudicator-cycle-0-output.jsonl").read_text())
        self.assertIn(first["error"], called.call_args_list[1].kwargs["argv"][-1])

    def test_adjudicator_invalid_twice_stops_after_two_physical_calls(self):
        invalid = {"verdict": "ADJUDICATION_COMPLETE", "findings": [],
                   "adjudication": {"correction_required": False, "classifications": {},
                                    "accepted_refs": [], "correction_brief": None}}
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke_raw("adjudicator", [invalid, invalid])
        self.assertEqual("INVALID_MODEL_OUTPUT", caught.exception.code)
        self.assertEqual(2, caught.exception.called.call_count)
        self.assertEqual(1, len(list(self.run_dir.glob("attempts/*/structural_retry/*invalid-output.json"))))

    def test_reviewer_repair_reuses_profile_and_rechecks_mutation(self):
        invalid = {"verdict": "PASS", "findings": [{"severity": "HIGH", "text": "bad"}]}
        valid = {"verdict": "PASS", "findings": []}
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke_raw("reviewer", [invalid, valid],
                            changed=lambda a, b: ["src/changed.py"])
        self.assertEqual("READONLY_ROLE_WROTE_REPO", caught.exception.code)
        self.assertEqual(1, caught.exception.called.call_count)
        (result, record), called = self.invoke_raw("reviewer", [invalid, valid])
        self.assertEqual("PASS", result["verdict"])
        self.assertEqual("reviewer", record["profile"])
        self.assertEqual(2, called.call_count)
        self.assertEqual(["fake/beta-one", "fake/beta-one"],
                         [call.kwargs["argv"][5] for call in called.call_args_list])

    def test_reviewer_repaired_attempt_mutation_is_rejected(self):
        invalid = {"verdict": "PASS", "findings": [{"severity": "HIGH", "text": "bad"}]}
        valid = {"verdict": "PASS", "findings": []}
        deltas = iter([[], ["src/changed.py"]])
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke_raw("reviewer", [invalid, valid], changed=lambda a, b: next(deltas))
        self.assertEqual("READONLY_ROLE_WROTE_REPO", caught.exception.code)
        self.assertEqual(2, caught.exception.called.call_count)

    def test_architect_amode_and_bmode_contract_retry(self):
        plan = {"objective_interpretation": "Plan", "implementation_steps": ["Edit src/a"],
                "invariants": [], "allowed_scope": ["src/"], "do_not_change": [],
                "validation_expectations": [], "known_risks": []}
        bad = {"verdict": "PLAN_READY", "findings": [], "architect_plan": {}}
        good = {"verdict": "PLAN_READY", "findings": [], "architect_plan": plan}
        self.invoke_raw("architect", [bad, good])
        self.assertEqual(2, self.control.used["model_calls"])
        self.run_dir = self.root / "bmode-run"; self.run_dir.mkdir()
        self.control.used["model_calls"] = 0
        self.control.used["retries"] = 0
        bmode_context = agentflow._bmode_architect_context(2)
        bmode_good = json.loads(json.dumps(good))
        bmode_good["architect_plan"]["subtasks"] = [{
            "subtask_id": "s1", "objective": "Edit src/a", "allowed_paths": ["src/"],
            "invariants": [], "expected_outputs": []}]
        self.invoke_raw("architect", [good, bmode_good], context=bmode_context)
        first = json.loads((self.run_dir / "architect-cycle-0-invalid-output.json").read_text())
        self.assertIn("architect_plan.subtasks is required in B-mode", first["error"])

    def test_allowed_writer_partial_delta_prohibits_recovery(self):
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("PROVIDER_TRANSIENT", "x")],
                        role="worker", changed=lambda a, b: ["src/a.py"])
        self.assertEqual(1, caught.exception.called.call_count)

    def test_unauthorized_writer_delta_is_fatal(self):
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("PROVIDER_TRANSIENT", "x")],
                        role="worker", changed=lambda a, b: ["outside.txt"])
        self.assertEqual("UNAUTHORIZED_PATH_CHANGE", caught.exception.code)

    def test_fallback_is_never_retried_or_repeated(self):
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("PROVIDER_QUOTA_EXHAUSTED", "x"),
                         agentflow.AgentFlowError("PROVIDER_TRANSIENT", "x")])
        self.assertEqual(2, caught.exception.called.call_count)

    def test_attempt_evidence_is_distinct(self):
        result = ({"ok": True}, {})
        self.invoke([agentflow.AgentFlowError("PROVIDER_TRANSIENT", "x"), result])
        names = {p.name for p in (self.item / "transitions").iterdir()}
        self.assertTrue(any("primary-terminal" in n for n in names))
        self.assertTrue(any("retry-terminal" in n for n in names))
        self.assertTrue(any("primary-to-retry" in n for n in names))

    def test_unavailable_retry_budget_can_still_fallback(self):
        self.control.budgets["retries"] = 0
        result = ({"ok": True}, {})
        got, called = self.invoke([agentflow.AgentFlowError("PROVIDER_TRANSIENT", "x"), result])
        self.assertEqual(result, got); self.assertEqual(2, called.call_count)
        self.assertEqual((0, 1), (self.control.used["retries"], self.control.used["fallbacks"]))

    def test_unavailable_fallback_budget_does_not_consume(self):
        self.control.budgets["fallbacks"] = 0
        with self.assertRaises(agentflow.AgentFlowError):
            self.invoke([agentflow.AgentFlowError("PROVIDER_QUOTA_EXHAUSTED", "x")])
        self.assertEqual(0, self.control.used["fallbacks"])

    def test_correction_invocation_reserves_global_correction(self):
        token = agentflow._ACTIVE_EXECUTION_CONTROL.set(self.control)
        try:
            with mock.patch("agentflow._invoke_model_once", return_value=({"ok": True}, {})), \
                 mock.patch("agentflow.capture_baseline", return_value={}):
                agentflow.invoke_model(
                    role="worker", profile_name="worker", profile=models()["profiles"]["worker"],
                    task=self.task, run_dir=self.run_dir, cycle=1,
                    context={"kind": "adjudicated_correction"}, lease=mock.Mock(),
                    exec_repo=self.root)
        finally:
            agentflow._ACTIVE_EXECUTION_CONTROL.reset(token)
        self.assertEqual(1, self.control.used["corrections"])

    def test_readonly_delta_is_fatal(self):
        with self.assertRaises(agentflow.AgentFlowError) as caught:
            self.invoke([agentflow.AgentFlowError("PROVIDER_TRANSIENT", "x")],
                        changed=lambda a, b: ["src/a.py"])
        self.assertEqual("READONLY_ROLE_WROTE_REPO", caught.exception.code)


class QueueControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.queue_path = self.root / "q.json"
        self.q = queue_doc(3); self.queue_path.write_text(json.dumps(self.q), encoding="utf-8")
        self.frozen = [agentflow.FrozenQueueItem(
            ordinal=n, item_id=f"i{n}", queue_item=self.q["items"][n-1],
            program_path=self.root / f"p{n}.json", program=program(f"p{n}"),
            task_path=self.root / f"t{n}.json", task={**task(self.root), "task_id": f"t{n}"},
            source_repo=self.root, baseline_commit=SHA, profiles={}, hashes={})
            for n in range(1, 4)]

    def outcome(self, identity, item, outcome_class="HUMAN_GATE", verdict="HUMAN_GATE"):
        identity.run_dir.mkdir(parents=True, exist_ok=True)
        final = {"run_id": identity.run_id, "program_id": item.program["program_id"],
                 "task_id": item.task["task_id"], "verdict": verdict,
                 "status": "SUCCESS" if verdict == "HUMAN_GATE" else "STOPPED",
                 "human_gate": verdict == "HUMAN_GATE"}
        path = identity.run_dir / "final.json"; agentflow.atomic_json(path, final)
        return agentflow.ProgramOutcome(
            run_id=identity.run_id, run_dir=str(identity.run_dir), final_path=str(path),
            final_sha256=agentflow.sha256_path(path), program_id=item.program["program_id"],
            task_id=item.task["task_id"], verdict=verdict, status=final["status"],
            human_gate=final["human_gate"], outcome_class=outcome_class,
            primary_failure=None if verdict == "HUMAN_GATE" else verdict,
            secondary_failures=[], budget_dimension=None, execution_repo=str(self.root / identity.run_id),
            baseline_commit=SHA, preservation_status="PROVEN", preservation_evidence_path="workspace.json",
            process_quiescence="PROVEN", final=final)

    def run_queue_case(self, classes):
        calls = []
        def execute(p, t, identity, control):
            n = len(calls); calls.append((p["program_id"], identity.run_id))
            cls, verdict = classes[n]
            item = self.frozen[n]
            return self.outcome(identity, item, cls, verdict)
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            result = agentflow.run_queue(self.queue_path)
        return result, calls

    def test_human_gate_continues_in_exact_order(self):
        (code, run_dir, final), calls = self.run_queue_case([("HUMAN_GATE", "HUMAN_GATE")] * 3)
        self.assertEqual(0, code); self.assertEqual("HUMAN_GATES_READY", final["verdict"])
        self.assertEqual(["p1", "p2", "p3"], [c[0] for c in calls])
        self.assertEqual(3, len(final["pending_human_gates"]))

    def test_local_failure_continues(self):
        (_code, _dir, final), calls = self.run_queue_case([
            ("PROGRAM_LOCAL_FAILURE", "VALIDATOR_FAILED"),
            ("HUMAN_GATE", "HUMAN_GATE"), ("HUMAN_GATE", "HUMAN_GATE")])
        self.assertEqual(3, len(calls)); self.assertEqual("COMPLETED_WITH_PROGRAM_FAILURES", final["verdict"])

    def test_queue_fatal_stops_without_later_marker(self):
        (_code, run_dir, final), calls = self.run_queue_case([
            ("QUEUE_FATAL_FAILURE", "UNAUTHORIZED_PATH_CHANGE")])
        self.assertEqual(1, len(calls)); self.assertEqual(2, len(final["not_started_items"]))
        self.assertFalse((run_dir / "programs" / "02-i2" / "item-started.json").exists())

    def test_unproven_quiescence_stops_queue_even_for_local_verdict(self):
        calls = []
        def execute(p, t, identity, control):
            calls.append(identity.run_id)
            base = self.outcome(
                identity, self.frozen[0], "PROGRAM_LOCAL_FAILURE", "VALIDATOR_FAILED"
            )
            return agentflow.ProgramOutcome(**{
                **base.__dict__, "process_quiescence": "UNCERTAIN",
            })
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            _code, _run_dir, final = agentflow.run_queue(self.queue_path)
        self.assertEqual("INTERNAL_ERROR", final["verdict"])
        self.assertEqual(1, len(calls))
        self.assertEqual(2, len(final["not_started_items"]))

    def test_budget_stop_stops(self):
        (_code, _dir, final), calls = self.run_queue_case([("BUDGET_STOP", "BUDGET_EXHAUSTED")])
        self.assertEqual(1, len(calls)); self.assertEqual("BUDGET_EXHAUSTED", final["verdict"])

    def test_item_terminal_precedes_next_started(self):
        events = []
        original = agentflow.atomic_json_fsync
        def record(path, value):
            events.append(Path(path).name); return original(path, value)
        with mock.patch("agentflow.atomic_json_fsync", side_effect=record):
            self.run_queue_case([("HUMAN_GATE", "HUMAN_GATE")] * 3)
        first_terminal = events.index("item-terminal.json")
        self.assertGreater(events.index("item-started.json", first_terminal + 1), first_terminal)

    def test_distinct_program_run_directories(self):
        (_result, calls) = self.run_queue_case([("HUMAN_GATE", "HUMAN_GATE")] * 3)
        self.assertEqual(3, len({run_id for _p, run_id in calls}))

    def test_mixed_a_and_b_mode_queue_uses_same_executor_in_order(self):
        self.frozen[1].program["max_subtasks"] = 2
        seen = []
        def execute(p, t, identity, control):
            seen.append((p["program_id"], "max_subtasks" in p))
            return self.outcome(identity, self.frozen[len(seen) - 1])
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            code, _run_dir, _final = agentflow.run_queue(self.queue_path)
        self.assertEqual(0, code)
        self.assertEqual([("p1", False), ("p2", True), ("p3", False)], seen)

    def test_queue_consumes_structured_outcome_not_cli_text(self):
        with mock.patch("agentflow.run_program", side_effect=AssertionError("must not be called")):
            (code, _dir, _final), _calls = self.run_queue_case([("HUMAN_GATE", "HUMAN_GATE")] * 3)
        self.assertEqual(0, code)

    def test_digest_mismatch_becomes_queue_fatal(self):
        calls = []
        def execute(p, t, identity, control):
            calls.append(identity.run_id)
            outcome = self.outcome(identity, self.frozen[0])
            Path(outcome.final_path).write_text("{}", encoding="utf-8")
            return outcome
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            _code, _run_dir, final = agentflow.run_queue(self.queue_path)
        self.assertEqual("INTERNAL_ERROR", final["verdict"])
        self.assertEqual(1, len(calls))

    def test_program_outcome_semantic_mismatch_prevents_item_terminal_success(self):
        def execute(p, t, identity, control):
            outcome = self.outcome(identity, self.frozen[0])
            return agentflow.ProgramOutcome(**{**outcome.__dict__, "status": "STOPPED"})
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            _code, run_dir, final = agentflow.run_queue(self.queue_path)
        terminal = json.loads(
            (run_dir / "programs" / "01-i1" / "item-terminal.json").read_text()
        )
        self.assertEqual("INTERNAL_ERROR", terminal["program_outcome"]["verdict"])
        self.assertEqual("INTERNAL_ERROR", final["verdict"])

    def test_queue_state_snapshot_follows_item_terminal(self):
        events = []
        original = agentflow.atomic_json_fsync
        def record(path, value):
            events.append(Path(path).name); return original(path, value)
        with mock.patch("agentflow.atomic_json_fsync", side_effect=record):
            self.run_queue_case([("QUEUE_FATAL_FAILURE", "INTERNAL_ERROR")])
        self.assertLess(events.index("item-terminal.json"), events.index("queue-state.json"))

    def test_item_terminal_follows_final_integrity_and_safety_verification(self):
        events = []
        original_verify = agentflow.verify_program_outcome
        original_write = agentflow.atomic_json_fsync
        def verify(outcome):
            events.append("verified")
            self.assertEqual("PROVEN", outcome.preservation_status)
            self.assertEqual("PROVEN", outcome.process_quiescence)
            return original_verify(outcome)
        def write(path, value):
            if Path(path).name == "item-terminal.json":
                events.append("terminal")
            return original_write(path, value)
        with mock.patch("agentflow.verify_program_outcome", side_effect=verify), \
             mock.patch("agentflow.atomic_json_fsync", side_effect=write):
            self.run_queue_case([("HUMAN_GATE", "HUMAN_GATE")] * 3)
        self.assertLess(events.index("verified"), events.index("terminal"))

    def test_prior_precise_failure_survives_preservation_uncertainty(self):
        def execute(p, t, identity, control):
            base = self.outcome(identity, self.frozen[0], "PRESERVATION_UNCERTAIN", "VALIDATOR_FAILED")
            return agentflow.ProgramOutcome(**{
                **base.__dict__, "preservation_status": "UNCERTAIN",
                "primary_failure": "VALIDATOR_FAILED",
                "secondary_failures": [{"code": "WORKSPACE_PRESERVATION_FAILED"}],
            })
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            _code, _run_dir, final = agentflow.run_queue(self.queue_path)
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])

    def test_human_gate_preservation_uncertainty_stops_before_continuation(self):
        calls = []
        def execute(p, t, identity, control):
            calls.append(identity.run_id)
            base = self.outcome(identity, self.frozen[0])
            return agentflow.ProgramOutcome(**{
                **base.__dict__, "outcome_class": "PRESERVATION_UNCERTAIN",
                "preservation_status": "UNCERTAIN",
                "secondary_failures": [{"code": "WORKSPACE_PRESERVATION_FAILED"}],
            })
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            _code, _run_dir, final = agentflow.run_queue(self.queue_path)
        self.assertEqual(1, len(calls))
        self.assertEqual([], final["pending_human_gates"])
        self.assertEqual("WORKSPACE_PRESERVATION_FAILED", final["verdict"])

    def test_two_items_share_one_immutable_global_deadline(self):
        clock = Clock()
        seen = []
        frozen = self.frozen[:2]
        q = {**self.q, "items": self.q["items"][:2]}
        def execute(p, t, identity, control):
            seen.append(control.deadline)
            item = frozen[len(seen) - 1]
            clock.value += 9
            return self.outcome(identity, item)
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(q, frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            code, _run_dir, _final = agentflow.run_queue(self.queue_path, monotonic=clock)
        self.assertEqual(0, code)
        self.assertEqual([60.0, 60.0], seen)

    def test_precise_failure_remains_primary_when_deadline_expires_later(self):
        clock = Clock()
        calls = []
        def execute(p, t, identity, control):
            calls.append(identity.run_id)
            outcome = self.outcome(
                identity, self.frozen[0], "PROGRAM_LOCAL_FAILURE", "VALIDATOR_FAILED"
            )
            clock.value = 61
            return outcome
        with mock.patch.object(agentflow, "QUEUE_RUNS_DIR", self.root / "queues"), \
             mock.patch.object(agentflow, "RUNS_DIR", self.root / "runs"), \
             mock.patch("agentflow.preflight_queue", return_value=(self.q, self.frozen, models())), \
             mock.patch("agentflow.execute_program", side_effect=execute):
            _code, _run_dir, final = agentflow.run_queue(self.queue_path, monotonic=clock)
        self.assertEqual(1, len(calls))
        self.assertEqual("VALIDATOR_FAILED", final["verdict"])
        self.assertEqual("WALL_CLOCK", final["budget_dimension"])


class RealQueueExecutorIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"; self.source.mkdir()
        subprocess.run(["git", "init"], cwd=self.source, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "queue@test.invalid"],
            cwd=self.source, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Queue Test"],
            cwd=self.source, check=True, capture_output=True,
        )
        (self.source / "README.md").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.source, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "baseline"],
            cwd=self.source, check=True, capture_output=True,
        )
        self.head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.source, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        self.fake = self.root / "fake-model"
        self.fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "prompt = sys.argv[-1]\n"
            "role = next((r for r in ('adjudicator','architect','worker','reviewer') "
            "if '\"role\": \"' + r + '\"' in prompt), 'reviewer')\n"
            "result = {'files_changed': [], 'validators': {}, 'findings': [], "
            "'open_risks': [], 'verdict': 'PASS'}\n"
            "if role == 'architect':\n"
            " result.update(verdict='PLAN_READY', architect_plan={"
            "'objective_interpretation':'bounded queue test',"
            "'implementation_steps':['leave baseline unchanged'],"
            "'invariants':[],'allowed_scope':[],'do_not_change':[],"
            "'validation_expectations':['validator passes'],'known_risks':[]})\n"
            "elif role == 'adjudicator':\n"
            " result.update(verdict='ADJUDICATION_COMPLETE', adjudication={"
            "'correction_required':False,'classifications':{},'accepted_refs':[],"
            "'correction_brief':None,'stop_reason':None})\n"
            "sys.stdout.write(json.dumps(result))\n",
            encoding="utf-8",
        )
        self.fake.chmod(0o755)

    def test_real_executor_preserves_two_human_gates_without_publication(self):
        specs = self.root / "specs"; specs.mkdir()
        items = []
        for ordinal in (1, 2):
            task_doc = {
                "task_id": f"real-t{ordinal}", "repo": str(self.source),
                "risk": "LOW", "objective": "exercise real queue boundary",
                "allowed_paths": ["src/"],
                "validators": [{"name": "local", "command": ["/usr/bin/true"]}],
                "isolation": {"enabled": True, "baseline_commit": self.head},
            }
            (specs / f"task{ordinal}.json").write_text(
                json.dumps(task_doc), encoding="utf-8"
            )
            program_doc = {
                "program_id": f"real-p{ordinal}", "task": f"task{ordinal}.json",
                "roles": {"architect": "arch", "worker": "worker", "reviewer": "reviewer"},
                "max_corrections": 1,
            }
            program_path = specs / f"program{ordinal}.json"
            program_path.write_text(json.dumps(program_doc), encoding="utf-8")
            items.append({"item_id": f"real-i{ordinal}", "program": str(program_path)})
        queue_path = specs / "queue.json"
        queue_path.write_text(json.dumps({
            "queue_id": "real-boundary", "items": items,
            "budgets": {"wall_clock_seconds": 120, "model_calls": 20,
                        "retries": 0, "fallbacks": 0, "corrections": 1},
        }), encoding="utf-8")
        def profile(provider, model, agent, roles):
            return {"backend": "opencode", "command": str(self.fake),
                    "provider": provider, "model": model, "variant": None,
                    "agent": agent, "available": True,
                    "eligible_roles": list(roles)}
        local_models = {"profiles": {
            "arch": profile("arch-local", "local/architect", "agentflow-architect",
                            ("architect", "adjudicator")),
            "worker": profile("worker-local", "local/worker", "agentflow-worker",
                              ("worker",)),
            "reviewer": profile("review-local", "local/reviewer", "agentflow-reviewer",
                                ("reviewer",)),
        }}
        runs = self.root / "runs"; queues = runs / "queues"
        locks = self.root / "locks"; worktrees = self.root / "worktrees"
        runs.mkdir(); locks.mkdir(); worktrees.mkdir()
        commands = []
        writes = []
        original_queue_process = agentflow._run_queue_process
        original_run_process = agentflow.run_process
        original_atomic = agentflow.atomic_json
        original_atomic_fsync = agentflow.atomic_json_fsync
        def queue_spy(argv, **kwargs):
            commands.append(tuple(argv)); return original_queue_process(argv, **kwargs)
        def process_spy(argv, **kwargs):
            commands.append(tuple(argv)); return original_run_process(argv, **kwargs)
        def atomic_spy(path, value):
            writes.append(str(path)); return original_atomic(path, value)
        def atomic_fsync_spy(path, value):
            writes.append(str(path)); return original_atomic_fsync(path, value)
        with mock.patch.object(agentflow, "RUNS_DIR", runs), \
             mock.patch.object(agentflow, "QUEUE_RUNS_DIR", queues), \
             mock.patch.object(agentflow, "LOCKS_DIR", locks), \
             mock.patch.dict(os.environ, {"AGENTFLOW_WORKTREES_DIR": str(worktrees)}), \
             mock.patch("agentflow.load_models", return_value=local_models), \
             mock.patch("agentflow._run_queue_process", side_effect=queue_spy), \
             mock.patch("agentflow.run_process", side_effect=process_spy), \
             mock.patch("agentflow.atomic_json", side_effect=atomic_spy), \
             mock.patch("agentflow.atomic_json_fsync", side_effect=atomic_fsync_spy):
            code, queue_run_dir, final = agentflow.run_queue(queue_path)

        self.assertEqual(0, code, final)
        self.assertEqual("HUMAN_GATES_READY", final["verdict"])
        self.assertEqual(2, len(final["pending_human_gates"]))
        execution_repos = [Path(item["execution_repo"]) for item in final["pending_human_gates"]]
        self.assertEqual(2, len(set(execution_repos)))
        for repo in execution_repos:
            self.assertTrue(repo.is_dir())
            self.assertTrue(agentflow._is_worktree_registered(self.source, repo))
        persisted = json.loads((queue_run_dir / "final.json").read_text())
        self.assertEqual(
            [str(path) for path in execution_repos],
            [item["execution_repo"] for item in persisted["pending_human_gates"]],
        )
        forbidden = {
            "commit", "push", "merge", "stash", "reset", "cherry-pick",
            "rebase", "branch", "switch", "tag",
        }
        git_subcommands = [
            argv[1] for argv in commands
            if argv and Path(argv[0]).name == "git" and len(argv) > 1
        ]
        self.assertTrue(git_subcommands)
        self.assertTrue(forbidden.isdisjoint(git_subcommands), git_subcommands)
        self.assertNotIn("remove", [
            argv[2] for argv in commands
            if len(argv) > 2 and Path(argv[0]).name == "git" and argv[1] == "worktree"
        ])
        self.assertFalse(any("telemetry" in path.lower() for path in writes))


class OutcomeVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make(self):
        final = {"run_id": "r", "program_id": "p", "task_id": "t", "verdict": "HUMAN_GATE",
                 "status": "SUCCESS", "human_gate": True}
        path = self.root / "final.json"; agentflow.atomic_json(path, final)
        return agentflow.ProgramOutcome(
            run_id="r", run_dir=str(self.root), final_path=str(path),
            final_sha256=agentflow.sha256_path(path), program_id="p", task_id="t",
            verdict="HUMAN_GATE", status="SUCCESS", human_gate=True,
            outcome_class="HUMAN_GATE", primary_failure=None, secondary_failures=[],
            budget_dimension=None, execution_repo=str(self.root), baseline_commit=SHA,
            preservation_status="PROVEN", preservation_evidence_path="workspace.json",
            process_quiescence="PROVEN", final=final)

    def test_matching_final_is_accepted(self):
        agentflow.verify_program_outcome(self.make())

    def test_semantic_mismatch_is_fatal(self):
        outcome = self.make(); outcome.final["status"] = "STOPPED"
        with self.assertRaises(agentflow.AgentFlowError): agentflow.verify_program_outcome(outcome)

    def test_missing_final_is_fatal(self):
        outcome = self.make(); Path(outcome.final_path).unlink()
        with self.assertRaises(agentflow.AgentFlowError): agentflow.verify_program_outcome(outcome)

    def test_unproven_quiescence_is_fatal(self):
        outcome = self.make()
        bad = agentflow.ProgramOutcome(**{**outcome.__dict__, "process_quiescence": "UNCERTAIN"})
        with self.assertRaises(agentflow.AgentFlowError): agentflow.verify_program_outcome(bad)

    def test_non_internal_verdict_uses_actual_unproven_process_evidence(self):
        run_dir = self.root / "run"; run_dir.mkdir()
        final = {"run_id": "r2", "program_id": "p", "task_id": "t",
                 "verdict": "VALIDATOR_FAILED", "status": "STOPPED", "human_gate": False}
        agentflow.atomic_json(run_dir / "final.json", final)
        control = agentflow.ExecutionControl(
            queue_id="q", queue_run_dir=self.root, item_dir=self.root,
            budgets={"wall_clock_seconds": 60, "model_calls": 1, "retries": 0,
                     "fallbacks": 0, "corrections": 0},
            fallback_profiles={}, models=models(),
        )
        control.start(); control.note_process_started()
        nonisolated_task = task(self.root)
        nonisolated_task.pop("isolation")
        outcome = agentflow._verified_program_outcome(
            program=program(), task=nonisolated_task,
            run_identity=agentflow.RunIdentity("r2", run_dir),
            returned_final=final, execution_control=control,
        )
        self.assertEqual("VALIDATOR_FAILED", outcome.verdict)
        self.assertEqual("UNCERTAIN", outcome.process_quiescence)
        self.assertEqual("QUEUE_FATAL_FAILURE", outcome.outcome_class)


class StandaloneCompatibilityTests(unittest.TestCase):
    def test_no_control_means_no_recovery_or_reservation(self):
        expected = ({"ok": True}, {"record": True})
        with mock.patch("agentflow._invoke_model_once", return_value=expected) as once:
            got = agentflow.invoke_model(
                role="reviewer", profile_name="reviewer", profile=models()["profiles"]["reviewer"],
                task=task(Path("/tmp")), run_dir=Path("/tmp"), cycle=0)
        self.assertEqual(expected, got); once.assert_called_once()

    def test_cli_queue_run_shape(self):
        final = {"verdict": "HUMAN_GATES_READY", "status": "SUCCESS"}
        stdout = io.StringIO()
        with mock.patch("agentflow.run_queue", return_value=(0, Path("/tmp/q"), final)), \
             contextlib.redirect_stdout(stdout):
            code = agentflow.main(["queue", "run", "q.json"])
        self.assertEqual(0, code); self.assertIn("queue_run_dir", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
