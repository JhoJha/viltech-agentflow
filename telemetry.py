#!/usr/bin/env python3
"""VilTech Telemetry V0 (TEL-001): capture durable human + external evidence.

OBSERVE, never control. This module is fully independent from the AgentFlow
runtime: it never imports agentflow.py and never writes runs/, .locks/,
config/, tasks/ or any existing file. It only appends new JSON event files
under telemetry/v1/events/ and reads (never writes) runs/ + config + self
for artifact provenance and environment hashes.

Append-only semantics: one JSON file per event, atomic publication,
O_EXCL, never overwrite, never edit. Human corrections are NEW events
that reference supersedes_event_id. Re-running the same content creates a
new visible event (no semantic idempotency in V0).
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TELEMETRY_VERSION = 1
ROOT = Path(__file__).resolve().parent
EVENTS_DIR = ROOT / "telemetry" / "v1" / "events"
RUNS_DIR = ROOT / "runs"
MODELS_FILE = ROOT / "config" / "models.json"
AGENTFLOW_FILE = ROOT / "agentflow.py"

EVENT_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
UTC_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

GATE_DECISIONS = ("accepted_as_is", "accepted_with_changes", "rejected", "superseded")
SESSION_TYPES = ("persistent", "fresh", "unknown")
TIMING_SOURCES = ("observed", "provided", "unknown")
TOKEN_SOURCES = ("reported", "partial", "unavailable")
COST_SOURCES = ("provider_reported", "harness_estimated", "unavailable")
ACTOR_KINDS_KNOWN = ("model", "human", "tool")

NOTE_MAX = 2000
SUMMARY_MAX = 500
ACTOR_MAX = 200

# High-confidence secret shapes only. Never auto-redact: a match rejects the
# write. Free-text notes that merely mention the word "secret" do not match
# because every pattern requires an assignment shape or a known token shape.
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(ghp_[A-Za-z0-9]{8,}|gho_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|xox[bpas]-[A-Za-z0-9-]{6,})\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{10,}"),
    re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|pwd|token|bearer|credentials?)\b\s*[:=]\s*\S+"),
)


class TelemetryError(RuntimeError):
    pass


def utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_event_id(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    return moment.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def parse_utc_z(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not UTC_TS_RE.match(value):
        raise TelemetryError(f"{label} must be UTC ISO-8601 ending in Z")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise TelemetryError(f"{label} is not a valid UTC timestamp") from exc


def check_secret_free(text: str | None, label: str) -> None:
    if text is None:
        return
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            raise TelemetryError(f"{label} looks like it contains a secret; refusing to record")


def _check_utf8_encodable(text: str, label: str) -> None:
    """Reject writer text that can never be stored (lone surrogates).

    Lone surrogates are legal argv/JSON string content but unencodable:
    publish_event serializes with ensure_ascii=False + UTF-8, so such
    text would raise UnicodeEncodeError there (traceback, exit 1,
    nothing written). Validation must fail first with a controlled
    TelemetryError (CLI exit 2, nothing written). Input is never
    silently mutated: the write is refused, not rewritten.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TelemetryError(
            f"{label} is not valid UTF-8 text and cannot be recorded") from exc


def check_plain_text(text: Any, label: str, limit: int) -> str | None:
    if text is None:
        return None
    if not isinstance(text, str):
        raise TelemetryError(f"{label} must be a string or null")
    if len(text) > limit:
        raise TelemetryError(f"{label} exceeds {limit} characters")
    if any(ord(char) < 32 and char not in ("\n", "\t") for char in text):
        raise TelemetryError(f"{label} contains control characters")
    _check_utf8_encodable(text, label)
    check_secret_free(text, label)
    return text


def check_actor(actor: Any) -> str:
    if not isinstance(actor, str) or not actor.strip():
        raise TelemetryError("actor is required and must be a non-empty string")
    if len(actor) > ACTOR_MAX:
        raise TelemetryError(f"actor exceeds {ACTOR_MAX} characters")
    if any(ord(char) < 32 for char in actor):
        raise TelemetryError("actor contains control characters")
    _check_utf8_encodable(actor, "actor")
    check_secret_free(actor, "actor")
    return actor


def check_task_id(task_id: Any) -> str:
    if not isinstance(task_id, str) or not task_id.strip():
        raise TelemetryError("task_id is required and must be a non-empty string")
    if len(task_id) > 200:
        raise TelemetryError("task_id exceeds 200 characters")
    return task_id


def check_optional_task_id(task_id: Any) -> str | None:
    if task_id is None:
        return None
    return check_task_id(task_id)


def check_run_id(run_id: Any) -> str | None:
    if run_id is None:
        return None
    if not isinstance(run_id, str) or not run_id.strip():
        raise TelemetryError("run_id must be a non-empty string or null")
    if "/" in run_id or run_id in (".", "..") or ".." in run_id or run_id.startswith("."):
        raise TelemetryError("run_id is not a plain run directory name")
    return run_id


def check_finite_number(value: Any, label: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TelemetryError(f"{label} must be a finite number")
    try:
        finite = math.isfinite(value)
    except (OverflowError, ValueError):
        raise TelemetryError(f"{label} must be finite (NaN/Infinity rejected)")
    if not finite:
        raise TelemetryError(f"{label} must be finite (NaN/Infinity rejected)")
    return value


def _is_supported_version(value: Any) -> bool:
    """Strict version gate: only exact int 1 counts, never bool/float.

    Python's == would accept True == 1 and 1.0 == 1; verify must not treat
    those as semantic version 1.
    """
    return type(value) is int and value == TELEMETRY_VERSION


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def environment_hashes(root: Path | None = None) -> dict[str, str | None]:
    """Hash the harness files that define the rules of play. Read-only.

    Returns nulls (never raises) when a file is unavailable; provenance is
    best-effort evidence, not a gate on recording. A null hash means
    "provenance unavailable/degraded", never "provenance verified": nothing
    is invented, and a visible warning goes to stderr so degraded
    provenance can never pass silently.
    """
    base = ROOT if root is None else Path(root)
    out: dict[str, str | None] = {"models_sha256": None, "agentflow_sha256": None}
    missing: list[str] = []
    try:
        out["models_sha256"] = sha256_file(base / "config" / "models.json")
    except OSError:
        missing.append("models_sha256")
    try:
        out["agentflow_sha256"] = sha256_file(base / "agentflow.py")
    except OSError:
        missing.append("agentflow_sha256")
    if missing:
        print(
            "telemetry: warning: degraded environment provenance "
            f"({', '.join(missing)} unavailable, recorded as null; "
            "null means provenance unavailable, not verified)",
            file=sys.stderr,
        )
    return out


def _path_label_invalid(label: str, value: str) -> str | None:
    """Return a reason when a JSON string cannot be a filesystem path.

    NUL bytes and lone surrogates are legal JSON string content but can never
    name a file: OS calls raise ValueError (embedded null byte) or
    UnicodeEncodeError (a ValueError subclass). Such refs are structurally
    unsafe (ARTIFACT_INVALID), never "historical unavailable".
    """
    if "\x00" in value:
        return f"artifact ref {label} contains NUL (not a usable filesystem path)"
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return f"artifact ref {label} is not a usable filesystem path"
    return None


def _symlink_loop_reason(target: Path) -> str | None:
    """Return a reason when an artifact target is unreachable specifically
    because a symlink loop sits on the path, else None.

    Background: Path.resolve() in non-strict mode behaves
    version-dependently for symlink loops — some versions raise
    RuntimeError ("Symlink loop"), newer ones resolve lexically and the
    target merely looks missing (is_file() False, no exception). A loop
    is structurally unsafe (ARTIFACT_INVALID), never "historical
    artifact unavailable": re-resolving strictly surfaces ELOOP
    (errno 40) only for loops, while genuinely missing files raise
    ENOENT and unreadable paths raise other OSErrors (both map to
    None here so the caller's missing/unavailable path is unchanged).
    Never raises: strictly a read-only probe.
    """
    try:
        target.resolve(strict=True)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return ("artifact ref traverses a symlink loop "
                    f"and cannot be resolved: {exc}")
        return None
    except (ValueError, RuntimeError) as exc:
        return f"artifact ref cannot be resolved: {exc}"
    return None


def validate_artifact_ref(ref: Any, runs_dir: Path) -> dict[str, str]:
    """Validate one artifact citation. Resolves content hash from disk."""
    if not isinstance(ref, dict):
        raise TelemetryError("artifact ref must be an object")
    run_id = ref.get("run_id")
    relpath = ref.get("relpath")
    if not isinstance(run_id, str) or not run_id or "/" in run_id or ".." in run_id or run_id.startswith("."):
        raise TelemetryError("artifact ref run_id must be a plain run directory name")
    if not isinstance(relpath, str) or not relpath:
        raise TelemetryError("artifact ref relpath must be a non-empty relative path")
    for _label, _value in (("run_id", run_id), ("relpath", relpath)):
        _bad = _path_label_invalid(_label, _value)
        if _bad is not None:
            raise TelemetryError(_bad)
    if relpath.startswith("/") or relpath.startswith("~") or ".." in Path(relpath).parts:
        raise TelemetryError("artifact ref relpath must stay inside runs/<run_id>/")
    run_root = runs_dir / run_id
    # A symlinked run root (runs/<run_id> -> elsewhere) must be rejected
    # lexically, BEFORE any resolve(): resolving first and then checking
    # containment would trust the symlink target and allow hashing files
    # outside runs/.
    try:
        if run_root.is_symlink():
            raise TelemetryError("artifact ref run root must not be a symlink")
    except (OSError, ValueError) as exc:
        raise TelemetryError(f"artifact ref cannot be resolved: {exc}") from exc
    target = runs_dir / run_id / relpath
    try:
        resolved = target.resolve()
        expected_root = (runs_dir / run_id).resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        # Narrow path-resolution boundary: some Python versions raise
        # RuntimeError ("Symlink loop") from resolve() instead of OSError.
        # Only resolve() is guarded — unrelated internal RuntimeErrors
        # elsewhere still propagate.
        raise TelemetryError(f"artifact ref cannot be resolved: {exc}") from exc
    if resolved != expected_root and expected_root not in resolved.parents:
        raise TelemetryError("artifact ref escapes runs/<run_id>/")
    try:
        if target.is_symlink() or resolved.is_symlink():
            raise TelemetryError("artifact ref must not be a symlink")
        if not resolved.is_file():
            loop_reason = _symlink_loop_reason(target)
            if loop_reason is not None:
                raise TelemetryError(loop_reason)
            raise TelemetryError("artifact ref must be a regular file that exists")
    except (OSError, ValueError) as exc:
        raise TelemetryError(f"artifact ref cannot be resolved: {exc}") from exc
    try:
        digest = sha256_file(resolved)
    except (OSError, ValueError) as exc:
        raise TelemetryError(f"artifact ref cannot be read/hashed: {exc}") from exc
    return {"run_id": run_id, "relpath": relpath, "sha256": digest}


def check_event_id(value: Any, label: str = "event_id") -> str:
    if not isinstance(value, str) or not EVENT_ID_RE.match(value):
        raise TelemetryError(f"{label} must match YYYYMMDDTHHMMSSZ-<6hex>")
    return value


def load_event(events_dir: Path, event_id: str) -> dict[str, Any]:
    path = events_dir / f"{event_id}.json"
    # A prior event used for supersession must be a regular file physically
    # contained in the events directory, never a symlink: a planted
    # events/<event_id>.json link (to an outside file OR to another event
    # inside the dir) must not be trusted as prior evidence. The symlink
    # check is lexical (no following) so within-directory links are caught
    # too — resolve-then-contain alone would miss those.
    try:
        if path.is_symlink():
            raise TelemetryError(f"referenced event must not be a symlink: {event_id}")
    except OSError as exc:
        raise TelemetryError(f"referenced event cannot be resolved: {event_id}") from exc
    try:
        resolved = path.resolve()
        expected_dir = events_dir.resolve()
    except OSError as exc:
        raise TelemetryError(f"referenced event cannot be resolved: {event_id}") from exc
    if resolved != expected_dir and expected_dir not in resolved.parents:
        raise TelemetryError(f"referenced event escapes the events directory: {event_id}")
    if not resolved.exists():
        raise TelemetryError(f"referenced event not found: {event_id}")
    if resolved.is_symlink() or not resolved.is_file():
        raise TelemetryError(f"referenced event must be a regular file: {event_id}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TelemetryError(f"referenced event not found: {event_id}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TelemetryError(f"referenced event is not valid JSON: {event_id}") from exc
    if not isinstance(data, dict):
        raise TelemetryError(f"referenced event is not an object: {event_id}")
    return data


def check_supersedes(value: Any, current: dict[str, Any], events_dir: Path) -> str | None:
    if value is None:
        return None
    supersedes = check_event_id(value, "supersedes_event_id")
    previous = load_event(events_dir, supersedes)
    if previous.get("event_type") != current.get("event_type"):
        raise TelemetryError("supersedes_event_id must reference the same event_type")
    if previous.get("task_id") != current.get("task_id"):
        raise TelemetryError("supersedes_event_id must reference the same task_id")
    return supersedes


_GATE_KNOWN_KEYS = frozenset({
    "telemetry_version", "event_id", "event_type", "recorded_at", "task_id",
    "run_id", "actor", "decision_source", "environment", "supersedes_event_id",
    "artifact_refs", "decision", "decided_at", "note",
})


_EXTERNAL_KNOWN_KEYS = frozenset({
    "telemetry_version", "event_id", "event_type", "recorded_at", "task_id",
    "run_id", "actor", "actor_kind", "attestation_source", "environment",
    "supersedes_event_id", "artifact_refs", "roles", "model", "session_type",
    "timing", "outcome", "usage", "note",
})


def passthrough_unknowns(event: dict[str, Any], known: frozenset[str]) -> dict[str, Any]:
    """Preserve forward-compatible unknown fields (readers must tolerate them;
    writers must not drop them). Unknowns never override validated keys."""
    return {key: value for key, value in event.items() if key not in known}


def validate_gate_event(event: Any, runs_dir: Path, events_dir: Path) -> dict[str, Any]:
    """Validate a fully built human_gate event. Pure: no I/O except loading
    a referenced superseded event."""
    if not isinstance(event, dict):
        raise TelemetryError("gate event must be an object")
    if not _is_supported_version(event.get("telemetry_version")):
        raise TelemetryError("gate event has unsupported telemetry_version")
    check_event_id(event.get("event_id"))
    if event.get("event_type") != "human_gate":
        raise TelemetryError("gate event must have event_type human_gate")
    parse_utc_z(event.get("recorded_at"), "recorded_at")  # type: ignore[arg-type]
    task_id = check_task_id(event.get("task_id"))
    run_id = check_run_id(event.get("run_id"))
    actor = check_actor(event.get("actor"))
    if event.get("decision_source") != "human":
        raise TelemetryError('gate decision_source must be exactly "human"')
    decision = event.get("decision")
    if decision not in GATE_DECISIONS:
        raise TelemetryError("gate decision must be one of: " + ", ".join(GATE_DECISIONS))
    supersedes = check_supersedes(event.get("supersedes_event_id"), event, events_dir)
    if decision == "superseded" and supersedes is None:
        raise TelemetryError('decision "superseded" requires supersedes_event_id')
    decided_at = event.get("decided_at")
    if decided_at is not None:
        decided = parse_utc_z(decided_at, "decided_at")
        recorded = parse_utc_z(event["recorded_at"], "recorded_at")
        if decided > recorded:
            raise TelemetryError("decided_at must not be after recorded_at")
    refs = event.get("artifact_refs")
    if not isinstance(refs, list):
        raise TelemetryError("artifact_refs must be a list")
    validated_refs = [validate_artifact_ref(ref, runs_dir) for ref in refs]
    note = check_plain_text(event.get("note"), "note", NOTE_MAX)
    env = event.get("environment")
    if env is not None:
        if not isinstance(env, dict):
            raise TelemetryError("environment must be an object or null")
        for key in ("models_sha256", "agentflow_sha256"):
            if env.get(key) is not None and (
                not isinstance(env[key], str) or not re.fullmatch(r"[0-9a-f]{64}", env[key])
            ):
                raise TelemetryError(f"environment.{key} must be a sha256 hex string or null")
    return {
        **passthrough_unknowns(event, _GATE_KNOWN_KEYS),
        "telemetry_version": TELEMETRY_VERSION,
        "event_id": event["event_id"],
        "event_type": "human_gate",
        "recorded_at": event["recorded_at"],
        "task_id": task_id,
        "run_id": run_id,
        "actor": actor,
        "decision_source": "human",
        "environment": env,
        "supersedes_event_id": supersedes,
        "artifact_refs": validated_refs,
        "decision": decision,
        "decided_at": decided_at,
        "note": note,
    }


def check_token_count(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TelemetryError(f"{label} must be a non-negative integer or null")
    return value


def validate_external_event(event: Any, runs_dir: Path, events_dir: Path) -> dict[str, Any]:
    """Validate a fully built external_execution event. Pure except loading
    a referenced superseded event."""
    if not isinstance(event, dict):
        raise TelemetryError("external event must be an object")
    if not _is_supported_version(event.get("telemetry_version")):
        raise TelemetryError("external event has unsupported telemetry_version")
    check_event_id(event.get("event_id"))
    if event.get("event_type") != "external_execution":
        raise TelemetryError("external event must have event_type external_execution")
    parse_utc_z(event.get("recorded_at"), "recorded_at")  # type: ignore[arg-type]
    task_id = check_optional_task_id(event.get("task_id"))
    run_id = check_run_id(event.get("run_id"))
    actor = check_actor(event.get("actor"))
    actor_kind = event.get("actor_kind")
    if not isinstance(actor_kind, str) or not actor_kind.strip():
        raise TelemetryError("actor_kind is required and must be a non-empty string")
    if len(actor_kind) > 40:
        raise TelemetryError("actor_kind exceeds 40 characters")
    if "decision_source" in event:
        raise TelemetryError("external_execution must not carry decision_source; it is not a decision")
    if event.get("attestation_source") != "human":
        raise TelemetryError('external attestation_source must be exactly "human"')
    roles = event.get("roles")
    if not isinstance(roles, list) or not roles:
        raise TelemetryError("roles must be a non-empty array")
    for role in roles:
        if not isinstance(role, str) or not role.strip() or len(role) > 40:
            raise TelemetryError("each role must be a non-empty string of at most 40 characters")
    model = event.get("model")
    if not isinstance(model, dict):
        raise TelemetryError("model must be an object")
    for key in ("provider", "model_id", "variant"):
        value = model.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 200):
            raise TelemetryError(f"model.{key} must be a non-empty string or null")
    session_type = event.get("session_type", "unknown")
    if session_type not in SESSION_TYPES:
        raise TelemetryError("session_type must be one of: " + ", ".join(SESSION_TYPES))
    if "session_id" in event or "thread_id" in event or "session_ref" in event:
        raise TelemetryError("provider session identifiers must not be recorded; use session_type")
    timing = event.get("timing") or {}
    if not isinstance(timing, dict):
        raise TelemetryError("timing must be an object")
    timing_source = timing.get("timing_source", "unknown")
    if timing_source not in TIMING_SOURCES:
        raise TelemetryError("timing_source must be one of: " + ", ".join(TIMING_SOURCES))
    started = timing.get("started_at")
    finished = timing.get("finished_at")
    if started is not None:
        parse_utc_z(started, "timing.started_at")
    if finished is not None:
        parse_utc_z(finished, "timing.finished_at")
    if started is not None and finished is not None:
        if parse_utc_z(finished, "timing.finished_at") < parse_utc_z(started, "timing.started_at"):
            raise TelemetryError("timing.finished_at must not be before timing.started_at")
    outcome = event.get("outcome") or {}
    if not isinstance(outcome, dict):
        raise TelemetryError("outcome must be an object")
    verdict = outcome.get("verdict")
    if verdict is not None and (not isinstance(verdict, str) or not verdict.strip() or len(verdict) > 80):
        raise TelemetryError("outcome.verdict must be a short non-empty string or null")
    summary = check_plain_text(outcome.get("summary"), "outcome.summary", SUMMARY_MAX)
    usage = event.get("usage") or {}
    if not isinstance(usage, dict):
        raise TelemetryError("usage must be an object")
    token_source = usage.get("token_source", "unavailable")
    if token_source not in TOKEN_SOURCES:
        raise TelemetryError("token_source must be one of: " + ", ".join(TOKEN_SOURCES))
    tokens = usage.get("tokens") or {}
    if not isinstance(tokens, dict):
        raise TelemetryError("usage.tokens must be an object")
    token_counts = {key: check_token_count(tokens.get(key), f"usage.tokens.{key}") for key in ("in", "out", "reasoning", "cached")}
    cost = usage.get("cost") or {}
    if not isinstance(cost, dict):
        raise TelemetryError("usage.cost must be an object")
    cost_source = cost.get("source", "unavailable")
    if cost_source not in COST_SOURCES:
        raise TelemetryError("cost.source must be one of: " + ", ".join(COST_SOURCES))
    cost_value = cost.get("value")
    if cost_value is not None:
        check_finite_number(cost_value, "usage.cost.value")
    currency = cost.get("currency")
    if cost_value is not None and (not isinstance(currency, str) or not currency.strip() or len(currency) > 16):
        raise TelemetryError("usage.cost.currency is required when cost.value is present")
    if currency is not None and (not isinstance(currency, str) or len(currency) > 16):
        raise TelemetryError("usage.cost.currency must be a short string or null")
    supersedes = check_supersedes(event.get("supersedes_event_id"), event, events_dir)
    refs = event.get("artifact_refs") or []
    if not isinstance(refs, list):
        raise TelemetryError("artifact_refs must be a list")
    validated_refs = [validate_artifact_ref(ref, runs_dir) for ref in refs]
    note = check_plain_text(event.get("note"), "note", NOTE_MAX)
    env = event.get("environment")
    if env is not None:
        if not isinstance(env, dict):
            raise TelemetryError("environment must be an object or null")
        for key in ("models_sha256", "agentflow_sha256"):
            if env.get(key) is not None and (
                not isinstance(env[key], str) or not re.fullmatch(r"[0-9a-f]{64}", env[key])
            ):
                raise TelemetryError(f"environment.{key} must be a sha256 hex string or null")
    return {
        **passthrough_unknowns(event, _EXTERNAL_KNOWN_KEYS),
        "telemetry_version": TELEMETRY_VERSION,
        "event_id": event["event_id"],
        "event_type": "external_execution",
        "recorded_at": event["recorded_at"],
        "task_id": task_id,
        "run_id": run_id,
        "actor": actor,
        "actor_kind": actor_kind,
        "attestation_source": "human",
        "environment": env,
        "supersedes_event_id": supersedes,
        "artifact_refs": validated_refs,
        "roles": roles,
        "model": {
            "provider": model.get("provider"),
            "model_id": model.get("model_id"),
            "variant": model.get("variant"),
        },
        "session_type": session_type,
        "timing": {"started_at": started, "finished_at": finished, "timing_source": timing_source},
        "outcome": {"verdict": verdict, "summary": summary},
        "usage": {
            "token_source": token_source,
            "tokens": token_counts,
            "cost": {"source": cost_source, "value": cost_value, "currency": currency},
        },
        "note": note,
    }


def _verify_finding(severity: str, code: str, filename: str | None,
                     event_id: str | None, detail: str) -> dict[str, Any]:
    return {
        "severity": severity,
        "code": code,
        "file": filename,
        "event_id": event_id,
        "detail": detail,
    }


def _duplicate_fingerprint(event: dict[str, Any]) -> str | None:
    """Conservative semantic fingerprint: whole payload minus the two
    inherently unique/temporal fields. Anything else differing (verdict,
    summary, note, roles, model, usage, artifacts, environment, ...) yields
    a different fingerprint, so merely similar events never match."""
    try:
        body = {key: value for key, value in event.items()
                if key not in ("event_id", "recorded_at")}
        return json.dumps(body, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        return None


def _hashable_task_id(value: Any) -> Any:
    """Return a hashable grouping key for duplicate detection.

    Adversarial stores may carry list/dict task_id. Using the raw value as
    a dict key would raise TypeError: unhashable and abort the whole scan.
    Valid events use str/None (already hashable); anything else is mapped
    to its canonical JSON form (or repr fallback) so the scan continues and
    the per-event validator still reports EVENT_INVALID.
    """
    try:
        hash(value)
        return value
    except TypeError:
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=False,
                              separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            try:
                return repr(value)
            except RecursionError:
                return "<unrepresentable-task-id>"


def _artifact_unavailable_or_invalid(ref: Any, reason: str) -> tuple[str, str]:
    sha = ref.get("sha256") if isinstance(ref, dict) else None
    if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha):
        return ("unavailable", reason + "; stored sha256 present, "
                "treated as historical artifact unavailable")
    return ("invalid", reason)


def _artifact_status(ref: Any, runs_dir: Path) -> tuple[str, str]:
    """Read-only classification of one stored artifact ref.

    Returns ("ok", reason) when the target is a trusted regular file,
    ("invalid", reason) when the ref itself is structurally unsafe, and
    ("unavailable", reason) when the ref is structurally sound with a valid
    stored hash but the backing file is gone. Never writes, never follows
    an untrusted link as evidence.
    """
    if not isinstance(ref, dict):
        return ("invalid", "artifact ref must be an object")
    run_id = ref.get("run_id")
    relpath = ref.get("relpath")
    if (not isinstance(run_id, str) or not run_id or "/" in run_id
            or ".." in run_id or run_id.startswith(".")):
        return ("invalid", "artifact ref run_id must be a plain run directory name")
    if not isinstance(relpath, str) or not relpath:
        return ("invalid", "artifact ref relpath must be a non-empty relative path")
    for _label, _value in (("run_id", run_id), ("relpath", relpath)):
        _bad = _path_label_invalid(_label, _value)
        if _bad is not None:
            return ("invalid", _bad)
    if (relpath.startswith("/") or relpath.startswith("~")
            or ".." in Path(relpath).parts):
        return ("invalid", "artifact ref relpath must stay inside runs/<run_id>/")
    run_root = runs_dir / run_id
    try:
        if run_root.is_symlink():
            return ("invalid", "artifact ref run root must not be a symlink")
    except (OSError, ValueError) as exc:
        return ("invalid", f"artifact ref cannot be resolved: {exc}")
    target = runs_dir / run_id / relpath
    try:
        resolved = target.resolve()
        expected_root = (runs_dir / run_id).resolve()
    except RuntimeError as exc:
        # Narrow path-resolution boundary: some Python versions raise
        # RuntimeError ("Symlink loop") from resolve() instead of OSError.
        # A loop is structurally unsafe — always ARTIFACT_INVALID, never
        # "historical unavailable". Only resolve() is guarded.
        return ("invalid",
                f"artifact ref traverses a symlink loop "
                f"and cannot be resolved: {exc}")
    except (OSError, ValueError) as exc:
        return _artifact_unavailable_or_invalid(
            ref, f"artifact ref cannot be resolved: {exc}")
    if resolved != expected_root and expected_root not in resolved.parents:
        return ("invalid", "artifact ref escapes runs/<run_id>/")
    try:
        if target.is_symlink() or resolved.is_symlink():
            return ("invalid", "artifact ref must not be a symlink")
    except (OSError, ValueError) as exc:
        return ("invalid", f"artifact ref cannot be resolved: {exc}")
    try:
        is_file = resolved.is_file()
    except (OSError, ValueError) as exc:
        return _artifact_unavailable_or_invalid(
            ref, f"artifact ref cannot be resolved: {exc}")
    if not is_file:
        loop_reason = _symlink_loop_reason(target)
        if loop_reason is not None:
            return ("invalid", loop_reason)
        return _artifact_unavailable_or_invalid(
            ref, "artifact ref target is missing (historical artifact unavailable)")
    try:
        sha256_file(resolved)
    except (OSError, ValueError) as exc:
        return _artifact_unavailable_or_invalid(
            ref, f"artifact ref cannot be read/hashed: {exc}")
    return ("ok", "artifact ref resolves to a regular file")


def _provenance_finding(event: dict[str, Any]) -> dict[str, Any] | None:
    """Return a DEGRADED_PROVENANCE warning when nulls are honest data.

    Only fires when the environment value shape is otherwise legal (absent,
    null, or valid sha256 hex): malformed hex is a hard EVENT_INVALID owned
    by the validator, never a soft provenance warning.
    """
    env = event.get("environment")
    if env is None:
        return ("models_sha256 and agentflow_sha256 unavailable "
                "(environment null; provenance degraded, not verified)")
    if not isinstance(env, dict):
        return None
    nulls: list[str] = []
    for key in ("models_sha256", "agentflow_sha256"):
        value = env.get(key)
        if value is None:
            nulls.append(key)
        elif not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            return None
    if not nulls:
        return None
    return ("degraded environment provenance "
            f"({', '.join(nulls)} null; provenance unavailable, not verified)")


def verify_event_store(events_dir: Path | None = None,
                       runs_dir: Path | None = None) -> dict[str, Any]:
    """Inspect the full event store without modifying anything.

    Pure read-only: lists the events directory, lstats each entry (never
    following symlinks as trusted events), parses JSON, checks filename /
    event_id coherence, supported version, authoritative Python validation,
    supersession integrity, provenance nulls, artifact refs, and exact
    semantic duplicates. One bad file never aborts the scan. Never creates,
    edits, renames, deletes, migrates, locks, or publishes anything.
    """
    events_base = EVENTS_DIR if events_dir is None else Path(events_dir)
    runs_base = RUNS_DIR if runs_dir is None else Path(runs_dir)
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    events_parsed = 0
    human_gate = 0
    external_execution = 0
    parsed_pool: list[tuple[str, dict[str, Any]]] = []

    try:
        entries = sorted(events_base.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        entries = []
    except NotADirectoryError as exc:
        findings.append(_verify_finding(
            "ERROR", "EVENT_NOT_REGULAR", None, None,
            f"events path is not a directory: {exc}"))
        entries = []
    except OSError as exc:
        findings.append(_verify_finding(
            "ERROR", "EVENT_NOT_REGULAR", None, None,
            f"events directory cannot be listed: {exc}"))
        entries = []

    try:
        expected_dir = events_base.resolve()
    except OSError:
        expected_dir = None

    for entry in entries:
        name = entry.name
        if name == ".gitkeep":
            continue
        files_scanned += 1
        try:
            entry_lstat = os.lstat(entry)
        except OSError as exc:
            findings.append(_verify_finding(
                "ERROR", "EVENT_NOT_REGULAR", name, None,
                f"entry cannot be examined: {exc}"))
            continue
        if stat.S_ISLNK(entry_lstat.st_mode):
            findings.append(_verify_finding(
                "ERROR", "EVENT_SYMLINK", name, None,
                "event entry must be a regular file, never a symlink; "
                "symlinked entries are not trusted or followed"))
            continue
        if not stat.S_ISREG(entry_lstat.st_mode):
            findings.append(_verify_finding(
                "ERROR", "EVENT_NOT_REGULAR", name, None,
                "event entry must be a regular file physically contained "
                "in the events directory"))
            continue
        if expected_dir is not None:
            try:
                resolved_entry = entry.resolve()
                if (resolved_entry != expected_dir
                        and expected_dir not in resolved_entry.parents):
                    findings.append(_verify_finding(
                        "ERROR", "EVENT_NOT_REGULAR", name, None,
                        "event entry escapes the events directory"))
                    continue
            except OSError as exc:
                findings.append(_verify_finding(
                    "ERROR", "EVENT_NOT_REGULAR", name, None,
                    f"event entry cannot be resolved: {exc}"))
                continue
        if entry.suffix != ".json":
            findings.append(_verify_finding(
                "ERROR", "UNEXPECTED_FILE", name, None,
                "unexpected non-JSON file in the events directory; "
                "only <event_id>.json events plus .gitkeep belong here"))
            continue
        try:
            raw = entry.read_bytes()
        except OSError as exc:
            findings.append(_verify_finding(
                "ERROR", "JSON_INVALID", name, None,
                f"event file cannot be read: {exc}"))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            findings.append(_verify_finding(
                "ERROR", "JSON_INVALID", name, None,
                f"event file is not valid UTF-8 JSON: {exc}"))
            continue
        try:
            data = json.loads(text)
        except (ValueError, RecursionError) as exc:
            findings.append(_verify_finding(
                "ERROR", "JSON_INVALID", name, None,
                f"event file is not valid JSON: {exc}"))
            continue
        if not isinstance(data, dict):
            findings.append(_verify_finding(
                "ERROR", "EVENT_INVALID", name, None,
                "event must be a JSON object"))
            continue
        events_parsed += 1
        event_type = data.get("event_type")
        if event_type == "human_gate":
            human_gate += 1
        elif event_type == "external_execution":
            external_execution += 1
        parsed_pool.append((name, data))

        raw_id = data.get("event_id")
        file_event_id = raw_id if isinstance(raw_id, str) else None
        if not isinstance(raw_id, str) or entry.stem != raw_id:
            findings.append(_verify_finding(
                "ERROR", "EVENT_ID_FILENAME_MISMATCH", name, file_event_id,
                f"filename stem {entry.stem!r} does not match "
                f"event_id {raw_id!r}; names are never renamed automatically"))
        if not _is_supported_version(data.get("telemetry_version")):
            findings.append(_verify_finding(
                "ERROR", "UNSUPPORTED_VERSION", name, file_event_id,
                f"unsupported telemetry_version {data.get('telemetry_version')!r}; "
                f"supported version is {TELEMETRY_VERSION}; no migration attempted"))
        else:
            validation_ok = False
            try:
                if event_type == "human_gate":
                    validate_gate_event(data, runs_base, events_base)
                elif event_type == "external_execution":
                    validate_external_event(data, runs_base, events_base)
                else:
                    raise TelemetryError(
                        f"unknown event_type {event_type!r}; "
                        "expected human_gate or external_execution")
                validation_ok = True
            except TelemetryError as exc:
                message = str(exc)
                lowered = message.lower()
                if "supersedes_event_id" in lowered or "referenced event" in lowered:
                    findings.append(_verify_finding(
                        "ERROR", "SUPERSESSION_INVALID", name, file_event_id,
                        f"broken supersession reference: {message}"))
                elif "artifact" in lowered:
                    refs = data.get("artifact_refs")
                    if not isinstance(refs, list):
                        findings.append(_verify_finding(
                            "ERROR", "ARTIFACT_INVALID", name, file_event_id,
                            f"invalid artifact refs: {message}"))
                    else:
                        reported = False
                        for ref in refs:
                            status, reason = _artifact_status(ref, runs_base)
                            if status == "invalid":
                                findings.append(_verify_finding(
                                    "ERROR", "ARTIFACT_INVALID", name,
                                    file_event_id,
                                    f"invalid artifact ref: {reason}"))
                                reported = True
                            elif status == "unavailable":
                                findings.append(_verify_finding(
                                    "WARNING", "ARTIFACT_UNAVAILABLE", name,
                                    file_event_id,
                                    f"historical artifact unavailable: {reason}"))
                                reported = True
                        if not reported:
                            findings.append(_verify_finding(
                                "ERROR", "ARTIFACT_INVALID", name,
                                file_event_id,
                                f"invalid artifact ref: {message}"))
                else:
                    findings.append(_verify_finding(
                        "ERROR", "EVENT_INVALID", name, file_event_id,
                        f"event failed authoritative validation: {message}"))
            except (OSError, ValueError) as exc:
                # Narrow filesystem/path boundary: an OS failure or an
                # OS-unrepresentable path (e.g. unreadable artifact, NUL byte,
                # lone surrogate — UnicodeEncodeError derives from ValueError)
                # during authoritative validation must never abort the store
                # scan. Classify without traceback and continue.
                refs = data.get("artifact_refs")
                if isinstance(refs, list) and refs:
                    reported = False
                    for ref in refs:
                        try:
                            status, reason = _artifact_status(ref, runs_base)
                        except (OSError, ValueError) as inner:
                            findings.append(_verify_finding(
                                "WARNING", "ARTIFACT_UNAVAILABLE", name,
                                file_event_id,
                                f"historical artifact unavailable: "
                                f"artifact ref cannot be read/hashed: {inner}"))
                            reported = True
                            continue
                        if status == "invalid":
                            findings.append(_verify_finding(
                                "ERROR", "ARTIFACT_INVALID", name,
                                file_event_id,
                                f"invalid artifact ref: {reason}"))
                            reported = True
                        elif status == "unavailable":
                            findings.append(_verify_finding(
                                "WARNING", "ARTIFACT_UNAVAILABLE", name,
                                file_event_id,
                                f"historical artifact unavailable: {reason}"))
                            reported = True
                    if not reported:
                        findings.append(_verify_finding(
                            "WARNING", "ARTIFACT_UNAVAILABLE", name,
                            file_event_id,
                            f"historical artifact unavailable: "
                            f"artifact ref cannot be read/hashed: {exc}"))
                else:
                    findings.append(_verify_finding(
                        "ERROR", "EVENT_INVALID", name, file_event_id,
                        f"event failed authoritative validation: {exc}"))
            if validation_ok:
                # Integrity gap closure (read-only): stored sha256 must match
                # current file content. Never repairs, never edits.
                refs_raw = data.get("artifact_refs")
                if isinstance(refs_raw, list):
                    for ref in refs_raw:
                        if not isinstance(ref, dict):
                            continue
                        stored = ref.get("sha256")
                        run_id = ref.get("run_id")
                        relpath = ref.get("relpath")
                        try:
                            status, reason = _artifact_status(ref, runs_base)
                        except (OSError, ValueError) as exc:
                            findings.append(_verify_finding(
                                "WARNING", "ARTIFACT_UNAVAILABLE", name,
                                file_event_id,
                                f"historical artifact unavailable: "
                                f"artifact ref cannot be read/hashed: {exc}"))
                            continue
                        if status == "invalid":
                            findings.append(_verify_finding(
                                "ERROR", "ARTIFACT_INVALID", name,
                                file_event_id,
                                f"invalid artifact ref: {reason}"))
                            continue
                        if status == "unavailable":
                            findings.append(_verify_finding(
                                "WARNING", "ARTIFACT_UNAVAILABLE", name,
                                file_event_id,
                                f"historical artifact unavailable: {reason}"))
                            continue
                        try:
                            current = sha256_file(
                                (runs_base / run_id / relpath).resolve())
                        except (OSError, ValueError, RuntimeError) as exc:
                            # Narrow path-resolution boundary (TOCTOU: the
                            # link layout may change mid-scan); RuntimeError
                            # covers the symlink-loop family on some versions.
                            findings.append(_verify_finding(
                                "WARNING", "ARTIFACT_UNAVAILABLE", name,
                                file_event_id,
                                f"historical artifact unavailable: "
                                f"artifact ref cannot be read/hashed: {exc}"))
                            continue
                        except (TypeError, ValueError, AttributeError) as exc:
                            findings.append(_verify_finding(
                                "ERROR", "ARTIFACT_INVALID", name,
                                file_event_id,
                                f"invalid artifact ref: {exc}"))
                            continue
                        if stored != current:
                            expected = stored if isinstance(stored, str) else repr(stored)
                            findings.append(_verify_finding(
                                "ERROR", "ARTIFACT_HASH_MISMATCH", name,
                                file_event_id,
                                f"artifact hash mismatch: {run_id}:{relpath} "
                                f"expected {expected} actual {current}; "
                                "stored sha256 does not match current file "
                                "content (no auto-repair attempted)"))
        degraded = _provenance_finding(data)
        if degraded is not None:
            findings.append(_verify_finding(
                "WARNING", "DEGRADED_PROVENANCE", name, file_event_id, degraded))

    groups: dict[tuple[Any, Any, str], list[str]] = {}
    for filename, event in parsed_pool:
        event_type = event.get("event_type")
        if event_type not in ("human_gate", "external_execution"):
            continue
        fingerprint = _duplicate_fingerprint(event)
        if fingerprint is None:
            continue
        key = (event_type, _hashable_task_id(event.get("task_id")), fingerprint)
        raw_id = event.get("event_id")
        label = raw_id if isinstance(raw_id, str) else filename
        groups.setdefault(key, []).append(label)
    duplicate_groups = 0
    for (event_type, task_id, _fp), labels in sorted(
            groups.items(), key=lambda item: (str(item[0][0]), str(item[0][1]))):
        unique_sorted = sorted(set(labels))
        if len(unique_sorted) > 1:
            duplicate_groups += 1
            findings.append(_verify_finding(
                "WARNING", "EXACT_SEMANTIC_DUPLICATE", None, unique_sorted[0],
                f"exact semantic duplicate {event_type}/{task_id!r}: "
                f"{', '.join(unique_sorted)} share the same payload apart "
                "from event_id/recorded_at; kept as-is, never deduplicated"))

    findings.sort(key=lambda item: (
        item["file"] or "", item["code"], item["event_id"] or ""))
    errors = sum(1 for item in findings if item["severity"] == "ERROR")
    warnings = sum(1 for item in findings if item["severity"] == "WARNING")
    return {
        "events_dir": str(events_base),
        "files_scanned": files_scanned,
        "events_parsed": events_parsed,
        "human_gate": human_gate,
        "external_execution": external_execution,
        "errors": errors,
        "warnings": warnings,
        "exact_semantic_duplicates": duplicate_groups,
        "degraded_provenance": sum(
            1 for item in findings if item["code"] == "DEGRADED_PROVENANCE"),
        "broken_supersession_refs": sum(
            1 for item in findings if item["code"] == "SUPERSESSION_INVALID"),
        "artifact_warnings": sum(
            1 for item in findings if item["code"] == "ARTIFACT_UNAVAILABLE"),
        "findings": findings,
        "ok": errors == 0,
    }


def _safe_display(value: Any) -> str:
    """Render arbitrary JSON string content for terminal display.

    A JSON-legal lone surrogate (e.g. inside event_id) survives parsing
    and reaches findings, but cannot be encoded to UTF-8 stdout: printing
    it raises UnicodeEncodeError (traceback, exit 1, no usable report).
    Only lone surrogates are unencodable under UTF-8, so only they are
    escaped (as \\uXXXX); every other code point — including valid
    non-ASCII text — passes through untouched (no ASCII-folding).
    Structured report data is never mutated: this applies at render
    time only, so the API report stays usable.
    """
    text = value if isinstance(value, str) else str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return "".join(
            f"\\u{ord(char):04x}" if 0xD800 <= ord(char) <= 0xDFFF else char
            for char in text
        )
    return text


def format_verify_report(report: dict[str, Any]) -> str:
    """Render a compact deterministic human-readable verify report.

    All interpolated content passes through _safe_display so arbitrary
    JSON string content can never crash UTF-8 stdout; the returned text
    always encodes cleanly. No finding is dropped.
    """
    lines = [
        f"telemetry verify: {_safe_display(report['events_dir'])}",
        (f"files_scanned={report['files_scanned']} "
         f"events_parsed={report['events_parsed']} "
         f"human_gate={report['human_gate']} "
         f"external_execution={report['external_execution']} "
         f"errors={report['errors']} warnings={report['warnings']}"),
        (f"exact_semantic_duplicates={report['exact_semantic_duplicates']} "
         f"degraded_provenance={report['degraded_provenance']} "
         f"broken_supersession_refs={report['broken_supersession_refs']} "
         f"artifact_warnings={report['artifact_warnings']}"),
    ]
    for item in report["findings"]:
        where = _safe_display(item["file"] or item["event_id"] or "?")
        lines.append(
            f"[{_safe_display(item['severity'])}] "
            f"{_safe_display(item['code'])} {where}: "
            f"{_safe_display(item['detail'])}")
    lines.append("VERIFY OK" if report["ok"] else "VERIFY FAIL")
    return "\n".join(lines) + "\n"


def cmd_verify(args: argparse.Namespace) -> int:
    """Read-only store verification. Never writes anything anywhere."""
    _ = args
    report = verify_event_store()
    text = format_verify_report(report)
    try:
        sys.stdout.write(text)
    except (UnicodeEncodeError, ValueError):
        # Exotic-locale last resort: UTF-8 stdout never reaches here
        # (format_verify_report already escapes lone surrogates), but a
        # stdout with a narrower encoding must still get a usable report
        # rather than a traceback. Information is preserved as escapes.
        sys.stdout.write(text.encode("utf-8", "backslashreplace").decode("utf-8"))
    return 0 if report["ok"] else 2


def publish_event(validated: dict[str, Any], events_dir: Path | None = None) -> Path:
    """Atomically publish one validated event. The ONLY writer in this module.

    Guarantees: if <event_id>.json exists afterwards, it holds the complete
    event. A colliding final name is a hard error (no silent retry): the
    operator re-runs the CLI and gets a fresh event_id.
    """
    base = EVENTS_DIR if events_dir is None else Path(events_dir)
    final_path = base / f"{validated['event_id']}.json"
    try:
        payload = (json.dumps(validated, indent=2, ensure_ascii=False,
                              allow_nan=False) + "\n").encode("utf-8")
    except UnicodeEncodeError as exc:
        # Unencodable content (e.g. a lone surrogate in actor/note/
        # summary) must fail as a controlled TelemetryError — CLI exit 2,
        # nothing written, no partial event — never a traceback from the
        # writer. This runs before any directory or temp file is created,
        # so either the complete event lands or nothing does.
        raise TelemetryError(
            "event contains text that is not valid UTF-8 "
            f"and cannot be recorded: {exc}") from exc
    base.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{final_path.name}.", suffix=".tmp", dir=base)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp_path, final_path)
        except FileExistsError as exc:
            raise TelemetryError(
                f"event file already exists (no-overwrite, no idempotency in V0): {final_path.name}; "
                "re-run the command to record a new event"
            ) from exc
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass
    dir_fd = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return final_path


def build_gate_event(args: argparse.Namespace, root: Path | None = None) -> dict[str, Any]:
    base = ROOT if root is None else Path(root)
    runs_dir = base / "runs"
    events_dir = base / "telemetry" / "v1" / "events"
    recorded_at = utc_now_z()
    decided_raw = getattr(args, "decided_at", None)
    decided_at = None
    if decided_raw is not None:
        decided = parse_utc_z(decided_raw, "decided_at")
        if decided > parse_utc_z(recorded_at, "recorded_at"):
            raise TelemetryError("decided_at must not be after recorded_at")
        decided_at = decided_raw
    refs = []
    for spec in getattr(args, "artifact", None) or []:
        if ":" in spec:
            run_part, rel = spec.split(":", 1)
        else:
            if not getattr(args, "run", None):
                raise TelemetryError("--artifact without RUN: prefix requires --run")
            run_part, rel = args.run, spec
        refs.append(validate_artifact_ref({"run_id": run_part, "relpath": rel}, runs_dir))
    return {
        "telemetry_version": TELEMETRY_VERSION,
        "event_id": generate_event_id(),
        "event_type": "human_gate",
        "recorded_at": recorded_at,
        "task_id": check_task_id(args.task),
        "run_id": check_run_id(args.run),
        "actor": check_actor(args.actor),
        "decision_source": "human",
        "environment": environment_hashes(base),
        "supersedes_event_id": check_supersedes(getattr(args, "supersedes", None), {"event_type": "human_gate", "task_id": args.task}, events_dir) if getattr(args, "supersedes", None) else None,
        "artifact_refs": refs,
        "decision": args.decision,
        "decided_at": decided_at,
        "note": check_plain_text(getattr(args, "note", None), "note", NOTE_MAX),
    }


def build_external_event(args: argparse.Namespace, root: Path | None = None) -> dict[str, Any]:
    base = ROOT if root is None else Path(root)
    runs_dir = base / "runs"
    recorded_at = utc_now_z()
    refs = []
    for spec in getattr(args, "artifact", None) or []:
        if ":" not in spec:
            raise TelemetryError("--artifact for external events must use RUN:relpath form")
        run_part, rel = spec.split(":", 1)
        refs.append(validate_artifact_ref({"run_id": run_part, "relpath": rel}, runs_dir))
    token_source = getattr(args, "token_source", None) or "unavailable"
    counts = {key: getattr(args, f"tokens_{key}", None) for key in ("in", "out", "reasoning", "cached")}
    if any(value is not None for value in counts.values()) and token_source == "unavailable":
        raise TelemetryError("token counts require --token-source reported|partial")
    cost_source = getattr(args, "cost_source", None) or "unavailable"
    cost_value = getattr(args, "cost_value", None)
    currency = getattr(args, "currency", None)
    timing_source = getattr(args, "timing_source", None) or "unknown"
    started = getattr(args, "started_at", None)
    finished = getattr(args, "finished_at", None)
    if args.actor_kind not in ACTOR_KINDS_KNOWN:
        print(
            f"telemetry external: warning: unknown actor_kind {args.actor_kind!r} "
            "(accepted; open vocabulary)",
            file=sys.stderr,
        )
    return {
        "telemetry_version": TELEMETRY_VERSION,
        "event_id": generate_event_id(),
        "event_type": "external_execution",
        "recorded_at": recorded_at,
        "task_id": check_optional_task_id(getattr(args, "task", None)),
        "run_id": check_run_id(getattr(args, "run", None)),
        "actor": check_actor(args.actor),
        "actor_kind": args.actor_kind,
        "attestation_source": "human",
        "environment": environment_hashes(base),
        "supersedes_event_id": None,
        "artifact_refs": refs,
        "roles": [role.strip() for role in str(args.roles).split(",") if role.strip()],
        "model": {
            "provider": getattr(args, "provider", None),
            "model_id": getattr(args, "model", None),
            "variant": getattr(args, "variant", None),
        },
        "session_type": getattr(args, "session_type", None) or "unknown",
        "timing": {"started_at": started, "finished_at": finished, "timing_source": timing_source},
        "outcome": {"verdict": getattr(args, "verdict", None), "summary": getattr(args, "summary", None)},
        "usage": {
            "token_source": token_source,
            "tokens": counts,
            "cost": {"source": cost_source, "value": cost_value, "currency": currency},
        },
        "note": check_plain_text(getattr(args, "note", None), "note", NOTE_MAX),
    }


def cmd_gate(args: argparse.Namespace) -> int:
    try:
        raw = build_gate_event(args)
        validated = validate_gate_event(raw, RUNS_DIR, EVENTS_DIR)
        path = publish_event(validated)
    except TelemetryError as exc:
        print(f"telemetry gate: error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(validated, indent=2))
    print(str(path))
    return 0


def cmd_external(args: argparse.Namespace) -> int:
    try:
        raw = build_external_event(args)
        validated = validate_external_event(raw, RUNS_DIR, EVENTS_DIR)
        path = publish_event(validated)
    except TelemetryError as exc:
        print(f"telemetry external: error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(validated, indent=2))
    print(str(path))
    return 0


def add_common_artifact_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--artifact", action="append", default=[],
        help="artifact citation as RUN:relpath (repeatable); relpath is relative to runs/<run>/",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    gate = sub.add_parser("gate", help="record a human gate decision (explicit flags only)")
    gate.add_argument("--task", required=True)
    gate.add_argument("--run", default=None)
    gate.add_argument("--actor", required=True)
    gate.add_argument("--decision", required=True,
                      choices=["accepted_as_is", "accepted_with_changes", "rejected", "superseded"])
    gate.add_argument("--decided-at", default=None)
    gate.add_argument("--supersedes", default=None)
    gate.add_argument("--note", default=None)
    add_common_artifact_argument(gate)
    gate.set_defaults(func=cmd_gate)

    external = sub.add_parser("external", help="record an external (non-AgentFlow) execution")
    external.add_argument("--task", default=None)
    external.add_argument("--run", default=None)
    external.add_argument("--actor", required=True)
    external.add_argument("--actor-kind", default="model")
    external.add_argument("--roles", required=True, help="comma-separated, e.g. architect,worker")
    external.add_argument("--provider", default=None)
    external.add_argument("--model", default=None)
    external.add_argument("--variant", default=None)
    external.add_argument("--session-type", default="unknown", choices=list(SESSION_TYPES))
    external.add_argument("--timing-source", default="unknown", choices=list(TIMING_SOURCES))
    external.add_argument("--started-at", default=None)
    external.add_argument("--finished-at", default=None)
    external.add_argument("--verdict", default=None)
    external.add_argument("--summary", default=None)
    external.add_argument("--token-source", default="unavailable", choices=list(TOKEN_SOURCES))
    external.add_argument("--tokens-in", type=int, default=None)
    external.add_argument("--tokens-out", type=int, default=None)
    external.add_argument("--tokens-reasoning", type=int, default=None)
    external.add_argument("--tokens-cached", type=int, default=None)
    external.add_argument("--cost-source", default="unavailable", choices=list(COST_SOURCES))
    external.add_argument("--cost-value", type=float, default=None)
    external.add_argument("--currency", default=None)
    external.add_argument("--note", default=None)
    add_common_artifact_argument(external)
    external.set_defaults(func=cmd_external)

    verify = sub.add_parser("verify", help="verify the event store read-only (never writes)")
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
