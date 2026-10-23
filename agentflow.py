#!/usr/bin/env python3
"""VilTech AgentFlow V0: a small, fail-closed local coordination harness."""

from __future__ import annotations

import argparse
import contextvars
import contextlib
import datetime as dt
import errno
import fcntl
import hashlib
import json
import locale
import os
import re
import shlex
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator


ROOT = Path(__file__).resolve().parent
MODELS_FILE = ROOT / "config" / "models.json"
RESULT_SCHEMA = ROOT / "schemas" / "result.schema.json"
QUEUE_SCHEMA = ROOT / "schemas" / "queue.schema.json"
RUNS_DIR = ROOT / "runs"
QUEUE_RUNS_DIR = RUNS_DIR / "queues"
LOCKS_DIR = ROOT / ".locks"
PROC_ROOT = Path("/proc")
BOOT_ID_PATH = PROC_ROOT / "sys" / "kernel" / "random" / "boot_id"
MAX_LINUX_PID = 2**31 - 1  # largest value os.kill()/pid_t can represent; anything above is malformed
MAX_LINUX_START_TIME = 2**63 - 1  # /proc stat uses an unsigned long long-sized counter

FORBIDDEN_GIT = {
    "stash", "reset", "restore", "checkout", "clean", "rebase", "commit",
    "push", "merge", "switch", "branch",
}
FORBIDDEN_ACTIONS = [
    "git stash", "git reset", "git restore", "git checkout", "git clean",
    "git rebase", "git commit", "git push", "git merge", "git switch",
    "git branch", "deploy", "alembic upgrade", "alembic downgrade",
    "database mutation", "Meta real",
]
SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|authorization|cookie|credential)", re.I
)

PROGRAM_MAX_CORRECTIONS = 1
QUEUE_HARD_MAX = 8
_QUEUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# PROGRAM-001B: opt-in sequential subtasks. Hard maximum of 4 children.
PROGRAM_BMODE_HARD_MAX = 4
_SUBTASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SUBTASK_ALLOWED_KEYS = frozenset({
    "subtask_id", "objective", "allowed_paths", "invariants", "expected_outputs",
})

WORKTREE_ROOT_ENV = "AGENTFLOW_WORKTREES_DIR"
_WORKTREE_STATUSES = ("CREATING", "READY", "CANDIDATE", "PRESERVED", "CLEANED")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


class AgentFlowError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class BudgetExhausted(AgentFlowError):
    def __init__(self, dimension: str, message: str | None = None):
        self.dimension = dimension
        super().__init__("BUDGET_EXHAUSTED", message or f"Queue {dimension} budget exhausted")


class ProviderFailureClass(str, Enum):
    TRANSIENT_NETWORK = "TRANSIENT_NETWORK"
    RATE_LIMITED = "RATE_LIMITED"
    TEMPORARILY_UNAVAILABLE = "TEMPORARILY_UNAVAILABLE"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    AUTH_OR_CONFIGURATION = "AUTH_OR_CONFIGURATION"
    MODEL_NOT_FOUND_OR_DISABLED = "MODEL_NOT_FOUND_OR_DISABLED"
    PROCESS_NONZERO_UNKNOWN = "PROCESS_NONZERO_UNKNOWN"


@dataclass(frozen=True)
class RunIdentity:
    run_id: str
    run_dir: Path


@dataclass(frozen=True)
class ProgramOutcome:
    run_id: str
    run_dir: str
    final_path: str
    final_sha256: str
    program_id: str
    task_id: str
    verdict: str
    status: str
    human_gate: bool
    outcome_class: str
    primary_failure: str | None
    secondary_failures: list[dict[str, Any]]
    budget_dimension: str | None
    execution_repo: str
    baseline_commit: str
    preservation_status: str
    preservation_evidence_path: str | None
    process_quiescence: str
    final: dict[str, Any]


@dataclass(frozen=True)
class QueueProcessIdentity:
    """Immutable Linux identity for one queue-owned process group."""

    boot_id: str
    leader_pid: int
    leader_start_time: int
    pgid: int
    session_id: int


@dataclass(frozen=True)
class QueueProcessMember:
    """One exact, revalidatable member of a queue-owned process group."""

    pid: int
    start_time: int


@dataclass(frozen=True)
class FrozenQueueItem:
    ordinal: int
    item_id: str
    queue_item: dict[str, Any]
    program_path: Path
    program: dict[str, Any]
    task_path: Path
    task: dict[str, Any]
    source_repo: Path
    baseline_commit: str
    profiles: dict[str, dict[str, Any]]
    hashes: dict[str, str]


_ACTIVE_EXECUTION_CONTROL: contextvars.ContextVar["ExecutionControl | None"] = (
    contextvars.ContextVar("agentflow_execution_control", default=None)
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-")[:80] or "task"


def _canonical_sha(raw: str) -> str:
    """Canonicalize a full 40-hex SHA to lowercase."""
    sha = raw.strip().lower()
    if not _HEX40_RE.match(sha):
        raise AgentFlowError("BASELINE_COMMIT_UNKNOWN", f"Not a full 40-hex SHA: {raw!r}")
    return sha


def _error_code_for(exc: BaseException) -> str:
    """Map an exception to a failure verdict code (M2)."""
    if isinstance(exc, AgentFlowError):
        return exc.code
    if isinstance(exc, subprocess.TimeoutExpired):
        return "PROCESS_TIMEOUT"
    return "INTERNAL_ERROR"


def _execution_dirty_state(repo: Path) -> bool:
    """Return actual Git dirty state; fail closed to True (L5)."""
    try:
        proc = git(repo, ["status", "--porcelain"])
        if proc.returncode != 0:
            return True
        return bool(proc.stdout.strip())
    except Exception:
        return True


def _mark_workspace_preserved(
    workspace: dict[str, Any],
    exec_repo: Path,
) -> None:
    dirty = _execution_dirty_state(exec_repo)
    workspace["preserved_dirty"] = dirty
    workspace["status"] = "PRESERVED"


def _best_effort_persist_workspace(run_dir: Path, workspace: dict[str, Any]) -> None:
    """Persist workspace.json best-effort (M2 orphan binding)."""
    try:
        atomic_json(run_dir / "workspace.json", workspace)
    except Exception:
        with contextlib.suppress(Exception):
            (run_dir / "workspace.json").write_text(
                json.dumps(workspace, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )


def _reconcile_unbound_worktree(
    source: Path, dest: Path, run_dir: Path, workspace: dict[str, Any]
) -> None:
    """Close READY persistence window: never leave registered-but-unbound orphan (M2).

    Dirty candidate is never auto-removed; ensure a minimal durable binding
    instead. A clean newly-created worktree may be safely removed.
    """
    try:
        dirty = _execution_dirty_state(dest)
    except Exception:
        dirty = True
    if dirty:
        _best_effort_persist_workspace(run_dir, workspace)
        return
    try:
        root = worktree_root()
        try:
            dest_r = dest.resolve()
            src_r = source.resolve()
            root_r = root.resolve()
        except Exception:
            _best_effort_persist_workspace(run_dir, workspace)
            return
        try:
            dest_r.relative_to(root_r)
            contained = True
        except ValueError:
            contained = False
        if contained and dest_r != src_r and _is_worktree_registered(source, dest):
            with contextlib.suppress(Exception):
                git(source, ["worktree", "remove", "--force", str(dest)])
            # Mark cleaned best-effort so the later failure handler skips
            # preservation of a worktree that no longer exists.
            workspace["status"] = "CLEANED"
            workspace["preserved_dirty"] = False
            _best_effort_persist_workspace(run_dir, workspace)
        else:
            _best_effort_persist_workspace(run_dir, workspace)
    except Exception:
        _best_effort_persist_workspace(run_dir, workspace)


def worktree_root() -> Path:
    """Derive the persistent worktree root directory."""
    env = os.environ.get(WORKTREE_ROOT_ENV)
    if env:
        return Path(env).resolve()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).resolve() / "agentflow" / "worktrees"
    return Path.home().resolve() / ".local" / "share" / "agentflow" / "worktrees"


def _worktree_destination(run_id: str, root: Path | None = None) -> Path:
    """Compute the safe destination path for a worktree from a run_id."""
    root = root or worktree_root()
    slug = safe_slug(run_id)
    if not slug or slug in (".", ".."):
        raise AgentFlowError("WORKTREE_PATH_ESCAPE", f"Unsafe run_id slug: {run_id!r}")
    dest = (root / slug).resolve()
    root_resolved = root.resolve()
    try:
        dest.relative_to(root_resolved)
    except ValueError:
        raise AgentFlowError("WORKTREE_PATH_ESCAPE", f"Destination escapes root: {dest}")
    return dest


def _path_is_inside(candidate: Path, parent: Path) -> bool:
    """True if candidate is inside parent (not equal)."""
    try:
        candidate.resolve().relative_to(parent.resolve())
        return candidate.resolve() != parent.resolve()
    except ValueError:
        return False


def _worktree_safety_check(dest: Path, source: Path, root: Path) -> None:
    """Validate worktree destination safety."""
    dest_resolved = dest.resolve()
    source_resolved = source.resolve()
    root_resolved = root.resolve()
    if dest_resolved == source_resolved:
        raise AgentFlowError("WORKTREE_PATH_ESCAPE", "Destination equals source repo")
    if _path_is_inside(dest_resolved, source_resolved):
        raise AgentFlowError("WORKTREE_PATH_ESCAPE", "Destination inside source working tree")
    if _path_is_inside(source_resolved, dest_resolved):
        raise AgentFlowError("WORKTREE_PATH_ESCAPE", "Source inside destination")
    if _path_is_inside(dest_resolved, root_resolved) is False and dest_resolved != root_resolved:
        raise AgentFlowError("WORKTREE_PATH_ESCAPE", "Destination outside worktree root")
    if dest_resolved.exists():
        raise AgentFlowError("WORKTREE_EXISTS", f"Destination already exists: {dest_resolved}")
    if dest_resolved.is_symlink():
        raise AgentFlowError("WORKTREE_PATH_ESCAPE", "Destination is a symlink")


def _resolve_source_head(source: Path) -> str:
    """Get the canonical HEAD SHA of source repo."""
    proc = git(source, ["rev-parse", "--verify", "HEAD"])
    if proc.returncode:
        raise AgentFlowError("NOT_A_GIT_REPO", f"Cannot resolve HEAD: {proc.stderr}")
    return proc.stdout.strip()


def _resolve_commit_object(source: Path, sha: str) -> str:
    """Verify sha resolves to a commit object; return canonical SHA."""
    proc = git(source, ["cat-file", "-t", sha])
    if proc.returncode or proc.stdout.strip() != "commit":
        raise AgentFlowError("BASELINE_COMMIT_UNKNOWN", f"{sha} is not a commit object")
    proc2 = git(source, ["rev-parse", "--verify", sha])
    if proc2.returncode:
        raise AgentFlowError("BASELINE_COMMIT_UNKNOWN", f"Cannot canonicalize {sha}")
    return proc2.stdout.strip()


def _is_worktree_registered(source: Path, dest: Path) -> bool:
    """Check if dest is a registered worktree for source."""
    proc = git(source, ["worktree", "list", "--porcelain"])
    if proc.returncode:
        return False
    dest_resolved = str(dest.resolve())
    for line in proc.stdout.splitlines():
        if line.startswith("worktree ") and line[9:].strip() == dest_resolved:
            return True
    return False


def _worktree_head(dest: Path) -> str | None:
    """Get HEAD of a worktree, or None if not a git repo."""
    proc = git(dest, ["rev-parse", "--verify", "HEAD"])
    if proc.returncode:
        return None
    return proc.stdout.strip()


def _worktree_is_detached(dest: Path) -> bool:
    """Check if worktree is in detached HEAD state."""
    proc = git(dest, ["symbolic-ref", "--quiet", "HEAD"])
    return proc.returncode != 0


def create_isolated_worktree(
    *,
    source: Path,
    baseline_commit: str,
    run_id: str,
    root: Path | None = None,
) -> tuple[Path, str]:
    """Create a detached Git worktree for isolated execution.

    Returns (destination, canonical_sha).
    """
    root = root or worktree_root()
    root.mkdir(parents=True, exist_ok=True)
    canonical = _canonical_sha(baseline_commit)
    canonical = _resolve_commit_object(source, canonical)
    dest = _worktree_destination(run_id, root)
    _worktree_safety_check(dest, source, root)

    proc = git(source, ["worktree", "add", "--detach", str(dest), canonical])
    if proc.returncode:
        raise AgentFlowError(
            "WORKTREE_CREATE_FAILED",
            f"git worktree add failed: {proc.stderr or proc.stdout}",
        )

    try:
        if not dest.is_dir():
            raise AgentFlowError("WORKTREE_CREATE_FAILED", "Destination directory not created")
        head = _worktree_head(dest)
        if head != canonical:
            raise AgentFlowError(
                "WORKTREE_CREATE_FAILED",
                f"HEAD mismatch: expected {canonical}, got {head}",
            )
        if not _worktree_is_detached(dest):
            raise AgentFlowError("WORKTREE_CREATE_FAILED", "Worktree is not detached")
        if not _is_worktree_registered(source, dest):
            raise AgentFlowError("WORKTREE_CREATE_FAILED", "Worktree not registered")
        status = git(dest, ["status", "--porcelain"])
        if status.returncode:
            raise AgentFlowError("WORKTREE_CREATE_FAILED", "Cannot verify worktree clean status")
        if status.stdout.strip():
            raise AgentFlowError("WORKTREE_CREATE_FAILED", "Worktree not clean after creation")
    except (AgentFlowError, OSError):
        with contextlib.suppress(Exception):
            git(source, ["worktree", "remove", "--force", str(dest)])
        raise

    return dest, canonical


def _remove_worktree(source: Path, dest: Path, *, force: bool = False) -> None:
    """Remove a registered worktree."""
    argv = ["worktree", "remove"]
    if force:
        argv.append("--force")
    argv.append(str(dest))
    proc = git(source, argv)
    if proc.returncode:
        raise AgentFlowError(
            "WORKTREE_CLEANUP_REFUSED",
            f"git worktree remove failed: {proc.stderr or proc.stdout}",
        )


class ExecutionContext:
    """Separates source repo from execution repo for isolated tasks."""

    def __init__(
        self,
        source_repo: Path,
        execution_repo: Path,
        baseline_commit: str,
        isolated: bool,
    ):
        self.source_repo = source_repo
        self.execution_repo = execution_repo
        self.baseline_commit = baseline_commit
        self.isolated = isolated

    def __repr__(self) -> str:
        return (
            f"ExecutionContext(source={self.source_repo}, exec={self.execution_repo}, "
            f"baseline={self.baseline_commit[:12]}, isolated={self.isolated})"
        )


def build_execution_context(task: dict[str, Any], run_id: str) -> ExecutionContext:
    """Build an execution context for a task, creating a worktree if isolation is enabled."""
    source = Path(task["repo"]).resolve()
    isolation = task.get("isolation")
    if isolation and isinstance(isolation, dict) and isolation.get("enabled"):
        baseline_raw = isolation.get("baseline_commit")
        if not isinstance(baseline_raw, str) or not baseline_raw.strip():
            raise AgentFlowError("INVALID_TASK", "isolation.baseline_commit must be a non-empty string")
        canonical = _canonical_sha(baseline_raw)
        canonical = _resolve_commit_object(source, canonical)
        expected = task.get("expected_baseline") or {}
        exp_head = expected.get("head") if isinstance(expected, dict) else None
        if exp_head:
            # L1: canonicalize expected head so uppercase spelling matches.
            try:
                exp_canonical = _canonical_sha(str(exp_head))
            except AgentFlowError:
                raise AgentFlowError(
                    "INVALID_TASK",
                    f"expected_baseline.head ({exp_head!r}) != "
                    f"isolation.baseline_commit ({canonical})",
                ) from None
            if exp_canonical != canonical:
                raise AgentFlowError(
                    "INVALID_TASK",
                    f"expected_baseline.head ({expected['head']}) != "
                    f"isolation.baseline_commit ({canonical})",
                )
        root = worktree_root()
        with WriteLease(source, task["task_id"], run_id) as admin_lease:
            dest, canonical = create_isolated_worktree(
                source=source,
                baseline_commit=canonical,
                run_id=run_id,
                root=root,
            )
        return ExecutionContext(
            source_repo=source,
            execution_repo=dest,
            baseline_commit=canonical,
            isolated=True,
        )
    # L3: legacy non-isolated runs must not resolve HEAD early; unborn
    # repos (head None) remain compatible via capture_baseline downstream.
    try:
        head = _resolve_source_head(source)
    except AgentFlowError:
        head = ""
    return ExecutionContext(
        source_repo=source,
        execution_repo=source,
        baseline_commit=head,
        isolated=False,
    )


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def fsync_directory(path: Path) -> None:
    """Durably commit a directory entry after an atomic rename."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json_fsync(path: Path, value: Any) -> None:
    """Atomically replace JSON and durably commit both file and directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        fsync_directory(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


class ExecutionControl:
    """Queue-only budgets, recovery policy, and immutable attempt evidence.

    This object deliberately has no knowledge of program phases.  The program
    runner asks it only about physical launches, correction starts, the
    monotonic deadline, recovery profiles, and attempt evidence.
    """

    def __init__(
        self,
        *,
        queue_id: str,
        queue_run_dir: Path,
        item_dir: Path,
        budgets: dict[str, int],
        fallback_profiles: dict[str, str],
        models: dict[str, Any],
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.queue_id = queue_id
        self.queue_run_dir = queue_run_dir
        self.item_dir = item_dir
        self.budgets = dict(budgets)
        self.fallback_profiles = dict(fallback_profiles)
        self.models = json.loads(json.dumps(models))
        self.monotonic = monotonic
        self.started_monotonic: float | None = None
        self.deadline: float | None = None
        self.used = {"model_calls": 0, "retries": 0, "fallbacks": 0, "corrections": 0}
        self.reservations: list[dict[str, Any]] = []
        self._attempt_counter = 0
        self._logical_counter = 0
        self._lock = threading.Lock()
        self.finalizing = False
        self._launched_processes = 0
        self._unresolved_processes = 0
        self._process_quiescence_uncertain = False

    def start(self) -> None:
        if self.started_monotonic is not None:
            return
        self.started_monotonic = self.monotonic()
        self.deadline = self.started_monotonic + self.budgets["wall_clock_seconds"]

    def remaining_time(self) -> float:
        if self.deadline is None:
            return float(self.budgets["wall_clock_seconds"])
        return max(0.0, self.deadline - self.monotonic())

    def check_deadline(self) -> None:
        if self.deadline is not None and self.monotonic() >= self.deadline:
            raise BudgetExhausted("WALL_CLOCK")

    def abort_check(self, now: float) -> AbortRequest | None:
        if self.deadline is not None and now >= self.deadline:
            return AbortRequest(
                "BUDGET_EXHAUSTED",
                "Queue wall-clock budget exhausted during model invocation",
                {"budget_dimension": "WALL_CLOCK"},
            )
        return None

    def persist_budget_state(self) -> None:
        state = {
            "queue_id": self.queue_id,
            "limits": self.budgets,
            "used": dict(self.used),
            "remaining": {
                key: self.budgets[key] - self.used[key]
                for key in ("model_calls", "retries", "fallbacks", "corrections")
            },
            "wall_clock_remaining_seconds": self.remaining_time(),
            "reservations": list(self.reservations),
            "updated_at": utc_now(),
        }
        atomic_json_fsync(self.queue_run_dir / "budget-state.json", state)

    def next_logical_id(self, role: str, cycle: int) -> str:
        with self._lock:
            self._logical_counter += 1
            return f"{self._logical_counter:03d}-{safe_slug(role)}-cycle-{cycle}"

    def reserve_attempt(
        self, *, logical_id: str, attempt: str, correction_start: bool = False
    ) -> dict[str, Any]:
        with self._lock:
            self.check_deadline()
            if self.used["model_calls"] >= self.budgets["model_calls"]:
                raise BudgetExhausted("MODEL_CALLS")
            counter: str | None = None
            if attempt in {"RETRY", "STRUCTURAL_RETRY"}:
                counter = "retries"
            elif attempt == "FALLBACK":
                counter = "fallbacks"
            if counter is not None and self.used[counter] >= self.budgets[counter]:
                raise BudgetExhausted(counter.upper())
            if correction_start and self.used["corrections"] >= self.budgets["corrections"]:
                raise BudgetExhausted("CORRECTIONS")
            self.used["model_calls"] += 1
            if counter is not None:
                self.used[counter] += 1
            if correction_start:
                self.used["corrections"] += 1
            self._attempt_counter += 1
            reservation = {
                "reservation_id": self._attempt_counter,
                "logical_invocation": logical_id,
                "attempt": attempt,
                "model_call": self.used["model_calls"],
                "reserved_at": utc_now(),
                "correction_start": correction_start,
            }
            self.reservations.append(reservation)
            self.persist_budget_state()
            return reservation

    def transition_available(self, kind: str) -> bool:
        key = "retries" if kind == "RETRY" else "fallbacks"
        return (
            self.used[key] < self.budgets[key]
            and self.used["model_calls"] < self.budgets["model_calls"]
            and self.remaining_time() > 0
        )

    def fallback_for_role(self, role: str) -> tuple[str, dict[str, Any]] | None:
        mapped = "architect" if role == "adjudicator" else role
        name = self.fallback_profiles.get(mapped)
        if not name:
            return None
        profile = self.models["profiles"].get(name)
        if not isinstance(profile, dict):
            return None
        # F-05: a fallback is not exempt from role eligibility. Fail closed
        # rather than silently substituting an ineligible profile.
        _check_role_eligible(profile, role)
        return (name, profile)

    def write_attempt(
        self, logical_id: str, attempt: str, phase: str, payload: dict[str, Any]
    ) -> Path:
        transitions = self.item_dir / "transitions"
        transitions.mkdir(parents=True, exist_ok=True)
        path = transitions / f"{logical_id}-{attempt.lower()}-{phase}.json"
        atomic_json_fsync(path, payload)
        return path

    def write_transition(self, logical_id: str, source: str, target: str, reason: str) -> Path:
        transitions = self.item_dir / "transitions"
        transitions.mkdir(parents=True, exist_ok=True)
        path = transitions / f"{logical_id}-{source.lower()}-to-{target.lower()}.json"
        atomic_json_fsync(path, {
            "logical_invocation": logical_id,
            "from": source,
            "to": target,
            "reason": reason,
            "recorded_at": utc_now(),
        })
        return path

    def enter_finalization(self) -> None:
        self.finalizing = True

    def note_process_started(self) -> None:
        """Record that a queue-owned process exists until positively cleared."""
        with self._lock:
            self._launched_processes += 1
            self._unresolved_processes += 1

    def note_process_quiescent(self) -> None:
        """Record positive lifecycle evidence for one launched process group."""
        with self._lock:
            if self._unresolved_processes > 0:
                self._unresolved_processes -= 1

    def note_process_uncertain(self) -> None:
        """Make missing lifecycle evidence sticky for this queue item."""
        with self._lock:
            self._process_quiescence_uncertain = True

    def reset_item_process_evidence(self) -> None:
        """Begin one sequential item with no inherited process uncertainty."""
        with self._lock:
            self._launched_processes = 0
            self._unresolved_processes = 0
            self._process_quiescence_uncertain = False

    def process_quiescence(self) -> str:
        """Return positive evidence, not an inference from the program verdict."""
        with self._lock:
            proven = (
                not self._process_quiescence_uncertain
                and self._unresolved_processes == 0
            )
        return "PROVEN" if proven else "UNCERTAIN"


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def summarized(text: str, limit: int = 12000) -> str:
    text = text.replace("\x00", "")
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + f"\n...[{len(text) - limit} chars omitted]...\n" + text[-half:]


def run_process(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


_QUEUE_GROUP_ORIGINAL_ACTIVE = "ORIGINAL_ACTIVE"
_QUEUE_GROUP_ORIGINAL_QUIESCENT = "ORIGINAL_QUIESCENT"
_QUEUE_GROUP_TRANSIENTLY_UNCERTAIN = "TRANSIENTLY_UNCERTAIN"
_QUEUE_GROUP_IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
_QUEUE_GROUP_SCAN_ATTEMPTS = 3
_QUEUE_EXEC_GATE = (
    "import os,sys; "
    "fd=int(sys.argv[1]); token=os.read(fd,1); os.close(fd); "
    "os._exit(126) if token != b'G' else None; "
    "os.execvp(sys.argv[2],sys.argv[2:])"
)


def _queue_proc_identity(pid: int) -> tuple[int, int, int, str]:
    """Return starttime, PGID, SID, and state from one Linux /proc record."""
    raw = (PROC_ROOT / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    end = raw.rfind(")")
    if end < 0:
        raise OSError(f"malformed /proc/{pid}/stat")
    fields = raw[end + 1:].split()
    if len(fields) < 20:
        raise OSError(f"truncated /proc/{pid}/stat")
    try:
        return int(fields[19]), int(fields[2]), int(fields[3]), fields[0]
    except ValueError as exc:
        raise OSError(f"invalid identity in /proc/{pid}/stat") from exc


def _capture_queue_process_identity(proc: subprocess.Popen[Any]) -> QueueProcessIdentity:
    """Capture identity while the launch gate prevents the child from execing."""
    boot_id = read_boot_id()
    start_time, pgid, session_id, _state = _queue_proc_identity(proc.pid)
    if pgid != proc.pid or session_id != proc.pid:
        raise OSError("queue process did not start in its own process group/session")
    return QueueProcessIdentity(boot_id, proc.pid, start_time, pgid, session_id)


def _scan_queue_process_group(
    identity: QueueProcessIdentity,
) -> tuple[str, tuple[QueueProcessMember, ...]]:
    """Classify a group by immutable identity, never numeric existence alone."""
    try:
        if read_boot_id() != identity.boot_id:
            return _QUEUE_GROUP_IDENTITY_MISMATCH, ()
        try:
            leader = _queue_proc_identity(identity.leader_pid)
        except FileNotFoundError:
            leader = None
        if leader is not None and (
            leader[0] != identity.leader_start_time
            or leader[1] != identity.pgid
            or leader[2] != identity.session_id
        ):
            return _QUEUE_GROUP_IDENTITY_MISMATCH, ()
        entries = list(PROC_ROOT.iterdir())
    except OSError:
        return _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()

    members: list[QueueProcessMember] = []
    ambiguous = False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            start_time, pgid, session_id, state = _queue_proc_identity(pid)
        except FileNotFoundError:
            # Normal process churn: an entry disappearing during enumeration
            # says nothing adverse about the target identity.
            continue
        except OSError:
            ambiguous = True
            continue
        if pid == identity.leader_pid and start_time != identity.leader_start_time:
            return _QUEUE_GROUP_IDENTITY_MISMATCH, ()
        if pgid == identity.pgid and session_id == identity.session_id and state != "Z":
            members.append(QueueProcessMember(pid, start_time))
    if ambiguous:
        return _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()
    if members:
        return _QUEUE_GROUP_ORIGINAL_ACTIVE, tuple(members)
    # Close the enumerate/read race without treating numeric existence as
    # identity.  Success is only uncertainty and can never authorize a signal;
    # ESRCH after the identity-aware scan proves the original group is gone.
    try:
        os.kill(-identity.pgid, 0)
    except ProcessLookupError:
        return _QUEUE_GROUP_ORIGINAL_QUIESCENT, ()
    except (PermissionError, OverflowError, ValueError):
        return _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return _QUEUE_GROUP_ORIGINAL_QUIESCENT, ()
        return _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()
    return _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()


def _queue_group_status(
    identity: QueueProcessIdentity,
    *,
    scanner: Callable[
        [QueueProcessIdentity], tuple[str, tuple[QueueProcessMember, ...]]
    ] | None = None,
    attempts: int = _QUEUE_GROUP_SCAN_ATTEMPTS,
) -> tuple[str, tuple[QueueProcessMember, ...]]:
    """Boundedly rescan transient /proc ambiguity without sleeping."""
    active_scanner = _scan_queue_process_group if scanner is None else scanner
    for _attempt in range(attempts):
        status, members = active_scanner(identity)
        if status != _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN:
            return status, members
    return _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN, ()


def _signal_queue_members(
    identity: QueueProcessIdentity,
    members: tuple[QueueProcessMember, ...],
    sig: signal.Signals,
) -> None:
    """Signal only pidfd-pinned members revalidated against original identity."""
    for member in members:
        try:
            pidfd = os.pidfd_open(member.pid, 0)
        except ProcessLookupError:
            continue
        except OSError as exc:
            raise AgentFlowError(
                "INTERNAL_ERROR", f"Cannot pin queue process identity: {exc}"
            ) from exc
        try:
            try:
                start_time, pgid, session_id, _state = _queue_proc_identity(member.pid)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise AgentFlowError(
                    "INTERNAL_ERROR", f"Cannot revalidate queue process identity: {exc}"
                ) from exc
            if (
                read_boot_id() != identity.boot_id
                or start_time != member.start_time
                or pgid != identity.pgid
                or session_id != identity.session_id
            ):
                continue
            try:
                signal.pidfd_send_signal(pidfd, sig)
            except ProcessLookupError:
                continue
            except OSError as exc:
                raise AgentFlowError(
                    "INTERNAL_ERROR", f"Cannot signal verified queue process: {exc}"
                ) from exc
        finally:
            os.close(pidfd)


def _terminate_plain_process_group(
    proc: subprocess.Popen[Any], identity: QueueProcessIdentity
) -> None:
    """Boundedly terminate only identity-verified queue process members."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        rounds = 1 if sig == signal.SIGTERM else _QUEUE_GROUP_SCAN_ATTEMPTS
        for _round in range(rounds):
            status, members = _queue_group_status(identity)
            if status in {
                _QUEUE_GROUP_ORIGINAL_QUIESCENT,
                _QUEUE_GROUP_IDENTITY_MISMATCH,
            }:
                with contextlib.suppress(Exception):
                    proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
                return
            if status == _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN:
                raise AgentFlowError(
                    "INTERNAL_ERROR", "Cannot prove queue process group identity/quiescence"
                )
            _signal_queue_members(identity, members, sig)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
            status, _members = _queue_group_status(identity)
            if status in {
                _QUEUE_GROUP_ORIGINAL_QUIESCENT,
                _QUEUE_GROUP_IDENTITY_MISMATCH,
            }:
                return
            if status == _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN:
                raise AgentFlowError(
                    "INTERNAL_ERROR", "Cannot prove queue process group quiescence"
                )
            if sig == signal.SIGTERM:
                break
    raise AgentFlowError(
        "INTERNAL_ERROR", f"Original queue process group {identity.pgid} remains active"
    )


def _run_queue_process(
    argv: list[str], *, cwd: Path, local_timeout: float, control: ExecutionControl,
    enforce_queue_deadline: bool = True,
) -> subprocess.CompletedProcess[str]:
    if enforce_queue_deadline:
        control.check_deadline()
        remaining = control.remaining_time()
        queue_first = remaining < float(local_timeout)
        effective = min(float(local_timeout), remaining)
    else:
        queue_first = False
        effective = float(local_timeout)
    gate_read, gate_write = os.pipe()
    try:
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", _QUEUE_EXEC_GATE, str(gate_read), *argv],
                cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True,
                pass_fds=(gate_read,),
            )
        except BaseException:
            os.close(gate_write)
            raise
    finally:
        os.close(gate_read)
    control.note_process_started()
    try:
        identity = _capture_queue_process_identity(proc)
    except Exception as exc:
        os.close(gate_write)
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
        control.note_process_quiescent()
        raise AgentFlowError(
            "INTERNAL_ERROR", f"Cannot capture queue process identity: {exc}"
        ) from exc
    try:
        os.write(gate_write, b"G")
    finally:
        os.close(gate_write)
    try:
        stdout, stderr = proc.communicate(timeout=effective)
    except subprocess.TimeoutExpired as exc:
        try:
            _terminate_plain_process_group(proc, identity)
        except AgentFlowError:
            control.note_process_uncertain()
            raise
        control.note_process_quiescent()
        try:
            stdout, stderr = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired as drain_exc:
            control.note_process_uncertain()
            raise AgentFlowError("INTERNAL_ERROR", "Cannot drain terminated process pipes") from drain_exc
        if queue_first:
            raise BudgetExhausted("WALL_CLOCK") from exc
        raise subprocess.TimeoutExpired(
            argv, local_timeout, output=stdout or None, stderr=stderr or None
        ) from exc
    group, _members = _queue_group_status(identity)
    if group == _QUEUE_GROUP_ORIGINAL_ACTIVE:
        try:
            _terminate_plain_process_group(proc, identity)
        except AgentFlowError:
            control.note_process_uncertain()
            raise
    elif group == _QUEUE_GROUP_TRANSIENTLY_UNCERTAIN:
        control.note_process_uncertain()
        raise AgentFlowError("INTERNAL_ERROR", "Cannot prove queue process group quiescence")
    control.note_process_quiescent()
    if enforce_queue_deadline and control.remaining_time() <= 0 and proc.returncode == 0:
        raise BudgetExhausted("WALL_CLOCK")
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def git(repo: Path, args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    control = _ACTIVE_EXECUTION_CONTROL.get()
    if control is not None:
        return _run_queue_process(
            ["git", *args], cwd=repo, local_timeout=timeout, control=control,
            enforce_queue_deadline=not control.finalizing,
        )
    return run_process(["git", *args], cwd=repo, timeout=timeout)


def sha256_path(path: Path) -> str:
    if not path.exists() and not path.is_symlink():
        return "<missing>"
    if path.is_symlink():
        return "symlink:" + os.readlink(path)
    if path.is_dir():
        return "<directory>"
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# --- F-04: trusted control-plane integrity invariant ---
#
# The protected control plane is always rooted at the running AgentFlow ROOT,
# never at exec_repo. For each logical run the manifest is captured exactly
# once before untrusted execution, kept immutable, verified before and after
# every model invocation (including failure paths, before retry/fallback),
# and verified again immediately before HUMAN_GATE. Any difference fails
# closed as CONTROL_PLANE_MUTATED with no retry, fallback, correction, or
# gate progression. Queues treat it as fatal.

_CONTROL_PLANE_FIXED = (
    "agentflow.py",
    "config/models.json",
    "schemas/result.schema.json",
)
_CONTROL_PLANE_TREE_DIRS = ("prompts", "opencode")
_CONTROL_PLANE_EXCLUDED_PARTS = frozenset({"node_modules", "__pycache__"})

_CONTROL_PLANE_BASELINE: contextvars.ContextVar["dict[str, Any] | None"] = (
    contextvars.ContextVar("agentflow_control_plane_baseline", default=None)
)
_CONTROL_PLANE_FALLBACK: dict[str, dict[str, Any]] = {}
_CONTROL_PLANE_FALLBACK_LOCK = threading.Lock()


def _control_plane_root() -> Path:
    return Path(ROOT).resolve()


def _control_plane_rel_excluded(rel_posix: str) -> bool:
    return any(part in _CONTROL_PLANE_EXCLUDED_PARTS for part in Path(rel_posix).parts)


def _control_plane_hash_file_nofollow(path: Path) -> str:
    """Hash a regular file without ever following symlinks."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return "<missing>"
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            try:
                return "symlink:" + os.readlink(path)
            except OSError:
                return "<symlink-unreadable>"
        return "<unreadable>"
    try:
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return "sha256:" + digest.hexdigest()
    except OSError:
        return "<unreadable>"
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _control_plane_entry(path: Path) -> str:
    """Deterministic lstat-based entry that never follows symlinks."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "<missing>"
    except OSError:
        return "<unreadable>"
    if stat.S_ISLNK(st.st_mode):
        try:
            return "symlink:" + os.readlink(path)
        except OSError:
            return "<symlink-unreadable>"
    if stat.S_ISDIR(st.st_mode):
        return "<directory>"
    if stat.S_ISREG(st.st_mode):
        return _control_plane_hash_file_nofollow(path)
    return "<special>"


def _collect_control_plane_root_py(root: Path, files: dict[str, str]) -> None:
    """Scan all *.py entries directly under ROOT (no recursion, no symlink following).

    Catches sitecustomize-style injection: a worker creating a .py file at
    the AgentFlow root could have it auto-imported by a later Python child
    or coordinator process.  The scan covers sitecustomize.py,
    usercustomize.py, and any other runtime-affecting .py injection at the
    ROOT level.  Files already covered by _CONTROL_PLANE_FIXED are
    skipped (the earlier entry is authoritative).
    """
    try:
        for entry in sorted(root.iterdir(), key=lambda e: e.name):
            if not entry.name.endswith(".py"):
                continue
            rel = entry.name
            if rel in files:
                continue
            files[rel] = _control_plane_entry(entry)
    except OSError:
        pass


def _collect_control_plane_tree(top: Path, root: Path, files: dict[str, str]) -> None:
    """Record every entry under top without following symlinks."""
    try:
        st = os.lstat(top)
    except FileNotFoundError:
        return
    except OSError:
        return
    try:
        rel_top = Path(os.path.relpath(top, root)).as_posix()
    except ValueError:
        return
    if rel_top in (".", ""):
        return
    if _control_plane_rel_excluded(rel_top):
        return
    if stat.S_ISLNK(st.st_mode):
        try:
            files[rel_top] = "symlink:" + os.readlink(top)
        except OSError:
            files[rel_top] = "<symlink-unreadable>"
        return
    if not stat.S_ISDIR(st.st_mode):
        files[rel_top] = _control_plane_entry(top)
        return
    files[rel_top] = "<directory>"
    stack = [top]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            continue
        for entry in entries:
            try:
                rel = Path(os.path.relpath(entry.path, root)).as_posix()
            except ValueError:
                continue
            if _control_plane_rel_excluded(rel):
                continue
            try:
                if entry.is_symlink():
                    try:
                        files[rel] = "symlink:" + os.readlink(entry.path)
                    except OSError:
                        files[rel] = "<symlink-unreadable>"
                    continue
            except OSError:
                files[rel] = "<unreadable>"
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    files[rel] = "<directory>"
                    stack.append(Path(entry.path))
                    continue
            except OSError:
                files[rel] = "<unreadable>"
                continue
            files[rel] = _control_plane_entry(Path(entry.path))


def capture_control_plane_manifest(root: Path | None = None) -> dict[str, Any]:
    """Capture the protected control-plane manifest (never follows symlinks)."""
    resolved = Path(root).resolve() if root is not None else _control_plane_root()
    files: dict[str, str] = {}
    for rel in _CONTROL_PLANE_FIXED:
        files[rel] = _control_plane_entry(resolved / rel)
    for dirname in _CONTROL_PLANE_TREE_DIRS:
        _collect_control_plane_tree(resolved / dirname, resolved, files)
    # Scan all *.py files directly under ROOT to catch sitecustomize-style
    # injection: a worker can create ROOT/sitecustomize.py (auto-imported by
    # Python) without touching the fixed manifest or tree dirs above.
    _collect_control_plane_root_py(resolved, files)
    digest = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return {
        "root": str(resolved),
        "captured_at": utc_now(),
        "files": files,
        "digest": digest,
    }


def canonical_control_plane_digest(manifest: dict[str, Any]) -> str:
    files = manifest.get("files", {}) if isinstance(manifest, dict) else {}
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def diff_control_plane_manifest(
    before: dict[str, Any], after: dict[str, Any]
) -> list[str]:
    left = before.get("files", {}) if isinstance(before, dict) else {}
    right = after.get("files", {}) if isinstance(after, dict) else {}
    if not isinstance(left, dict) or not isinstance(right, dict):
        return ["<manifest-shape-changed>"]
    delta: list[str] = []
    for key in sorted(set(left) | set(right)):
        old = left.get(key, "<absent>")
        new = right.get(key, "<absent>")
        if old != new:
            delta.append(f"{key}: {old!r} -> {new!r}")
    return delta


def assert_control_plane_unchanged(
    before: dict[str, Any], after: dict[str, Any], *, context: str = ""
) -> None:
    delta = diff_control_plane_manifest(before, after)
    if before.get("root") != after.get("root"):
        where = f" in {context}" if context else ""
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            f"Control-plane root changed{where}: "
            f"{before.get('root')!r} -> {after.get('root')!r}",
        )
    if delta:
        where = f" in {context}" if context else ""
        shown = "; ".join(delta[:10])
        suffix = "..." if len(delta) > 10 else ""
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            f"Control-plane mutation detected{where}: "
            f"{len(delta)} change(s): {shown}{suffix}",
        )


def _reset_control_plane_baselines() -> None:
    """Test-only reset for the fallback baseline cache and active scope."""
    _CONTROL_PLANE_BASELINE.set(None)
    with _CONTROL_PLANE_FALLBACK_LOCK:
        _CONTROL_PLANE_FALLBACK.clear()


def _control_plane_ensure_baseline(run_dir: Path) -> dict[str, Any]:
    """Return the immutable run-scoped baseline, capturing exactly once."""
    current = _CONTROL_PLANE_BASELINE.get()
    if isinstance(current, dict) and isinstance(current.get("manifest"), dict):
        return current["manifest"]
    try:
        key = f"{_control_plane_root()}::{Path(run_dir).resolve()}"
    except Exception:
        key = str(run_dir)
    with _CONTROL_PLANE_FALLBACK_LOCK:
        existing = _CONTROL_PLANE_FALLBACK.get(key)
        if existing is not None:
            return existing
        manifest = capture_control_plane_manifest()
        frozen = {
            "root": manifest["root"],
            "captured_at": manifest["captured_at"],
            "files": dict(manifest["files"]),
            "digest": manifest["digest"],
        }
        _CONTROL_PLANE_FALLBACK[key] = frozen
        return frozen


@contextlib.contextmanager
def _control_plane_run_scope(run_dir: Path) -> Iterator[dict[str, Any]]:
    """Establish one immutable baseline for a logical run (reentrant)."""
    current = _CONTROL_PLANE_BASELINE.get()
    if isinstance(current, dict) and isinstance(current.get("manifest"), dict):
        yield current["manifest"]
        return
    manifest = capture_control_plane_manifest()
    frozen = {
        "root": manifest["root"],
        "captured_at": manifest["captured_at"],
        "files": dict(manifest["files"]),
        "digest": manifest["digest"],
    }
    token = _CONTROL_PLANE_BASELINE.set({"run_dir": str(run_dir), "manifest": frozen})
    try:
        yield frozen
    finally:
        _CONTROL_PLANE_BASELINE.reset(token)


def _persist_control_plane_mutation(
    run_dir: Path,
    baseline: dict[str, Any],
    current: dict[str, Any],
    delta: list[str],
    phase: str,
) -> None:
    try:
        target = Path(run_dir)
        target.mkdir(parents=True, exist_ok=True)
        atomic_json(target / "control-plane-mutated.json", {
            "verdict": "CONTROL_PLANE_MUTATED",
            "phase": phase,
            "detected_at": utc_now(),
            "root": baseline.get("root"),
            "baseline_digest": baseline.get("digest"),
            "current_digest": current.get("digest"),
            "delta": list(delta),
        })
    except Exception:
        pass


def _verify_control_plane(run_dir: Path, *, phase: str) -> None:
    """Fail closed as CONTROL_PLANE_MUTATED when the run baseline moved."""
    baseline = _control_plane_ensure_baseline(run_dir)
    current = capture_control_plane_manifest()
    if baseline.get("root") != current.get("root"):
        delta = [
            f"<root-changed>: {baseline.get('root')!r} -> {current.get('root')!r}"
        ] + diff_control_plane_manifest(baseline, current)
        _persist_control_plane_mutation(run_dir, baseline, current, delta, phase)
        # F-04: durably record the post-mutation manifest so a later
        # logical run can never accept it as a fresh trusted baseline.
        _record_control_plane_poison(
            current, phase=phase, baseline_digest=baseline.get("digest")
        )
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            f"Control-plane root changed ({phase}): "
            f"{baseline.get('root')!r} -> {current.get('root')!r}",
        )
    delta = diff_control_plane_manifest(baseline, current)
    if delta:
        _persist_control_plane_mutation(run_dir, baseline, current, delta, phase)
        # F-04: durably record the post-mutation manifest so a later
        # logical run can never accept it as a fresh trusted baseline.
        _record_control_plane_poison(
            current, phase=phase, baseline_digest=baseline.get("digest")
        )
        shown = "; ".join(delta[:10])
        suffix = "..." if len(delta) > 10 else ""
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            f"Control-plane mutation detected ({phase}): "
            f"{len(delta)} change(s): {shown}{suffix}",
        )


def _verify_control_plane_before_gate(run_dir: Path) -> None:
    _verify_control_plane(run_dir, phase="pre-human-gate")


def _control_plane_enter_run(run_dir: Path) -> Any:
    """Capture the immutable run baseline exactly once (reentrant no-op)."""
    current = _CONTROL_PLANE_BASELINE.get()
    if isinstance(current, dict) and isinstance(current.get("manifest"), dict):
        return None
    manifest = capture_control_plane_manifest()
    frozen = {
        "root": manifest["root"],
        "captured_at": manifest["captured_at"],
        "files": dict(manifest["files"]),
        "digest": manifest["digest"],
    }
    return _CONTROL_PLANE_BASELINE.set({"run_dir": str(run_dir), "manifest": frozen})


def _control_plane_exit_run(token: Any) -> None:
    if token is not None:
        with contextlib.suppress(Exception):
            _CONTROL_PLANE_BASELINE.reset(token)


@contextlib.contextmanager
def _control_plane_restored_scope(run_dir: Path, manifest: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Temporarily install and verify a previously persisted F-04 baseline.

    This deliberately narrow entry point is for finding-run scopes. It never
    captures or refreshes trust: the supplied original manifest must be
    structurally valid, rooted at this AgentFlow checkout, and content-bound.
    """
    if not isinstance(manifest, dict) or set(manifest) != {"root", "captured_at", "files", "digest"}:
        raise AgentFlowError("CONTROL_PLANE_MUTATED", "Persisted control-plane manifest shape is invalid")
    root, files, digest = manifest.get("root"), manifest.get("files"), manifest.get("digest")
    if not isinstance(root, str) or root != str(_control_plane_root()):
        raise AgentFlowError("CONTROL_PLANE_MUTATED", "Persisted control-plane root is invalid")
    if not isinstance(manifest.get("captured_at"), str) or not manifest["captured_at"]:
        raise AgentFlowError("CONTROL_PLANE_MUTATED", "Persisted control-plane timestamp is invalid")
    if not isinstance(files, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in files.items()
    ):
        raise AgentFlowError("CONTROL_PLANE_MUTATED", "Persisted control-plane files map is invalid")
    canonical = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    if not isinstance(digest, str) or digest != canonical:
        raise AgentFlowError("CONTROL_PLANE_MUTATED", "Persisted control-plane digest is invalid")
    current_scope = _CONTROL_PLANE_BASELINE.get()
    if current_scope is not None:
        raise AgentFlowError("CONTROL_PLANE_MUTATED", "Cannot restore F-04 baseline inside another scope")
    frozen = {"root": root, "captured_at": manifest["captured_at"], "files": dict(files), "digest": digest}
    token = _CONTROL_PLANE_BASELINE.set({"run_dir": str(run_dir), "manifest": frozen})
    try:
        _control_plane_check_poison(run_dir)
        _verify_control_plane(run_dir, phase="finding-resume-entry")
        yield frozen
    finally:
        try:
            _verify_control_plane(run_dir, phase="finding-scope-exit")
        finally:
            _CONTROL_PLANE_BASELINE.reset(token)


# --- F-04: durable control-plane poison ledger ---
#
# Same-run verification alone is not enough: a worker that mutated the
# trusted control plane and was stopped leaves that poisoned state on
# disk. Without durable evidence, a later logical run would simply
# capture the poisoned state as its fresh baseline and trust it. The
# poison ledger closes that window: every manifest that AgentFlow itself
# observed as mutated is recorded (content-bound, keyed by its canonical
# manifest digest) under LOCKS_DIR, and every logical run refuses to
# start when its freshly captured manifest matches a recorded entry.
#
# The ledger lives under .locks, which is NOT part of the protected
# manifest (only agentflow.py, config/models.json, schemas/ and the
# prompts/ and opencode/ trees are), so recording cannot recursively
# trigger detection. A ledger that exists but cannot be safely parsed or
# verified fails closed as CONTROL_PLANE_MUTATED; malformed durable
# poison evidence is never treated as "no poison".

_CONTROL_PLANE_POISON_LEDGER_NAME = "control-plane-poison.json"
_CONTROL_PLANE_POISON_MAX_ENTRIES = 32


def _control_plane_poison_ledger_path() -> Path:
    return Path(LOCKS_DIR) / _CONTROL_PLANE_POISON_LEDGER_NAME


def _load_control_plane_poison_entries() -> list[dict[str, Any]]:
    """Read and verify the poison ledger; fail closed on any doubt.

    Returns recorded entries (possibly empty). Raises
    CONTROL_PLANE_MUTATED when the ledger exists but is unreadable,
    malformed, structurally invalid, internally inconsistent (a stored
    files map does not hash to its stored canonical digest), or exceeds
    the bounded entry count. Absent ledger yields [].
    """
    path = _control_plane_poison_ledger_path()
    try:
        if not path.is_file():
            return []
        with path.open(encoding="utf-8") as handle:
            raw = json.load(handle)
    except AgentFlowError:
        raise
    except Exception as exc:
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            f"Control-plane poison ledger exists but cannot be read "
            f"({path}): {exc}",
        ) from exc
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            f"Control-plane poison ledger has an unsupported shape "
            f"({path})",
        )
    entries = raw.get("entries")
    if not isinstance(entries, list) or len(entries) > _CONTROL_PLANE_POISON_MAX_ENTRIES:
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            f"Control-plane poison ledger entries are invalid "
            f"({path})",
        )
    for entry in entries:
        if not isinstance(entry, dict):
            raise AgentFlowError(
                "CONTROL_PLANE_MUTATED",
                f"Control-plane poison ledger entry is not an object ({path})",
            )
        files = entry.get("files")
        digest = entry.get("digest")
        if not isinstance(files, dict) or not isinstance(digest, str):
            raise AgentFlowError(
                "CONTROL_PLANE_MUTATED",
                f"Control-plane poison ledger entry lacks content-bound "
                f"evidence ({path})",
            )
        recomputed = hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if recomputed != digest:
            raise AgentFlowError(
                "CONTROL_PLANE_MUTATED",
                f"Control-plane poison ledger entry fails digest "
                f"verification ({path}): {digest}",
            )
    return entries


def _record_control_plane_poison(
    current: dict[str, Any],
    *,
    phase: str = "",
    baseline_digest: str | None = None,
) -> None:
    """Durably record a manifest observed as mutated (coordinator-written).

    Bounded to _CONTROL_PLANE_POISON_MAX_ENTRIES most-recent entries,
    deduplicated by canonical digest, persisted atomically with fsync.
    Cross-process safe: the entire read-modify-write is protected by an
    OS advisory lock (fcntl.flock) so concurrent detections cannot lose
    an entry.  Lock lifetime is deterministic: acquired before read,
    released after write (or on any exception) in a finally block.
    Failures are fatal (still CONTROL_PLANE_MUTATED): a run must never
    proceed as if the poisoned state had been recorded when it was not.
    """
    files = current.get("files") if isinstance(current, dict) else None
    if not isinstance(files, dict) or not files:
        return
    digest = canonical_control_plane_digest(current)
    ledger_path = _control_plane_poison_ledger_path()
    guard_path = ledger_path.with_name(f"{ledger_path.stem}.guard")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(guard_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        entries = _load_control_plane_poison_entries()
        if any(entry.get("digest") == digest for entry in entries):
            return
        entries.append({
            "digest": digest,
            "files": dict(files),
            "root": current.get("root") if isinstance(current, dict) else None,
            "recorded_at": utc_now(),
            "phase": str(phase),
            "baseline_digest": (
                baseline_digest if isinstance(baseline_digest, str) else None
            ),
        })
        if len(entries) > _CONTROL_PLANE_POISON_MAX_ENTRIES:
            entries = entries[-_CONTROL_PLANE_POISON_MAX_ENTRIES:]
        try:
            atomic_json_fsync(
                ledger_path,
                {"version": 1, "updated_at": utc_now(), "entries": entries},
            )
        except Exception as exc:
            # A run must never proceed as if poisoned evidence were recorded
            # when it was not; the failure stays queue-fatal and non-retryable.
            raise AgentFlowError(
                "CONTROL_PLANE_MUTATED",
                f"Cannot durably record control-plane poison evidence: {exc}",
            ) from exc
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _control_plane_check_poison(run_dir: Path) -> None:
    """Fail closed at logical-run start on a recorded poisoned manifest.

    Called after the run baseline manifest has been computed but before
    any worktree creation or model invocation. A manifest that matches a
    previously observed poisoned state is never accepted as the trusted
    baseline of a later run.
    """
    baseline = _control_plane_ensure_baseline(run_dir)
    entries = _load_control_plane_poison_entries()
    if not entries:
        return
    current_digest = canonical_control_plane_digest(baseline)
    for entry in entries:
        if entry.get("digest") != current_digest:
            continue
        current = {
            "root": baseline.get("root"),
            "files": baseline.get("files", {}),
            "digest": current_digest,
        }
        delta = [
            "<matches-durable-poison-ledger>: "
            f"{entry.get('phase', '')} recorded {current_digest}"
        ]
        _persist_control_plane_mutation(
            Path(run_dir), baseline, current, delta,
            phase="run-start poison ledger",
        )
        raise AgentFlowError(
            "CONTROL_PLANE_MUTATED",
            "Control plane matches a previously observed poisoned state "
            f"(durable poison ledger): {current_digest}",
        )


def status_entries(repo: Path) -> list[tuple[str, str]]:
    proc = git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if proc.returncode:
        raise AgentFlowError("GIT_STATUS_FAILED", summarized(proc.stderr or proc.stdout))
    raw = proc.stdout.split("\0")
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(raw):
        item = raw[index]
        index += 1
        if not item:
            continue
        status, path = item[:2], item[3:]
        # Porcelain v1 -z rename/copy record layout (verified against real
        # git): the XY field is followed by the DESTINATION path, and the
        # next NUL-terminated field is the bare SOURCE path, e.g.
        #   "R  outside/leaked.txt\0allowed/keep.txt\0"
        # Scope enforcement must see BOTH endpoints: retaining only one lets
        # a rename escape child/parent allowed_paths checks. Emit an entry
        # per endpoint so dirty_paths/path_state (and therefore
        # changed_since deltas) cover source and destination.
        if ("R" in status or "C" in status) and index < len(raw) and raw[index]:
            source = raw[index]
            index += 1
            entries.append((status, path))
            entries.append((status, source))
        else:
            entries.append((status, path))
    return entries


def read_git_identity(repo: Path) -> dict[str, Any] | None:
    """Live Git identity probe: branch/detached identity + HEAD SHA.

    Returns ``{"branch": str|None, "head": str|None}`` when the repo is a
    verifiable work tree, else None (non-git dirs, unborn without HEAD
    resolution failure tolerated as dict). Never raises: probe failures
    return None so direct non-git unit probes stay no-ops while verified
    identities fail closed in the comparator.
    """
    try:
        repo_path = Path(repo)
    except Exception:
        return None
    try:
        inside = git(repo_path, ["rev-parse", "--is-inside-work-tree"])
    except Exception:
        return None
    try:
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return None
    except Exception:
        return None
    try:
        branch_proc = git(repo_path, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    except Exception:
        return None
    try:
        head_proc = git(repo_path, ["rev-parse", "--verify", "HEAD"])
    except Exception:
        return None
    try:
        branch = branch_proc.stdout.strip() if branch_proc.returncode == 0 else None
        head = head_proc.stdout.strip() if head_proc.returncode == 0 else None
    except Exception:
        return None
    if branch == "":
        branch = None
    if head == "":
        head = None
    return {"branch": branch, "head": head}


def assert_git_identity_unchanged(
    expected: dict[str, Any] | None,
    actual: dict[str, Any] | None,
    *,
    context: str = "",
) -> None:
    """Fail closed when Git branch/HEAD identity moved.

    Pure comparator. ``expected None`` (non-git probe) is a no-op.
    Dicts without branch/head keys (mocked ``{}`` harnesses) are no-ops.
    Both-None identity is a no-op (unborn). Otherwise any branch or head
    difference, or a lost (None) actual after a verified expected, raises
    ``GIT_IDENTITY_MOVED``.
    """
    if expected is None:
        return
    if not isinstance(expected, dict):
        return
    if "branch" not in expected and "head" not in expected:
        return
    exp_branch = expected.get("branch")
    exp_head = expected.get("head")
    if exp_branch is None and exp_head is None:
        return
    if actual is None:
        where = f" in {context}" if context else ""
        raise AgentFlowError(
            "GIT_IDENTITY_MOVED",
            f"Git identity unreadable after verified baseline{where}: "
            f"expected branch={exp_branch!r} head={exp_head!r}",
        )
    if not isinstance(actual, dict):
        where = f" in {context}" if context else ""
        raise AgentFlowError(
            "GIT_IDENTITY_MOVED", f"Git identity mismatch{where}: non-dict actual"
        )
    if "branch" not in actual and "head" not in actual:
        where = f" in {context}" if context else ""
        raise AgentFlowError(
            "GIT_IDENTITY_MOVED",
            f"Git identity unreadable after verified baseline{where}: "
            f"expected branch={exp_branch!r} head={exp_head!r}",
        )
    act_branch = actual.get("branch")
    act_head = actual.get("head")
    if exp_branch != act_branch or exp_head != act_head:
        where = f" in {context}" if context else ""
        raise AgentFlowError(
            "GIT_IDENTITY_MOVED",
            f"Git identity moved{where}: "
            f"expected branch={exp_branch!r} head={exp_head!r} "
            f"actual branch={act_branch!r} head={act_head!r}",
        )


def capture_baseline(repo: Path) -> dict[str, Any]:
    if not repo.is_dir():
        raise AgentFlowError("REPO_NOT_FOUND", str(repo))
    identity = read_git_identity(repo)
    if identity is None:
        raise AgentFlowError("NOT_A_GIT_REPO", str(repo))
    branch = identity.get("branch")
    head = identity.get("head")
    entries = status_entries(repo)
    dirty = sorted(path for status, path in entries if status != "??")
    untracked = sorted(path for status, path in entries if status == "??")
    states = {path: sha256_path(repo / path) for _, path in entries}
    diff_check = git(repo, ["diff", "--check"])
    return {
        "captured_at": utc_now(),
        "repo": str(repo.resolve()),
        "branch": branch,
        "head": head,
        "dirty_paths": dirty,
        "untracked_paths": untracked,
        "path_state": states,
        "git_diff_check": {
            "exit_code": diff_check.returncode,
            "stdout": summarized(diff_check.stdout),
            "stderr": summarized(diff_check.stderr),
        },
    }


def capture_candidate_manifest(candidate: Path, source_repo: Path, baseline_commit: str) -> dict[str, Any]:
    """Capture complete deterministic candidate state, including ignored files.

    Only the root worktree's Git administrative entry is excluded. Nested
    repositories and Git submodules fail closed because their contents cannot
    be represented as one v0 candidate.
    """
    candidate = Path(candidate).resolve(strict=True)
    source_repo = Path(source_repo).resolve(strict=True)
    baseline = _canonical_sha(baseline_commit)
    if not candidate.is_dir() or not source_repo.is_dir():
        raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Candidate or source repository is missing")
    head = _worktree_head(candidate)
    detached = _worktree_is_detached(candidate)
    registered = _is_worktree_registered(source_repo, candidate)
    git_dir = git(candidate, ["rev-parse", "--absolute-git-dir"])
    top = git(candidate, ["rev-parse", "--show-toplevel"])
    if (not registered or not detached or head != baseline or git_dir.returncode
            or top.returncode or Path(top.stdout.strip()).resolve() != candidate):
        raise AgentFlowError(
            "CANDIDATE_INTEGRITY_CHANGED",
            "Candidate worktree registration, detached identity, or frozen HEAD is invalid",
        )

    index_proc = git(candidate, ["ls-files", "--stage", "-z"])
    if index_proc.returncode:
        raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Cannot read semantic Git index")
    index: list[dict[str, Any]] = []
    for raw in index_proc.stdout.split("\0"):
        if not raw:
            continue
        try:
            meta, path = raw.split("\t", 1)
            mode, object_id, stage = meta.split(" ")
            if mode == "160000":
                raise ValueError("gitlink")
            index.append({"path": path, "mode": mode, "object_id": object_id, "stage": int(stage)})
        except (ValueError, TypeError) as exc:
            raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Unsupported Git index entry") from exc
    index.sort(key=lambda item: (item["path"], item["stage"], item["mode"], item["object_id"]))

    inventory: list[dict[str, Any]] = []
    stack: list[tuple[Path, str]] = [(candidate, "")]
    while stack:
        directory, rel_dir = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name, reverse=True)
        except OSError as exc:
            raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", f"Cannot inventory candidate: {exc}") from exc
        for entry in entries:
            if not rel_dir and entry.name == ".git":
                continue
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            if rel_dir and entry.name == ".git":
                raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", f"Nested repository at {rel}")
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", f"Cannot stat candidate entry {rel}: {exc}") from exc
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                inventory.append({"path": rel, "type": "symlink", "mode": mode, "target": os.readlink(entry.path)})
            elif stat.S_ISDIR(st.st_mode):
                if entry.name == ".git":
                    raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", f"Nested repository at {rel}")
                inventory.append({"path": rel, "type": "directory", "mode": mode})
                stack.append((Path(entry.path), rel))
            elif stat.S_ISREG(st.st_mode):
                path = Path(entry.path)
                if path.name == ".git":
                    raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", f"Nested repository at {rel}")
                digest = hashlib.sha256()
                try:
                    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    with os.fdopen(fd, "rb") as handle:
                        for block in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(block)
                except OSError as exc:
                    raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", f"Cannot hash candidate entry {rel}: {exc}") from exc
                inventory.append({"path": rel, "type": "file", "mode": mode, "sha256": digest.hexdigest()})
            else:
                raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", f"Unsupported special file at {rel}")
    inventory.sort(key=lambda item: item["path"])
    semantic = {
        "candidate": str(candidate),
        "source_repo": str(source_repo),
        "registered": registered,
        "detached": detached,
        "head": head,
        "baseline_commit": baseline,
        "git_dir": str(Path(git_dir.stdout.strip()).resolve()),
        "index": index,
        "filesystem": inventory,
    }
    return {**semantic, "captured_at": utc_now(), "candidate_digest": _json_hash(semantic)}


def candidate_manifest_digest(manifest: dict[str, Any]) -> str:
    if not isinstance(manifest, dict):
        raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Candidate manifest is malformed")
    semantic = {key: value for key, value in manifest.items() if key not in {"captured_at", "candidate_digest"}}
    digest = _json_hash(semantic)
    if manifest.get("candidate_digest") != digest:
        raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Candidate manifest digest is invalid")
    return digest


def baseline_mismatches(actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    mismatches = []
    for field in ("branch", "head", "dirty_paths", "untracked_paths"):
        if field in expected:
            wanted = expected[field]
            got = actual[field]
            if field.endswith("paths"):
                wanted, got = sorted(wanted), sorted(got)
            if wanted != got:
                mismatches.append(f"{field}: expected={wanted!r} actual={got!r}")
    if actual["git_diff_check"]["exit_code"] != 0:
        mismatches.append("git diff --check failed")
    return mismatches


def changed_since(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    left = before.get("path_state", {})
    right = after.get("path_state", {})
    return sorted(path for path in set(left) | set(right) if left.get(path) != right.get(path))


def normalize_allowed(paths: list[str]) -> list[str]:
    normalized = []
    for raw in paths:
        path = Path(raw)
        if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
            raise AgentFlowError("INVALID_ALLOWED_PATH", raw)
        normalized.append(path.as_posix().rstrip("/"))
    return sorted(set(normalized))


def path_allowed(path: str, allowed: list[str]) -> bool:
    return any(path == item or path.startswith(item + "/") for item in allowed)


def read_boot_id() -> str:
    """Return the Linux boot id that scopes process-start-time comparisons."""
    boot_id = BOOT_ID_PATH.read_text(encoding="ascii").strip()
    if not boot_id:
        raise OSError(f"empty boot id in {BOOT_ID_PATH}")
    return boot_id


def _read_proc_stat(pid: int) -> tuple[int, int, int]:
    """Return ``(starttime, process_group, session)`` from Linux proc stat."""
    raw = (PROC_ROOT / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    end = raw.rfind(")")
    if end < 0:
        raise OSError(f"malformed /proc/{pid}/stat")
    fields = raw[end + 1:].split()
    if len(fields) < 20:
        raise OSError(f"truncated /proc/{pid}/stat")
    try:
        return int(fields[19]), int(fields[2]), int(fields[3])
    except ValueError as exc:
        raise OSError(f"invalid identity in /proc/{pid}/stat") from exc


def process_start_time(pid: int) -> int:
    """Return field 22 (starttime) of /proc/<pid>/stat.

    FileNotFoundError means the pid has no /proc entry. Any other OSError means
    the process identity cannot be verified, so callers must fail closed.
    """
    return _read_proc_stat(pid)[0]


def process_group_identity(pid: int) -> tuple[int, int]:
    """Return ``(process_group, session)`` for a live Linux process."""
    _, pgid, session_id = _read_proc_stat(pid)
    return pgid, session_id


def pid_exists(pid: int) -> bool | None:
    """True/False when the kernel proves liveness/death, None when unverifiable."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OverflowError, ValueError):
        return None
    except OSError:
        return None
    return True


class WriteLease:
    """Exclusive per-repo lease bound to the controller and writer lifecycle.

    V3 keeps the V2 controller identity checks and adds a token-owned writer
    record.  A worker is started in a new session and waits on a pipe; the
    controller records that process and group durably before sending GO.  This
    makes an abandoned controller unable to accidentally authorize a worker.
    """

    FORMAT = 3
    _RECOVERY_ATTEMPTS = 3
    _ARCHIVE_ATTEMPTS = 4
    _WRITER_STATES = {
        "not_started", "starting", "pending", "running", "active", "registered",
        "quiescent", "exited", "stopped", "done",
    }

    def __init__(self, repo: Path, task_id: str, run_id: str):
        repo_key = hashlib.sha256(str(repo.resolve()).encode()).hexdigest()[:20]
        self.path = LOCKS_DIR / f"{repo_key}.json"
        try:
            controller = {
                "pid": os.getpid(),
                "boot_id": read_boot_id(),
                "process_start_time": process_start_time(os.getpid()),
            }
        except OSError as exc:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Cannot resolve own process identity: {exc}") from exc
        self.controller_identity = controller
        self.data = {
            "format": self.FORMAT,
            "task_id": task_id,
            "run_id": run_id,
            "repo": str(repo.resolve()),
            "token": uuid.uuid4().hex,
            "acquired_at": utc_now(),
            # Keep the V2 names as controller aliases for diagnostics and
            # compatibility while making the V3 ownership explicit.
            "controller": dict(controller),
            "controller_pid": controller["pid"],
            "controller_boot_id": controller["boot_id"],
            "controller_process_start_time": controller["process_start_time"],
            "controller_start_time": controller["process_start_time"],
            "pid": controller["pid"],
            "boot_id": controller["boot_id"],
            "process_start_time": controller["process_start_time"],
        }
        self._set_writer_payload(self.data, self._writer_payload("not_started"))
        self.acquired = False

    @contextlib.contextmanager
    def _guard(self) -> Iterator[None]:
        # The guard file name also matches ".locks/*.json", so it stays
        # git-ignored; it must persist to keep flock mutual exclusion stable.
        guard_path = self.path.with_name(f"{self.path.stem}.guard.json")
        fd = os.open(guard_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read_lease(self) -> tuple[dict[str, Any], bytes]:
        raw = self.path.read_bytes()
        try:
            existing = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Malformed lease: {self.path}") from exc
        if not isinstance(existing, dict):
            raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Malformed lease: {self.path}")
        return existing, raw

    @staticmethod
    def _positive_int(value: Any, label: str, *, maximum: int = MAX_LINUX_PID) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Lease has no verifiable {label}; failing closed")
        return value

    @classmethod
    def _identity_from_mapping(
        cls,
        mapping: dict[str, Any],
        *,
        label: str,
        require_group: bool = False,
    ) -> dict[str, Any]:
        def field(names: tuple[str, ...], field_label: str, *, required: bool = True) -> Any:
            present = [(name, mapping[name]) for name in names if name in mapping]
            if not present:
                if required:
                    raise AgentFlowError(
                        "WRITE_LEASE_CONFLICT",
                        f"Lease has no verifiable {label} {field_label}; failing closed",
                    )
                return None
            value = present[0][1]
            if any(other != value for _, other in present[1:]):
                raise AgentFlowError(
                    "WRITE_LEASE_CONFLICT",
                    f"Lease has conflicting {label} {field_label}; failing closed",
                )
            return value

        pid = cls._positive_int(field(("pid",), "pid"), f"{label} pid")
        boot_id = field(("boot_id",), "boot id")
        if not isinstance(boot_id, str) or not boot_id.strip():
            raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Lease has no verifiable {label} boot id; failing closed")
        start_time = cls._positive_int(
            field(("process_start_time", "start_time"), "process start time"),
            f"{label} process start time",
            maximum=MAX_LINUX_START_TIME,
        )
        result = {
            "pid": pid,
            "boot_id": boot_id.strip(),
            "process_start_time": start_time,
        }
        if require_group:
            pgid = cls._positive_int(
                field(("pgid", "process_group_id"), "process group id"),
                f"{label} process group id",
            )
            session_id = cls._positive_int(
                field(("session_id", "sid"), "session id"),
                f"{label} session id",
            )
            result.update({"pgid": pgid, "session_id": session_id})
        return result

    @classmethod
    def _lease_identity(cls, existing: dict[str, Any]) -> tuple[int, str, int]:
        """Return the V3 controller identity, retaining the V2 helper API."""
        if "controller" in existing and existing["controller"] is None:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease controller identity is null; failing closed")
        controller = existing.get("controller")
        if controller is not None:
            if not isinstance(controller, dict):
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease controller identity is malformed; failing closed")
            mapping = dict(controller)
            fallback_fields = {
                "pid": ("controller_pid", "pid"),
                "boot_id": ("controller_boot_id", "boot_id"),
                "process_start_time": (
                    "controller_process_start_time", "controller_start_time", "process_start_time"
                ),
            }
            for field_name, names in fallback_fields.items():
                nested_names = {
                    "pid": ("pid",),
                    "boot_id": ("boot_id",),
                    "process_start_time": ("process_start_time", "start_time"),
                }[field_name]
                if not any(name in mapping for name in nested_names):
                    present = [existing[name] for name in names if name in existing]
                    if present:
                        if any(value != present[0] for value in present[1:]):
                            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease controller aliases disagree; failing closed")
                        mapping[field_name] = present[0]
            identity = cls._identity_from_mapping(mapping, label="controller")
            aliases = {
                "pid": ("controller_pid", "pid"),
                "boot_id": ("controller_boot_id", "boot_id"),
                "process_start_time": (
                    "controller_process_start_time", "controller_start_time", "process_start_time"
                ),
            }
            for name, names in aliases.items():
                for alias_name in names:
                    if alias_name in existing and existing[alias_name] != identity[name]:
                        raise AgentFlowError(
                            "WRITE_LEASE_CONFLICT",
                            f"Lease controller {name} mismatch; failing closed",
                        )
        else:
            if any(
                name in existing
                for name in ("controller_pid", "controller_boot_id", "controller_process_start_time", "controller_start_time")
            ):
                mapping = {
                    "pid": existing.get("controller_pid"),
                    "boot_id": existing.get("controller_boot_id"),
                    "process_start_time": existing.get(
                        "controller_process_start_time", existing.get("controller_start_time")
                    ),
                }
            else:
                mapping = {
                    "pid": existing.get("pid"),
                    "boot_id": existing.get("boot_id"),
                    "process_start_time": existing.get("process_start_time"),
                }
            identity = cls._identity_from_mapping(mapping, label="controller")
        return identity["pid"], identity["boot_id"], identity["process_start_time"]

    @staticmethod
    def _writer_payload(
        state: str,
        identity: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        identity = identity or {}
        pgid = identity.get("pgid")
        session_id = identity.get("session_id", identity.get("sid"))
        return {
            "state": state,
            "lifecycle_state": state,
            "pid": identity.get("pid"),
            "process_start_time": identity.get("process_start_time"),
            "boot_id": identity.get("boot_id"),
            "pgid": pgid,
            "process_group_id": pgid,
            "session_id": session_id,
            "sid": session_id,
        }

    @classmethod
    def _writer_from_lease(cls, existing: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        def mapping_field(mapping: dict[str, Any], names: tuple[str, ...]) -> Any:
            present = [(name, mapping[name]) for name in names if name in mapping]
            if not present:
                return None
            value = present[0][1]
            if any(other != value for _, other in present[1:]):
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease writer aliases disagree; failing closed")
            return value

        if "writer" in existing and existing["writer"] is None:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease writer state is null; failing closed")
        writer = existing.get("writer")
        if writer is None:
            if not any(
                name in existing
                for name in (
                    "writer_state", "writer_pid", "writer_process_start_time", "writer_start_time",
                    "writer_boot_id", "writer_pgid", "writer_process_group_id",
                    "writer_session_id", "writer_sid",
                )
            ):
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease has no verifiable writer state; failing closed")
            writer = {
                "state": existing.get("writer_state"),
                "pid": existing.get("writer_pid"),
                "process_start_time": existing.get(
                    "writer_process_start_time", existing.get("writer_start_time")
                ),
                "boot_id": existing.get("writer_boot_id"),
                "pgid": mapping_field(existing, ("writer_pgid", "writer_process_group_id")),
                "session_id": mapping_field(existing, ("writer_session_id", "writer_sid")),
            }
        if not isinstance(writer, dict):
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease writer state is malformed; failing closed")
        state = writer.get("state", writer.get("lifecycle_state", existing.get("writer_state")))
        if not isinstance(state, str) or state not in cls._WRITER_STATES:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease has an unknown writer state; failing closed")
        if "lifecycle_state" in writer and writer["lifecycle_state"] != state:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease writer state aliases disagree; failing closed")
        if "writer_state" in existing and existing["writer_state"] != state:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease writer state alias disagrees; failing closed")

        identity_values = {
            "pid": mapping_field(writer, ("pid",)),
            "process_start_time": mapping_field(writer, ("process_start_time", "start_time")),
            "boot_id": mapping_field(writer, ("boot_id",)),
            "pgid": mapping_field(writer, ("pgid", "process_group_id")),
            "session_id": mapping_field(writer, ("session_id", "sid")),
        }
        aliases = {
            "pid": ("writer_pid",),
            "process_start_time": ("writer_process_start_time", "writer_start_time"),
            "boot_id": ("writer_boot_id",),
            "pgid": ("writer_pgid", "writer_process_group_id"),
            "session_id": ("writer_session_id", "writer_sid"),
        }
        for name, names in aliases.items():
            alias_present = any(alias_name in existing for alias_name in names)
            alias_value = mapping_field(existing, names) if alias_present else None
            nested_present = (
                (name == "process_start_time" and any(key in writer for key in ("process_start_time", "start_time")))
                or (name == "pgid" and any(key in writer for key in ("pgid", "process_group_id")))
                or (name == "session_id" and any(key in writer for key in ("session_id", "sid")))
                or name in writer
            )
            if not nested_present:
                identity_values[name] = alias_value
            if alias_present and identity_values[name] != alias_value:
                raise AgentFlowError(
                    "WRITE_LEASE_CONFLICT",
                    f"Lease writer {name} aliases disagree; failing closed",
                )

        if state == "not_started":
            if any(value is not None for value in identity_values.values()):
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Unstarted lease contains writer identity; failing closed")
            return state, None
        if state in {"starting", "pending"} and all(value is None for value in identity_values.values()):
            # A controller that dies in this window cannot be recovered: the
            # not-yet-registered child is deliberately unverifiable.
            return state, None
        identity = cls._identity_from_mapping(
            {
                "pid": identity_values["pid"],
                "process_start_time": identity_values["process_start_time"],
                "boot_id": identity_values["boot_id"],
                "pgid": identity_values["pgid"],
                "session_id": identity_values["session_id"],
            },
            label="writer",
            require_group=True,
        )
        return state, identity

    @staticmethod
    def _set_writer_payload(existing: dict[str, Any], payload: dict[str, Any]) -> None:
        existing["writer"] = dict(payload)
        existing["writer_state"] = payload["state"]
        existing["writer_pid"] = payload["pid"]
        existing["writer_process_start_time"] = payload["process_start_time"]
        existing["writer_start_time"] = payload["process_start_time"]
        existing["writer_boot_id"] = payload["boot_id"]
        existing["writer_pgid"] = payload["pgid"]
        existing["writer_process_group_id"] = payload["process_group_id"]
        existing["writer_session_id"] = payload["session_id"]
        existing["writer_sid"] = payload["sid"]

    @staticmethod
    def _same_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
        return all(left.get(name) == right.get(name) for name in ("pid", "boot_id", "process_start_time"))

    def _validate_v3(self, existing: dict[str, Any]) -> None:
        if (
            isinstance(existing.get("format"), bool)
            or not isinstance(existing.get("format"), int)
            or existing.get("format") != self.FORMAT
        ):
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Legacy or unsupported lease format; failing closed")
        token = existing.get("token")
        if not isinstance(token, str) or not token.strip():
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Lease has no verifiable token; failing closed")
        self._lease_identity(existing)
        self._writer_from_lease(existing)

    def _owned_existing_locked(self) -> dict[str, Any]:
        try:
            existing, _ = self._read_lease()
        except (OSError, AgentFlowError) as exc:
            if isinstance(exc, AgentFlowError):
                raise
            raise AgentFlowError("WRITE_LEASE_OWNERSHIP_LOST", str(self.path)) from exc
        if existing.get("token") != self.data["token"]:
            raise AgentFlowError("WRITE_LEASE_OWNERSHIP_LOST", str(self.path))
        self._validate_v3(existing)
        controller_tuple = self._lease_identity(existing)
        expected = self.controller_identity
        if controller_tuple != (
            expected["pid"], expected["boot_id"], expected["process_start_time"]
        ):
            raise AgentFlowError("WRITE_LEASE_OWNERSHIP_LOST", str(self.path))
        return existing

    def _persist_locked(self, existing: dict[str, Any]) -> None:
        atomic_json_fsync(self.path, existing)
        self.data = existing

    def _create_exclusive(self) -> None:
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            fsync_directory(self.path.parent)
        except BaseException:
            with contextlib.suppress(OSError):
                self.path.unlink()
            raise

    @staticmethod
    def _process_status(identity: dict[str, Any], *, require_group: bool = False) -> str:
        """Return active, inactive, or unknown for one exact process identity."""
        try:
            current_boot_id = read_boot_id()
        except OSError:
            return "unknown"
        if identity["boot_id"] != current_boot_id:
            return "inactive"
        try:
            observed_start_time = process_start_time(identity["pid"])
        except FileNotFoundError:
            exists = pid_exists(identity["pid"])
            if exists is False:
                return "inactive"
            return "unknown"
        except OSError:
            return "unknown"
        if observed_start_time != identity["process_start_time"]:
            return "inactive"
        if require_group:
            try:
                observed_pgid, observed_session = process_group_identity(identity["pid"])
            except FileNotFoundError:
                exists = pid_exists(identity["pid"])
                if exists is False:
                    return "inactive"
                return "unknown"
            except OSError:
                return "unknown"
            if (
                observed_pgid != identity["pgid"]
                or observed_session != identity["session_id"]
            ):
                return "unknown"
        return "active"

    @staticmethod
    def _scan_process_group(pgid: int, session_id: int) -> str:
        try:
            entries = list(PROC_ROOT.iterdir())
        except OSError:
            return "unknown"
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                _, observed_pgid, observed_session = _read_proc_stat(int(entry.name))
            except FileNotFoundError:
                if pid_exists(int(entry.name)) is False:
                    continue
                return "unknown"
            except OSError:
                return "unknown"
            if observed_pgid == pgid:
                if observed_session != session_id:
                    return "unknown"
                return "active"
        return "inactive"

    @classmethod
    def _group_status(cls, pgid: int, session_id: int) -> str:
        if isinstance(pgid, bool) or not isinstance(pgid, int) or pgid <= 0 or pgid > MAX_LINUX_PID:
            return "unknown"
        if isinstance(session_id, bool) or not isinstance(session_id, int) or session_id <= 0 or session_id > MAX_LINUX_PID:
            return "unknown"
        try:
            os.kill(-pgid, 0)
        except ProcessLookupError:
            pass
        except PermissionError:
            return "unknown"
        except (OverflowError, ValueError):
            return "unknown"
        except OSError as exc:
            if exc.errno != errno.ESRCH:
                return "unknown"
        else:
            return "active"

        scanned = cls._scan_process_group(pgid, session_id)
        if scanned != "inactive":
            return scanned
        # Close the scan/check race: a process can join the group immediately
        # after /proc was enumerated.
        try:
            os.kill(-pgid, 0)
        except ProcessLookupError:
            return "inactive"
        except PermissionError:
            return "unknown"
        except (OverflowError, ValueError):
            return "unknown"
        except OSError as exc:
            return "inactive" if exc.errno == errno.ESRCH else "unknown"
        return "active"

    @classmethod
    def _writer_status(cls, existing: dict[str, Any]) -> str:
        state, identity = cls._writer_from_lease(existing)
        if state == "not_started":
            return "inactive"
        if identity is None:
            return "unknown"
        process_state = cls._process_status(identity, require_group=True)
        group_state = cls._group_status(identity["pgid"], identity["session_id"])
        if process_state == "active" or group_state == "active":
            return "active"
        if process_state == "unknown" or group_state == "unknown":
            return "unknown"
        return "inactive"

    def _stale_reason(self, existing: dict[str, Any]) -> str | None:
        """None means active; a returned value proves all V3 owners are gone."""
        self._validate_v3(existing)
        controller_tuple = self._lease_identity(existing)
        controller = {
            "pid": controller_tuple[0],
            "boot_id": controller_tuple[1],
            "process_start_time": controller_tuple[2],
        }
        controller_state = self._process_status(controller)
        if controller_state == "active":
            return None
        if controller_state == "unknown":
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Controller identity is unverifiable; failing closed")
        writer_state = self._writer_status(existing)
        if writer_state == "active":
            return None
        if writer_state == "unknown":
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer lifecycle is unverifiable; failing closed")
        if controller_tuple[1] != self.controller_identity["boot_id"]:
            return "controller boot-id mismatch"
        if controller_tuple[2] != self.controller_identity["process_start_time"]:
            return "controller process-start-time mismatch"
        return "controller and writer lifecycle inactive"

    def _archive_path(self) -> Path:
        stamp = f"{time.time_ns()}-{uuid.uuid4().hex[:8]}"
        return self.path.with_name(f"{self.path.stem}.stale-{stamp}{self.path.suffix}")

    def _archive_stale(self, raw: bytes) -> Path:
        """Copy a stale lease to a fresh archive without ever overwriting one."""
        for _ in range(self._ARCHIVE_ATTEMPTS):
            archive = self._archive_path()
            try:
                fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                fsync_directory(archive.parent)
                os.unlink(self.path)
                fsync_directory(archive.parent)
            except BaseException:
                # If the lease was already removed, retain its archive as
                # evidence; otherwise clean up the incomplete archive.
                if self.path.exists():
                    with contextlib.suppress(OSError):
                        archive.unlink()
                raise
            return archive
        raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Cannot archive stale lease without overwriting: {self.path}")

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._guard():
            for _ in range(self._RECOVERY_ATTEMPTS):
                try:
                    self._create_exclusive()
                except FileExistsError:
                    try:
                        existing, raw = self._read_lease()
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Unreadable lease: {self.path}") from exc
                    if self._stale_reason(existing) is None:
                        raise AgentFlowError(
                            "WRITE_LEASE_CONFLICT",
                            f"Active lease task={existing.get('task_id')} run={existing.get('run_id')} "
                            f"pid={existing.get('pid', existing.get('controller_pid'))}",
                        )
                    self._archive_stale(raw)
                    continue
                self.acquired = True
                return
        raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Could not acquire write lease: {self.path}")

    def prepare_writer(self) -> None:
        """Durably mark the short pre-registration window as unverifiable."""
        if not self.acquired:
            raise AgentFlowError("WRITE_LEASE_OWNERSHIP_LOST", str(self.path))
        with self._guard():
            existing = self._owned_existing_locked()
            updated = dict(existing)
            self._set_writer_payload(updated, self._writer_payload("starting"))
            self._persist_locked(updated)

    begin_writer = prepare_writer

    def register_writer(
        self,
        pid: int,
        process_start: int | None = None,
        boot_id: str | None = None,
        pgid: int | None = None,
        session_id: int | None = None,
        **aliases: Any,
    ) -> dict[str, Any]:
        """Persist an isolated worker identity before the pipe gate is opened."""
        if not self.acquired:
            raise AgentFlowError("WRITE_LEASE_OWNERSHIP_LOST", str(self.path))
        for alias_name in ("process_start_time", "start_time"):
            if alias_name in aliases:
                alias_value = aliases.pop(alias_name)
                if process_start is not None and process_start != alias_value:
                    raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer start time aliases disagree")
                process_start = alias_value
        if "sid" in aliases:
            alias_value = aliases.pop("sid")
            if session_id is not None and session_id != alias_value:
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer session aliases disagree")
            session_id = alias_value
        if aliases:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Unknown writer identity field")
        with self._guard():
            existing = self._owned_existing_locked()
            try:
                observed_boot_id = read_boot_id()
                observed_start_time = process_start_time(pid)
                observed_pgid, observed_session = process_group_identity(pid)
                identity = {
                    "pid": pid,
                    "boot_id": observed_boot_id,
                    "process_start_time": observed_start_time,
                    "pgid": observed_pgid,
                    "session_id": observed_session,
                }
                if boot_id is not None and (
                    not isinstance(boot_id, str) or boot_id.strip() != observed_boot_id
                ):
                    raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer boot id changed; failing closed")
                if process_start is not None and process_start != observed_start_time:
                    raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer start time changed; failing closed")
                if pgid is not None and pgid != observed_pgid:
                    raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer process group changed; failing closed")
                if session_id is not None and session_id != observed_session:
                    raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer session changed; failing closed")
                canonical = self._identity_from_mapping(identity, label="writer", require_group=True)
            except AgentFlowError:
                raise
            except OSError as exc:
                raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Cannot register writer identity: {exc}") from exc
            if canonical["pgid"] != canonical["pid"] or canonical["session_id"] != canonical["pid"]:
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer is not isolated in its own session; failing closed")
            updated = dict(existing)
            self._set_writer_payload(updated, self._writer_payload("running", canonical))
            self._persist_locked(updated)
            return canonical

    register_writer_identity = register_writer

    def mark_writer_quiescent(self) -> None:
        """Record completion while retaining identity for release verification."""
        if not self.acquired:
            raise AgentFlowError("WRITE_LEASE_OWNERSHIP_LOST", str(self.path))
        with self._guard():
            existing = self._owned_existing_locked()
            state, identity = self._writer_from_lease(existing)
            updated = dict(existing)
            if state in {"starting", "pending"} and identity is None:
                self._set_writer_payload(updated, self._writer_payload("not_started"))
            elif state == "not_started":
                self._set_writer_payload(updated, self._writer_payload("not_started"))
            else:
                lifecycle = self._writer_status(existing)
                next_state = "quiescent" if lifecycle == "inactive" else "exited"
                self._set_writer_payload(updated, self._writer_payload(next_state, identity))
            self._persist_locked(updated)

    writer_quiescent = mark_writer_quiescent

    def release(self) -> None:
        if not self.acquired:
            return
        with self._guard():
            try:
                existing = self._owned_existing_locked()
            except AgentFlowError:
                # A token or controller mismatch must never turn into an
                # unlink of a different owner's lease. Preserve the original
                # fail-closed ownership error for unreadable/replaced files.
                self.acquired = False
                raise
            lifecycle = self._writer_status(existing)
            if lifecycle == "active":
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Owned writer lifecycle is still active")
            if lifecycle == "unknown":
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Owned writer lifecycle is unverifiable")
            try:
                self.path.unlink()
                fsync_directory(self.path.parent)
            except FileNotFoundError:
                self.acquired = False
                raise AgentFlowError("WRITE_LEASE_OWNERSHIP_LOST", str(self.path))
            except OSError as exc:
                raise AgentFlowError("WRITE_LEASE_CONFLICT", f"Cannot release write lease: {exc}") from exc
            self.acquired = False

    def __enter__(self) -> "WriteLease":
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


def validate_task(task: dict[str, Any]) -> dict[str, Any]:
    required = {"task_id", "repo", "risk", "objective", "allowed_paths", "validators"}
    missing = sorted(required - task.keys())
    if missing:
        raise AgentFlowError("INVALID_TASK", f"Missing fields: {missing}")
    if task["risk"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise AgentFlowError("INVALID_TASK", "risk must be LOW/MEDIUM/HIGH/CRITICAL")
    task["allowed_paths"] = normalize_allowed(task["allowed_paths"])
    task.setdefault("invariants", [])
    task.setdefault("forbidden_actions", FORBIDDEN_ACTIONS)
    task.setdefault("expected_baseline", {})
    task.setdefault("max_corrections", 2)
    if not 0 <= int(task["max_corrections"]) <= 2:
        raise AgentFlowError("INVALID_TASK", "max_corrections must be between 0 and 2")
    if not isinstance(task["validators"], list) or not task["validators"]:
        raise AgentFlowError("INVALID_TASK", "validators must be a non-empty list")
    # Optional model output-inactivity limit: absent disables detection;
    # present values must be a positive integer strictly below the effective
    # model timeout. Raises INVALID_TASK on any violation.
    _model_inactivity_threshold(task)
    isolation = task.get("isolation")
    if isolation is not None:
        if not isinstance(isolation, dict):
            raise AgentFlowError("INVALID_TASK", "isolation must be an object")
        enabled = isolation.get("enabled")
        if not isinstance(enabled, bool):
            raise AgentFlowError("INVALID_TASK", "isolation.enabled must be a boolean")
        baseline = isolation.get("baseline_commit")
        if not isinstance(baseline, str) or not baseline.strip():
            raise AgentFlowError("INVALID_TASK", "isolation.baseline_commit must be a non-empty string")
        if enabled:
            _canonical_sha(baseline)
    return task


def validate_program(program: dict[str, Any]) -> dict[str, Any]:
    required = {"program_id", "task", "roles", "max_corrections"}
    missing = sorted(required - program.keys())
    if missing:
        raise AgentFlowError("INVALID_PROGRAM", f"Missing fields: {missing}")
    if not isinstance(program["program_id"], str) or not program["program_id"].strip():
        raise AgentFlowError("INVALID_PROGRAM", "program_id must be a non-empty string")
    program["program_id"] = safe_slug(program["program_id"])
    if not isinstance(program["task"], str) or not program["task"].strip():
        raise AgentFlowError("INVALID_PROGRAM", "task must be a non-empty string path")
    roles = program["roles"]
    if not isinstance(roles, dict):
        raise AgentFlowError("INVALID_PROGRAM", "roles must be an object")
    for required_role in ("architect", "worker", "reviewer"):
        if required_role not in roles:
            raise AgentFlowError("INVALID_PROGRAM", f"roles.{required_role} is required")
        if not isinstance(roles[required_role], str) or not roles[required_role].strip():
            raise AgentFlowError("INVALID_PROGRAM", f"roles.{required_role} must be a non-empty string")
    max_corrections = program["max_corrections"]
    # bool is an int subclass; only a real integer 0/1 is acceptable here.
    if type(max_corrections) is not int or max_corrections not in (0, 1):
        raise AgentFlowError("INVALID_PROGRAM", "max_corrections must be 0 or 1")
    # PROGRAM-001B opt-in sequential subtasks: absence preserves 001A behavior.
    if "max_subtasks" in program:
        max_subtasks = program["max_subtasks"]
        # Exact integer; bool is rejected via type identity check.
        if type(max_subtasks) is not int:
            raise AgentFlowError("INVALID_PROGRAM", "max_subtasks must be an integer 1..4")
        if not 1 <= max_subtasks <= PROGRAM_BMODE_HARD_MAX:
            raise AgentFlowError("INVALID_PROGRAM", "max_subtasks must be an integer 1..4")
    return program


def safe_validator_argv(command: str | list[str]) -> list[str]:
    if isinstance(command, list):
        argv = [str(item) for item in command]
    else:
        if any(token in command for token in (";", "&&", "||", "|", ">", "<", "`", "$(", "\n")):
            raise AgentFlowError("UNSAFE_VALIDATOR", command)
        argv = shlex.split(command)
    if not argv:
        raise AgentFlowError("UNSAFE_VALIDATOR", "empty command")
    exe = Path(argv[0]).name
    if exe in {"sh", "bash", "zsh", "fish", "env", "docker"}:
        raise AgentFlowError("UNSAFE_VALIDATOR", exe)
    if exe.startswith("python") and "-c" in argv:
        raise AgentFlowError("UNSAFE_VALIDATOR", "python -c")
    if exe == "git" and len(argv) > 1 and argv[1] in FORBIDDEN_GIT:
        raise AgentFlowError("HUMAN_GATE", " ".join(argv[:2]))
    if exe == "alembic" and len(argv) > 1 and argv[1] in {"upgrade", "downgrade"}:
        raise AgentFlowError("HUMAN_GATE", " ".join(argv[:2]))
    if exe in {"psql", "mysql", "redis-cli", "curl", "wget", "ssh", "scp"}:
        raise AgentFlowError("UNSAFE_VALIDATOR", exe)
    return argv


def run_validators(repo: Path, validators: list[Any], run_dir: Path, cycle: int) -> list[dict[str, Any]]:
    results = []
    for index, item in enumerate(validators, start=1):
        if isinstance(item, str):
            name, command, timeout = f"validator-{index}", item, 1800
        else:
            name = item.get("name", f"validator-{index}")
            command = item.get("command", [])
            timeout = int(item.get("timeout_seconds", 1800))
        argv = safe_validator_argv(command)
        started = utc_now()
        try:
            control = _ACTIVE_EXECUTION_CONTROL.get()
            if control is None:
                proc = run_process(argv, cwd=repo, timeout=timeout)
            else:
                proc = _run_queue_process(
                    argv, cwd=repo, local_timeout=timeout, control=control
                )
            result = {
                "name": name,
                "command": shlex.join(argv),
                "started_at": started,
                "finished_at": utc_now(),
                "exit_code": proc.returncode,
                "status": "PASS" if proc.returncode == 0 else "FAIL",
                "stdout": summarized(proc.stdout),
                "stderr": summarized(proc.stderr),
            }
        except subprocess.TimeoutExpired as exc:
            result = {
                "name": name,
                "command": shlex.join(argv),
                "started_at": started,
                "finished_at": utc_now(),
                "exit_code": None,
                "status": "TIMEOUT",
                "stdout": summarized(exc.stdout or ""),
                "stderr": summarized(exc.stderr or ""),
            }
        results.append(result)
        atomic_json(run_dir / f"validators-cycle-{cycle}.json", results)
        if result["status"] != "PASS":
            break
    return results


def load_models() -> dict[str, Any]:
    return read_json(MODELS_FILE)


def model_family(profile: dict[str, Any]) -> str:
    name = profile["model"].split("/", 1)[-1]
    return name.split("-", 1)[0].lower()


# F-05: centralized role-policy source of truth. Permission class is derived
# from the logical role, never from profile identity. Semantic eligibility
# (eligible_roles) and permission containment (OpenCode agent / Codex sandbox)
# are distinct concepts checked together in _check_role_eligible.
ROLE_PERMISSION_CLASS = {
    "worker": "write",
    "reviewer": "read_only",
    "architect": "read_only",
    "adjudicator": "read_only",
}
_READ_ONLY_OPENCODE_AGENTS = frozenset({"agentflow-reviewer", "agentflow-architect"})
_WRITE_OPENCODE_AGENTS = frozenset({"agentflow-worker"})


def _role_permission_class(role: str) -> str:
    try:
        return ROLE_PERMISSION_CLASS[role]
    except KeyError:
        raise AgentFlowError("ROLE_NOT_ELIGIBLE", f"unknown role {role!r}") from None


def _logical_role(role: str) -> str:
    """Map queue fallback labels ("fallback worker") to the logical role."""
    if isinstance(role, str) and role.startswith("fallback "):
        return role.split(" ", 1)[1]
    return role


def _check_role_eligible(profile: dict[str, Any], role: str) -> None:
    """Fail closed unless profile may fill logical role.

    Two independent checks, both centralized here:
      * semantic eligibility: a declared ``eligible_roles`` set must contain
        the requested role. Missing or malformed ``eligible_roles`` fails
        closed with ROLE_NOT_ELIGIBLE; there is no undeclared-profile
        exception.
      * permission containment: an OpenCode profile must carry an explicitly
        approved agent of the permission class the role requires. Write roles
        require a write-capable AgentFlow agent and read-only roles require a
        read-only AgentFlow agent; arbitrary/custom agent strings are rejected
        even when they differ from known write agents. Codex containment stays
        role-derived through the sandbox.
    """
    perm = _role_permission_class(role)
    if not isinstance(profile, dict):
        raise AgentFlowError("ROLE_NOT_ELIGIBLE", f"{role} profile is not an object")
    eligible = profile.get("eligible_roles")
    if eligible is None:
        raise AgentFlowError(
            "ROLE_NOT_ELIGIBLE",
            f"profile model {profile.get('model')!r} has no eligible_roles",
        )
    if not isinstance(eligible, (list, tuple, set, frozenset)):
        raise AgentFlowError(
            "ROLE_NOT_ELIGIBLE",
            f"profile model {profile.get('model')!r} has malformed eligible_roles",
        )
    if role not in eligible:
        raise AgentFlowError(
            "ROLE_NOT_ELIGIBLE",
            f"profile model {profile.get('model')!r} is not eligible for role {role!r}",
        )
    if profile.get("backend") == "opencode":
        agent = profile.get("agent")
        agent_missing = agent is None or (
            isinstance(agent, str) and not agent.strip()
        )
        if perm == "read_only":
            if agent_missing or not isinstance(agent, str):
                raise AgentFlowError(
                    "ROLE_NOT_ELIGIBLE",
                    f"read-only role {role!r} requires a read-only OpenCode agent",
                )
            if agent not in _READ_ONLY_OPENCODE_AGENTS:
                raise AgentFlowError(
                    "ROLE_NOT_ELIGIBLE",
                    f"agent {agent!r} cannot fill read-only role {role!r}",
                )
        else:
            if agent_missing or not isinstance(agent, str):
                raise AgentFlowError(
                    "ROLE_NOT_ELIGIBLE",
                    f"worker role {role!r} requires a write-capable OpenCode agent",
                )
            if agent not in _WRITE_OPENCODE_AGENTS:
                raise AgentFlowError(
                    "ROLE_NOT_ELIGIBLE",
                    f"agent {agent!r} cannot fill worker role {role!r}",
                )


def _check_adjudicator_independence(
    worker_profile: dict[str, Any],
    reviewer_profile: dict[str, Any],
    adjudicator_profile: dict[str, Any],
) -> None:
    """Enforce adjudicator independence from worker and reviewer by family.

    Unconditional whenever the adjudicator path is used; never gated on
    ``eligible_roles`` declaration.
    """
    if model_family(worker_profile) == model_family(adjudicator_profile):
        raise AgentFlowError(
            "ADJUDICATOR_NOT_INDEPENDENT",
            model_family(worker_profile),
        )
    if model_family(reviewer_profile) == model_family(adjudicator_profile):
        raise AgentFlowError(
            "ADJUDICATOR_NOT_INDEPENDENT",
            model_family(reviewer_profile),
        )


def choose_profile(task: dict[str, Any], role: str, models: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    profiles = models["profiles"]
    if role == "reviewer":
        choices = [task.get("preferred_reviewer"), "independent_reviewer"]
    elif task.get("preferred_worker"):
        choices = [task["preferred_worker"]]
    else:
        choices = models["routing"][task["risk"]]
    seen_ineligible = False
    for name in choices:
        if not name or name not in profiles:
            continue
        profile = profiles[name]
        if profile.get("available") and shutil.which(profile["command"]):
            try:
                _check_role_eligible(profile, role)
            except AgentFlowError as exc:
                if exc.code == "ROLE_NOT_ELIGIBLE":
                    seen_ineligible = True
                    continue
                raise
            return name, profile
    if seen_ineligible:
        raise AgentFlowError("ROLE_NOT_ELIGIBLE", f"No role-eligible {role} profile in {choices}")
    raise AgentFlowError("MODEL_UNAVAILABLE", f"No available {role} profile in {choices}")


def redact_config(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("<redacted>" if SECRET_KEY_RE.search(key) else redact_config(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_config(item) for item in value]
    return value


def result_valid(result: Any) -> tuple[bool, str]:
    required = {
        "task_id", "role", "harness", "provider", "model", "variant",
        "files_changed", "validators", "findings", "open_risks", "verdict",
    }
    if not isinstance(result, dict):
        return False, "result is not an object"
    missing = required - result.keys()
    if missing:
        return False, f"missing fields: {sorted(missing)}"
    if result["role"] not in {"worker", "reviewer", "architect", "adjudicator"}:
        return False, f"invalid role: {result['role']}"
    if not isinstance(result["files_changed"], list) or not isinstance(result["findings"], list):
        return False, "files_changed/findings must be arrays"
    if not isinstance(result["open_risks"], list) or not isinstance(result["verdict"], str):
        return False, "open_risks must be array and verdict must be string"
    if result["role"] == "architect":
        if "architect_plan" not in result:
            return False, "architect role requires architect_plan"
        if result["files_changed"]:
            return False, "architect files_changed must be empty"
    if result["role"] == "adjudicator":
        if "adjudication" not in result:
            return False, "adjudicator role requires adjudication"
        if result["files_changed"]:
            return False, "adjudicator files_changed must be empty"
    if result["role"] == "reviewer" and normalize_reviewer_verdict(result["verdict"]) is None:
        return False, "reviewer verdict must be a non-empty string"
    return True, ""


# Canonical role-aware reviewer contract.  The result schema stays
# deliberately permissive (principle E); reviewer vocabulary is enforced
# here in code, not as a global enum.
_REVIEWER_VERDICTS = {"PASS", "BLOCKER"}
_REVIEWER_SEVERITIES = {"BLOCKER", "HIGH", "MEDIUM", "LOW"}
_REVIEWER_BLOCKING_SEVERITIES = {"HIGH", "BLOCKER"}


def normalize_reviewer_verdict(value: Any) -> str | None:
    """Return the canonical reviewer verdict or None when unusable."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized or None


def normalize_finding_severity(value: Any) -> str | None:
    """Return the canonical finding severity or None when unusable."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized or None


def validate_reviewer_result(result: dict[str, Any]) -> None:
    """Fail closed on reviewer results violating the canonical contract.

    Contract: verdict is PASS or BLOCKER (normalized); every finding is a
    structured object with a contractual severity (BLOCKER/HIGH/MEDIUM/LOW);
    PASS together with a HIGH/BLOCKER finding is a contradiction.  Unknown
    verdicts, string findings, missing/invalid severities and contradictions
    raise INVALID_MODEL_OUTPUT; they never pass silently.
    """
    if not isinstance(result, dict):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "reviewer result must be an object")
    if result.get("role") != "reviewer":
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT",
            f"reviewer result role must be 'reviewer', got {result.get('role')!r}",
        )
    verdict = normalize_reviewer_verdict(result.get("verdict"))
    if verdict is None:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT", "reviewer verdict must be a non-empty string"
        )
    if verdict not in _REVIEWER_VERDICTS:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT", f"unknown reviewer verdict: {result.get('verdict')!r}"
        )
    findings = result.get("findings")
    if not isinstance(findings, list):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "reviewer findings must be an array")
    blocking = False
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT",
                f"reviewer finding {index} must be a structured object with severity",
            )
        severity = normalize_finding_severity(finding.get("severity"))
        if severity is None:
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT",
                f"reviewer finding {index} severity must be a non-empty string",
            )
        if severity not in _REVIEWER_SEVERITIES:
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT",
                f"unknown reviewer finding severity: {finding.get('severity')!r}",
            )
        if severity in _REVIEWER_BLOCKING_SEVERITIES:
            blocking = True
    if verdict == "PASS" and blocking:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT",
            "reviewer verdict PASS contradicts a blocking (HIGH/BLOCKER) finding",
        )


def json_candidates(text: str) -> Iterator[dict[str, Any]]:
    decoder = json.JSONDecoder()
    for offset, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[offset:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            yield value


def collect_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in {"text", "content", "output", "message", "result"}:
                yield from collect_strings(item)
            elif isinstance(item, (dict, list)):
                yield from collect_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from collect_strings(item)


def parse_model_result(raw: str) -> dict[str, Any]:
    texts = [raw]
    for line in raw.splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            texts.extend(collect_strings(json.loads(line)))
    candidates = []
    for text in texts:
        candidates.extend(json_candidates(text))
    for candidate in reversed(candidates):
        if "verdict" in candidate and ("findings" in candidate or "files_changed" in candidate):
            return candidate
    raise AgentFlowError("INVALID_MODEL_OUTPUT", "No structured result object found")


def render_prompt(
    role: str,
    task: dict[str, Any],
    invocation: dict[str, Any],
    context: dict[str, Any] | None,
) -> str:
    template = (ROOT / "prompts" / f"{role}.md").read_text(encoding="utf-8")
    packet = {
        key: task[key]
        for key in (
            "task_id", "repo", "risk", "objective", "allowed_paths",
            "forbidden_actions", "invariants",
        )
    }
    identity = {
        "harness": invocation["harness"],
        "provider": invocation["provider"],
        "model": invocation["model"],
        "variant": invocation.get("variant"),
        "role": role,
    }
    return (
        template
        + "\n\nTASK_PACKET\n"
        + json.dumps(packet, indent=2, ensure_ascii=False)
        + "\n\nINVOCATION_IDENTITY (the coordinator will overwrite these fields)\n"
        + json.dumps(identity, indent=2)
        + ("\n\nCOORDINATOR_CONTEXT\n" + json.dumps(context, indent=2, ensure_ascii=False) if context else "")
        + "\n\nReturn exactly one JSON object matching result.schema.json. No Markdown fences."
    )


def invocation_record(
    role: str,
    profile_name: str,
    profile: dict[str, Any],
    cycle: int,
) -> dict[str, Any]:
    return {
        "profile": profile_name,
        "role": role,
        "harness": profile["backend"],
        "provider": profile["provider"],
        "model": profile["model"],
        "variant": profile.get("variant"),
        "agent": profile.get("agent"),
        "cycle": cycle,
        "invoked_at": utc_now(),
    }


_STRUCTURAL_RETRY_ROLES = frozenset({"architect", "reviewer", "adjudicator"})


def _validate_model_output_contract(
    role: str,
    result: dict[str, Any],
    task: dict[str, Any],
    context: dict[str, Any] | None,
) -> None:
    """Validate the role contract before the pipeline advances to another phase."""
    if role == "reviewer":
        validate_reviewer_result(result)
    elif role == "architect":
        plan = _validate_architect_plan(result)
        if any(
            not path_allowed(path, task["allowed_paths"])
            for path in plan["allowed_scope"]
        ):
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT",
                "architect_plan.allowed_scope exceeds task.allowed_paths",
            )
        if isinstance(context, dict) and context.get("bmode_active") is True:
            _validate_bmode_architect_plan(
                result, context["max_subtasks"], task["allowed_paths"]
            )
    elif role == "adjudicator":
        findings = context.get("initial_review_findings", []) if isinstance(context, dict) else []
        _validate_adjudication(result, [finding["ref"] for finding in findings])


def _structural_retry_context(
    context: dict[str, Any] | None, error: str
) -> dict[str, Any]:
    """Build stable, error-specific feedback for the single structural retry."""
    retry_context = dict(context) if isinstance(context, dict) else {}
    retry_context["structural_retry_feedback"] = {
        "code": "INVALID_MODEL_OUTPUT",
        "error": error,
        "instruction": (
            "The previous response violated the required structural contract. "
            "Correct the response so it satisfies the exact error above. Return "
            "one JSON object matching the required result schema, with no prose "
            "or Markdown."
        ),
    }
    return retry_context


def _persist_invalid_model_output(
    evidence_dir: Path,
    *,
    prefix: str,
    role: str,
    profile_name: str,
    cycle: int,
    error: str,
    result: dict[str, Any] | None = None,
    raw_output: str | None = None,
    raw_output_file: str | None = None,
) -> Path:
    """Keep the rejected response and its exact contract error as evidence."""
    path = evidence_dir / f"{prefix}-invalid-output.json"
    evidence: dict[str, Any] = {}
    if path.is_file():
        with contextlib.suppress(OSError, UnicodeDecodeError, json.JSONDecodeError):
            prior = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(prior, dict):
                evidence.update(prior)
    evidence.update({
        "code": "INVALID_MODEL_OUTPUT",
        "error": error,
        "role": role,
        "profile": profile_name,
        "cycle": cycle,
        "recorded_at": utc_now(),
    })
    evidence.setdefault(
        "raw_output_file",
        raw_output_file or (
            f"{prefix}-last-message.json"
            if (evidence_dir / f"{prefix}-last-message.json").is_file()
            else f"{prefix}-output.jsonl"
        ),
    )
    if raw_output_file is not None:
        evidence["raw_output_file"] = raw_output_file
    if result is not None:
        evidence["invalid_result"] = result
    if raw_output is not None:
        evidence["raw_output"] = raw_output
    atomic_json_fsync(path, evidence)
    return path


WRITER_WRAPPER_MODE = "_writer_wrapper"
WRITER_GO = b"GO\n"


def writer_wrapper(command: list[str]) -> int:
    """Wait for the controller's pipe gate, then replace this process.

    EOF (the normal result of controller death) and every gate other than the
    exact protocol line terminate before the worker command is ever exec'ed.
    """
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        return 125
    try:
        gate = sys.stdin.buffer.readline()
    except (AttributeError, OSError):
        return 125
    if gate != WRITER_GO:
        return 125
    try:
        os.execvpe(command[0], command, os.environ.copy())
    except OSError as exc:
        sys.stderr.write(f"writer exec failed: {exc}\n")
        return 127
    return 127  # pragma: no cover - os.execvpe either replaces or raises


def _decode_process_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _close_process_stdin(proc: subprocess.Popen[Any]) -> None:
    if proc.stdin is not None:
        with contextlib.suppress(OSError, ValueError):
            proc.stdin.close()


# --- Generic controller-thread abort seam ---
#
# The supervisor below understands one small optional hook:
#
#     abort_check(now: float) -> AbortRequest | None
#
# ``now`` is the controller's current ``time.monotonic()`` sample. A return of
# None means "continue supervising"; a valid AbortRequest asks the supervisor
# to re-poll the leader, snapshot partial output, invoke the existing
# termination callback, perform bounded reader cleanup, and raise
# AbortedProcessError. The supervisor owns no output policy: it never decides
# which quiet period is too long and never computes activity limits itself.


class AbortRequest:
    """Generic request asking the supervisor to end a live supervised process.

    Carries an opaque failure ``code``, a human-readable ``message``, and a
    ``details`` mapping with structured context. The supervisor validates the
    shape and otherwise treats the code as opaque data.
    """

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        self.code = code
        self.message = message
        self.details = dict(details) if details is not None else {}


class AbortedProcessError(AgentFlowError):
    """Structured generic failure for a supervisor-executed abort request.

    Carries the originating ``request`` plus the raw partial stdout/stderr
    bytes snapshotted before termination. The error code is the request code,
    so existing failure handling maps it without any new branches.
    """

    def __init__(
        self,
        request: AbortRequest,
        partial_stdout: bytes,
        partial_stderr: bytes,
        return_code: int | None = None,
    ):
        super().__init__(request.code, request.message)
        self.request = request
        self.partial_stdout = partial_stdout
        self.partial_stderr = partial_stderr
        self.return_code = return_code


def _valid_abort_request(value: Any) -> bool:
    """True only for a well-shaped AbortRequest the supervisor may execute."""
    return (
        isinstance(value, AbortRequest)
        and isinstance(value.code, str)
        and bool(value.code.strip())
        and isinstance(value.message, str)
        and isinstance(value.details, dict)
    )


# --- OPT-001: policy-neutral model-process supervision seam ---
#
# One shared supervisor drains binary stdout/stderr concurrently, reports raw
# byte activity, and enforces a monotonic absolute deadline. It owns no
# WriteLease state, no GO gate, no provider routing, and no execution policy
# beyond draining, activity reporting, and deadline enforcement.

_MODEL_PIPE_CHUNK_SIZE = 65536
_MODEL_SUPERVISOR_POLL_INTERVAL = 0.02
_MODEL_READER_JOIN_TIMEOUT = 5.0
_MODEL_SIGNAL_WAIT_TIMEOUT = 5.0


def _supervise_model_process(
    proc: subprocess.Popen[bytes],
    *,
    result_args: list[str],
    timeout: float,
    terminate: Callable[[subprocess.Popen[bytes]], None],
    decode_output: Callable[[bytes], str],
    on_activity: Callable[[str, int], None] | None = None,
    abort_check: Callable[[float], AbortRequest | None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Supervise one binary-piped model process under an absolute deadline.

    The deadline (``time.monotonic() + timeout``) is computed on supervisor
    entry, so worker registration/GO setup performed before entry never
    consumes execution budget, and timeout activity never extends it.

    SUCCESS requires all three: the process leader exited, stdout reached EOF,
    and stderr reached EOF. A TIMEOUT raises ``subprocess.TimeoutExpired``
    with ``cmd=proc.args`` and raw-byte (or None) partial output. Reader I/O
    failures, unprovable termination, and unstoppable readers fail closed
    with ``AgentFlowError("INTERNAL_ERROR", ...)`` instead of success.
    ``KeyboardInterrupt``/``SystemExit`` in the controller always propagate.

    The optional ``abort_check`` hook runs only on the controller thread, once
    per iteration, after the absolute-deadline check and only while the leader
    is still alive. It receives the current ``time.monotonic()`` sample and
    returns None (continue) or a valid AbortRequest. A valid request re-polls
    the leader first -- an exited leader is never classified as aborted --
    then snapshots partial output, invokes ``terminate``, performs the same
    bounded reader cleanup as the timeout path, and raises
    AbortedProcessError carrying the request and both partial byte streams.
    An absolute deadline reached in the same iteration always wins over a hook
    request. An invalid hook return or an ordinary hook exception triggers
    controlled cleanup and INTERNAL_ERROR; termination problems stay
    authoritative and are never masked by a requested abort.
    """
    deadline = time.monotonic() + timeout
    if proc.stdout is None or proc.stderr is None:
        raise AgentFlowError("INTERNAL_ERROR", "Model process has no captured pipes")
    stdout_pipe = proc.stdout
    stderr_pipe = proc.stderr
    lock = threading.Lock()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    reader_state: dict[str, Any] = {
        "stdout_eof": False,
        "stderr_eof": False,
        "stdout_error": None,
        "stderr_error": None,
    }

    def _drain_pipe(
        stream: str,
        pipe: Any,
        chunks: list[bytes],
        eof_key: str,
        error_key: str,
    ) -> None:
        try:
            while True:
                try:
                    chunk = pipe.read1(_MODEL_PIPE_CHUNK_SIZE)
                except BaseException as exc:
                    # Reader I/O failure: report it so the controller fails
                    # closed instead of returning partial success.
                    with lock:
                        if reader_state[error_key] is None:
                            reader_state[error_key] = exc
                    return
                if chunk == b"":
                    with lock:
                        reader_state[eof_key] = True
                    return
                if not chunk:
                    continue
                # Instrumentation must never kill drainage: the chunk is
                # appended first, and only the observer call is guarded.
                with lock:
                    chunks.append(chunk)
                if on_activity is not None:
                    try:
                        on_activity(stream, len(chunk))
                    except BaseException:
                        pass
        finally:
            with contextlib.suppress(Exception):
                pipe.close()

    stdout_reader = threading.Thread(
        target=_drain_pipe,
        args=("stdout", stdout_pipe, stdout_chunks, "stdout_eof", "stdout_error"),
        name="agentflow-model-stdout",
        daemon=True,
    )
    stderr_reader = threading.Thread(
        target=_drain_pipe,
        args=("stderr", stderr_pipe, stderr_chunks, "stderr_eof", "stderr_error"),
        name="agentflow-model-stderr",
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()

    def _snapshot() -> tuple[bytes, bytes]:
        with lock:
            return b"".join(stdout_chunks), b"".join(stderr_chunks)

    def _join_readers(bound: float) -> None:
        stdout_reader.join(timeout=bound)
        stderr_reader.join(timeout=bound)

    def _close_pipes_if_readers_done() -> None:
        # Bounded cleanup: the controller must never call
        # BufferedReader.close() while a reader may be blocked in read1().
        # That blocks indefinitely on the reader lock when an escaped or
        # out-of-scope descendant holds the pipe write end open (verified
        # with a synthetic sleeper: close() did not return within 3s).
        # os.close(pipe.fileno()) is non-blocking but does not wake the
        # blocked read1 (verified: reader stayed alive) and lets the later
        # reader finally close() an unrelated reused fd (verified EBADF
        # corruption), so it is not used. Closing only after both readers
        # are dead is lock-free and safe; live readers self-close on EOF
        # or error, and failure paths already fail closed without success.
        if stdout_reader.is_alive() or stderr_reader.is_alive():
            return
        with contextlib.suppress(Exception):
            stdout_pipe.close()
        with contextlib.suppress(Exception):
            stderr_pipe.close()

    def _cleanup_best_effort() -> None:
        with contextlib.suppress(BaseException):
            terminate(proc)
        with contextlib.suppress(BaseException):
            _join_readers(_MODEL_READER_JOIN_TIMEOUT)
        _close_pipes_if_readers_done()

    try:
        while True:
            with lock:
                stdout_eof = reader_state["stdout_eof"]
                stderr_eof = reader_state["stderr_eof"]
                reader_error = (
                    reader_state["stdout_error"] or reader_state["stderr_error"]
                )
            if reader_error is not None:
                _cleanup_best_effort()
                cause = (
                    reader_error if isinstance(reader_error, BaseException) else None
                )
                raise AgentFlowError(
                    "INTERNAL_ERROR",
                    f"Model pipe reader failed; failing closed: {reader_error!r}",
                ) from cause
            leader_done = proc.poll() is not None
            if leader_done and stdout_eof and stderr_eof:
                break
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                partial_out, partial_err = _snapshot()
                try:
                    terminate(proc)
                finally:
                    with contextlib.suppress(BaseException):
                        _join_readers(_MODEL_READER_JOIN_TIMEOUT)
                    _close_pipes_if_readers_done()
                raise subprocess.TimeoutExpired(
                    proc.args,
                    timeout,
                    output=partial_out if partial_out else None,
                    stderr=partial_err if partial_err else None,
                )
            if abort_check is not None and not leader_done:
                try:
                    request = abort_check(now)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException as exc:
                    _cleanup_best_effort()
                    raise AgentFlowError(
                        "INTERNAL_ERROR",
                        f"Model abort hook failed; failing closed: {exc!r}",
                    ) from exc
                if request is not None:
                    if not _valid_abort_request(request):
                        _cleanup_best_effort()
                        raise AgentFlowError(
                            "INTERNAL_ERROR",
                            "Model abort hook returned an invalid request; failing closed",
                        )
                    if proc.poll() is not None:
                        # The leader exited between the hook decision and this
                        # re-poll: a dead leader is never classified as an
                        # abort, so re-enter the loop and let the normal
                        # leader-exit/EOF/timeout handling decide.
                        continue
                    partial_out, partial_err = _snapshot()
                    try:
                        terminate(proc)
                    except AgentFlowError:
                        with contextlib.suppress(BaseException):
                            _join_readers(_MODEL_READER_JOIN_TIMEOUT)
                        _close_pipes_if_readers_done()
                        raise
                    except (KeyboardInterrupt, SystemExit):
                        with contextlib.suppress(BaseException):
                            _join_readers(_MODEL_READER_JOIN_TIMEOUT)
                        _close_pipes_if_readers_done()
                        raise
                    except BaseException as exc:
                        with contextlib.suppress(BaseException):
                            _join_readers(_MODEL_READER_JOIN_TIMEOUT)
                        _close_pipes_if_readers_done()
                        raise AgentFlowError(
                            "INTERNAL_ERROR",
                            "Model process group termination failed; "
                            f"failing closed: {exc!r}",
                        ) from exc
                    with contextlib.suppress(BaseException):
                        _join_readers(_MODEL_READER_JOIN_TIMEOUT)
                    _close_pipes_if_readers_done()
                    with contextlib.suppress(Exception):
                        ended_code = proc.poll()
                    raise AbortedProcessError(
                        request, partial_out, partial_err, ended_code
                    )
            try:
                proc.wait(
                    timeout=min(remaining, _MODEL_SUPERVISOR_POLL_INTERVAL)
                )
            except subprocess.TimeoutExpired:
                pass
    except (KeyboardInterrupt, SystemExit):
        # Controller cancellation always propagates; attempt bounded cleanup
        # first so no controlled group or reader is abandoned silently.
        _cleanup_best_effort()
        raise
    _join_readers(_MODEL_READER_JOIN_TIMEOUT)
    if stdout_reader.is_alive() or stderr_reader.is_alive():
        # A bounded join must never turn missing EOF into success.
        _cleanup_best_effort()
        raise AgentFlowError(
            "INTERNAL_ERROR", "Model pipe readers did not stop; failing closed"
        )
    with lock:
        if reader_state["stdout_error"] is not None or reader_state["stderr_error"] is not None:
            raise AgentFlowError(
                "INTERNAL_ERROR", "Model pipe reader failed; failing closed"
            )
        raw_stdout = b"".join(stdout_chunks)
        raw_stderr = b"".join(stderr_chunks)
    return subprocess.CompletedProcess(
        result_args,
        proc.returncode,
        decode_output(raw_stdout),
        decode_output(raw_stderr),
    )


class _ModelInactivityPolicy:
    """Track output quiet time for one supervised model process.

    Armed immediately before supervisor entry: creation is the initial
    activity instant, so earlier setup (registration, GO gate) never consumes
    budget. ``note_activity`` refreshes on any positive raw-byte chunk from
    either pipe and runs on reader threads; ``abort_check`` runs only on the
    controller thread. Both use ``time.monotonic()``. One small lock makes the
    commit/check boundary deterministic. No extra thread, no event loop.
    """

    def __init__(self, threshold_seconds: float) -> None:
        self._threshold = float(threshold_seconds)
        self._lock = threading.Lock()
        self._last_activity = time.monotonic()

    @property
    def threshold_seconds(self) -> float:
        return self._threshold

    def note_activity(self, stream: str, nbytes: int) -> None:
        _ = stream
        if nbytes > 0:
            with self._lock:
                self._last_activity = time.monotonic()

    def abort_check(self, now: float) -> AbortRequest | None:
        with self._lock:
            last = self._last_activity
        quiet = now - last
        if quiet < self._threshold:
            return None
        return AbortRequest(
            code="STALL_DETECTED",
            message=(
                "Model inactivity limit reached: no stdout/stderr output for "
                f"{quiet:.2f}s (limit {self._threshold:.2f}s)"
            ),
            details={
                "threshold_seconds": self._threshold,
                "inactive_seconds": quiet,
            },
        )


def _with_inactivity_accounting(
    policy: _ModelInactivityPolicy | None,
    user_observer: Callable[[str, int], None] | None,
) -> Callable[[str, int], None] | None:
    """Order policy accounting strictly before the user observer.

    The policy sees every raw-byte chunk first, so a failing user observer
    can never defeat activity accounting or pipe drainage.
    """
    if policy is None:
        return user_observer
    if user_observer is None:
        return policy.note_activity

    def _combined(stream: str, nbytes: int) -> None:
        policy.note_activity(stream, nbytes)
        try:
            user_observer(stream, nbytes)
        except BaseException:
            pass

    return _combined


def _combined_model_abort_check(
    policy: _ModelInactivityPolicy | None,
    queue_check: Callable[[float], AbortRequest | None] | None,
) -> Callable[[float], AbortRequest | None] | None:
    """Preserve native timeout > inactivity > queue budget precedence."""
    if policy is None:
        return queue_check
    if queue_check is None:
        return policy.abort_check

    def check(now: float) -> AbortRequest | None:
        inactivity = policy.abort_check(now)
        return inactivity if inactivity is not None else queue_check(now)

    return check


def _model_inactivity_threshold(task: dict[str, Any]) -> int | None:
    """Return the configured model inactivity limit, or None when absent.

    Absent configuration disables detection and preserves existing behavior
    exactly. A present value must be a genuine integer (booleans rejected)
    above zero and strictly below the effective model timeout.
    """
    if "model_inactivity_timeout_seconds" not in task:
        return None
    value = task["model_inactivity_timeout_seconds"]
    if type(value) is not int or value <= 0:
        raise AgentFlowError(
            "INVALID_TASK",
            "model_inactivity_timeout_seconds must be a positive integer",
        )
    try:
        effective = int(task.get("model_timeout_seconds", 3600))
    except (TypeError, ValueError) as exc:
        raise AgentFlowError(
            "INVALID_TASK",
            "model_timeout_seconds must be an integer "
            "when model_inactivity_timeout_seconds is set",
        ) from exc
    if value >= effective:
        raise AgentFlowError(
            "INVALID_TASK",
            "model_inactivity_timeout_seconds must be strictly less than "
            "the effective model_timeout_seconds",
        )
    return value


def _persist_model_failure_evidence(
    run_dir: Path,
    prefix: str,
    *,
    failure_code: str,
    absolute_timeout_seconds: int,
    inactivity_threshold_seconds: int | None,
    inactive_seconds: float | None,
    stdout_bytes: bytes,
    stderr_bytes: bytes,
    return_code: int | None,
) -> None:
    """Persist failure evidence next to the existing invocation artifacts.

    Partial output uses lossy decoding so invalid model bytes cannot erase
    the incident record; normal success-path decoding is untouched. No
    monotonic clock samples are persisted, only durations and byte counts.
    Best-effort: persistence trouble never masks the original failure.
    """
    payload = {
        "failure_code": failure_code,
        "absolute_timeout_seconds": absolute_timeout_seconds,
        "inactivity_threshold_seconds": inactivity_threshold_seconds,
        "inactive_seconds": inactive_seconds,
        "stdout_byte_count": len(stdout_bytes),
        "stderr_byte_count": len(stderr_bytes),
        "return_code": return_code,
        "partial_stdout": stdout_bytes.decode("utf-8", errors="replace"),
        "partial_stderr": stderr_bytes.decode("utf-8", errors="replace"),
    }
    try:
        atomic_json(run_dir / f"{prefix}-failure.json", payload)
    except Exception:
        pass


def _decode_readonly_model_output(data: bytes) -> str:
    """Decode readonly success output like run_process(text=True): effective
    locale encoding with strict errors plus universal-newline translation
    (CRLF and lone CR become LF). Worker decoding stays UTF-8/replace."""
    text = data.decode(locale.getpreferredencoding(False), errors="strict")
    # Universal-newline order matters: CRLF first, then lone CR.
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _terminate_readonly_group(proc: subprocess.Popen[bytes]) -> None:
    """Terminate the controlled session/process group of a readonly model process.

    The Popen was created with ``start_new_session=True``, so the group and
    session are rooted at ``proc.pid``. Escalates SIGTERM to SIGKILL with
    bounded verification and reaps the leader. ESRCH is accepted only after
    the leader is gone AND the group is provably inactive; every other
    signaling failure fails closed.
    """
    pgid = proc.pid
    session_id = proc.pid

    def _quiet() -> tuple[bool, str]:
        leader_gone = proc.poll() is not None
        group = WriteLease._group_status(pgid, session_id)
        return leader_gone, group

    def _reap() -> None:
        with contextlib.suppress(Exception):
            proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)

    leader_gone, group = _quiet()
    if leader_gone and group == "inactive":
        _reap()
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(-pgid, sig)
        except ProcessLookupError as exc:
            leader_gone, group = _quiet()
            if leader_gone and group == "inactive":
                _reap()
                return
            raise AgentFlowError(
                "INTERNAL_ERROR",
                f"Model process group signal failed while state is unproven: {exc}",
            ) from exc
        except (PermissionError, OSError) as exc:
            # Group signaling failed while the leader may still be alive:
            # best-effort direct leader cleanup, then fail closed unless
            # quiescence can be proven.
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
            leader_gone, group = _quiet()
            if leader_gone and group == "inactive":
                _reap()
                return
            raise AgentFlowError(
                "INTERNAL_ERROR",
                f"Cannot terminate model process group; failing closed: {exc}",
            ) from exc
        signal_deadline = time.monotonic() + _MODEL_SIGNAL_WAIT_TIMEOUT
        while True:
            leader_gone, group = _quiet()
            if leader_gone and group == "inactive":
                _reap()
                return
            if time.monotonic() >= signal_deadline:
                break
            time.sleep(_MODEL_SUPERVISOR_POLL_INTERVAL)
    leader_gone, group = _quiet()
    if leader_gone and group == "inactive":
        _reap()
        return
    raise AgentFlowError(
        "INTERNAL_ERROR",
        f"Model process group {pgid} remains {group}; failing closed",
    )


def _run_readonly_model_process(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None,
    on_activity: Callable[[str, int], None] | None = None,
    inactivity_timeout_seconds: int | None = None,
    abort_check: Callable[[float], AbortRequest | None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Model-only readonly execution adapter: no WriteLease, no GO gate, no
    writable stdin. Git, validators, and ordinary short subprocesses stay on
    run_process()."""
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        text=False,
    )
    # Armed immediately before shared supervision, so process creation above
    # never consumes either budget.
    policy = (
        _ModelInactivityPolicy(inactivity_timeout_seconds)
        if inactivity_timeout_seconds is not None
        else None
    )
    return _supervise_model_process(
        proc,
        result_args=list(argv),
        timeout=timeout,
        terminate=_terminate_readonly_group,
        decode_output=_decode_readonly_model_output,
        on_activity=_with_inactivity_accounting(policy, on_activity),
        abort_check=_combined_model_abort_check(policy, abort_check),
    )


def _terminate_registered_group(identity: dict[str, Any], proc: subprocess.Popen[Any]) -> None:
    """Terminate only a safely-attributable, registered worker session.

    When the leader is still the verified process, the historical safeguards
    apply. When the leader has exited but members remain inside the registered
    process group, those members are terminated only after boot-identity and
    group/session ownership checks still attribute the group to this worker.
    UNKNOWN state fails closed instead of signaling an arbitrary group.
    """
    pgid = identity["pgid"]
    session_id = identity["session_id"]
    leader = WriteLease._process_status(identity, require_group=True)
    if leader == "active":
        try:
            os.kill(-pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            return
        try:
            proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            if WriteLease._group_status(pgid, session_id) == "active":
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.kill(-pgid, signal.SIGKILL)
        return
    if leader == "unknown":
        raise AgentFlowError(
            "INTERNAL_ERROR", "Worker identity is unverifiable; failing closed"
        )
    # Leader exited: inspect the REGISTERED group/session before touching it.
    group = WriteLease._group_status(pgid, session_id)
    if group == "inactive":
        with contextlib.suppress(Exception):
            proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
        return
    if group == "unknown":
        raise AgentFlowError(
            "INTERNAL_ERROR", "Worker group state is unverifiable; failing closed"
        )
    # Remaining members exist inside the registered group: refuse to signal a
    # possibly-reused group unless boot identity still matches this worker.
    try:
        current_boot_id = read_boot_id()
    except OSError as exc:
        raise AgentFlowError(
            "INTERNAL_ERROR", f"Cannot verify boot identity; failing closed: {exc}"
        ) from exc
    if current_boot_id != identity["boot_id"]:
        raise AgentFlowError(
            "INTERNAL_ERROR",
            "Worker boot identity changed; refusing to signal a reused group",
        )
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(-pgid, sig)
        except ProcessLookupError as exc:
            if WriteLease._group_status(pgid, session_id) == "inactive":
                with contextlib.suppress(Exception):
                    proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
                return
            raise AgentFlowError(
                "INTERNAL_ERROR",
                f"Worker group signal failed while state is unproven: {exc}",
            ) from exc
        except (PermissionError, OSError) as exc:
            raise AgentFlowError(
                "INTERNAL_ERROR",
                f"Cannot terminate worker group; failing closed: {exc}",
            ) from exc
        signal_deadline = time.monotonic() + _MODEL_SIGNAL_WAIT_TIMEOUT
        while True:
            group = WriteLease._group_status(pgid, session_id)
            if group == "inactive":
                with contextlib.suppress(Exception):
                    proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
                return
            if group == "unknown":
                raise AgentFlowError(
                    "INTERNAL_ERROR",
                    "Worker group state is unverifiable; failing closed",
                )
            if time.monotonic() >= signal_deadline:
                break
            time.sleep(_MODEL_SUPERVISOR_POLL_INTERVAL)
    if WriteLease._group_status(pgid, session_id) == "inactive":
        with contextlib.suppress(Exception):
            proc.wait(timeout=_MODEL_SIGNAL_WAIT_TIMEOUT)
        return
    raise AgentFlowError(
        "INTERNAL_ERROR",
        f"Worker group {pgid} remains active; failing closed",
    )


def run_lifecycle_process(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None,
    lease: WriteLease,
    on_activity: Callable[[str, int], None] | None = None,
    inactivity_timeout_seconds: int | None = None,
    abort_check: Callable[[float], AbortRequest | None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a model worker behind the durable lease registration gate."""
    lease.prepare_writer()
    wrapper_argv = [
        sys.executable,
        str(Path(__file__).resolve()),
        WRITER_WRAPPER_MODE,
        "--",
        *argv,
    ]
    proc: subprocess.Popen[Any] | None = None
    identity: dict[str, Any] | None = None
    quiescent_recorded = False
    try:
        proc = subprocess.Popen(
            wrapper_argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            identity = lease.register_writer(proc.pid)
            if proc.stdin is None:
                raise AgentFlowError("WRITE_LEASE_CONFLICT", "Writer pipe was not created")
            proc.stdin.write(WRITER_GO)
            proc.stdin.flush()
            proc.stdin.close()
            # The supervisor never touches stdin; the gate has already been sent
            # and the descriptor must be detached before supervising the
            # exec'ed worker.
            proc.stdin = None
        except BaseException:
            _close_process_stdin(proc)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            if proc.poll() is None and identity is not None:
                _terminate_registered_group(identity, proc)
            raise

        # The shared supervisor computes the absolute deadline on entry, so
        # registration/GO setup above never consumes execution timeout. The
        # inactivity policy below is likewise armed only here, immediately
        # before supervisor entry, so registration/GO latency consumes
        # neither budget.
        def _terminate_registered(target: subprocess.Popen[bytes]) -> None:
            assert identity is not None
            _terminate_registered_group(identity, target)

        policy = (
            _ModelInactivityPolicy(inactivity_timeout_seconds)
            if inactivity_timeout_seconds is not None
            else None
        )
        try:
            completed = _supervise_model_process(
                proc,
                result_args=argv,
                timeout=timeout,
                terminate=_terminate_registered,
                decode_output=_decode_process_output,
                on_activity=_with_inactivity_accounting(policy, on_activity),
                abort_check=_combined_model_abort_check(policy, abort_check),
            )
        finally:
            if proc.poll() is not None:
                lease.mark_writer_quiescent()
                quiescent_recorded = True
        return completed
    except BaseException:
        if proc is None:
            # Popen failed after the pre-registration marker was persisted.
            with contextlib.suppress(AgentFlowError):
                lease.mark_writer_quiescent()
        elif not quiescent_recorded and proc.poll() is not None:
            with contextlib.suppress(AgentFlowError):
                lease.mark_writer_quiescent()
        raise


def _run_model_command(
    *,
    role: str,
    argv: list[str],
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None,
    lease: WriteLease | None = None,
    on_activity: Callable[[str, int], None] | None = None,
    inactivity_timeout_seconds: int | None = None,
    abort_check: Callable[[float], AbortRequest | None] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Backend-independent model execution selector.

    Worker roles run behind the lease/GO lifecycle adapter; every other role
    uses the readonly model adapter. Git, validators, and ordinary short
    subprocesses stay on run_process().
    """
    if role == "worker":
        if lease is None:
            raise AgentFlowError("WRITE_LEASE_CONFLICT", "Worker invocation requires a write lease")
        return run_lifecycle_process(
            argv, cwd=cwd, timeout=timeout, env=env, lease=lease,
            on_activity=on_activity,
            inactivity_timeout_seconds=inactivity_timeout_seconds,
            abort_check=abort_check,
        )
    return _run_readonly_model_process(
        argv, cwd=cwd, timeout=timeout, env=env, on_activity=on_activity,
        inactivity_timeout_seconds=inactivity_timeout_seconds,
        abort_check=abort_check,
    )


def classify_provider_failure(
    stdout: str, stderr: str, condition: BaseException | None = None
) -> ProviderFailureClass:
    """Classify only documented machine-readable provider error codes.

    Free-form text is intentionally ignored even when it contains words such
    as "quota" or "rate limit".
    """
    aliases = {
        "TRANSIENT_NETWORK": ProviderFailureClass.TRANSIENT_NETWORK,
        "NETWORK_ERROR": ProviderFailureClass.TRANSIENT_NETWORK,
        "RATE_LIMITED": ProviderFailureClass.RATE_LIMITED,
        "RATE_LIMIT": ProviderFailureClass.RATE_LIMITED,
        "TEMPORARILY_UNAVAILABLE": ProviderFailureClass.TEMPORARILY_UNAVAILABLE,
        "SERVICE_UNAVAILABLE": ProviderFailureClass.TEMPORARILY_UNAVAILABLE,
        "QUOTA_EXHAUSTED": ProviderFailureClass.QUOTA_EXHAUSTED,
        "INSUFFICIENT_QUOTA": ProviderFailureClass.QUOTA_EXHAUSTED,
        "AUTH_OR_CONFIGURATION": ProviderFailureClass.AUTH_OR_CONFIGURATION,
        "AUTHENTICATION_ERROR": ProviderFailureClass.AUTH_OR_CONFIGURATION,
        "INVALID_API_KEY": ProviderFailureClass.AUTH_OR_CONFIGURATION,
        "MODEL_NOT_FOUND_OR_DISABLED": ProviderFailureClass.MODEL_NOT_FOUND_OR_DISABLED,
        "MODEL_NOT_FOUND": ProviderFailureClass.MODEL_NOT_FOUND_OR_DISABLED,
        "MODEL_DISABLED": ProviderFailureClass.MODEL_NOT_FOUND_OR_DISABLED,
    }

    def codes(value: Any) -> Iterator[str]:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"code", "error_code"} and isinstance(item, str):
                    yield item.upper()
                elif key in {"error", "details", "event", "data"}:
                    yield from codes(item)
        elif isinstance(value, list):
            for item in value:
                yield from codes(item)

    for stream in (stderr, stdout):
        for line in stream.splitlines():
            try:
                event = json.loads(line)
            except (ValueError, RecursionError):
                continue
            for code in codes(event):
                if code in aliases:
                    return aliases[code]
    if isinstance(condition, ConnectionError):
        return ProviderFailureClass.TRANSIENT_NETWORK
    if isinstance(condition, OSError) and condition.errno in {
        errno.ECONNABORTED, errno.ECONNREFUSED, errno.ECONNRESET,
        errno.EHOSTUNREACH, errno.ENETDOWN, errno.ENETUNREACH, errno.ETIMEDOUT,
    }:
        return ProviderFailureClass.TRANSIENT_NETWORK
    return ProviderFailureClass.PROCESS_NONZERO_UNKNOWN


_PROVIDER_VERDICTS = {
    ProviderFailureClass.TRANSIENT_NETWORK: "PROVIDER_TRANSIENT",
    ProviderFailureClass.RATE_LIMITED: "PROVIDER_RATE_LIMITED",
    ProviderFailureClass.TEMPORARILY_UNAVAILABLE: "PROVIDER_TEMPORARILY_UNAVAILABLE",
    ProviderFailureClass.QUOTA_EXHAUSTED: "PROVIDER_QUOTA_EXHAUSTED",
    ProviderFailureClass.AUTH_OR_CONFIGURATION: "PROVIDER_AUTH_OR_CONFIGURATION",
    ProviderFailureClass.MODEL_NOT_FOUND_OR_DISABLED: "MODEL_UNAVAILABLE",
    ProviderFailureClass.PROCESS_NONZERO_UNKNOWN: "MODEL_INVOCATION_FAILED",
}


def _stage_opencode_config(run_dir: Path, repo: Path) -> Path:
    """Copy trusted config into a fresh, provider-writable run directory.

    Source symlinks and special entries are rejected. File descriptors opened
    with O_NOFOLLOW keep a changed source entry from redirecting the copy.
    Runtime state is retained under runs/ as invocation evidence.
    """
    source = Path(ROOT) / "opencode"
    run_root = Path(run_dir).resolve()
    repo_root = Path(repo).resolve()
    source_root = source.resolve()
    if source.is_symlink() or not source.is_dir():
        raise AgentFlowError("UNSAFE_OPENCODE_CONFIG", f"Invalid source config: {source}")
    if run_root == repo_root or repo_root in run_root.parents:
        raise AgentFlowError("UNSAFE_OPENCODE_CONFIG", "Runtime directory is inside execution repository")
    if run_root == source_root or source_root in run_root.parents:
        raise AgentFlowError("UNSAFE_OPENCODE_CONFIG", "Runtime directory is inside trusted source config")
    runtime_parent = run_root / "runtime"
    runtime_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if runtime_parent.is_symlink() or runtime_parent.resolve() != runtime_parent:
        raise AgentFlowError("UNSAFE_OPENCODE_CONFIG", "Runtime parent redirects outside the run")
    invocation_dir = runtime_parent / uuid.uuid4().hex
    invocation_dir.mkdir(mode=0o700, exist_ok=False)
    destination = invocation_dir / "opencode-config"
    destination.mkdir(mode=0o700, exist_ok=False)

    def copy_dir(source_fd: int, dest: Path) -> None:
        with os.scandir(source_fd) as entries:
            for entry in entries:
                name = entry.name
                info = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                target = dest / name
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(
                        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=source_fd,
                    )
                    try:
                        target.mkdir(mode=0o700, exist_ok=False)
                        copy_dir(child_fd, target)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(info.st_mode):
                    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                    file_fd = os.open(name, flags, dir_fd=source_fd)
                    try:
                        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                            raise AgentFlowError("UNSAFE_OPENCODE_CONFIG", f"Source changed: {name}")
                        dest_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(file_fd, "rb", closefd=False) as src, os.fdopen(dest_fd, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                    finally:
                        os.close(file_fd)
                else:
                    raise AgentFlowError("UNSAFE_OPENCODE_CONFIG", f"Unsupported source entry: {name}")

    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            copy_dir(source_fd, destination)
        finally:
            os.close(source_fd)
    except OSError as exc:
        raise AgentFlowError("UNSAFE_OPENCODE_CONFIG", str(exc)) from exc
    return destination


def _invoke_model_once(
    *,
    role: str,
    profile_name: str,
    profile: dict[str, Any],
    task: dict[str, Any],
    run_dir: Path,
    cycle: int,
    context: dict[str, Any] | None = None,
    lease: WriteLease | None = None,
    exec_repo: Path | None = None,
    on_activity: Callable[[str, int], None] | None = None,
    runtime_run_dir: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    # F-05: role eligibility is checked before any model process invocation.
    _check_role_eligible(profile, role)
    repo = exec_repo if exec_repo is not None else Path(task["repo"]).resolve()
    effective_task = dict(task)
    effective_task["repo"] = str(repo)
    record = invocation_record(role, profile_name, profile, cycle)
    prompt = render_prompt(role, effective_task, record, context)
    prefix = f"{role}-cycle-{cycle}"
    atomic_json(run_dir / f"{prefix}-invocation.json", record)
    timeout = int(task.get("model_timeout_seconds", 3600))
    # One task-level limit applies to every model role; absent means disabled.
    inactivity_threshold = _model_inactivity_threshold(task)

    def _execute_model(
        argv: list[str], env: dict[str, str] | None
    ) -> subprocess.CompletedProcess[str]:
        control = _ACTIVE_EXECUTION_CONTROL.get()
        if control is not None:
            # The established model supervisors are the evidence source here:
            # a normal return or a non-INTERNAL exception means their bounded
            # cleanup contract completed.  INTERNAL_ERROR means it did not.
            control.note_process_started()
        try:
            completed = _run_model_command(
                role=role, argv=argv, cwd=repo, timeout=timeout, env=env,
                lease=lease, on_activity=on_activity,
                inactivity_timeout_seconds=inactivity_threshold,
                abort_check=control.abort_check if control is not None else None,
            )
            if control is not None:
                control.note_process_quiescent()
            return completed
        except FileNotFoundError as exc:
            if control is not None:
                control.note_process_quiescent()
            raise AgentFlowError("MODEL_UNAVAILABLE", str(exc)) from exc
        except AbortedProcessError as exc:
            if control is not None:
                control.note_process_quiescent()
            _persist_model_failure_evidence(
                run_dir,
                prefix,
                failure_code=exc.request.code,
                absolute_timeout_seconds=timeout,
                inactivity_threshold_seconds=inactivity_threshold,
                inactive_seconds=exc.request.details.get("inactive_seconds"),
                stdout_bytes=exc.partial_stdout or b"",
                stderr_bytes=exc.partial_stderr or b"",
                return_code=exc.return_code,
            )
            if exc.request.code == "BUDGET_EXHAUSTED":
                raise BudgetExhausted(
                    str(exc.request.details.get("budget_dimension", "WALL_CLOCK")),
                    str(exc),
                ) from exc
            raise
        except subprocess.TimeoutExpired as exc:
            if control is not None:
                control.note_process_quiescent()
            raw_out = exc.output
            raw_err = exc.stderr
            _persist_model_failure_evidence(
                run_dir,
                prefix,
                failure_code="PROCESS_TIMEOUT",
                absolute_timeout_seconds=timeout,
                inactivity_threshold_seconds=inactivity_threshold,
                inactive_seconds=None,
                stdout_bytes=(
                    bytes(raw_out)
                    if isinstance(raw_out, (bytes, bytearray))
                    else b""
                ),
                stderr_bytes=(
                    bytes(raw_err)
                    if isinstance(raw_err, (bytes, bytearray))
                    else b""
                ),
                return_code=None,
            )
            raise
        except AgentFlowError as exc:
            if control is not None:
                if exc.code == "INTERNAL_ERROR":
                    control.note_process_uncertain()
                else:
                    control.note_process_quiescent()
            raise
        except BaseException:
            if control is not None:
                control.note_process_uncertain()
            raise

    if profile["backend"] == "opencode":
        runtime_config = _stage_opencode_config(runtime_run_dir or run_dir, repo)
        record["runtime_config_dir"] = str(runtime_config)
        atomic_json(run_dir / f"{prefix}-invocation.json", record)
        argv = [
            profile["command"], "run", "--format", "json", "--model", profile["model"],
            "--agent", profile["agent"], "--dir", str(repo),
        ]
        if profile.get("variant"):
            argv += ["--variant", profile["variant"]]
        argv.append(prompt)
        env = os.environ.copy()
        env["OPENCODE_CONFIG_DIR"] = str(runtime_config)
        proc = _execute_model(argv, env)
        raw = proc.stdout
    elif profile["backend"] == "codex":
        output_file = run_dir / f"{prefix}-last-message.json"
        # F-05: Codex read-only-class roles receive preventive read-only
        # sandboxing, derived from the centralized role policy.
        sandbox = "read-only" if _role_permission_class(role) == "read_only" else "workspace-write"
        argv = [
            profile["command"], "exec", "--ephemeral", "--json", "-C", str(repo),
            "-s", sandbox, "-m", profile["model"],
            "-c", f'model_reasoning_effort="{profile["variant"]}"',
            "-c", 'approval_policy="never"', "--output-schema", str(RESULT_SCHEMA),
            "-o", str(output_file), prompt,
        ]
        proc = _execute_model(argv, None)
        raw = output_file.read_text(encoding="utf-8") if output_file.exists() else proc.stdout
    else:
        raise AgentFlowError("UNKNOWN_BACKEND", profile["backend"])
    (run_dir / f"{prefix}-output.jsonl").write_text(proc.stdout, encoding="utf-8")
    (run_dir / f"{prefix}-stderr.txt").write_text(summarized(proc.stderr), encoding="utf-8")
    record.update({"finished_at": utc_now(), "exit_code": proc.returncode})
    atomic_json(run_dir / f"{prefix}-invocation.json", record)
    if proc.returncode != 0:
        failure_class = classify_provider_failure(proc.stdout, proc.stderr)
        raise AgentFlowError(
            _PROVIDER_VERDICTS[failure_class], summarized(proc.stderr or proc.stdout)
        )
    try:
        result = parse_model_result(raw)
    except AgentFlowError as exc:
        if exc.code == "INVALID_MODEL_OUTPUT":
            _persist_invalid_model_output(
                run_dir, prefix=prefix, role=role, profile_name=profile_name,
                cycle=cycle, error=str(exc), raw_output=raw,
            )
        raise
    result.update(
        {
            "task_id": task["task_id"],
            "role": role,
            "harness": profile["backend"],
            "provider": profile["provider"],
            "model": profile["model"],
            "variant": profile.get("variant"),
        }
    )
    result.setdefault("files_changed", [])
    result.setdefault("validators", {})
    result.setdefault("findings", [])
    result.setdefault("open_risks", [])
    valid, reason = result_valid(result)
    if not valid:
        exc = AgentFlowError("INVALID_MODEL_OUTPUT", reason)
        _persist_invalid_model_output(
            run_dir, prefix=prefix, role=role, profile_name=profile_name,
            cycle=cycle, error=str(exc), result=result, raw_output=raw,
        )
        raise exc
    if role in _STRUCTURAL_RETRY_ROLES:
        try:
            _validate_model_output_contract(role, result, task, context)
        except AgentFlowError as exc:
            if exc.code == "INVALID_MODEL_OUTPUT":
                _persist_invalid_model_output(
                    run_dir, prefix=prefix, role=role, profile_name=profile_name,
                    cycle=cycle, error=str(exc), result=result, raw_output=raw,
                )
            raise
    atomic_json(run_dir / f"{prefix}-result.json", result)
    return result, record


_RETRYABLE_FAILURES = {
    "PROVIDER_TRANSIENT", "PROVIDER_RATE_LIMITED",
    "PROVIDER_TEMPORARILY_UNAVAILABLE", "STALL_DETECTED", "PROCESS_TIMEOUT",
}
_FALLBACK_FAILURES = _RETRYABLE_FAILURES | {"PROVIDER_QUOTA_EXHAUSTED", "MODEL_UNAVAILABLE"}


def invoke_model(
    *,
    role: str,
    profile_name: str,
    profile: dict[str, Any],
    task: dict[str, Any],
    run_dir: Path,
    cycle: int,
    context: dict[str, Any] | None = None,
    lease: WriteLease | None = None,
    exec_repo: Path | None = None,
    on_activity: Callable[[str, int], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Invoke one logical model call with queue-only bounded recovery.

    Physical execution remains routed through _run_model_command by the
    single-attempt helper; this wrapper adds no second process supervisor.
    """
    control = _ACTIVE_EXECUTION_CONTROL.get()
    if control is None:
        # F-04: bounded ownership scope for standalone invocation.
        # One immutable baseline per logical invocation (reentrant: nested
        # calls from run_task/program reuse the outer scope); durable
        # poison check BEFORE untrusted execution; cleanup after
        # completion/BaseException; unrelated later standalone calls
        # cannot inherit stale trust.
        with _control_plane_run_scope(run_dir):
            # F-04: durable poison gate — check BEFORE any untrusted
            # execution.  A manifest previously observed as mutated is
            # never accepted as the trusted baseline of this invocation.
            _control_plane_check_poison(run_dir)
            try:
                _probe_repo = (
                    exec_repo
                    if exec_repo is not None
                    else Path(task["repo"]).resolve()
                    if isinstance(task.get("repo"), str)
                    else None
                )
            except Exception:
                _probe_repo = None
            attempt_context = context
            structural_retry_used = False
            evidence_dir = Path(run_dir)
            while True:
                before_baseline: dict[str, Any] | None = None
                before_identity: dict[str, Any] | None = None
                if _probe_repo is not None:
                    with contextlib.suppress(Exception):
                        before_baseline = capture_baseline(Path(_probe_repo))
                    with contextlib.suppress(Exception):
                        before_identity = read_git_identity(Path(_probe_repo))
                _verify_control_plane(Path(run_dir), phase=f"{role} pre-invocation")
                attempted_result: dict[str, Any] | None = None
                try:
                    attempted_result, attempted_record = _invoke_model_once(
                        role=role, profile_name=profile_name, profile=profile,
                        task=task, run_dir=evidence_dir, cycle=cycle,
                        context=attempt_context, lease=lease,
                        exec_repo=exec_repo, on_activity=on_activity,
                    )
                    attempted_record["attempt"] = (
                        "STRUCTURAL_RETRY" if structural_retry_used else "PRIMARY"
                    )
                    atomic_json(
                        evidence_dir / f"{role}-cycle-{cycle}-invocation.json",
                        attempted_record,
                    )
                except Exception as _invoke_exc:
                    # F-04: failure-path verification masks the original error
                    # when the control plane moved.
                    try:
                        _verify_control_plane(
                            Path(run_dir), phase=f"{role} post-failure"
                        )
                    except AgentFlowError as _cp_exc:
                        if _cp_exc.code == "CONTROL_PLANE_MUTATED":
                            raise _cp_exc from _invoke_exc
                        raise
                    if _probe_repo is not None:
                        after_failure: dict[str, Any] | None = None
                        after_identity: dict[str, Any] | None = None
                        with contextlib.suppress(Exception):
                            after_failure = capture_baseline(Path(_probe_repo))
                        with contextlib.suppress(Exception):
                            after_identity = read_git_identity(Path(_probe_repo))
                        assert_git_identity_unchanged(
                            before_identity, after_identity,
                            context=f"{role} invocation (failure path)",
                        )
                        if (
                            role in _STRUCTURAL_RETRY_ROLES
                            and before_baseline is not None
                            and after_failure is not None
                        ):
                            delta = changed_since(before_baseline, after_failure)
                            if delta:
                                raise AgentFlowError(
                                    "READONLY_ROLE_WROTE_REPO",
                                    f"{role} modified: {delta!r}",
                                ) from _invoke_exc
                    if (
                        isinstance(_invoke_exc, AgentFlowError)
                        and _invoke_exc.code == "INVALID_MODEL_OUTPUT"
                        and role in _STRUCTURAL_RETRY_ROLES
                    ):
                        _persist_invalid_model_output(
                            evidence_dir,
                            prefix=f"{role}-cycle-{cycle}",
                            role=role,
                            profile_name=profile_name,
                            cycle=cycle,
                            error=str(_invoke_exc),
                            result=attempted_result,
                        )
                        if not structural_retry_used:
                            structural_retry_used = True
                            attempt_root = (
                                Path(run_dir) / "attempts"
                                / f"{role}-cycle-{cycle}" / "structural-retry"
                            )
                            attempt_root.mkdir(parents=True, exist_ok=False)
                            evidence_dir = attempt_root
                            attempt_context = _structural_retry_context(
                                context, str(_invoke_exc)
                            )
                            atomic_json_fsync(
                                evidence_dir / "structural-retry-feedback.json",
                                attempt_context["structural_retry_feedback"],
                            )
                            continue
                    raise
                _verify_control_plane(Path(run_dir), phase=f"{role} post-invocation")
                if _probe_repo is not None:
                    after_identity: dict[str, Any] | None = None
                    after_baseline: dict[str, Any] | None = None
                    with contextlib.suppress(Exception):
                        after_identity = read_git_identity(Path(_probe_repo))
                    if role in _STRUCTURAL_RETRY_ROLES and before_baseline is not None:
                        after_baseline = capture_baseline(Path(_probe_repo))
                    assert_git_identity_unchanged(
                        before_identity, after_identity,
                        context=f"{role} invocation",
                    )
                    if before_baseline is not None and after_baseline is not None:
                        delta = changed_since(before_baseline, after_baseline)
                        if delta:
                            raise AgentFlowError(
                                "READONLY_ROLE_WROTE_REPO", f"{role} modified: {delta!r}"
                            )
                if structural_retry_used:
                    atomic_json(
                        Path(run_dir) / f"{role}-cycle-{cycle}-result.json",
                        attempted_result,
                    )
                    atomic_json(
                        Path(run_dir) / f"{role}-cycle-{cycle}-invocation.json",
                        attempted_record,
                    )
                return attempted_result, attempted_record

    repo = exec_repo if exec_repo is not None else Path(task["repo"]).resolve()
    logical_id = control.next_logical_id(role, cycle)
    correction_start = bool(
        role == "worker" and cycle == 1 and isinstance(context, dict)
        and context.get("kind") == "adjudicated_correction"
    )
    attempts: list[tuple[str, str, dict[str, Any]]] = [("PRIMARY", profile_name, profile)]
    attempt_index = 0
    last_exc: AgentFlowError | None = None
    structural_retry_used = False
    attempt_context = context
    while attempt_index < len(attempts):
        attempt, active_name, active_profile = attempts[attempt_index]
        reservation = control.reserve_attempt(
            logical_id=logical_id, attempt=attempt,
            correction_start=correction_start and attempt == "PRIMARY",
        )
        evidence_dir = run_dir
        if attempt != "PRIMARY":
            evidence_dir = run_dir / "attempts" / logical_id / attempt.lower()
            evidence_dir.mkdir(parents=True, exist_ok=False)
            if attempt == "STRUCTURAL_RETRY":
                atomic_json_fsync(
                    evidence_dir / "structural-retry-feedback.json",
                    attempt_context["structural_retry_feedback"],
                )
        control.write_attempt(logical_id, attempt, "started", {
            **reservation, "role": role, "cycle": cycle,
            "profile": active_name, "started_at": utc_now(),
        })
        before = capture_baseline(repo)
        # F-04: pre-invocation control-plane check against the immutable
        # run baseline (top run_dir, never the per-attempt evidence_dir).
        _verify_control_plane(Path(run_dir), phase=f"{role} pre-invocation")
        attempted_result: dict[str, Any] | None = None
        try:
            attempted_result, invocation = _invoke_model_once(
                role=role, profile_name=active_name, profile=active_profile,
                task=task, run_dir=evidence_dir, cycle=cycle, context=attempt_context,
                lease=lease, exec_repo=repo, on_activity=on_activity,
                runtime_run_dir=run_dir,
            )
            invocation["attempt"] = attempt
            atomic_json(
                evidence_dir / f"{role}-cycle-{cycle}-invocation.json", invocation
            )
            # F-04: success still fails closed when the control plane moved.
            _verify_control_plane(Path(run_dir), phase=f"{role} post-invocation")
            was_success_finalizing = control.finalizing
            control.finalizing = True
            try:
                after_success = capture_baseline(repo)
            finally:
                control.finalizing = was_success_finalizing
            assert_git_identity_unchanged(
                before, after_success, context=f"{role} invocation"
            )
            if role in _STRUCTURAL_RETRY_ROLES:
                delta = changed_since(before, after_success)
                if delta:
                    raise AgentFlowError(
                        "READONLY_ROLE_WROTE_REPO", f"{role} modified: {delta!r}"
                    )
            if attempt == "STRUCTURAL_RETRY":
                atomic_json(
                    Path(run_dir) / f"{role}-cycle-{cycle}-result.json",
                    attempted_result,
                )
                atomic_json(
                    Path(run_dir) / f"{role}-cycle-{cycle}-invocation.json",
                    invocation,
                )
            control.write_attempt(logical_id, attempt, "terminal", {
                "logical_invocation": logical_id, "attempt": attempt,
                "status": "SUCCESS", "finished_at": utc_now(),
            })
            return attempted_result, invocation
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as raw_exc:
            exc = raw_exc if isinstance(raw_exc, AgentFlowError) else AgentFlowError(
                _error_code_for(raw_exc), str(raw_exc)
            )
            if exc.code == "INVALID_MODEL_OUTPUT" and role in _STRUCTURAL_RETRY_ROLES:
                _persist_invalid_model_output(
                    evidence_dir,
                    prefix=f"{role}-cycle-{cycle}",
                    role=role,
                    profile_name=active_name,
                    cycle=cycle,
                    error=str(exc),
                    result=attempted_result,
                )
            # F-04: mutation before retry/fallback/correction fails closed as
            # CONTROL_PLANE_MUTATED with no retry, fallback, or progression.
            if exc.code != "CONTROL_PLANE_MUTATED":
                try:
                    _verify_control_plane(
                        Path(run_dir), phase=f"{role} post-failure"
                    )
                except AgentFlowError as _cp_exc:
                    if _cp_exc.code == "CONTROL_PLANE_MUTATED":
                        control.write_attempt(logical_id, attempt, "terminal", {
                            "logical_invocation": logical_id, "attempt": attempt,
                            "status": "FAILED", "failure": _cp_exc.code,
                            "finished_at": utc_now(),
                        })
                        raise _cp_exc from raw_exc
                    raise
            last_exc = exc
            control.write_attempt(logical_id, attempt, "terminal", {
                "logical_invocation": logical_id, "attempt": attempt,
                "status": "FAILED", "failure": exc.code,
                "finished_at": utc_now(),
            })
            if exc.code in {"INTERNAL_ERROR", "BUDGET_EXHAUSTED", "CONTROL_PLANE_MUTATED",
                            "READONLY_ROLE_WROTE_REPO"}:
                raise exc

            # Recovery is safe only from a zero-delta failed invocation.
            was_finalizing = control.finalizing
            control.finalizing = True
            try:
                after = capture_baseline(repo)
            finally:
                control.finalizing = was_finalizing
            assert_git_identity_unchanged(
                before, after, context=f"{role} invocation (failure path)"
            )
            delta = changed_since(before, after)
            if role == "worker" and delta:
                unauthorized = [p for p in delta if not path_allowed(p, task["allowed_paths"])]
                if unauthorized:
                    raise AgentFlowError("UNAUTHORIZED_PATH_CHANGE", repr(unauthorized))
                raise exc
            if role != "worker" and delta:
                raise AgentFlowError("READONLY_ROLE_WROTE_REPO", f"{role} modified: {delta!r}")

            if (
                exc.code == "INVALID_MODEL_OUTPUT"
                and role in _STRUCTURAL_RETRY_ROLES
                and not structural_retry_used
            ):
                if control.transition_available("RETRY"):
                    control.write_transition(
                        logical_id, attempt, "STRUCTURAL_RETRY", str(exc)
                    )
                    attempts.append(("STRUCTURAL_RETRY", active_name, active_profile))
                    structural_retry_used = True
                    attempt_context = _structural_retry_context(context, str(exc))
                    attempt_index += 1
                    continue
                raise exc

            fallback = control.fallback_for_role(role)
            retry_allowed = (
                attempt == "PRIMARY" and exc.code in _RETRYABLE_FAILURES
                and control.transition_available("RETRY")
            )
            if retry_allowed:
                control.write_transition(logical_id, attempt, "RETRY", exc.code)
                attempts.append(("RETRY", active_name, active_profile))
            elif (
                attempt in {"PRIMARY", "RETRY"} and exc.code in _FALLBACK_FAILURES
                and fallback is not None and fallback[0] != active_name
                and control.transition_available("FALLBACK")
            ):
                control.write_transition(logical_id, attempt, "FALLBACK", exc.code)
                attempts.append(("FALLBACK", fallback[0], fallback[1]))
            else:
                raise exc
        attempt_index += 1
    assert last_exc is not None
    raise last_exc


_WORKER_BLOCKING_VERDICTS = {"BLOCKER", "CHANGES_REQUIRED"}


def reviewer_blocks(result: dict[str, Any]) -> bool:
    """Pure predicate over an already validated reviewer result.

    Only a canonical BLOCKER verdict (or a validated HIGH/BLOCKER finding)
    blocks.  Legacy aliases (FAIL, REJECT, CHANGES_REQUIRED, CRITICAL) are
    not part of the reviewer contract and raise through validation.
    """
    if not isinstance(result, dict) or result.get("role") != "reviewer":
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT", "reviewer_blocks requires a reviewer-role result"
        )
    if normalize_reviewer_verdict(result.get("verdict")) == "BLOCKER":
        return True
    findings = result.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if normalize_finding_severity(finding.get("severity")) in _REVIEWER_BLOCKING_SEVERITIES:
                return True
    return False


def worker_blocks(result: dict[str, Any]) -> bool:
    """Role-aware worker predicate: PASS/CHANGES_REQUIRED/BLOCKER contract."""
    if not isinstance(result, dict) or result.get("role") != "worker":
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT", "worker_blocks requires a worker-role result"
        )
    verdict = result.get("verdict")
    if not isinstance(verdict, str):
        return False
    return verdict.strip().upper() in _WORKER_BLOCKING_VERDICTS


def run_task(task_path: Path) -> tuple[int, Path, dict[str, Any]]:
    task = validate_task(read_json(task_path.resolve()))
    source_repo = Path(task["repo"]).resolve()
    timestamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    run_id = f"{timestamp}-{safe_slug(task['task_id'])}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    atomic_json(run_dir / "task.json", redact_config(task))
    final: dict[str, Any] = {
        "task_id": task["task_id"],
        "run_id": run_id,
        "started_at": utc_now(),
        "verdict": "RUNNING",
        "human_gate": True,
        "correction_cycles": 0,
    }
    workspace: dict[str, Any] | None = None
    ctx: ExecutionContext | None = None
    # F-04: capture the immutable run baseline exactly once before
    # untrusted execution (reentrant; nested scopes reuse the outer one).
    _cp_token = _control_plane_enter_run(run_dir)
    try:
        # F-04: durable poison gate — after computing the run baseline
        # manifest but BEFORE any worktree creation or model invocation,
        # refuse to accept a manifest previously observed as mutated.
        _control_plane_check_poison(run_dir)
        # L3: resolve source HEAD only for isolated runs (fail-closed);
        # legacy non-isolated runs must tolerate unborn repos.
        isolation_enabled = isinstance(task.get("isolation"), dict) and task["isolation"].get("enabled") is True
        source_head: str | None = None
        if isolation_enabled:
            source_head = _resolve_source_head(source_repo)

        ctx = build_execution_context(task, run_id)
        exec_repo = ctx.execution_repo

        if ctx.isolated:
            workspace = {
                "version": 1,
                "run_id": run_id,
                "source_repo": str(source_repo),
                "source_head": source_head,
                "baseline_commit": ctx.baseline_commit,
                "execution_repo": str(exec_repo),
                "worktree_root": str(worktree_root()),
                "created_at": utc_now(),
                "detached": True,
                "verified_head": ctx.baseline_commit,
                "status": "READY",
                "preserved_dirty": False,
                "cleanup": None,
            }
            try:
                atomic_json(run_dir / "source_baseline.json", capture_baseline(source_repo))
                atomic_json(run_dir / "workspace.json", workspace)
            except Exception:
                # M2 narrow window: worktree registered but not yet bound.
                _reconcile_unbound_worktree(source_repo, exec_repo, run_dir, workspace)
                raise

        baseline = capture_baseline(exec_repo)
        atomic_json(run_dir / "baseline.json", baseline)
        if not ctx.isolated:
            mismatches = baseline_mismatches(baseline, task["expected_baseline"])
            if mismatches:
                raise AgentFlowError("BASELINE_DRIFT", "; ".join(mismatches))

        models = load_models()
        worker_name, worker_profile = choose_profile(task, "worker", models)
        final["worker"] = invocation_record("worker", worker_name, worker_profile, 0)
        review_required = task["risk"] in {"HIGH", "CRITICAL"} or bool(task.get("review_required"))
        reviewer_name = reviewer_profile = None
        if review_required:
            reviewer_name, reviewer_profile = choose_profile(task, "reviewer", models)
            if model_family(worker_profile) == model_family(reviewer_profile):
                raise AgentFlowError("REVIEWER_NOT_INDEPENDENT", model_family(worker_profile))

        if workspace is not None:
            workspace["status"] = "CANDIDATE"
            atomic_json(run_dir / "workspace.json", workspace)

        context = None
        for cycle in range(int(task["max_corrections"]) + 1):
            before_worker = capture_baseline(exec_repo)
            with WriteLease(exec_repo, task["task_id"], run_id) as worker_lease:
                worker_result, worker_invocation = invoke_model(
                    role="worker", profile_name=worker_name, profile=worker_profile,
                    task=task, run_dir=run_dir, cycle=cycle, context=context,
                    lease=worker_lease, exec_repo=exec_repo,
                )
            after_worker = capture_baseline(exec_repo)
            assert_git_identity_unchanged(
                baseline, after_worker, context="legacy worker frozen baseline"
            )
            assert_git_identity_unchanged(
                before_worker, after_worker, context="legacy worker"
            )
            modified = changed_since(before_worker, after_worker)
            unauthorized = [path for path in modified if not path_allowed(path, task["allowed_paths"])]
            if unauthorized:
                raise AgentFlowError("UNAUTHORIZED_PATH_CHANGE", repr(unauthorized))
            worker_result["files_changed"] = modified
            worker_result["validators"] = {}
            final["worker"] = worker_invocation
            final["worker_result"] = worker_result
            atomic_json(run_dir / f"worker-cycle-{cycle}-result.json", worker_result)

            validator_results = run_validators(exec_repo, task["validators"], run_dir, cycle)
            after_validators = capture_baseline(exec_repo)
            assert_git_identity_unchanged(
                baseline, after_validators,
                context="legacy validators frozen baseline",
            )
            _check_scope(changed_since(before_worker, after_validators), task["allowed_paths"])
            worker_result["validators"] = {
                item["name"]: {"status": item["status"], "exit_code": item["exit_code"]}
                for item in validator_results
            }
            final["worker_result"] = worker_result
            atomic_json(run_dir / f"worker-cycle-{cycle}-result.json", worker_result)
            final["validators"] = validator_results
            if any(item["status"] != "PASS" for item in validator_results):
                raise AgentFlowError("VALIDATOR_FAILED", next(item["name"] for item in validator_results if item["status"] != "PASS"))

            if not review_required:
                final["worker_result"] = worker_result
                break

            before_review = capture_baseline(exec_repo)
            assert_git_identity_unchanged(
                baseline, before_review, context="legacy pre-review frozen baseline"
            )
            _legacy_anchor = baseline.get("head") if isinstance(baseline, dict) else None
            try:
                if _legacy_anchor:
                    diff = git(
                        exec_repo,
                        ["diff", str(_legacy_anchor), "--no-ext-diff", "--",
                         *task["allowed_paths"]],
                        timeout=120,
                    )
                    if diff.returncode != 0:
                        diff = git(
                            exec_repo,
                            ["diff", "--no-ext-diff", "--", *task["allowed_paths"]],
                            timeout=120,
                        )
                else:
                    diff = git(exec_repo, ["diff", "--no-ext-diff", "--", *task["allowed_paths"]], timeout=120)
            except Exception:
                diff = git(exec_repo, ["diff", "--no-ext-diff", "--", *task["allowed_paths"]], timeout=120)
            review_context = {
                "worker_result": worker_result,
                "validator_results": [
                    {key: item[key] for key in ("name", "command", "exit_code", "status")}
                    for item in validator_results
                ],
                "changed_files": modified,
                "git_diff": summarized(diff.stdout, 40000),
            }
            reviewer_result, reviewer_invocation = invoke_model(
                role="reviewer", profile_name=reviewer_name, profile=reviewer_profile,
                task=task, run_dir=run_dir, cycle=cycle, context=review_context,
                exec_repo=exec_repo,
            )
            after_review = capture_baseline(exec_repo)
            assert_git_identity_unchanged(
                baseline, after_review, context="legacy reviewer frozen baseline"
            )
            assert_git_identity_unchanged(
                before_review, after_review, context="legacy reviewer"
            )
            reviewer_writes = changed_since(before_review, after_review)
            if reviewer_writes:
                raise AgentFlowError("REVIEWER_WROTE_REPO", repr(reviewer_writes))
            final["reviewer"] = reviewer_invocation
            final["reviewer_result"] = reviewer_result
            final["worker_result"] = worker_result
            validate_reviewer_result(reviewer_result)
            if not reviewer_blocks(reviewer_result):
                break
            if cycle >= int(task["max_corrections"]):
                raise AgentFlowError("REVIEW_RETRY_CAP", "Reviewer still reports HIGH/BLOCKER")
            final["correction_cycles"] += 1
            context = {
                "kind": "review_correction",
                "reviewer_findings": reviewer_result["findings"],
                "reviewer_open_risks": reviewer_result["open_risks"],
                "reviewer_verdict": reviewer_result["verdict"],
            }

        # F-04: verify immediately before HUMAN_GATE; mutation fails
        # closed as CONTROL_PLANE_MUTATED with no gate.
        _verify_control_plane_before_gate(run_dir)
        _pre_gate_baseline = capture_baseline(exec_repo)
        assert_git_identity_unchanged(
            baseline, _pre_gate_baseline, context="legacy final frozen baseline"
        )
        final.update(
            {
                "finished_at": utc_now(),
                "verdict": "HUMAN_GATE",
                "status": "SUCCESS",
                "message": "Implementation, deterministic validators, and required review completed. No gated action was performed.",
                "final_baseline": _pre_gate_baseline,
            }
        )
        if ctx.isolated:
            assert workspace is not None
            _mark_workspace_preserved(workspace, exec_repo)
            atomic_json(run_dir / "workspace.json", workspace)
            final["workspace"] = {
                "isolated": True,
                "execution_repo": str(exec_repo),
                "baseline_commit": ctx.baseline_commit,
                "status": "PRESERVED",
            }
        atomic_json(run_dir / "final.json", final)
        return 0, run_dir, final
    except Exception as exc:
        # M2: handle Exception (not BaseException); map unexpected errors
        # to INTERNAL_ERROR.  KeyboardInterrupt/SystemExit propagate
        # through except Exception and are cleaned up by the finally block.
        code = _error_code_for(exc)
        final.update(
            {
                "finished_at": utc_now(),
                "verdict": code,
                "status": "STOPPED",
                "message": summarized(str(exc)),
            }
        )
        # F-04: a control-plane mutation stop must never advertise a gate.
        if code == "CONTROL_PLANE_MUTATED":
            final["human_gate"] = False
        if isinstance(exc, BudgetExhausted):
            final["budget_dimension"] = exc.dimension
        if workspace is not None and workspace.get("status") in ("READY", "CANDIDATE"):
            try:
                ws_exec = workspace.get("execution_repo")
                dirty_repo = (
                    Path(ws_exec)
                    if ws_exec
                    else ctx.execution_repo if ctx is not None else source_repo
                )
                _mark_workspace_preserved(workspace, dirty_repo)
            except Exception:
                workspace["preserved_dirty"] = True
                workspace["status"] = "PRESERVED"
            _best_effort_persist_workspace(run_dir, workspace)
        exec_repo_str = workspace.get("execution_repo") if workspace is not None else None
        try:
            exec_repo_path = (
                Path(exec_repo_str)
                if exec_repo_str
                else ctx.execution_repo if ctx is not None else source_repo
            )
        except Exception:
            exec_repo_path = ctx.execution_repo if ctx is not None else source_repo
        with contextlib.suppress(Exception):
            final["final_baseline"] = capture_baseline(exec_repo_path)
        if workspace is not None and workspace.get("execution_repo"):
            final["workspace"] = {
                "isolated": True,
                "execution_repo": workspace["execution_repo"],
                "baseline_commit": workspace.get("baseline_commit"),
                "status": workspace.get("status", "PRESERVED"),
            }
        try:
            atomic_json(run_dir / "final.json", final)
        except Exception:
            with contextlib.suppress(Exception):
                (run_dir / "final.json").write_text(
                    json.dumps(final, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
        return 2, run_dir, final
    finally:
        _control_plane_exit_run(_cp_token)


def _validate_architect_plan(result: dict[str, Any]) -> dict[str, Any]:
    plan = result.get("architect_plan")
    if not isinstance(plan, dict):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "architect_plan must be an object")
    required = {
        "objective_interpretation", "implementation_steps", "invariants",
        "allowed_scope", "do_not_change", "validation_expectations", "known_risks"
    }
    missing = sorted(required - plan.keys())
    if missing:
        raise AgentFlowError("INVALID_MODEL_OUTPUT", f"architect_plan missing fields: {missing}")
    if not isinstance(plan["objective_interpretation"], str) or not plan["objective_interpretation"].strip():
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "objective_interpretation must be a non-empty string")
    if not isinstance(plan["implementation_steps"], list) or not plan["implementation_steps"]:
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "implementation_steps must be a non-empty list")
    for key in ("invariants", "allowed_scope", "do_not_change", "validation_expectations", "known_risks"):
        if not isinstance(plan[key], list):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", f"{key} must be a list")
    for key in (
        "implementation_steps", "invariants", "allowed_scope", "do_not_change",
        "validation_expectations", "known_risks",
    ):
        if not all(isinstance(value, str) for value in plan[key]):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", f"{key} entries must be strings")
    # files_changed belongs to the generic result envelope, not the plan; a
    # missing nested value is accepted, a truthy one is rejected.
    if plan.get("files_changed"):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "architect_plan.files_changed must be empty")
    return plan


def _is_bmode_program(program: dict[str, Any]) -> bool:
    """True when the program opts into PROGRAM-001B sequential subtasks."""
    return "max_subtasks" in program


def _require_bmode_isolation(task: dict[str, Any]) -> None:
    """B-mode requires task.isolation.enabled == true."""
    isolation = task.get("isolation")
    if not (isinstance(isolation, dict) and isolation.get("enabled") is True):
        raise AgentFlowError(
            "INVALID_PROGRAM",
            "max_subtasks requires task.isolation.enabled == true",
        )


def _validate_bmode_subtasks(
    subtasks_raw: Any,
    max_subtasks: int,
    parent_allowed: list[str],
) -> list[dict[str, Any]]:
    """Validate architect_plan.subtasks for PROGRAM-001B.

    Returns normalized subtasks (allowed_paths normalized). Raises
    INVALID_MODEL_OUTPUT on any contract violation: non-list, empty,
    over max_subtasks/hard-max, unknown/missing fields, bad subtask_id,
    duplicates, bad objective, bad allowed_paths, non-list
    invariants/expected_outputs, or child scope broadening parent scope.
    """
    if not isinstance(subtasks_raw, list) or not subtasks_raw:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT",
            "architect_plan.subtasks must be a non-empty ordered array",
        )
    if len(subtasks_raw) > max_subtasks:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT",
            f"architect_plan.subtasks has {len(subtasks_raw)} items exceeding max_subtasks={max_subtasks}",
        )
    if len(subtasks_raw) > PROGRAM_BMODE_HARD_MAX:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT",
            f"architect_plan.subtasks exceeds hard maximum {PROGRAM_BMODE_HARD_MAX}",
        )
    try:
        normalized_parent = normalize_allowed(list(parent_allowed))
    except AgentFlowError as exc:
        raise AgentFlowError("INVALID_MODEL_OUTPUT", f"invalid parent allowed_paths: {exc}") from exc
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for item in subtasks_raw:
        if not isinstance(item, dict):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "subtask must be an object")
        keys = set(item.keys())
        if keys != set(_SUBTASK_ALLOWED_KEYS):
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT",
                f"subtask must have exactly {sorted(_SUBTASK_ALLOWED_KEYS)}; got {sorted(keys)}",
            )
        subtask_id = item["subtask_id"]
        if not isinstance(subtask_id, str) or not _SUBTASK_ID_RE.match(subtask_id):
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT", f"invalid subtask_id: {subtask_id!r}",
            )
        if subtask_id in seen:
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT", f"duplicate subtask_id: {subtask_id!r}",
            )
        seen.add(subtask_id)
        objective = item["objective"]
        if not isinstance(objective, str) or not objective.strip():
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "subtask objective must be a non-empty string")
        raw_allowed = item["allowed_paths"]
        if not isinstance(raw_allowed, list):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "subtask allowed_paths must be a list")
        for entry in raw_allowed:
            if not isinstance(entry, str):
                raise AgentFlowError("INVALID_MODEL_OUTPUT", "subtask allowed_paths entries must be strings")
        try:
            normalized_child = normalize_allowed(raw_allowed)
        except AgentFlowError as exc:
            raise AgentFlowError("INVALID_MODEL_OUTPUT", f"invalid subtask allowed_paths: {exc}") from exc
        # Child cannot broaden parent scope: every child path must fit parent.
        for child_path in normalized_child:
            if not path_allowed(child_path, normalized_parent):
                raise AgentFlowError(
                    "INVALID_MODEL_OUTPUT",
                    f"subtask {subtask_id!r} allowed_paths {child_path!r} exceeds parent scope",
                )
        invariants = item["invariants"]
        if not isinstance(invariants, list) or not all(isinstance(v, str) for v in invariants):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "subtask invariants must be a list of strings")
        expected_outputs = item["expected_outputs"]
        if not isinstance(expected_outputs, list) or not all(isinstance(v, str) for v in expected_outputs):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "subtask expected_outputs must be a list of strings")
        validated.append({
            "subtask_id": subtask_id,
            "objective": objective,
            "allowed_paths": normalized_child,
            "invariants": list(invariants),
            "expected_outputs": list(expected_outputs),
        })
    return validated


def _validate_bmode_architect_plan(
    result: dict[str, Any],
    max_subtasks: int,
    parent_allowed: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Validate the COMPLETE B-mode architect plan (legacy fields + subtasks)."""
    plan = _validate_architect_plan(result)
    if "subtasks" not in plan:
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "architect_plan.subtasks is required in B-mode")
    subtasks = _validate_bmode_subtasks(plan["subtasks"], max_subtasks, parent_allowed)
    return plan, subtasks


def _build_bmode_child_task(
    parent_task: dict[str, Any],
    subtask: dict[str, Any],
    exec_repo: Path,
) -> dict[str, Any]:
    """Construct the coordinator-owned child task for one validated subtask.

    Child inherits repo (execution worktree), risk, exact parent validators,
    unchanged forbidden_actions, parent+child invariants, and model timeout /
    inactivity budgets. Objective and allowed_paths come from the subtask.
    No child correction loop (max_corrections=0).
    """
    parent_invariants = parent_task.get("invariants") or []
    child_invariants = subtask.get("invariants") or []
    child: dict[str, Any] = {
        "task_id": f"{parent_task['task_id']}__{subtask['subtask_id']}",
        "repo": str(exec_repo),
        "risk": parent_task["risk"],
        "objective": subtask["objective"],
        "allowed_paths": list(subtask["allowed_paths"]),
        "validators": [dict(v) if isinstance(v, dict) else v for v in parent_task["validators"]],
        "forbidden_actions": list(parent_task.get("forbidden_actions") or []),
        "invariants": list(parent_invariants) + list(child_invariants),
        "expected_baseline": {},
        "max_corrections": 0,
    }
    if "model_timeout_seconds" in parent_task:
        child["model_timeout_seconds"] = parent_task["model_timeout_seconds"]
    if "model_inactivity_timeout_seconds" in parent_task:
        child["model_inactivity_timeout_seconds"] = parent_task[
            "model_inactivity_timeout_seconds"
        ]
    if parent_task.get("preferred_worker"):
        child["preferred_worker"] = parent_task["preferred_worker"]
    return child


def _baselines_equal_for_continuity(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Exact stable-state equality for PROGRAM_WORKSPACE_DRIFT checks.

    Compares branch identity (None means detached HEAD), head, sorted
    dirty/untracked paths, and the full path_state mapping.
    captured_at/repo/diff-check metadata are excluded so only workspace
    content identity matters. A detached→attached transition at the same
    commit is drift: the recorded branch identity differs.
    """
    if a.get("branch") != b.get("branch"):
        return False
    if a.get("head") != b.get("head"):
        return False
    if sorted(a.get("dirty_paths") or []) != sorted(b.get("dirty_paths") or []):
        return False
    if sorted(a.get("untracked_paths") or []) != sorted(b.get("untracked_paths") or []):
        return False
    if (a.get("path_state") or {}) != (b.get("path_state") or {}):
        return False
    return True


def _bmode_subtask_dir(run_dir: Path, ordinal: int, subtask_id: str) -> Path:
    """Deterministic per-subtask evidence directory."""
    return run_dir / "subtasks" / f"{ordinal}-{subtask_id}"


def _check_scope(
    delta: list[str],
    allowed: list[str],
    *,
    code: str = "UNAUTHORIZED_PATH_CHANGE",
) -> None:
    """Fail closed when any changed path escapes the allowed scope."""
    unauthorized = [path for path in delta if not path_allowed(path, allowed)]
    if unauthorized:
        raise AgentFlowError(code, repr(sorted(unauthorized)))


def _bmode_check_scope(
    delta: list[str],
    allowed: list[str],
    *,
    code: str = "UNAUTHORIZED_PATH_CHANGE",
) -> None:
    """B-mode call site for the shared scope-guard primitive."""
    _check_scope(delta, allowed, code=code)


def _accumulated_diff_stdout(
    repo: Path, allowed_paths: list[str], anchor_sha: str | None = None
) -> str:
    """Read-only working-tree + index evidence vs the execution baseline.

    B-mode runs on a detached worktree pinned at the baseline commit and
    workers cannot commit, so ``git diff HEAD`` faithfully describes staged
    AND unstaged tracked changes relative to the program execution
    baseline. Plain ``git diff`` (unstaged only) would silently hide
    ``git add`` / ``git mv`` content from the integrated reviewer.
    When ``anchor_sha`` (frozen baseline head) is supplied, diff against
    that commit so staged, unstaged, AND committed tracked content remain
    visible relative to the run baseline. Untracked paths remain covered
    by untracked/path-state evidence.
    Falls back to a staged+unstaged composition if HEAD is unresolvable.
    """
    if anchor_sha:
        try:
            anchored = git(
                repo, ["diff", str(anchor_sha), "--no-ext-diff", "--", *allowed_paths],
                timeout=120,
            )
            if anchored.returncode == 0:
                return anchored.stdout
        except Exception:
            pass
    head = git(repo, ["diff", "HEAD", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    if head.returncode == 0:
        return head.stdout
    cached = git(repo, ["diff", "--cached", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    unstaged = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    return "\n".join(part for part in (cached.stdout, unstaged.stdout) if part)


def _build_bmode_integrated_review_context(
    *,
    task: dict[str, Any],
    architect_plan: dict[str, Any],
    original_baseline: dict[str, Any],
    historical_completions: list[dict[str, Any]],
    integrated_correction: dict[str, Any] | None,
    current_baseline: dict[str, Any],
    accumulated_changed: list[str],
    repo: Path,
    allowed_paths: list[str],
    paths_later_modified_by_correction: list[str] | None = None,
) -> dict[str, Any]:
    """Integrated review context covering ALL children (never last-child only)."""
    anchor = original_baseline.get("head") if isinstance(original_baseline, dict) else None
    diff_stdout = _accumulated_diff_stdout(repo, allowed_paths, anchor_sha=anchor)
    return {
        "architect_plan": architect_plan,
        "original_program_execution_baseline": original_baseline,
        "historical_subtask_completions": historical_completions,
        "integrated_correction": integrated_correction,
        "current_final_candidate_baseline": current_baseline,
        "accumulated_changed_paths_from_program_baseline": accumulated_changed,
        "accumulated_diff_from_program_baseline": summarized(diff_stdout, 40000),
        "paths_later_modified_by_correction": list(
            paths_later_modified_by_correction or []
        ),
    }


def _bmode_verify_preservation(
    workspace: dict[str, Any] | None,
    source_repo: Path | None,
    exec_repo: Path,
    run_dir: Path,
) -> None:
    """Prove final preservation for HUMAN_GATE; fail closed otherwise.

    Checks workspace.json exists, status PRESERVED, the execution
    worktree directory still exists, AND the execution worktree is still
    registered in Git admin metadata via the WORKTREE-001A invariant
    _is_worktree_registered(source_repo, exec_repo). source_repo and
    exec_repo are kept distinct; registration cannot be proven without an
    explicit source_repo, so a missing source fails closed.
    Raises WORKSPACE_PRESERVATION_FAILED on any gap.
    """
    if workspace is None:
        raise AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "No workspace to preserve")
    ws_path = run_dir / "workspace.json"
    if not ws_path.is_file():
        raise AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "workspace.json missing")
    try:
        # Read directly (not via read_json) so program/task input mocks
        # cannot mask preservation evidence.
        persisted = json.loads(ws_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise AgentFlowError(
            "WORKSPACE_PRESERVATION_FAILED", f"workspace.json unreadable: {exc}"
        ) from exc
    if not isinstance(persisted, dict) or persisted.get("status") != "PRESERVED":
        raise AgentFlowError(
            "WORKSPACE_PRESERVATION_FAILED",
            f"workspace status is {persisted.get('status') if isinstance(persisted, dict) else type(persisted)}",
        )
    try:
        if not exec_repo.is_dir():
            raise AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "execution worktree missing")
    except AgentFlowError:
        raise
    except Exception as exc:
        raise AgentFlowError("WORKSPACE_PRESERVATION_FAILED", f"worktree check failed: {exc}") from exc
    # WORKTREE-001A registration proof: folder existence alone is not
    # preservation. Fail closed when the source is unavailable or the
    # execution worktree is no longer registered for that source.
    if source_repo is None:
        raise AgentFlowError(
            "WORKSPACE_PRESERVATION_FAILED", "source repo unavailable for registration proof"
        )
    try:
        registered = _is_worktree_registered(Path(source_repo), Path(exec_repo))
    except Exception as exc:
        raise AgentFlowError(
            "WORKSPACE_PRESERVATION_FAILED", f"worktree registration check failed: {exc}"
        ) from exc
    if not registered:
        raise AgentFlowError(
            "WORKSPACE_PRESERVATION_FAILED", "execution worktree not registered"
        )


def _validate_adjudication(result: dict[str, Any], issued_refs: list[str]) -> dict[str, Any]:
    adjudication = result.get("adjudication")
    if not isinstance(adjudication, dict):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "adjudication must be an object")
    required = {"correction_required", "classifications", "accepted_refs", "correction_brief", "stop_reason"}
    missing = sorted(required - adjudication.keys())
    if missing:
        raise AgentFlowError("INVALID_MODEL_OUTPUT", f"adjudication missing fields: {missing}")
    if not isinstance(adjudication["correction_required"], bool):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "correction_required must be a boolean")
    if not isinstance(adjudication["classifications"], dict):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "classifications must be an object")
    if not isinstance(adjudication["accepted_refs"], list):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "accepted_refs must be a list")
    if not all(isinstance(ref, str) for ref in adjudication["accepted_refs"]):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "accepted_refs entries must be strings")
    issued = set(issued_refs)
    classified = set(adjudication["classifications"].keys())
    if classified != issued:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT",
            "classifications must exactly cover the issued reviewer refs; "
            f"missing={sorted(issued - classified)} unknown={sorted(classified - issued)}",
        )
    if not set(adjudication["accepted_refs"]) <= issued:
        raise AgentFlowError(
            "INVALID_MODEL_OUTPUT",
            f"accepted_refs contains unissued refs: {sorted(set(adjudication['accepted_refs']) - issued)}",
        )
    valid_classifications = {"ACTIONABLE_REQUIRED", "ACTIONABLE_OPTIONAL", "NON_ACTIONABLE", "OUT_OF_SCOPE", "INCORRECT"}
    for ref, classification in adjudication["classifications"].items():
        if not isinstance(classification, str) or classification not in valid_classifications:
            raise AgentFlowError("INVALID_MODEL_OUTPUT", f"Invalid classification for {ref}: {classification}")
    if not adjudication["correction_required"]:
        if adjudication["accepted_refs"]:
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "accepted_refs must be empty when correction_required is false")
        if adjudication["correction_brief"] is not None:
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "correction_brief must be null when correction_required is false")
    else:
        if not adjudication["accepted_refs"]:
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "accepted_refs must be non-empty when correction_required is true")
        brief = adjudication["correction_brief"]
        if not isinstance(brief, dict):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "correction_brief must be an object")
        if not isinstance(brief.get("required_changes"), list) or not brief["required_changes"]:
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "correction_brief.required_changes must be a non-empty list")
        if not all(isinstance(change, str) for change in brief["required_changes"]):
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT",
                "correction_brief.required_changes entries must be strings",
            )
        for ref in adjudication["accepted_refs"]:
            if ref not in adjudication["classifications"]:
                raise AgentFlowError("INVALID_MODEL_OUTPUT", f"accepted_refs contains unknown ref: {ref}")
            classification = adjudication["classifications"][ref]
            if classification not in {"ACTIONABLE_REQUIRED", "ACTIONABLE_OPTIONAL"}:
                raise AgentFlowError("INVALID_MODEL_OUTPUT", f"accepted_refs can only contain ACTIONABLE_REQUIRED or ACTIONABLE_OPTIONAL refs, got {classification} for {ref}")
    if adjudication["stop_reason"] is not None and not isinstance(adjudication["stop_reason"], str):
        raise AgentFlowError("INVALID_MODEL_OUTPUT", "stop_reason must be a string or null")
    return adjudication


def _assign_finding_refs(findings: list[Any]) -> list[dict[str, Any]]:
    refs = []
    for idx, finding in enumerate(findings, start=1):
        ref = f"R1-F{idx}"
        if isinstance(finding, dict):
            finding_with_ref = dict(finding)
            finding_with_ref["ref"] = ref
        else:
            finding_with_ref = {"ref": ref, "text": str(finding)}
        refs.append(finding_with_ref)
    return refs


def _build_initial_review_context(
    task: dict[str, Any],
    architect_plan: dict[str, Any],
    worker_result: dict[str, Any],
    validator_results: list[dict[str, Any]],
    modified: list[str],
    repo: Path,
    allowed_paths: list[str],
    anchor_sha: str | None = None,
) -> dict[str, Any]:
    if anchor_sha:
        try:
            diff = git(
                repo, ["diff", str(anchor_sha), "--no-ext-diff", "--", *allowed_paths],
                timeout=120,
            )
            if diff.returncode != 0:
                diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
        except Exception:
            diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    else:
        diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    return {
        "architect_plan": architect_plan,
        "worker_result": worker_result,
        "validator_results": [
            {key: item[key] for key in ("name", "command", "exit_code", "status")}
            for item in validator_results
        ],
        "changed_files": modified,
        "git_diff": summarized(diff.stdout, 40000),
    }


def _build_adjudication_context(
    task: dict[str, Any],
    architect_plan: dict[str, Any],
    worker_result: dict[str, Any],
    validator_results: list[dict[str, Any]],
    initial_review_findings: list[dict[str, Any]],
    initial_reviewer_verdict: str,
    repo: Path,
    allowed_paths: list[str],
    anchor_sha: str | None = None,
) -> dict[str, Any]:
    if anchor_sha:
        try:
            diff = git(
                repo, ["diff", str(anchor_sha), "--no-ext-diff", "--", *allowed_paths],
                timeout=120,
            )
            if diff.returncode != 0:
                diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
        except Exception:
            diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    else:
        diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    return {
        "task": {k: task[k] for k in ("task_id", "risk", "objective", "allowed_paths", "invariants")},
        "architect_plan": architect_plan,
        "worker_result": worker_result,
        "validator_results": [
            {key: item[key] for key in ("name", "command", "exit_code", "status")}
            for item in validator_results
        ],
        "initial_review_findings": initial_review_findings,
        "initial_reviewer_verdict": initial_reviewer_verdict,
        "git_diff": summarized(diff.stdout, 40000),
    }


def _build_final_review_context(
    task: dict[str, Any],
    architect_plan: dict[str, Any],
    final_worker_result: dict[str, Any],
    final_validator_results: list[dict[str, Any]],
    final_modified: list[str],
    repo: Path,
    allowed_paths: list[str],
    anchor_sha: str | None = None,
) -> dict[str, Any]:
    if anchor_sha:
        try:
            diff = git(
                repo, ["diff", str(anchor_sha), "--no-ext-diff", "--", *allowed_paths],
                timeout=120,
            )
            if diff.returncode != 0:
                diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
        except Exception:
            diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    else:
        diff = git(repo, ["diff", "--no-ext-diff", "--", *allowed_paths], timeout=120)
    return {
        "architect_plan": architect_plan,
        "worker_result": final_worker_result,
        "validator_results": [
            {key: item[key] for key in ("name", "command", "exit_code", "status")}
            for item in final_validator_results
        ],
        "changed_files": final_modified,
        "git_diff": summarized(diff.stdout, 40000),
    }


def _build_correction_context(
    architect_plan: dict[str, Any],
    accepted_refs: list[str],
    correction_brief: dict[str, Any],
) -> dict[str, Any]:
    return {
        "kind": "adjudicated_correction",
        "architect_plan": architect_plan,
        "accepted_refs": accepted_refs,
        "correction_brief": correction_brief,
    }


def _check_readonly_mutation(
    repo: Path, before: dict[str, Any], role: str,
    expected: dict[str, Any] | None = None,
) -> None:
    after = capture_baseline(repo)
    assert_git_identity_unchanged(before, after, context=f"{role} readonly")
    if expected is not None:
        assert_git_identity_unchanged(expected, after, context=f"{role} frozen baseline")
    changed = changed_since(before, after)
    if changed:
        raise AgentFlowError("READONLY_ROLE_WROTE_REPO", f"{role} modified: {repr(changed)}")


def _read_program_input(path: Path, label: str) -> Any:
    """Load program/task JSON, converting I/O and parse failures to INVALID_PROGRAM."""
    try:
        return read_json(path)
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise AgentFlowError("INVALID_PROGRAM", f"Cannot load {label} {path}: {exc}") from exc


def _program_profile(models: Any, name: Any, role: str) -> dict[str, Any]:
    """Resolve one explicit program role profile without leaking raw KeyError."""
    profiles = models.get("profiles") if isinstance(models, dict) else None
    if not isinstance(profiles, dict):
        raise AgentFlowError("MODEL_UNAVAILABLE", "Models config has no profiles object")
    profile = profiles.get(name)
    if not isinstance(profile, dict):
        raise AgentFlowError("MODEL_UNAVAILABLE", f"No {role} profile named {name!r} in models config")
    command = profile.get("command")
    control = _ACTIVE_EXECUTION_CONTROL.get()
    command_missing = control is None and (not isinstance(command, str) or not shutil.which(command))
    if not profile.get("available") or not isinstance(command, str) or command_missing:
        raise AgentFlowError("MODEL_UNAVAILABLE", f"{role} profile {name!r} is unavailable")
    # F-05: a fallback is not exempt from role eligibility; fail closed.
    # Queue preflight labels fallbacks as "fallback <logical>"; resolve to
    # the logical role for the centralized eligibility check.
    logical = _logical_role(role)
    _check_role_eligible(profile, logical)
    if logical == "architect":
        # The architect profile is always reused as adjudicator by design.
        _check_role_eligible(profile, "adjudicator")
    return profile


def _queue_profile_usable(profile: dict[str, Any], role: str) -> None:
    """Stricter queue preflight for every primary/fallback physical backend."""
    backend = profile.get("backend")
    if backend not in {"opencode", "codex"}:
        raise AgentFlowError("INVALID_QUEUE", f"{role} profile has unusable backend {backend!r}")
    for key in ("provider", "model", "command"):
        if not isinstance(profile.get(key), str) or not profile[key].strip():
            raise AgentFlowError("INVALID_QUEUE", f"{role} profile has invalid {key}")
    if backend == "opencode" and (
        not isinstance(profile.get("agent"), str) or not profile["agent"].strip()
    ):
        raise AgentFlowError("INVALID_QUEUE", f"{role} OpenCode profile has no agent")
    # F-05: role eligibility is part of queue preflight. The role label may be
    # "fallback <logical>" for fallbacks; resolve to the logical role.
    logical = _logical_role(role)
    try:
        _check_role_eligible(profile, logical)
        # An architect profile is always reused as adjudicator by design, so
        # it must also be eligible for the adjudicator role.
        if logical == "architect":
            _check_role_eligible(profile, "adjudicator")
    except AgentFlowError as exc:
        if exc.code == "ROLE_NOT_ELIGIBLE":
            raise AgentFlowError("INVALID_QUEUE", f"{role} profile is not role-eligible: {exc}") from exc
        raise


def _bmode_architect_context(max_subtasks: int) -> dict[str, Any]:
    """Coordinator signal rendered into the ACTUAL B-mode architect request.

    invoke_model renders ``context`` verbatim as COORDINATOR_CONTEXT in the
    model-visible prompt, so this is the real signal — not an internal
    variable. A prompt-compliant architect emits sequential subtasks only
    when this instruction is present. A-mode passes context=None and is
    unaffected.
    """
    return {
        "kind": "program_001b_architect_planning",
        "mode": "program-001b",
        "bmode_active": True,
        "sequential_subtasks_requested": True,
        "instruction": (
            "PROGRAM-001B B-mode is active: plan SEQUENTIAL subtasks. "
            "Return a non-empty ordered architect_plan.subtasks array with "
            f"at most max_subtasks={max_subtasks} items (fewer than "
            "max_subtasks is allowed). Preserve all existing legacy "
            "architect_plan fields required by schema."
        ),
        "max_subtasks": max_subtasks,
        "subtasks_required": True,
    }


def _execute_bmode_program(
    *,
    program: dict[str, Any],
    task: dict[str, Any],
    source_repo: Path,
    run_id: str,
    run_dir: Path,
    final: dict[str, Any],
    workspace: dict[str, Any] | None,
    ctx: ExecutionContext | None,
    repo: Path,
    original_baseline: dict[str, Any],
    models: dict[str, Any],
) -> tuple[int, Path, dict[str, Any]]:
    """PROGRAM-001B sequential-subtask pipeline on ONE shared worktree.

    Crash order per child: program-plan.json -> started.json ->
    program-state RUNNING -> worker -> validators/checks -> completed.json ->
    program-state COMPLETED -> next started.json. Worker/validators PASS
    alone is never completion; completed.json is the durable point.
    """
    max_subtasks = program["max_subtasks"]
    final["max_subtasks"] = max_subtasks
    final["mode"] = "program-001b"
    current_ordinal = 0
    current_subtask_id: str | None = None
    current_subtask_dir: Path | None = None
    current_start_baseline: dict[str, Any] | None = None
    historical_completions: list[dict[str, Any]] = []
    architect_plan: dict[str, Any] | None = None
    subtasks: list[dict[str, Any]] = []
    worker_name: str | None = None
    worker_profile: dict[str, Any] | None = None
    reviewer_name: str | None = None
    reviewer_profile: dict[str, Any] | None = None
    try:
        _require_bmode_isolation(task)
        if ctx is None or not ctx.isolated or workspace is None:
            raise AgentFlowError("INVALID_PROGRAM", "B-mode requires an isolated execution worktree")

        architect_name_tmp = program["roles"]["architect"]
        # F-05: _program_profile also verifies the architect profile is
        # eligible for the adjudicator role it is reused for by design.
        architect_profile_tmp = _program_profile(models, architect_name_tmp, "architect")

        before_architect = capture_baseline(repo)
        architect_result, architect_invocation = invoke_model(
            role="architect", profile_name=architect_name_tmp,
            profile=architect_profile_tmp, task=task, run_dir=run_dir,
            cycle=0, context=_bmode_architect_context(max_subtasks),
            lease=None, exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_architect, "architect", expected=original_baseline
        )
        architect_plan, subtasks = _validate_bmode_architect_plan(
            architect_result, max_subtasks, task["allowed_paths"]
        )
        if any(
            not path_allowed(path, task["allowed_paths"])
            for path in architect_plan["allowed_scope"]
        ):
            raise AgentFlowError(
                "INVALID_MODEL_OUTPUT",
                "architect_plan.allowed_scope exceeds task.allowed_paths",
            )
        final["architect"] = architect_invocation
        final["architect_plan"] = architect_plan
        final["subtask_ids"] = [s["subtask_id"] for s in subtasks]
        atomic_json_fsync(
            run_dir / "program-plan.json",
            {
                "program_id": program["program_id"],
                "run_id": run_id,
                "max_subtasks": max_subtasks,
                "subtask_count": len(subtasks),
                "subtask_ids": [s["subtask_id"] for s in subtasks],
                "architect_plan": architect_plan,
                "validated_at": utc_now(),
            },
        )

        worker_name_tmp = program["roles"]["worker"]
        worker_profile_tmp = _program_profile(models, worker_name_tmp, "worker")
        reviewer_name_tmp = program["roles"]["reviewer"]
        reviewer_profile_tmp = _program_profile(models, reviewer_name_tmp, "reviewer")
        if model_family(worker_profile_tmp) == model_family(reviewer_profile_tmp):
            raise AgentFlowError(
                "REVIEWER_NOT_INDEPENDENT", model_family(worker_profile_tmp)
            )
        # F-05: adjudicator independence (architect profile acts as
        # adjudicator). Fail closed before any worker execution.
        _check_adjudicator_independence(
            worker_profile_tmp, reviewer_profile_tmp, architect_profile_tmp
        )
        worker_name, worker_profile = worker_name_tmp, worker_profile_tmp
        reviewer_name, reviewer_profile = reviewer_name_tmp, reviewer_profile_tmp

        for ordinal, subtask in enumerate(subtasks, start=1):
            current_ordinal = ordinal
            current_subtask_id = subtask["subtask_id"]
            subtask_dir = _bmode_subtask_dir(run_dir, ordinal, subtask["subtask_id"])
            current_subtask_dir = subtask_dir
            subtask_dir.mkdir(parents=True, exist_ok=False)
            atomic_json_fsync(
                subtask_dir / "subtask.json",
                {
                    "ordinal": ordinal,
                    "subtask_id": subtask["subtask_id"],
                    "subtask": subtask,
                    "parent_task_id": task["task_id"],
                    "persisted_at": utc_now(),
                },
            )
            if ordinal > 1:
                prev = subtasks[ordinal - 2]
                prev_dir = _bmode_subtask_dir(run_dir, ordinal - 1, prev["subtask_id"])
                if not (prev_dir / "completed.json").is_file():
                    raise AgentFlowError(
                        "PROGRAM_WORKSPACE_DRIFT",
                        f"previous subtask {prev['subtask_id']!r} has no completed.json",
                    )
                expected_start = historical_completions[-1]["end_baseline"]
            else:
                expected_start = original_baseline
            current_start = capture_baseline(repo)
            current_start_baseline = current_start
            if not _baselines_equal_for_continuity(current_start, expected_start):
                raise AgentFlowError(
                    "PROGRAM_WORKSPACE_DRIFT",
                    f"worktree drift before subtask {subtask['subtask_id']!r}",
                )
            atomic_json_fsync(
                subtask_dir / "started.json",
                {
                    "ordinal": ordinal,
                    "subtask_id": subtask["subtask_id"],
                    "start_baseline": current_start,
                    "started_at": utc_now(),
                },
            )
            atomic_json_fsync(
                run_dir / "program-state.json",
                {
                    "program_id": program["program_id"],
                    "run_id": run_id,
                    "status": "RUNNING",
                    "current_ordinal": ordinal,
                    "current_subtask_id": subtask["subtask_id"],
                    "completed_subtasks": [c["subtask_id"] for c in historical_completions],
                    "subtask_count": len(subtasks),
                    "updated_at": utc_now(),
                },
            )
            child_task = _build_bmode_child_task(task, subtask, repo)
            with WriteLease(repo, child_task["task_id"], run_id) as worker_lease:
                worker_result, worker_invocation = invoke_model(
                    role="worker", profile_name=worker_name,
                    profile=worker_profile, task=child_task,
                    run_dir=subtask_dir, cycle=0,
                    context={
                        "architect_plan": architect_plan,
                        "subtask": subtask,
                        "ordinal": ordinal,
                    },
                    lease=worker_lease, exec_repo=repo,
                )
            after_worker = capture_baseline(repo)
            assert_git_identity_unchanged(
                original_baseline, after_worker,
                context="bmode worker frozen baseline",
            )
            assert_git_identity_unchanged(
                current_start, after_worker, context="bmode worker"
            )
            child_delta = changed_since(current_start, after_worker)
            parent_delta = changed_since(original_baseline, after_worker)
            _bmode_check_scope(child_delta, subtask["allowed_paths"])
            _bmode_check_scope(parent_delta, task["allowed_paths"])
            worker_result["files_changed"] = child_delta
            worker_result["validators"] = {}
            final[f"subtask_{ordinal}_worker"] = worker_invocation
            atomic_json(subtask_dir / "worker-cycle-0-result.json", worker_result)
            if worker_blocks(worker_result):
                raise AgentFlowError(
                    "SUBTASK_WORKER_BLOCKED",
                    f"subtask {subtask['subtask_id']!r} worker blocked",
                )
            validator_results = run_validators(repo, task["validators"], subtask_dir, 0)
            worker_result["validators"] = {
                item["name"]: {"status": item["status"], "exit_code": item["exit_code"]}
                for item in validator_results
            }
            atomic_json(subtask_dir / "worker-cycle-0-result.json", worker_result)
            after_validators = capture_baseline(repo)
            assert_git_identity_unchanged(
                original_baseline, after_validators,
                context="bmode validators frozen baseline",
            )
            child_delta2 = changed_since(current_start, after_validators)
            parent_delta2 = changed_since(original_baseline, after_validators)
            _bmode_check_scope(child_delta2, subtask["allowed_paths"])
            _bmode_check_scope(parent_delta2, task["allowed_paths"])
            if any(item["status"] != "PASS" for item in validator_results):
                raise AgentFlowError(
                    "VALIDATOR_FAILED",
                    next(item["name"] for item in validator_results if item["status"] != "PASS"),
                )
            completed = {
                "ordinal": ordinal,
                "subtask_id": subtask["subtask_id"],
                "start_baseline": current_start,
                "end_baseline": after_validators,
                "child_changed_paths": child_delta2,
                "parent_accumulated_changed_paths": parent_delta2,
                "worker_verdict": worker_result.get("verdict"),
                "validators": [
                    {k: item[k] for k in ("name", "status", "exit_code")}
                    for item in validator_results
                ],
                "completed_at": utc_now(),
            }
            atomic_json_fsync(subtask_dir / "completed.json", completed)
            historical_completions.append(completed)
            if ordinal < len(subtasks):
                state_status = "RUNNING"
            else:
                state_status = "COMPLETED"
            atomic_json_fsync(
                run_dir / "program-state.json",
                {
                    "program_id": program["program_id"],
                    "run_id": run_id,
                    "status": state_status,
                    "current_ordinal": ordinal,
                    "current_subtask_id": subtask["subtask_id"],
                    "completed_subtasks": [c["subtask_id"] for c in historical_completions],
                    "subtask_count": len(subtasks),
                    "updated_at": utc_now(),
                },
            )
            current_subtask_dir = None
            current_start_baseline = None

        assert architect_plan is not None
        assert worker_name is not None and worker_profile is not None
        assert reviewer_name is not None and reviewer_profile is not None

        current_candidate = capture_baseline(repo)
        assert_git_identity_unchanged(
            original_baseline, current_candidate,
            context="bmode pre-review frozen baseline",
        )
        accumulated_changed = changed_since(original_baseline, current_candidate)
        integrated_context = _build_bmode_integrated_review_context(
            task=task, architect_plan=architect_plan,
            original_baseline=original_baseline,
            historical_completions=historical_completions,
            integrated_correction=None,
            current_baseline=current_candidate,
            accumulated_changed=accumulated_changed,
            repo=repo, allowed_paths=task["allowed_paths"],
        )
        before_review = capture_baseline(repo)
        assert_git_identity_unchanged(
            original_baseline, before_review,
            context="bmode pre-review frozen baseline",
        )
        reviewer_result, reviewer_invocation = invoke_model(
            role="reviewer", profile_name=reviewer_name,
            profile=reviewer_profile, task=task, run_dir=run_dir,
            cycle=0, context=integrated_context, exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_review, "integrated_reviewer",
            expected=original_baseline,
        )
        validate_reviewer_result(reviewer_result)
        integrated_reviewer_verdict = normalize_reviewer_verdict(reviewer_result.get("verdict"))
        findings_with_refs = _assign_finding_refs(reviewer_result.get("findings", []))
        reviewer_result["findings"] = findings_with_refs
        final["integrated_reviewer"] = reviewer_invocation
        final["integrated_reviewer_result"] = reviewer_result
        atomic_json(run_dir / "reviewer-cycle-0-result.json", reviewer_result)

        adjudicator_name = program["roles"]["architect"]
        # F-05: eligibility was checked in the earlier _program_profile call;
        # independence was enforced before the worker loop.
        adjudicator_profile = _program_profile(models, adjudicator_name, "architect")
        before_adjudicator = capture_baseline(repo)
        assert_git_identity_unchanged(
            original_baseline, before_adjudicator,
            context="bmode pre-adjudication frozen baseline",
        )
        _bmode_anchor = original_baseline.get("head") if isinstance(original_baseline, dict) else None
        diff_stdout = _accumulated_diff_stdout(
            repo, task["allowed_paths"], anchor_sha=_bmode_anchor
        )
        adjudication_context = {
            "task": {k: task[k] for k in ("task_id", "risk", "objective", "allowed_paths", "invariants")},
            "architect_plan": architect_plan,
            "historical_subtask_completions": historical_completions,
            "accumulated_changed_paths": accumulated_changed,
            "initial_review_findings": findings_with_refs,
            "initial_reviewer_verdict": integrated_reviewer_verdict,
            "git_diff": summarized(diff_stdout, 40000),
        }
        adjudicator_result, adjudicator_invocation = invoke_model(
            role="adjudicator", profile_name=adjudicator_name,
            profile=adjudicator_profile, task=task, run_dir=run_dir,
            cycle=0, context=adjudication_context, lease=None, exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_adjudicator, "adjudicator",
            expected=original_baseline,
        )
        issued_refs = [finding["ref"] for finding in findings_with_refs]
        adjudication = _validate_adjudication(adjudicator_result, issued_refs)
        final["adjudicator"] = adjudicator_invocation
        final["adjudication"] = adjudication
        atomic_json(run_dir / "adjudicator-cycle-0-result.json", adjudicator_result)

        correction_required = adjudication["correction_required"]
        accepted_refs = adjudication["accepted_refs"]
        correction_brief = adjudication["correction_brief"]
        stop_reason = adjudication["stop_reason"]
        if stop_reason:
            raise AgentFlowError("ADJUDICATION_STOP", stop_reason)

        integrated_correction: dict[str, Any] | None = None
        paths_later_modified: list[str] = []
        final_validator_results: list[dict[str, Any]] | None = None
        if correction_required:
            if program["max_corrections"] == 0:
                raise AgentFlowError(
                    "ADJUDICATION_STOP",
                    "Adjudicator requested correction but program max_corrections=0",
                )
            before_correction = capture_baseline(repo)
            assert_git_identity_unchanged(
                original_baseline, before_correction,
                context="bmode correction start frozen baseline",
            )
            atomic_json_fsync(
                run_dir / "correction-started.json",
                {
                    "start_baseline": before_correction,
                    "accepted_refs": accepted_refs,
                    "correction_brief": correction_brief,
                    "started_at": utc_now(),
                },
            )
            correction_context = _build_correction_context(
                architect_plan, accepted_refs, correction_brief
            )
            with WriteLease(repo, task["task_id"], run_id) as correction_lease:
                correction_result, correction_invocation = invoke_model(
                    role="worker", profile_name=worker_name,
                    profile=worker_profile, task=task, run_dir=run_dir,
                    cycle=1, context=correction_context,
                    lease=correction_lease, exec_repo=repo,
                )
            after_correction = capture_baseline(repo)
            assert_git_identity_unchanged(
                original_baseline, after_correction,
                context="bmode correction frozen baseline",
            )
            assert_git_identity_unchanged(
                before_correction, after_correction,
                context="bmode correction worker",
            )
            correction_parent_delta = changed_since(original_baseline, after_correction)
            _bmode_check_scope(correction_parent_delta, task["allowed_paths"])
            correction_result["files_changed"] = changed_since(before_correction, after_correction)
            final["correction_worker"] = correction_invocation
            final["correction_worker_result"] = correction_result
            atomic_json(run_dir / "worker-cycle-1-result.json", correction_result)
            correction_validators = run_validators(repo, task["validators"], run_dir, 1)
            correction_result["validators"] = {
                item["name"]: {"status": item["status"], "exit_code": item["exit_code"]}
                for item in correction_validators
            }
            final["correction_worker_result"] = correction_result
            atomic_json(run_dir / "worker-cycle-1-result.json", correction_result)
            final["validators_cycle_1"] = correction_validators
            after_correction_validators = capture_baseline(repo)
            assert_git_identity_unchanged(
                original_baseline, after_correction_validators,
                context="bmode correction validators frozen baseline",
            )
            correction_parent_delta2 = changed_since(original_baseline, after_correction_validators)
            _bmode_check_scope(correction_parent_delta2, task["allowed_paths"])
            if any(item["status"] != "PASS" for item in correction_validators):
                raise AgentFlowError(
                    "VALIDATOR_FAILED",
                    next(item["name"] for item in correction_validators if item["status"] != "PASS"),
                )
            integrated_correction = {
                "start_baseline": before_correction,
                "end_baseline": after_correction_validators,
                "correction_changed_paths": changed_since(before_correction, after_correction_validators),
                "parent_accumulated_changed_paths": correction_parent_delta2,
                "accepted_refs": accepted_refs,
                "correction_brief": correction_brief,
                "completed_at": utc_now(),
            }
            atomic_json_fsync(run_dir / "correction-completed.json", integrated_correction)
            paths_later_modified = changed_since(before_correction, after_correction_validators)
            final_validator_results = correction_validators
            final["correction_cycles"] = 1
        else:
            final["correction_cycles"] = 0

        current_final = capture_baseline(repo)
        assert_git_identity_unchanged(
            original_baseline, current_final,
            context="bmode final frozen baseline",
        )
        accumulated_final = changed_since(original_baseline, current_final)
        final_review_context = _build_bmode_integrated_review_context(
            task=task, architect_plan=architect_plan,
            original_baseline=original_baseline,
            historical_completions=historical_completions,
            integrated_correction=integrated_correction,
            current_baseline=current_final,
            accumulated_changed=accumulated_final,
            repo=repo, allowed_paths=task["allowed_paths"],
            paths_later_modified_by_correction=paths_later_modified,
        )
        before_final_review = capture_baseline(repo)
        assert_git_identity_unchanged(
            original_baseline, before_final_review,
            context="bmode pre-final-review frozen baseline",
        )
        final_reviewer_result, final_reviewer_invocation = invoke_model(
            role="reviewer", profile_name=reviewer_name,
            profile=reviewer_profile, task=task, run_dir=run_dir,
            cycle=1, context=final_review_context, exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_final_review, "final_reviewer",
            expected=original_baseline,
        )
        final["final_reviewer"] = final_reviewer_invocation
        final["final_reviewer_result"] = final_reviewer_result
        atomic_json(run_dir / "reviewer-cycle-1-result.json", final_reviewer_result)
        validate_reviewer_result(final_reviewer_result)
        if reviewer_blocks(final_reviewer_result):
            raise AgentFlowError("FINAL_REVIEW_BLOCKED", "Final reviewer verdict is BLOCKER/HIGH")

        # F-04: verify immediately before HUMAN_GATE.
        _verify_control_plane_before_gate(run_dir)
        active_control = _ACTIVE_EXECUTION_CONTROL.get()
        if active_control is not None:
            active_control.enter_finalization()
        _bmode_pre_gate = capture_baseline(repo)
        assert_git_identity_unchanged(
            original_baseline, _bmode_pre_gate,
            context="bmode final frozen baseline",
        )
        final.update(
            {
                "finished_at": utc_now(),
                "verdict": "HUMAN_GATE",
                "status": "SUCCESS",
                "human_gate": True,
                "message": "Program-001B pipeline completed. Awaiting human gate.",
                "final_baseline": _bmode_pre_gate,
                "subtask_count": len(subtasks),
                "accumulated_changed_paths": accumulated_final,
                "integrated_review_cycle": 0,
                "final_reviewer_cycle": 1,
            }
        )
        assert workspace is not None
        _mark_workspace_preserved(workspace, repo)
        atomic_json(run_dir / "workspace.json", workspace)
        final["workspace"] = {
            "isolated": True,
            "execution_repo": str(repo),
            "baseline_commit": ctx.baseline_commit if ctx is not None else None,
            "status": "PRESERVED",
        }
        try:
            _bmode_verify_preservation(workspace, source_repo, repo, run_dir)
        except AgentFlowError as exc:
            final.update(
                {
                    "finished_at": utc_now(),
                    "verdict": exc.code,
                    "status": "STOPPED",
                    "human_gate": False,
                    "message": summarized(str(exc)),
                }
            )
            with contextlib.suppress(Exception):
                atomic_json(run_dir / "final.json", final)
            return 2, run_dir, final
        atomic_json(run_dir / "final.json", final)
        return 0, run_dir, final
    except Exception as exc:
        active_control = _ACTIVE_EXECUTION_CONTROL.get()
        if active_control is not None:
            active_control.enter_finalization()
        code = _error_code_for(exc)
        if current_subtask_dir is not None and current_subtask_id is not None:
            try:
                failed_end = None
                with contextlib.suppress(Exception):
                    failed_end = capture_baseline(repo)
                atomic_json_fsync(
                    current_subtask_dir / "failed.json",
                    {
                        "ordinal": current_ordinal,
                        "subtask_id": current_subtask_id,
                        "start_baseline": current_start_baseline,
                        "end_baseline": failed_end,
                        "failure_code": code,
                        "message": summarized(str(exc)),
                        "failed_at": utc_now(),
                    },
                )
            except Exception:
                pass
            try:
                atomic_json_fsync(
                    run_dir / "program-state.json",
                    {
                        "program_id": program["program_id"],
                        "run_id": run_id,
                        "status": "STOPPED",
                        "current_ordinal": current_ordinal,
                        "current_subtask_id": current_subtask_id,
                        "completed_subtasks": [c["subtask_id"] for c in historical_completions],
                        "verdict": code,
                        "updated_at": utc_now(),
                    },
                )
            except Exception:
                pass
        final.update(
            {
                "finished_at": utc_now(),
                "verdict": code,
                "status": "STOPPED",
                "human_gate": False,
                "message": summarized(str(exc)),
            }
        )
        if isinstance(exc, BudgetExhausted):
            final["budget_dimension"] = exc.dimension
        preservation_secondary: dict[str, Any] | None = None
        if workspace is not None and workspace.get("status") in ("READY", "CANDIDATE"):
            try:
                ws_exec = workspace.get("execution_repo")
                dirty_repo = (
                    Path(ws_exec)
                    if ws_exec
                    else ctx.execution_repo if ctx is not None else source_repo
                )
                _mark_workspace_preserved(workspace, dirty_repo)
            except Exception:
                workspace["preserved_dirty"] = True
                workspace["status"] = "PRESERVED"
            _best_effort_persist_workspace(run_dir, workspace)
        try:
            exec_repo_str = workspace.get("execution_repo") if workspace is not None else None
            exec_repo_path = (
                Path(exec_repo_str)
                if exec_repo_str
                else ctx.execution_repo if ctx is not None else source_repo
            )
        except Exception:
            exec_repo_path = ctx.execution_repo if ctx is not None else source_repo
        with contextlib.suppress(Exception):
            final["final_baseline"] = capture_baseline(exec_repo_path)
        if workspace is not None and workspace.get("execution_repo"):
            final["workspace"] = {
                "isolated": True,
                "execution_repo": workspace["execution_repo"],
                "baseline_commit": workspace.get("baseline_commit"),
                "status": workspace.get("status", "PRESERVED"),
            }
        # Secondary preservation evidence must never mask the primary
        # failure: keep original verdict, persist preservation failure
        # separately. Verification failure (mocked or real) is authoritative.
        try:
            exec_check = (
                Path(workspace["execution_repo"])
                if workspace is not None and workspace.get("execution_repo")
                else exec_repo_path
            )
            _bmode_verify_preservation(workspace, source_repo, exec_check, run_dir)
        except AgentFlowError as preserv_exc:
            if code != preserv_exc.code:
                preservation_secondary = {
                    "code": preserv_exc.code,
                    "message": summarized(str(preserv_exc)),
                }
                final["preservation_failure"] = preservation_secondary
                with contextlib.suppress(Exception):
                    atomic_json(
                        run_dir / "preservation-failure.json", preservation_secondary
                    )
        except Exception:
            pass
        try:
            atomic_json(run_dir / "final.json", final)
        except Exception:
            with contextlib.suppress(Exception):
                (run_dir / "final.json").write_text(
                    json.dumps(final, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
        return 2, run_dir, final


def _run_validated_program_tuple(
    program: dict[str, Any], task: dict[str, Any], run_identity: RunIdentity
) -> tuple[int, Path, dict[str, Any]]:
    source_repo = Path(task["repo"]).resolve()
    run_id = run_identity.run_id
    run_dir = run_identity.run_dir
    run_dir.mkdir(parents=True, exist_ok=False)
    atomic_json(run_dir / "program.json", program)
    atomic_json(run_dir / "task.json", redact_config(task))

    final: dict[str, Any] = {
        "program_id": program["program_id"],
        "task_id": task["task_id"],
        "run_id": run_id,
        "started_at": utc_now(),
        "verdict": "RUNNING",
        "human_gate": False,
        "program_max_corrections": program["max_corrections"],
        "correction_cycles": 0,
    }
    workspace: dict[str, Any] | None = None
    ctx: ExecutionContext | None = None
    # F-04: immutable run baseline before untrusted execution.
    _cp_token = _control_plane_enter_run(run_dir)

    try:
        # F-04: durable poison gate — after computing the run baseline
        # manifest but BEFORE any worktree creation or model invocation
        # (A-mode and B-mode both dispatch from here), refuse to accept a
        # manifest previously observed as mutated.
        _control_plane_check_poison(run_dir)
        isolation_enabled = isinstance(task.get("isolation"), dict) and task["isolation"].get("enabled") is True
        source_head: str | None = None
        if isolation_enabled:
            source_head = _resolve_source_head(source_repo)

        ctx = build_execution_context(task, run_id)
        repo = ctx.execution_repo

        if ctx.isolated:
            workspace = {
                "version": 1,
                "run_id": run_id,
                "source_repo": str(source_repo),
                "source_head": source_head,
                "baseline_commit": ctx.baseline_commit,
                "execution_repo": str(repo),
                "worktree_root": str(worktree_root()),
                "created_at": utc_now(),
                "detached": True,
                "verified_head": ctx.baseline_commit,
                "status": "READY",
                "preserved_dirty": False,
                "cleanup": None,
            }
            try:
                atomic_json(run_dir / "source_baseline.json", capture_baseline(source_repo))
                atomic_json(run_dir / "workspace.json", workspace)
            except Exception:
                _reconcile_unbound_worktree(source_repo, repo, run_dir, workspace)
                raise

        baseline = capture_baseline(repo)
        atomic_json(run_dir / "baseline.json", baseline)
        if not ctx.isolated:
            mismatches = baseline_mismatches(baseline, task["expected_baseline"])
            if mismatches:
                raise AgentFlowError("BASELINE_DRIFT", "; ".join(mismatches))

        active_control = _ACTIVE_EXECUTION_CONTROL.get()
        if active_control is not None:
            models = active_control.models
        else:
            try:
                models = load_models()
            except AgentFlowError:
                raise
            except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
                raise AgentFlowError("MODEL_UNAVAILABLE", f"Cannot load models config: {exc}") from exc
        # Finding Runner freezes effective F-05 profiles in its preflight and
        # supplies that immutable snapshot in the derived task. The normal
        # Program path remains unchanged.
        frozen_profiles = task.get("_finding_frozen_profiles")
        if isinstance(frozen_profiles, dict):
            models = dict(models)
            models["profiles"] = dict(frozen_profiles)

        if workspace is not None:
            workspace["status"] = "CANDIDATE"
            atomic_json(run_dir / "workspace.json", workspace)

        # PROGRAM-001B opt-in dispatch: absence preserves 001A behavior.
        if _is_bmode_program(program):
            return _execute_bmode_program(
                program=program, task=task, source_repo=source_repo,
                run_id=run_id, run_dir=run_dir, final=final,
                workspace=workspace, ctx=ctx, repo=repo,
                original_baseline=baseline, models=models,
            )

        # --- Architect ---
        architect_name = program["roles"]["architect"]
        # F-05: _program_profile also verifies the architect profile is
        # eligible for the adjudicator role it is reused for by design.
        architect_profile = _program_profile(models, architect_name, "architect")

        before_architect = capture_baseline(repo)
        architect_result, architect_invocation = invoke_model(
            role="architect", profile_name=architect_name, profile=architect_profile,
            task=task, run_dir=run_dir, cycle=0, context=None, lease=None,
            exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_architect, "architect", expected=baseline
        )
        architect_plan = _validate_architect_plan(architect_result)
        if any(not path_allowed(path, task["allowed_paths"]) for path in architect_plan["allowed_scope"]):
            raise AgentFlowError("INVALID_MODEL_OUTPUT", "architect_plan.allowed_scope exceeds task.allowed_paths")
        final["architect"] = architect_invocation
        final["architect_plan"] = architect_plan

        # --- Pre-worker role resolution and independence (F-05) ---
        # Resolve every participating profile and prove reviewer and
        # adjudicator independence BEFORE the worker model can be invoked,
        # matching the B-mode pre-worker protection. A same-family
        # worker/adjudicator pair must never get a worker process spawn or
        # workspace mutation.
        worker_name = program["roles"]["worker"]
        worker_profile = _program_profile(models, worker_name, "worker")
        reviewer_name = program["roles"]["reviewer"]
        reviewer_profile = _program_profile(models, reviewer_name, "reviewer")
        if model_family(worker_profile) == model_family(reviewer_profile):
            raise AgentFlowError("REVIEWER_NOT_INDEPENDENT", model_family(worker_profile))
        _check_adjudicator_independence(
            worker_profile, reviewer_profile, architect_profile
        )

        # --- Worker Cycle 0 ---
        before_worker = capture_baseline(repo)
        with WriteLease(repo, task["task_id"], run_id) as worker_lease:
            worker_result, worker_invocation = invoke_model(
                role="worker", profile_name=worker_name, profile=worker_profile,
                task=task, run_dir=run_dir, cycle=0, context={"architect_plan": architect_plan},
                lease=worker_lease, exec_repo=repo,
            )
        after_worker = capture_baseline(repo)
        assert_git_identity_unchanged(
            baseline, after_worker, context="amode worker frozen baseline"
        )
        assert_git_identity_unchanged(
            before_worker, after_worker, context="amode worker"
        )
        modified = changed_since(before_worker, after_worker)
        unauthorized = [path for path in modified if not path_allowed(path, task["allowed_paths"])]
        if unauthorized:
            raise AgentFlowError("UNAUTHORIZED_PATH_CHANGE", repr(unauthorized))
        worker_result["files_changed"] = modified
        final["worker_cycle_0"] = worker_invocation
        final["worker_result"] = worker_result
        atomic_json(run_dir / "worker-cycle-0-result.json", worker_result)

        # --- Validators Cycle 0 ---
        validator_results = run_validators(repo, task["validators"], run_dir, 0)
        after_validators = capture_baseline(repo)
        assert_git_identity_unchanged(
            baseline, after_validators,
            context="amode validators frozen baseline",
        )
        _check_scope(changed_since(before_worker, after_validators), task["allowed_paths"])
        worker_result["validators"] = {
            item["name"]: {"status": item["status"], "exit_code": item["exit_code"]}
            for item in validator_results
        }
        final["worker_result"] = worker_result
        atomic_json(run_dir / "worker-cycle-0-result.json", worker_result)
        final["validators_cycle_0"] = validator_results
        if any(item["status"] != "PASS" for item in validator_results):
            raise AgentFlowError("VALIDATOR_FAILED", next(item["name"] for item in validator_results if item["status"] != "PASS"))

        # --- Initial Reviewer (Cycle 0) ---
        # F-05: worker/reviewer/adjudicator profiles were resolved and
        # independence was enforced at the single pre-worker preflight above.
        before_review = capture_baseline(repo)
        assert_git_identity_unchanged(
            baseline, before_review, context="amode pre-review frozen baseline"
        )
        _amode_anchor = baseline.get("head") if isinstance(baseline, dict) else None
        initial_review_context = _build_initial_review_context(
            task, architect_plan, worker_result, validator_results, modified, repo, task["allowed_paths"],
            anchor_sha=_amode_anchor,
        )
        reviewer_result, reviewer_invocation = invoke_model(
            role="reviewer", profile_name=reviewer_name, profile=reviewer_profile,
            task=task, run_dir=run_dir, cycle=0, context=initial_review_context,
            exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_review, "initial_reviewer", expected=baseline
        )
        validate_reviewer_result(reviewer_result)
        initial_reviewer_verdict = normalize_reviewer_verdict(reviewer_result.get("verdict"))
        initial_findings_with_refs = _assign_finding_refs(reviewer_result.get("findings", []))
        reviewer_result["findings"] = initial_findings_with_refs
        final["initial_reviewer"] = reviewer_invocation
        final["initial_reviewer_result"] = reviewer_result
        atomic_json(run_dir / "reviewer-cycle-0-result.json", reviewer_result)

        # --- Adjudicator ---
        adjudicator_name = program["roles"]["architect"]
        # F-05: architect_profile was eligibility-checked for the adjudicator
        # role; independence was enforced before the review invocation.
        adjudicator_profile = architect_profile

        before_adjudicator = capture_baseline(repo)
        assert_git_identity_unchanged(
            baseline, before_adjudicator,
            context="amode pre-adjudication frozen baseline",
        )
        adjudication_context = _build_adjudication_context(
            task, architect_plan, worker_result, validator_results,
            initial_findings_with_refs, initial_reviewer_verdict,
            repo, task["allowed_paths"],
            anchor_sha=_amode_anchor,
        )
        adjudicator_result, adjudicator_invocation = invoke_model(
            role="adjudicator", profile_name=adjudicator_name, profile=adjudicator_profile,
            task=task, run_dir=run_dir, cycle=0, context=adjudication_context, lease=None,
            exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_adjudicator, "adjudicator", expected=baseline
        )
        issued_refs = [finding["ref"] for finding in initial_findings_with_refs]
        adjudication = _validate_adjudication(adjudicator_result, issued_refs)
        final["adjudicator"] = adjudicator_invocation
        final["adjudication"] = adjudication
        atomic_json(run_dir / "adjudicator-cycle-0-result.json", adjudicator_result)

        correction_required = adjudication["correction_required"]
        accepted_refs = adjudication["accepted_refs"]
        correction_brief = adjudication["correction_brief"]
        stop_reason = adjudication["stop_reason"]

        if stop_reason:
            raise AgentFlowError("ADJUDICATION_STOP", stop_reason)

        # --- Optional Correction Worker (Cycle 1) ---
        worker_cycle_1_result = None
        if correction_required:
            if program["max_corrections"] == 0:
                raise AgentFlowError("ADJUDICATION_STOP", "Adjudicator requested correction but program max_corrections=0")
            before_correction = capture_baseline(repo)
            assert_git_identity_unchanged(
                baseline, before_correction,
                context="amode correction start frozen baseline",
            )
            correction_context = _build_correction_context(architect_plan, accepted_refs, correction_brief)
            with WriteLease(repo, task["task_id"], run_id) as worker_lease:
                worker_result_1, worker_invocation_1 = invoke_model(
                    role="worker", profile_name=worker_name, profile=worker_profile,
                    task=task, run_dir=run_dir, cycle=1, context=correction_context,
                    lease=worker_lease, exec_repo=repo,
                )
            after_correction = capture_baseline(repo)
            assert_git_identity_unchanged(
                baseline, after_correction,
                context="amode correction frozen baseline",
            )
            assert_git_identity_unchanged(
                before_correction, after_correction,
                context="amode correction worker",
            )
            modified_1 = changed_since(before_correction, after_correction)
            unauthorized_1 = [path for path in modified_1 if not path_allowed(path, task["allowed_paths"])]
            if unauthorized_1:
                raise AgentFlowError("UNAUTHORIZED_PATH_CHANGE", repr(unauthorized_1))
            worker_result_1["files_changed"] = modified_1
            final["worker_cycle_1"] = worker_invocation_1
            final["worker_result_cycle_1"] = worker_result_1
            atomic_json(run_dir / "worker-cycle-1-result.json", worker_result_1)

            # --- Validators Cycle 1 ---
            validator_results_1 = run_validators(repo, task["validators"], run_dir, 1)
            after_validators_1 = capture_baseline(repo)
            assert_git_identity_unchanged(
                baseline, after_validators_1,
                context="amode correction validators frozen baseline",
            )
            _check_scope(changed_since(before_correction, after_validators_1), task["allowed_paths"])
            worker_result_1["validators"] = {
                item["name"]: {"status": item["status"], "exit_code": item["exit_code"]}
                for item in validator_results_1
            }
            final["worker_result_cycle_1"] = worker_result_1
            atomic_json(run_dir / "worker-cycle-1-result.json", worker_result_1)
            final["validators_cycle_1"] = validator_results_1
            if any(item["status"] != "PASS" for item in validator_results_1):
                raise AgentFlowError("VALIDATOR_FAILED", next(item["name"] for item in validator_results_1 if item["status"] != "PASS"))

            worker_cycle_1_result = worker_result_1
            final_validator_results = validator_results_1
            final_modified = modified_1
            final["correction_cycles"] = 1
        else:
            final_validator_results = validator_results
            final_modified = modified

        # --- Final Reviewer (Cycle 1) ---
        # Freeze the exact candidate the existing final reviewer is about to
        # inspect. This is independent of Git's dirty/untracked report.
        finding_candidate = task.get("finding_candidate_integrity") is True
        if finding_candidate and (not ctx.isolated or ctx.baseline_commit != task["isolation"]["baseline_commit"]):
            raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Finding candidate is not isolated at its frozen baseline")
        reviewed_candidate_before = (
            capture_candidate_manifest(repo, source_repo, ctx.baseline_commit)
            if finding_candidate else None
        )
        before_final_review = capture_baseline(repo)
        assert_git_identity_unchanged(
            baseline, before_final_review,
            context="amode pre-final-review frozen baseline",
        )
        final_review_context = _build_final_review_context(
            task, architect_plan,
            worker_cycle_1_result if worker_cycle_1_result else worker_result,
            final_validator_results,
            final_modified,
            repo, task["allowed_paths"],
            anchor_sha=_amode_anchor,
        )
        final_reviewer_result, final_reviewer_invocation = invoke_model(
            role="reviewer", profile_name=reviewer_name, profile=reviewer_profile,
            task=task, run_dir=run_dir, cycle=1, context=final_review_context,
            exec_repo=repo,
        )
        _check_readonly_mutation(
            repo, before_final_review, "final_reviewer", expected=baseline
        )
        final["final_reviewer"] = final_reviewer_invocation
        final["final_reviewer_result"] = final_reviewer_result
        atomic_json(run_dir / "reviewer-cycle-1-result.json", final_reviewer_result)

        validate_reviewer_result(final_reviewer_result)
        if finding_candidate:
            reviewed_candidate_after = capture_candidate_manifest(repo, source_repo, ctx.baseline_commit)
            if candidate_manifest_digest(reviewed_candidate_before) != candidate_manifest_digest(reviewed_candidate_after):
                raise AgentFlowError(
                    "CANDIDATE_INTEGRITY_CHANGED",
                    "Candidate changed during final review",
                )
            reviewed_manifest_path = run_dir / "reviewed-candidate-manifest.json"
            atomic_json_fsync(reviewed_manifest_path, reviewed_candidate_after)
            final["reviewed_candidate"] = {
                "manifest": reviewed_manifest_path.name,
                "sha256": sha256_path(reviewed_manifest_path),
                "candidate_digest": candidate_manifest_digest(reviewed_candidate_after),
            }
        if reviewer_blocks(final_reviewer_result):
            raise AgentFlowError("FINAL_REVIEW_BLOCKED", "Final reviewer verdict is BLOCKER/HIGH")

        # --- HUMAN_GATE ---
        # F-04: verify immediately before HUMAN_GATE.
        _verify_control_plane_before_gate(run_dir)
        if finding_candidate:
            pre_gate_candidate = capture_candidate_manifest(repo, source_repo, ctx.baseline_commit)
            if candidate_manifest_digest(pre_gate_candidate) != final["reviewed_candidate"]["candidate_digest"]:
                raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Candidate changed after final review")
        active_control = _ACTIVE_EXECUTION_CONTROL.get()
        if active_control is not None:
            active_control.enter_finalization()
        _amode_pre_gate = capture_baseline(repo)
        assert_git_identity_unchanged(
            baseline, _amode_pre_gate, context="amode final frozen baseline"
        )
        final.update(
            {
                "finished_at": utc_now(),
                "verdict": "HUMAN_GATE",
                "status": "SUCCESS",
                "human_gate": True,
                "message": "Program pipeline completed. Awaiting human gate.",
                "final_baseline": _amode_pre_gate,
                "initial_reviewer_cycle": 0,
                "final_reviewer_cycle": 1,
            }
        )
        if ctx.isolated:
            assert workspace is not None
            _mark_workspace_preserved(workspace, repo)
            atomic_json(run_dir / "workspace.json", workspace)
            final["workspace"] = {
                "isolated": True,
                "execution_repo": str(repo),
                "baseline_commit": ctx.baseline_commit,
                "status": "PRESERVED",
            }
        if finding_candidate:
            final_candidate = capture_candidate_manifest(repo, source_repo, ctx.baseline_commit)
            if candidate_manifest_digest(final_candidate) != final["reviewed_candidate"]["candidate_digest"]:
                raise AgentFlowError("CANDIDATE_INTEGRITY_CHANGED", "Candidate changed immediately before Program HUMAN_GATE")
        atomic_json(run_dir / "final.json", final)
        return 0, run_dir, final

    except Exception as exc:
        active_control = _ACTIVE_EXECUTION_CONTROL.get()
        if active_control is not None:
            active_control.enter_finalization()
        code = _error_code_for(exc)
        final.update(
            {
                "finished_at": utc_now(),
                "verdict": code,
                "status": "STOPPED",
                "message": summarized(str(exc)),
            }
        )
        if isinstance(exc, BudgetExhausted):
            final["budget_dimension"] = exc.dimension
        if workspace is not None and workspace.get("status") in ("READY", "CANDIDATE"):
            try:
                ws_exec = workspace.get("execution_repo")
                dirty_repo = (
                    Path(ws_exec)
                    if ws_exec
                    else ctx.execution_repo if ctx is not None else source_repo
                )
                _mark_workspace_preserved(workspace, dirty_repo)
            except Exception:
                workspace["preserved_dirty"] = True
                workspace["status"] = "PRESERVED"
            _best_effort_persist_workspace(run_dir, workspace)
        exec_repo_str = workspace.get("execution_repo") if workspace is not None else None
        try:
            exec_repo_path = (
                Path(exec_repo_str)
                if exec_repo_str
                else ctx.execution_repo if ctx is not None else source_repo
            )
        except Exception:
            exec_repo_path = ctx.execution_repo if ctx is not None else source_repo
        with contextlib.suppress(Exception):
            final["final_baseline"] = capture_baseline(exec_repo_path)
        if workspace is not None and workspace.get("execution_repo"):
            final["workspace"] = {
                "isolated": True,
                "execution_repo": workspace["execution_repo"],
                "baseline_commit": workspace.get("baseline_commit"),
                "status": workspace.get("status", "PRESERVED"),
            }
        try:
            atomic_json(run_dir / "final.json", final)
        except Exception:
            with contextlib.suppress(Exception):
                (run_dir / "final.json").write_text(
                    json.dumps(final, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
        return 2, run_dir, final
    finally:
        _control_plane_exit_run(_cp_token)


_QUEUE_FATAL_VERDICTS = {
    "UNAUTHORIZED_PATH_CHANGE", "READONLY_ROLE_WROTE_REPO",
    "PROGRAM_WORKSPACE_DRIFT", "WORKSPACE_PRESERVATION_FAILED",
    "INTERNAL_ERROR", "WRITE_LEASE_CONFLICT", "WRITE_LEASE_OWNERSHIP_LOST",
    "GIT_STATUS_FAILED", "WORKTREE_CREATE_FAILED", "WORKTREE_PATH_ESCAPE",
    "WORKTREE_EXISTS", "REVIEWER_NOT_INDEPENDENT", "ADJUDICATOR_NOT_INDEPENDENT",
    "ROLE_NOT_ELIGIBLE", "PROVIDER_AUTH_OR_CONFIGURATION",
    "REPO_NOT_FOUND", "NOT_A_GIT_REPO", "BASELINE_COMMIT_UNKNOWN",
    "UNKNOWN_BACKEND", "INVALID_PROGRAM", "INVALID_TASK", "INVALID_QUEUE",
    "GIT_IDENTITY_MOVED", "CONTROL_PLANE_MUTATED", "CANDIDATE_INTEGRITY_CHANGED",
}


def _verified_program_outcome(
    *, program: dict[str, Any], task: dict[str, Any], run_identity: RunIdentity,
    returned_final: dict[str, Any], execution_control: ExecutionControl | None,
) -> ProgramOutcome:
    final_path = run_identity.run_dir / "final.json"
    verification_error: str | None = None
    try:
        with final_path.open(encoding="utf-8") as handle:
            durable = json.load(handle)
        if not isinstance(durable, dict) or durable != returned_final:
            verification_error = "returned ProgramOutcome does not agree with durable final.json"
    except Exception as exc:
        durable = {}
        verification_error = f"final.json missing or unreadable: {exc}"
    required = {"program_id": program["program_id"], "task_id": task["task_id"], "run_id": run_identity.run_id}
    if verification_error is None and any(durable.get(k) != v for k, v in required.items()):
        verification_error = "final.json identity mismatch"
    if verification_error is not None:
        durable = dict(returned_final) if isinstance(returned_final, dict) else {}
        durable.update({
            **required, "finished_at": utc_now(), "verdict": "INTERNAL_ERROR",
            "status": "STOPPED", "human_gate": False,
            "message": verification_error,
        })
        atomic_json_fsync(final_path, durable)
        with final_path.open(encoding="utf-8") as handle:
            durable = json.load(handle)
    try:
        with final_path.open("rb") as handle:
            os.fsync(handle.fileno())
        fsync_directory(final_path.parent)
    except OSError as exc:
        durable.update({
            "finished_at": utc_now(), "verdict": "INTERNAL_ERROR",
            "status": "STOPPED", "human_gate": False,
            "message": f"Cannot prove final.json durability: {exc}",
        })
        atomic_json_fsync(final_path, durable)
    digest = sha256_path(final_path)

    workspace_path = run_identity.run_dir / "workspace.json"
    preservation = "NOT_REQUIRED"
    preservation_evidence: str | None = None
    execution_repo = str(Path(task["repo"]).resolve())
    baseline_commit = str(task.get("isolation", {}).get("baseline_commit", ""))
    secondary: list[dict[str, Any]] = []
    isolated = isinstance(task.get("isolation"), dict) and task["isolation"].get("enabled") is True
    if isolated:
        preservation_evidence = str(workspace_path)
        if not workspace_path.is_file():
            expected_repo = _worktree_destination(run_identity.run_id)
            try:
                allocated = expected_repo.exists() or _is_worktree_registered(
                    Path(task["repo"]).resolve(), expected_repo
                )
            except Exception:
                allocated = True
            if allocated:
                preservation = "UNCERTAIN"
                secondary.append({
                    "code": "WORKSPACE_PRESERVATION_FAILED",
                    "message": "isolated worktree may exist without workspace evidence",
                })
            else:
                preservation = "NOT_REQUIRED"
                preservation_evidence = None
        else:
            try:
                with workspace_path.open(encoding="utf-8") as handle:
                    workspace = json.load(handle)
                execution_repo = str(workspace["execution_repo"])
                baseline_commit = str(workspace["baseline_commit"])
                if workspace.get("status") != "PRESERVED":
                    raise AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "workspace is not PRESERVED")
                if execution_control is not None:
                    if not Path(execution_repo).is_dir() or not _is_worktree_registered(
                        Path(workspace["source_repo"]), Path(execution_repo)
                    ):
                        raise AgentFlowError(
                            "WORKSPACE_PRESERVATION_FAILED", "worktree registration is not proven"
                        )
                preservation = "PROVEN"
            except Exception as exc:
                preservation = "UNCERTAIN"
                secondary.append({
                    "code": "WORKSPACE_PRESERVATION_FAILED", "message": summarized(str(exc))
                })
    # Queue mode consumes positive lifecycle evidence from the process
    # adapters.  Standalone behavior remains compatible because it has no
    # queue control/evidence contract.
    process_quiescence = (
        execution_control.process_quiescence()
        if execution_control is not None
        else "UNCERTAIN" if durable.get("verdict") == "INTERNAL_ERROR" else "PROVEN"
    )
    verdict = str(durable.get("verdict", "INTERNAL_ERROR"))
    if preservation == "UNCERTAIN" and execution_control is not None:
        outcome_class = "PRESERVATION_UNCERTAIN"
    elif verdict == "BUDGET_EXHAUSTED":
        outcome_class = "BUDGET_STOP"
    elif durable.get("human_gate") is True and verdict == "HUMAN_GATE":
        outcome_class = "HUMAN_GATE"
    elif verdict in _QUEUE_FATAL_VERDICTS or process_quiescence != "PROVEN":
        outcome_class = "QUEUE_FATAL_FAILURE"
    else:
        outcome_class = "PROGRAM_LOCAL_FAILURE"
    primary = None if outcome_class == "HUMAN_GATE" else verdict
    if isinstance(durable.get("preservation_failure"), dict):
        secondary.append(dict(durable["preservation_failure"]))
    return ProgramOutcome(
        run_id=run_identity.run_id, run_dir=str(run_identity.run_dir),
        final_path=str(final_path), final_sha256=digest,
        program_id=program["program_id"], task_id=task["task_id"],
        verdict=verdict, status=str(durable.get("status", "STOPPED")),
        human_gate=bool(durable.get("human_gate", False)), outcome_class=outcome_class,
        primary_failure=primary, secondary_failures=secondary,
        budget_dimension=durable.get("budget_dimension"), execution_repo=execution_repo,
        baseline_commit=baseline_commit, preservation_status=preservation,
        preservation_evidence_path=preservation_evidence,
        process_quiescence=process_quiescence, final=durable,
    )


def execute_program(
    validated_program: dict[str, Any], validated_task: dict[str, Any],
    run_identity: RunIdentity, execution_control: ExecutionControl | None = None,
) -> ProgramOutcome:
    """Execute the existing A/B program state machine and return queue evidence."""
    token = _ACTIVE_EXECUTION_CONTROL.set(execution_control)
    # F-04: one immutable control-plane baseline per queue item / program run.
    _cp_token = _control_plane_enter_run(run_identity.run_dir)
    try:
        _code, _run_dir, final = _run_validated_program_tuple(
            validated_program, validated_task, run_identity
        )
        return _verified_program_outcome(
            program=validated_program, task=validated_task, run_identity=run_identity,
            returned_final=final, execution_control=execution_control,
        )
    finally:
        _control_plane_exit_run(_cp_token)
        _ACTIVE_EXECUTION_CONTROL.reset(token)


def verify_program_outcome(outcome: ProgramOutcome) -> None:
    """Fail closed unless queue-consumed evidence is durable and identical."""
    path = Path(outcome.final_path)
    if not path.is_file() or sha256_path(path) != outcome.final_sha256:
        raise AgentFlowError("INTERNAL_ERROR", "ProgramOutcome final digest mismatch")
    try:
        with path.open(encoding="utf-8") as handle:
            durable = json.load(handle)
    except Exception as exc:
        raise AgentFlowError("INTERNAL_ERROR", f"ProgramOutcome final unreadable: {exc}") from exc
    if durable != outcome.final:
        raise AgentFlowError("INTERNAL_ERROR", "ProgramOutcome semantic mismatch")
    for key, expected in (
        ("run_id", outcome.run_id), ("program_id", outcome.program_id),
        ("task_id", outcome.task_id), ("verdict", outcome.verdict),
        ("status", outcome.status), ("human_gate", outcome.human_gate),
    ):
        if durable.get(key) != expected:
            raise AgentFlowError("INTERNAL_ERROR", f"ProgramOutcome {key} mismatch")
    if (
        outcome.preservation_status == "UNCERTAIN"
        and outcome.outcome_class != "PRESERVATION_UNCERTAIN"
    ):
        raise AgentFlowError("WORKSPACE_PRESERVATION_FAILED", "preservation is not proven")
    if outcome.process_quiescence != "PROVEN":
        raise AgentFlowError("INTERNAL_ERROR", "process quiescence is not proven")


def _load_program_and_task(program_path: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    resolved_program = program_path.resolve()
    program = validate_program(_read_program_input(resolved_program, "program spec"))
    task_path = Path(program["task"])
    task_path = (
        (resolved_program.parent / task_path).resolve()
        if not task_path.is_absolute() else task_path.resolve()
    )
    task = validate_task(_read_program_input(task_path, "program task"))
    return program, task, task_path


def run_program(program_path: Path) -> tuple[int, Path, dict[str, Any]]:
    """Standalone compatibility wrapper; no queue-only behavior is enabled."""
    program, task, _task_path = _load_program_and_task(program_path)
    timestamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    run_id = f"{timestamp}-{safe_slug(program['program_id'])}"
    identity = RunIdentity(run_id, RUNS_DIR / run_id)
    outcome = execute_program(program, task, identity, None)
    return (0 if outcome.human_gate else 2), identity.run_dir, outcome.final


def _json_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_keys(value: Any, allowed: set[str], required: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentFlowError("INVALID_QUEUE", f"{label} must be an object")
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown or missing:
        raise AgentFlowError("INVALID_QUEUE", f"{label}: unknown={unknown}, missing={missing}")
    return value


def preflight_queue(queue_path: Path) -> tuple[dict[str, Any], list[FrozenQueueItem], dict[str, Any]]:
    """Validate and freeze the complete queue before creating any artifact."""
    try:
        raw = read_json(queue_path.resolve())
    except Exception as exc:
        raise AgentFlowError("INVALID_QUEUE", f"Cannot load queue: {exc}") from exc
    queue = _strict_keys(
        raw, {"queue_id", "items", "budgets", "recovery"},
        {"queue_id", "items", "budgets"}, "queue",
    )
    queue_id = queue["queue_id"]
    if not isinstance(queue_id, str) or not _QUEUE_ID_RE.fullmatch(queue_id):
        raise AgentFlowError("INVALID_QUEUE", "queue_id is not a safe identifier")
    items = queue["items"]
    if not isinstance(items, list) or not 1 <= len(items) <= QUEUE_HARD_MAX:
        raise AgentFlowError("INVALID_QUEUE", "items must contain 1..8 entries")
    budgets = _strict_keys(
        queue["budgets"],
        {"wall_clock_seconds", "model_calls", "retries", "fallbacks", "corrections"},
        {"wall_clock_seconds", "model_calls", "retries", "fallbacks", "corrections"},
        "budgets",
    )
    ranges = {
        "wall_clock_seconds": (1, 86400), "model_calls": (1, 128),
        "retries": (0, 128), "fallbacks": (0, 128), "corrections": (0, 8),
    }
    for key, (low, high) in ranges.items():
        value = budgets[key]
        if type(value) is not int or not low <= value <= high:
            raise AgentFlowError("INVALID_QUEUE", f"budgets.{key} must be an integer {low}..{high}")
    recovery = queue.get("recovery", {})
    _strict_keys(recovery, {"fallback_profiles"}, set(), "recovery")
    fallback_names = recovery.get("fallback_profiles", {})
    _strict_keys(fallback_names, {"architect", "worker", "reviewer"}, set(), "fallback_profiles")
    for role, name in fallback_names.items():
        if not isinstance(name, str) or not name.strip():
            raise AgentFlowError("INVALID_QUEUE", f"fallback profile for {role} must be a name")

    try:
        models = load_models()
    except Exception as exc:
        raise AgentFlowError("INVALID_QUEUE", f"Cannot load models config: {exc}") from exc
    profiles = models.get("profiles") if isinstance(models, dict) else None
    if not isinstance(profiles, dict):
        raise AgentFlowError("INVALID_QUEUE", "models config has no profiles")
    resolved_fallbacks: dict[str, dict[str, Any]] = {}
    for role, name in fallback_names.items():
        try:
            resolved_fallbacks[role] = _program_profile(models, name, f"fallback {role}")
            _queue_profile_usable(resolved_fallbacks[role], f"fallback {role}")
        except AgentFlowError as exc:
            raise AgentFlowError("INVALID_QUEUE", str(exc)) from exc

    frozen: list[FrozenQueueItem] = []
    seen: set[str] = set()
    for ordinal, raw_item in enumerate(items, start=1):
        item = _strict_keys(raw_item, {"item_id", "program"}, {"item_id", "program"}, f"items[{ordinal}]")
        item_id = item["item_id"]
        if not isinstance(item_id, str) or not _QUEUE_ID_RE.fullmatch(item_id):
            raise AgentFlowError("INVALID_QUEUE", f"invalid item_id at ordinal {ordinal}")
        if item_id in seen:
            raise AgentFlowError("INVALID_QUEUE", f"duplicate item_id {item_id!r}")
        seen.add(item_id)
        if not isinstance(item["program"], str) or not item["program"].strip():
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id} program must be a path")
        program_path = Path(item["program"])
        program_path = (
            (queue_path.resolve().parent / program_path).resolve()
            if not program_path.is_absolute() else program_path.resolve()
        )
        try:
            program, task, task_path = _load_program_and_task(program_path)
        except Exception as exc:
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: {exc}") from exc
        isolation = task.get("isolation")
        if not isinstance(isolation, dict) or isolation.get("enabled") is not True:
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id} requires task.isolation.enabled=true")
        try:
            baseline = _canonical_sha(str(isolation.get("baseline_commit", "")))
        except AgentFlowError as exc:
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: {exc}") from exc
        source_repo = Path(task["repo"]).resolve()
        for validator_index, validator in enumerate(task["validators"], start=1):
            if isinstance(validator, str):
                command, validator_timeout = validator, 1800
            elif isinstance(validator, dict):
                command = validator.get("command", [])
                validator_timeout = validator.get("timeout_seconds", 1800)
            else:
                raise AgentFlowError(
                    "INVALID_QUEUE", f"item {item_id}: validator {validator_index} is invalid"
                )
            if type(validator_timeout) is not int or validator_timeout <= 0:
                raise AgentFlowError(
                    "INVALID_QUEUE", f"item {item_id}: validator {validator_index} timeout is invalid"
                )
            try:
                safe_validator_argv(command)
            except AgentFlowError as exc:
                raise AgentFlowError(
                    "INVALID_QUEUE", f"item {item_id}: validator {validator_index}: {exc}"
                ) from exc
        try:
            resolved_baseline = _resolve_commit_object(source_repo, baseline)
        except AgentFlowError as exc:
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: {exc}") from exc
        role_profiles: dict[str, dict[str, Any]] = {}
        for role in ("architect", "worker", "reviewer"):
            name = program["roles"][role]
            try:
                role_profiles[role] = _program_profile(models, name, role)
                _queue_profile_usable(role_profiles[role], role)
            except AgentFlowError as exc:
                raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: {exc}") from exc
            fallback_name = fallback_names.get(role)
            if fallback_name == name:
                raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: {role} fallback equals primary")
        worker_options = [role_profiles["worker"]]
        reviewer_options = [role_profiles["reviewer"]]
        architect_options = [role_profiles["architect"]]
        if "worker" in resolved_fallbacks:
            worker_options.append(resolved_fallbacks["worker"])
        if "reviewer" in resolved_fallbacks:
            reviewer_options.append(resolved_fallbacks["reviewer"])
        if "architect" in resolved_fallbacks:
            architect_options.append(resolved_fallbacks["architect"])
        try:
            independence_broken = any(
                model_family(w) == model_family(r)
                for w in worker_options for r in reviewer_options
            )
            # F-05: adjudicator (== architect profile) must be independent
            # from worker and reviewer across all primary/fallback combos.
            adjudicator_broken = any(
                model_family(w) == model_family(a)
                for w in worker_options for a in architect_options
            ) or any(
                model_family(r) == model_family(a)
                for r in reviewer_options for a in architect_options
            )
        except Exception as exc:
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: invalid model profile: {exc}") from exc
        if independence_broken:
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: reviewer independence is not invariant")
        if adjudicator_broken:
            raise AgentFlowError("INVALID_QUEUE", f"item {item_id}: adjudicator independence is not invariant")
        frozen_program = json.loads(json.dumps(program))
        frozen_task = json.loads(json.dumps(task))
        effective_profiles = {
            **{f"primary_{k}": json.loads(json.dumps(v)) for k, v in role_profiles.items()},
            **{f"fallback_{k}": json.loads(json.dumps(v)) for k, v in resolved_fallbacks.items()},
        }
        frozen.append(FrozenQueueItem(
            ordinal=ordinal, item_id=item_id, queue_item=json.loads(json.dumps(item)),
            program_path=program_path, program=frozen_program,
            task_path=task_path, task=frozen_task, source_repo=source_repo,
            baseline_commit=resolved_baseline, profiles=effective_profiles,
            hashes={
                "queue_item_sha256": _json_hash(item),
                "program_sha256": _json_hash(frozen_program),
                "task_sha256": _json_hash(frozen_task),
                "models_sha256": sha256_path(MODELS_FILE),
                "effective_profiles_sha256": _json_hash(effective_profiles),
            },
        ))
    return json.loads(json.dumps(queue)), frozen, models


def _queue_snapshot(
    queue_id: str, completed: list[dict[str, Any]], current: str | None, status: str
) -> dict[str, Any]:
    return {
        "queue_id": queue_id, "status": status, "current_item_id": current,
        "completed_item_ids": [item["item_id"] for item in completed],
        "updated_at": utc_now(),
    }


def run_queue(
    queue_path: Path, *, monotonic: Callable[[], float] = time.monotonic
) -> tuple[int, Path | None, dict[str, Any]]:
    """Run a fully preflighted queue sequentially; there is deliberately no resume."""
    try:
        queue, frozen, models = preflight_queue(queue_path)
    except AgentFlowError as exc:
        return 2, None, {"verdict": "INVALID_QUEUE", "status": "STOPPED", "message": str(exc)}

    timestamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    queue_run_id = f"{timestamp}-{safe_slug(queue['queue_id'])}-{uuid.uuid4().hex[:8]}"
    queue_run_dir = QUEUE_RUNS_DIR / queue_run_id
    queue_run_dir.mkdir(parents=True, exist_ok=False)
    plan = {
        "queue_id": queue["queue_id"], "queue_run_id": queue_run_id,
        "queue_sha256": _json_hash(queue),
        "budgets": queue["budgets"], "recovery": queue.get("recovery", {}),
        "items": [{
            "ordinal": item.ordinal, "item_id": item.item_id,
            "queue_item": item.queue_item, "program_path": str(item.program_path),
            "task_path": str(item.task_path), "program": item.program,
            "task": redact_config(item.task), "source_repo": str(item.source_repo),
            "baseline_commit": item.baseline_commit, "effective_profiles": redact_config(item.profiles),
            "hashes": item.hashes,
        } for item in frozen],
        "planned_at": utc_now(),
    }
    atomic_json_fsync(queue_run_dir / "queue-plan.json", plan)
    programs_dir = queue_run_dir / "programs"
    programs_dir.mkdir(parents=True, exist_ok=True)
    fallback_names = queue.get("recovery", {}).get("fallback_profiles", {})
    control = ExecutionControl(
        queue_id=queue["queue_id"], queue_run_dir=queue_run_dir,
        item_dir=programs_dir, budgets=queue["budgets"],
        fallback_profiles=fallback_names, models=models, monotonic=monotonic,
    )
    control.start()
    atomic_json_fsync(queue_run_dir / "queue-started.json", {
        "queue_id": queue["queue_id"], "queue_run_id": queue_run_id,
        "started_at": utc_now(), "item_count": len(frozen),
    })
    control.persist_budget_state()
    completed: list[dict[str, Any]] = []
    human_gates: list[dict[str, Any]] = []
    first_precise_failure: str | None = None
    stop_verdict: str | None = None
    stop_dimension: str | None = None
    for item in frozen:
        try:
            control.check_deadline()
            if control.used["model_calls"] >= control.budgets["model_calls"]:
                raise BudgetExhausted("MODEL_CALLS")
        except BudgetExhausted as exc:
            stop_verdict, stop_dimension = exc.code, exc.dimension
            break
        item_dir = programs_dir / f"{item.ordinal:02d}-{safe_slug(item.item_id)}"
        item_dir.mkdir(parents=True, exist_ok=False)
        control.item_dir = item_dir
        control.finalizing = False
        control.reset_item_process_evidence()
        run_id = f"{queue_run_id}-{item.ordinal:02d}-{safe_slug(item.item_id)}"
        identity = RunIdentity(run_id, RUNS_DIR / run_id)
        atomic_json_fsync(item_dir / "item-started.json", {
            "ordinal": item.ordinal, "item_id": item.item_id,
            "program_id": item.program["program_id"], "task_id": item.task["task_id"],
            "run_id": run_id, "run_dir": str(identity.run_dir), "started_at": utc_now(),
        })
        outcome = execute_program(item.program, item.task, identity, control)
        try:
            verify_program_outcome(outcome)
        except AgentFlowError as integrity_exc:
            repaired = dict(outcome.final)
            repaired.update({
                "program_id": item.program["program_id"], "task_id": item.task["task_id"],
                "run_id": run_id, "verdict": "INTERNAL_ERROR", "status": "STOPPED",
                "human_gate": False, "message": str(integrity_exc), "finished_at": utc_now(),
            })
            final_path = identity.run_dir / "final.json"
            atomic_json_fsync(final_path, repaired)
            outcome = ProgramOutcome(
                run_id=run_id, run_dir=str(identity.run_dir), final_path=str(final_path),
                final_sha256=sha256_path(final_path), program_id=item.program["program_id"],
                task_id=item.task["task_id"], verdict="INTERNAL_ERROR", status="STOPPED",
                human_gate=False, outcome_class="QUEUE_FATAL_FAILURE",
                primary_failure="INTERNAL_ERROR",
                secondary_failures=[{"code": integrity_exc.code, "message": str(integrity_exc)}],
                budget_dimension=None, execution_repo=outcome.execution_repo,
                baseline_commit=item.baseline_commit,
                preservation_status=outcome.preservation_status,
                preservation_evidence_path=outcome.preservation_evidence_path,
                process_quiescence=outcome.process_quiescence, final=repaired,
            )
        terminal = {
            "ordinal": item.ordinal, "item_id": item.item_id,
            "program_outcome": asdict(outcome), "terminal_at": utc_now(),
        }
        atomic_json_fsync(item_dir / "item-terminal.json", terminal)
        summary = {
            "ordinal": item.ordinal, "item_id": item.item_id,
            "program_id": outcome.program_id, "task_id": outcome.task_id,
            "run_id": outcome.run_id, "run_dir": outcome.run_dir,
            "verdict": outcome.verdict, "status": outcome.status,
            "outcome_class": outcome.outcome_class,
            "final_path": outcome.final_path, "final_sha256": outcome.final_sha256,
            "execution_repo": outcome.execution_repo,
            "baseline_commit": outcome.baseline_commit,
            "final_baseline": outcome.final.get("final_baseline"),
            "final_change_summary": {
                "dirty_paths": (outcome.final.get("final_baseline") or {}).get("dirty_paths", []),
                "untracked_paths": (outcome.final.get("final_baseline") or {}).get("untracked_paths", []),
                "accumulated_changed_paths": outcome.final.get("accumulated_changed_paths", []),
            },
        }
        completed.append(summary)
        if (
            first_precise_failure is None
            and outcome.outcome_class == "PROGRAM_LOCAL_FAILURE"
        ):
            first_precise_failure = outcome.primary_failure or outcome.verdict
        if outcome.outcome_class == "HUMAN_GATE":
            human_gates.append(summary)
        atomic_json_fsync(
            queue_run_dir / "queue-state.json",
            _queue_snapshot(queue["queue_id"], completed, item.item_id, "RUNNING"),
        )
        control.persist_budget_state()
        if outcome.outcome_class in {"QUEUE_FATAL_FAILURE", "PRESERVATION_UNCERTAIN"}:
            stop_verdict = (
                (outcome.primary_failure or outcome.verdict)
                if outcome.outcome_class == "PRESERVATION_UNCERTAIN"
                and (outcome.primary_failure or outcome.verdict) != "HUMAN_GATE"
                else "WORKSPACE_PRESERVATION_FAILED"
                if outcome.outcome_class == "PRESERVATION_UNCERTAIN"
                else outcome.primary_failure or outcome.verdict
            )
            break
        if outcome.outcome_class == "BUDGET_STOP":
            stop_verdict = first_precise_failure or "BUDGET_EXHAUSTED"
            stop_dimension = outcome.budget_dimension
            break

    processed = len(completed)
    not_started = [{
        "ordinal": item.ordinal, "item_id": item.item_id, "status": "NOT_STARTED",
        "program_id": item.program["program_id"], "task_id": item.task["task_id"],
    } for item in frozen[processed:]]
    if stop_verdict is not None:
        verdict = (
            first_precise_failure
            if stop_verdict == "BUDGET_EXHAUSTED" and first_precise_failure is not None
            else stop_verdict
        )
        status = "STOPPED"
    elif all(item["outcome_class"] == "HUMAN_GATE" for item in completed):
        verdict, status = "HUMAN_GATES_READY", "SUCCESS"
    else:
        verdict, status = "COMPLETED_WITH_PROGRAM_FAILURES", "COMPLETED"
    final = {
        "queue_id": queue["queue_id"], "queue_run_id": queue_run_id,
        "verdict": verdict, "status": status, "budget_dimension": stop_dimension,
        "completed_items": completed, "not_started_items": not_started,
        "pending_human_gates": human_gates, "finished_at": utc_now(),
    }
    atomic_json_fsync(queue_run_dir / "final.json", final)
    atomic_json_fsync(
        queue_run_dir / "queue-state.json",
        _queue_snapshot(queue["queue_id"], completed, None, status),
    )
    control.persist_budget_state()
    return (0 if status in {"SUCCESS", "COMPLETED"} else 2), queue_run_dir, final


def cmd_inspect() -> int:
    payload = {
        "agentflow_root": str(ROOT),
        "python": sys.version.split()[0],
        "codex": shutil.which("codex"),
        "opencode": shutil.which("opencode"),
        "models_config": str(MODELS_FILE),
        "runs": str(RUNS_DIR),
        "human_gates": FORBIDDEN_ACTIONS,
    }
    print(json.dumps(payload, indent=2))
    return 0


STATUS_CLASSIFICATIONS = ("NO_LEASE", "ACTIVE", "STALE", "UNKNOWN", "MALFORMED")

STATUS_RECOMMENDATIONS = {
    "NO_LEASE": (
        "No lease file. Safe to prepare a run "
        "(still verify baseline and approvals). Do not create any lock manually."
    ),
    "ACTIVE": (
        "Lease ACTIVE. DO NOT launch a writer, DO NOT archive/breakglass/release. "
        "Wait for the owning run/PID or escalate to a human."
    ),
    "STALE": (
        "Lease looks STALE (all owners provably inactive). This command never "
        "recovers automatically. A human must decide recovery via the normal "
        "acquire path; do not delete the file manually."
    ),
    "UNKNOWN": (
        "Lease state UNKNOWN/inverifiable. FAIL CLOSED. Do not launch, archive, "
        "or delete. Escalate to a human."
    ),
    "MALFORMED": (
        "Lease MALFORMED or legacy. FAIL CLOSED. Do not launch or delete. "
        "Escalate for manual triage; never breakglass an apparently active owner."
    ),
}


def lease_path_for_repo(repo: Path | str, locks_dir: Path | None = None) -> Path:
    """Return the lease file path for a repo without touching disk.

    Pure helper: no file creation, no locking, no process signaling.
    """
    base = LOCKS_DIR if locks_dir is None else Path(locks_dir)
    repo_key = hashlib.sha256(str(Path(repo).resolve()).encode()).hexdigest()[:20]
    return base / f"{repo_key}.json"


def _summarize_lease_owner(existing: dict[str, Any]) -> dict[str, Any]:
    """Extract a redacted owner/writer summary without trusting it.

    Never includes the token value, only whether one is present.
    """
    controller = existing.get("controller")
    if not isinstance(controller, dict):
        controller = {}
    writer = existing.get("writer")
    if not isinstance(writer, dict):
        writer = {}
    token = existing.get("token")
    return {
        "task_id": existing.get("task_id"),
        "run_id": existing.get("run_id"),
        "repo": existing.get("repo"),
        "format": existing.get("format"),
        "acquired_at": existing.get("acquired_at"),
        "token_present": isinstance(token, str) and bool(token.strip()),
        "controller_pid": controller.get("pid", existing.get("controller_pid", existing.get("pid"))),
        "writer_state": writer.get("state", writer.get("lifecycle_state", existing.get("writer_state"))),
        "writer_pid": writer.get("pid", existing.get("writer_pid")),
        "writer_pgid": writer.get("pgid", writer.get("process_group_id", existing.get("writer_pgid"))),
    }


def classify_lease(
    repo: Path | str,
    locks_dir: Path | None = None,
) -> dict[str, Any]:
    """Classify a repo lease without mutating anything.

    READ-ONLY: reads one file, parses JSON, and performs signal-0 liveness
    probes through the existing pure helpers. Never acquires, archives,
    releases, locks exclusively, writes, renames, unlinks, or signals
    processes with a terminating signal. UNKNOWN is never reported as STALE
    and MALFORMED is never reported as recoverable.
    """
    lease_path = lease_path_for_repo(repo, locks_dir)
    try:
        raw = lease_path.read_bytes()
    except FileNotFoundError:
        return {
            "classification": "NO_LEASE",
            "lease_path": str(lease_path),
            "reason": "no lease file present",
            "owner": {},
        }
    except OSError as exc:
        return {
            "classification": "UNKNOWN",
            "lease_path": str(lease_path),
            "reason": f"unreadable lease file: {exc}",
            "owner": {},
        }
    try:
        existing = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return {
            "classification": "MALFORMED",
            "lease_path": str(lease_path),
            "reason": f"unparseable lease JSON: {type(exc).__name__}",
            "owner": {},
        }
    if not isinstance(existing, dict):
        return {
            "classification": "MALFORMED",
            "lease_path": str(lease_path),
            "reason": "lease JSON is not an object",
            "owner": {},
        }
    owner = _summarize_lease_owner(existing)
    try:
        probe = WriteLease(Path(repo), "status-probe", "status-probe")
    except (AgentFlowError, OSError) as exc:
        return {
            "classification": "UNKNOWN",
            "lease_path": str(lease_path),
            "reason": f"own process identity unverifiable: {exc}",
            "owner": owner,
        }
    try:
        probe._validate_v3(existing)
    except AgentFlowError as exc:
        return {
            "classification": "MALFORMED",
            "lease_path": str(lease_path),
            "reason": f"lease failed V3 validation: {exc}",
            "owner": owner,
        }
    try:
        stale_reason = probe._stale_reason(existing)
    except AgentFlowError as exc:
        return {
            "classification": "UNKNOWN",
            "lease_path": str(lease_path),
            "reason": f"liveness unverifiable, failing closed: {exc}",
            "owner": owner,
        }
    if stale_reason is None:
        return {
            "classification": "ACTIVE",
            "lease_path": str(lease_path),
            "reason": "controller or writer lifecycle is active",
            "owner": owner,
        }
    return {
        "classification": "STALE",
        "lease_path": str(lease_path),
        "reason": stale_reason,
        "owner": owner,
    }


def _safe_read_json_file(path: Path) -> tuple[bool, Any]:
    """Read and parse a JSON file. Returns (ok, value); never raises."""
    try:
        return True, json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return False, None


def _inventory_run_dir(run_dir: Path) -> dict[str, Any]:
    """Summarize one run directory without writing anything."""
    try:
        names = sorted(item.name for item in run_dir.iterdir() if item.is_file())
    except OSError as exc:
        return {"run_dir": str(run_dir), "readable": False, "reason": str(exc)}
    inventory: dict[str, Any] = {"run_dir": str(run_dir), "readable": True, "files": names}
    has_invocation = any(name.endswith("-invocation.json") for name in names)
    has_worker_result = any(
        name.startswith("worker-cycle-") and name.endswith("-result.json") for name in names
    )
    has_validators = any(name.startswith("validators-cycle-") for name in names)
    # Presence is checked on the filesystem entry (not just regular files) so
    # that a non-file final.json can never be silently treated as "no final".
    has_final = (run_dir / "final.json").exists()
    inventory.update(
        {
            "has_invocation": has_invocation,
            "has_worker_result": has_worker_result,
            "has_validators": has_validators,
            "has_final": has_final,
        }
    )
    task_ok, task = _safe_read_json_file(run_dir / "task.json") if "task.json" in names else (False, None)
    inventory["task_readable"] = task_ok
    if task_ok and isinstance(task, dict):
        inventory["task_id"] = task.get("task_id")
        inventory["task_repo"] = task.get("repo")
    final_ok, final = _safe_read_json_file(run_dir / "final.json") if has_final else (False, None)
    inventory["final_readable"] = final_ok
    inventory["final_is_object"] = final_ok and isinstance(final, dict)
    if inventory["final_is_object"]:
        inventory["final_verdict"] = final.get("verdict")
        inventory["final_status"] = final.get("status")
        worker = final.get("worker") if isinstance(final.get("worker"), dict) else {}
        inventory["worker_exit_code"] = worker.get("exit_code")
        reviewer_result = final.get("reviewer_result")
        if isinstance(reviewer_result, dict):
            inventory["reviewer_verdict"] = reviewer_result.get("verdict")
    return inventory


def diagnose_run(
    repo: Path | str,
    lease_info: dict[str, Any] | None = None,
    runs_dir: Path | None = None,
    run_hint: str | None = None,
) -> dict[str, Any]:
    """Infer the associated run conservatively. READ-ONLY, never writes.

    An explicit run_hint is a strong operator intent: when it is given, only
    that exact run directory is ever reported (with run_hint_found True/False)
    and there is no silent fallback to another run. Association is otherwise
    exact (lease run_id matches a directory), heuristic (latest run for the
    same repo), or none. Phase is one of NO_RUN, IN_PROGRESS, FINALIZED, or
    UNKNOWN; partial artifacts yield IN_PROGRESS or UNKNOWN, never a
    fabricated precise stage.
    """
    base = RUNS_DIR if runs_dir is None else Path(runs_dir)
    try:
        resolved_repo = str(Path(repo).resolve())
    except OSError:
        resolved_repo = str(repo)
    lease_run_id = (lease_info or {}).get("owner", {}).get("run_id")
    if run_hint is not None:
        if (
            not run_hint
            or run_hint in (".", "..")
            or "/" in run_hint
            or ".." in run_hint
            or run_hint.startswith(".")
        ):
            return {
                "association": "none",
                "phase": "UNKNOWN",
                "reason": "explicit --run hint is not a plain run directory name; refusing to resolve",
                "run_dir": None,
                "run_hint": run_hint,
                "run_hint_found": False,
                "artifacts": {},
            }
        hinted = base / run_hint
        if hinted.is_dir():
            inventory = _inventory_run_dir(hinted)
            return {
                "association": "hinted",
                "phase": _phase_from_inventory(inventory),
                "reason": "explicit --run hint",
                "run_dir": str(hinted),
                "run_hint": run_hint,
                "run_hint_found": True,
                "artifacts": inventory,
            }
        return {
            "association": "none",
            "phase": "UNKNOWN",
            "reason": "explicit --run hint not found; refusing silent fallback to another run",
            "run_dir": None,
            "run_hint": run_hint,
            "run_hint_found": False,
            "artifacts": {},
        }
    candidates: list[Path] = []
    try:
        candidates = sorted(
            (item for item in base.iterdir() if item.is_dir() and not item.name.startswith(".")),
            key=lambda item: item.name,
        )
    except OSError as exc:
        return {
            "association": "none",
            "phase": "UNKNOWN",
            "reason": f"runs directory unreadable: {exc}",
            "run_dir": None,
            "run_hint": run_hint,
            "run_hint_found": None if run_hint is None else False,
            "artifacts": {},
        }
    if lease_run_id and (base / str(lease_run_id)).is_dir():
        inventory = _inventory_run_dir(base / str(lease_run_id))
        return {
            "association": "exact",
            "phase": _phase_from_inventory(inventory),
            "reason": "lease run_id matches run directory",
            "run_dir": str(base / str(lease_run_id)),
            "run_hint": run_hint,
            "run_hint_found": None,
            "artifacts": inventory,
        }
    same_repo: list[Path] = []
    for candidate in candidates:
        task_path = candidate / "task.json"
        if not task_path.is_file():
            continue
        ok, task = _safe_read_json_file(task_path)
        if not ok or not isinstance(task, dict):
            continue
        try:
            candidate_repo = str(Path(task.get("repo", "")).resolve()) if task.get("repo") else ""
        except OSError:
            candidate_repo = str(task.get("repo", ""))
        if candidate_repo and candidate_repo == resolved_repo:
            same_repo.append(candidate)
    if not same_repo:
        if lease_run_id:
            return {
                "association": "none",
                "phase": "UNKNOWN",
                "reason": "lease names a run_id with no matching directory; refusing to guess",
                "run_dir": None,
                "run_hint": run_hint,
                "run_hint_found": None,
                "artifacts": {},
            }
        return {
            "association": "none",
            "phase": "NO_RUN",
            "reason": "no run directory found for this repo",
            "run_dir": None,
            "run_hint": run_hint,
            "run_hint_found": None,
            "artifacts": {},
        }
    latest = same_repo[-1]
    inventory = _inventory_run_dir(latest)
    return {
        "association": "heuristic-latest",
        "phase": _phase_from_inventory(inventory),
        "reason": "newest run directory for this repo; verify before acting",
        "run_dir": str(latest),
        "run_hint": run_hint,
        "run_hint_found": None,
        "artifacts": inventory,
    }


def _phase_from_inventory(inventory: dict[str, Any]) -> str:
    """Map a read-only inventory to a conservative phase label.

    A present-but-unreadable final, a final that is not a JSON object, or a
    final without a usable string verdict is inconsistency, not progress:
    all of those map to UNKNOWN (fail closed).
    """
    if not inventory.get("readable", False):
        return "UNKNOWN"
    if inventory.get("has_final"):
        if not inventory.get("final_readable") or not inventory.get("final_is_object"):
            return "UNKNOWN"
        verdict = inventory.get("final_verdict")
        if verdict == "RUNNING":
            return "IN_PROGRESS"
        if isinstance(verdict, str) and verdict.strip():
            return "FINALIZED"
        return "UNKNOWN"
    if (
        inventory.get("has_invocation")
        or inventory.get("has_worker_result")
        or inventory.get("has_validators")
    ):
        return "IN_PROGRESS"
    if "task.json" in (inventory.get("files") or []) and inventory.get("task_readable"):
        return "IN_PROGRESS"
    return "UNKNOWN"


def diagnose_repo(
    repo: Path | str,
    locks_dir: Path | None = None,
    runs_dir: Path | None = None,
    run_hint: str | None = None,
) -> dict[str, Any]:
    """Full read-only diagnosis for one repo: lease + run + recommendation."""
    lease_info = classify_lease(repo, locks_dir)
    if lease_info.get("classification") not in STATUS_CLASSIFICATIONS:
        lease_info = {
            "classification": "UNKNOWN",
            "lease_path": lease_info.get("lease_path", ""),
            "reason": "internal classification error; failing closed",
            "owner": {},
        }
    run_info = diagnose_run(repo, lease_info, runs_dir, run_hint)
    conflicts: list[str] = []
    if run_info.get("association") == "heuristic-latest":
        conflicts.append("run association is heuristic, not exact; confirm run_dir before acting")
    if run_info.get("run_hint_found") is False:
        conflicts.append("explicit --run hint did not resolve; no fallback run was substituted")
    if run_info.get("phase") == "UNKNOWN":
        conflicts.append("run artifacts incomplete or inconsistent; refusing precise phase")
    try:
        locks_base = LOCKS_DIR if locks_dir is None else Path(locks_dir)
        stem = Path(lease_info["lease_path"]).stem
        stale_archives = sorted(
            item.name
            for item in locks_base.glob(f"{stem}.stale-*.json")
            if item.is_file()
        )
        breakglass = sorted(
            item.name
            for item in locks_base.glob(f"{stem}.breakglass-*.json")
            if item.is_file()
        )
    except OSError:
        stale_archives, breakglass = [], []
    try:
        resolved_display = str(Path(repo).resolve())
    except OSError:
        resolved_display = str(repo)
    return {
        "tool": "agentflow-status",
        "status_version": 1,
        "checked_at": utc_now(),
        "repo": resolved_display,
        "lease": lease_info,
        "run": run_info,
        "prior_stale_archives": stale_archives,
        "prior_breakglass_archives": breakglass,
        "conflicts": conflicts,
        "recommendation": STATUS_RECOMMENDATIONS.get(
            lease_info.get("classification", "UNKNOWN"),
            STATUS_RECOMMENDATIONS["UNKNOWN"],
        ),
    }


def cmd_status(args: Any) -> int:
    """Implement `status`/`diagnose`: print read-only JSON diagnosis."""
    report = diagnose_repo(getattr(args, "repo"), run_hint=getattr(args, "run", None))
    print(json.dumps(report, indent=2))
    return 0


def cmd_models() -> int:
    print(json.dumps(load_models(), indent=2))
    return 0


def cmd_worktree_remove(run_id: str, *, force: bool = False) -> int:
    """Remove an isolated worktree for a completed/failed run."""
    if not run_id or run_id in (".", "..") or "/" in run_id or ".." in run_id:
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "Invalid run_id"}, indent=2))
        return 2
    run_dir = RUNS_DIR / run_id
    workspace_path = run_dir / "workspace.json"
    if not workspace_path.is_file():
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": f"No workspace.json for run {run_id}"}, indent=2))
        return 2
    ok, workspace = _safe_read_json_file(workspace_path)
    if not ok or not isinstance(workspace, dict):
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "workspace.json unreadable"}, indent=2))
        return 2
    # M1: cross-run identity — binding must belong to the requested run.
    ws_run_id = workspace.get("run_id")
    if not isinstance(ws_run_id, str) or ws_run_id != run_id:
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "workspace run_id mismatch"}, indent=2))
        return 2
    exec_str = workspace.get("execution_repo")
    source_str = workspace.get("source_repo")
    if not exec_str or not source_str:
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "workspace.json missing repo paths"}, indent=2))
        return 2
    try:
        exec_basename = Path(exec_str).name
    except Exception:
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "workspace execution_repo unreadable"}, indent=2))
        return 2
    if exec_basename != safe_slug(run_id):
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "workspace execution_repo does not match run_id"}, indent=2))
        return 2
    if isinstance(exec_str, str) and Path(exec_str).is_symlink():
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "Destination is a symlink"}, indent=2))
        return 2
    dest = Path(exec_str).resolve()
    source = Path(source_str).resolve()
    root = worktree_root()
    root_resolved = root.resolve()
    try:
        dest.relative_to(root_resolved)
    except ValueError:
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "Destination outside worktree root"}, indent=2))
        return 2
    if dest == source.resolve():
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "Destination equals source"}, indent=2))
        return 2
    if not _is_worktree_registered(source, dest):
        print(json.dumps({"error": "WORKTREE_CLEANUP_REFUSED", "message": "Not a registered worktree"}, indent=2))
        return 2
    if not force:
        status = workspace.get("status")
        if status in ("CANDIDATE", "PRESERVED"):
            dirty = workspace.get("preserved_dirty", False)
            if dirty or status == "CANDIDATE":
                print(json.dumps({
                    "error": "WORKTREE_CLEANUP_REFUSED",
                    "message": f"Worktree is {status} (dirty={dirty}); use --force to remove",
                }, indent=2))
                return 2
    try:
        _remove_worktree(source, dest, force=force)
    except AgentFlowError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, indent=2))
        return 2
    workspace["status"] = "CLEANED"
    workspace["cleanup"] = {"cleaned_at": utc_now(), "force": force}
    atomic_json(workspace_path, workspace)
    print(json.dumps({"status": "CLEANED", "run_id": run_id}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    wrapper_parser = sub.add_parser(WRITER_WRAPPER_MODE, help=argparse.SUPPRESS)
    wrapper_parser.add_argument("worker_command", nargs=argparse.REMAINDER)
    sub.add_parser("inspect", help="show local harness paths and hard gates")
    sub.add_parser("models", help="show configured real model IDs and variants")
    status_parser = sub.add_parser("status", help="read-only lease/run diagnosis (never mutates)")
    status_parser.add_argument("--repo", type=Path, required=True)
    status_parser.add_argument("--run", type=str, default=None)
    diagnose_parser = sub.add_parser("diagnose", help="alias for status (read-only)")
    diagnose_parser.add_argument("--repo", type=Path, required=True)
    diagnose_parser.add_argument("--run", type=str, default=None)
    run_parser = sub.add_parser("run", help="run one task packet and stop at the human gate")
    run_parser.add_argument("task", type=Path)
    program_parser = sub.add_parser("program", help="program runner (additive)")
    program_sub = program_parser.add_subparsers(dest="program_command", required=True)
    program_run_parser = program_sub.add_parser("run", help="run a program spec")
    program_run_parser.add_argument("program", type=Path)
    queue_parser = sub.add_parser("queue", help="sequential autonomous program queue")
    queue_sub = queue_parser.add_subparsers(dest="queue_command", required=True)
    queue_run_parser = queue_sub.add_parser("run", help="run a queue spec")
    queue_run_parser.add_argument("queue", type=Path)
    finding_parser = sub.add_parser("finding", help="finding pipeline runner")
    finding_sub = finding_parser.add_subparsers(dest="finding_command", required=True)
    finding_run_parser = finding_sub.add_parser("run", help="run one frozen finding")
    finding_run_parser.add_argument("finding", type=Path)
    finding_status_parser = finding_sub.add_parser("status", help="read-only finding run status")
    finding_status_parser.add_argument("finding_run_id")
    finding_resume_parser = finding_sub.add_parser("resume", help="resume a safe completed finding boundary")
    finding_resume_parser.add_argument("finding_run_id")
    worktree_parser = sub.add_parser("worktree", help="worktree management")
    worktree_sub = worktree_parser.add_subparsers(dest="worktree_command", required=True)
    wt_remove_parser = worktree_sub.add_parser("remove", help="remove an isolated worktree")
    wt_remove_parser.add_argument("--run", type=str, required=True, help="run_id to clean up")
    wt_remove_parser.add_argument("--force", action="store_true", help="force remove dirty worktree")
    args = parser.parse_args(argv)
    if args.command == WRITER_WRAPPER_MODE:
        return writer_wrapper(args.worker_command)
    if args.command == "inspect":
        return cmd_inspect()
    if args.command == "models":
        return cmd_models()
    if args.command in ("status", "diagnose"):
        return cmd_status(args)
    if args.command == "worktree":
        if args.worktree_command == "remove":
            return cmd_worktree_remove(args.run, force=args.force)
    if args.command == "program":
        if args.program_command == "run":
            code, run_dir, final = run_program(args.program)
            print(json.dumps({"run_dir": str(run_dir), "verdict": final["verdict"], "status": final["status"]}, indent=2))
            return code
    if args.command == "queue":
        code, queue_run_dir, final = run_queue(args.queue)
        print(json.dumps({
            "queue_run_dir": str(queue_run_dir) if queue_run_dir is not None else None,
            "verdict": final["verdict"], "status": final["status"],
        }, indent=2))
        return code
    if args.command == "finding":
        # Canonical CLI execution loads this file as __main__. Bind that
        # executing module under the canonical name before finding_runner's
        # "import agentflow as af" so one AgentFlow module identity (and one
        # F-04 ContextVar state) is shared. Ordinary imports are unaffected:
        # sys.modules already holds the canonical module and setdefault no-ops.
        sys.modules.setdefault("agentflow", sys.modules[__name__])
        from finding_runner import cli as finding_cli
        argument = str(args.finding) if args.finding_command == "run" else args.finding_run_id
        return finding_cli(args.finding_command, argument)
    code, run_dir, final = run_task(args.task)
    print(json.dumps({"run_dir": str(run_dir), "verdict": final["verdict"], "status": final["status"]}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
