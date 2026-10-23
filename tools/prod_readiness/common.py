#!/usr/bin/env python3
"""Shared, fail-closed support for PROD-READINESS campaign runners.

This module deliberately reuses the Stage A PR-HARNESS-001 containment and
resource primitives.  It is harness code, not AgentFlow production code.
"""

from __future__ import annotations

import dataclasses
import enum
import contextlib
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from tests.prod_readiness_support import (  # PR-HARNESS-001
    ContainmentPolicy,
    HarnessSafetyError,
    SignalSentinel,
    capture_resource_snapshot,
    process_identity,
    registered_worktrees,
    terminate_owned_process_group,
)


RUN_LAYOUT = (
    "manifest",
    "environment",
    "suites",
    "scenarios",
    "crash",
    "mutation",
    "stress",
    "soak",
    "providers",
    "resources",
    "sandboxes",
    "findings",
    "state",
    "assessment",
    "integrity",
)
RUN_ROOT_ENV = "PROD_READINESS_RUN_ROOT"


class ErrorCode(str, enum.Enum):
    INVALID_MANIFEST = "INVALID_MANIFEST"
    UNSAFE_TARGET = "UNSAFE_TARGET"
    CANONICAL_TARGET_REFUSED = "CANONICAL_TARGET_REFUSED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    RUN_ROOT_INVALID = "RUN_ROOT_INVALID"
    SECRET_REDACTION_FAILED = "SECRET_REDACTION_FAILED"
    MUTANT_INVALID = "MUTANT_INVALID"
    STRESS_THRESHOLD_FAILED = "STRESS_THRESHOLD_FAILED"
    SOAK_THRESHOLD_FAILED = "SOAK_THRESHOLD_FAILED"
    REAL_PROVIDER_NOT_ARMED = "REAL_PROVIDER_NOT_ARMED"
    PROVIDER_BUDGET_EXHAUSTED = "PROVIDER_BUDGET_EXHAUSTED"
    EVIDENCE_VERIFY_FAILED = "EVIDENCE_VERIFY_FAILED"
    INTEGRITY_MISMATCH = "INTEGRITY_MISMATCH"
    INCOMPLETE = "INCOMPLETE"
    INTERNAL_HARNESS_ERROR = "INTERNAL_HARNESS_ERROR"


class RunnerError(RuntimeError):
    """Stable machine-readable campaign failure."""

    def __init__(self, code: ErrorCode | str, message: str, **details: Any):
        self.code = ErrorCode(code)
        self.details = details
        super().__init__(f"{self.code.value}: {message}")

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "message": str(self), "details": self.details}


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_paths(paths: Iterable[Path]) -> dict[str, str]:
    return {str(path): sha256_path(path) for path in sorted(paths, key=str)}


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _split_lexical_relative(relative: str) -> tuple[str, ...]:
    """Validate lexical internal relative components only."""
    if not isinstance(relative, str) or not relative:
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, "relative path must be non-empty"
        )
    candidate = Path(relative)
    if candidate.is_absolute():
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, "relative path must not be absolute"
        )
    parts = candidate.parts
    if not parts:
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, "relative path is empty"
        )
    for part in parts:
        if part in ("", ".", ".."):
            raise RunnerError(
                ErrorCode.RUN_ROOT_INVALID,
                "relative path must be lexical without traversal",
                part=part,
            )
        if "/" in part or "\x00" in part:
            raise RunnerError(
                ErrorCode.RUN_ROOT_INVALID, "relative component is malformed"
            )
    return parts


class OwnedRunRoot:
    """Durable run-root capability holding the authorized directory fd.

    AUTHORIZATION AND ACTUAL FILESYSTEM OPERATION SHARE THE SAME PHYSICAL
    IDENTITY: all authoritative writes are rooted through the held fd via
    dir_fd/openat operations and never re-resolve the pathname.
    """

    def __init__(
        self,
        *,
        canonical_path: Path,
        fd: int,
        st_dev: int,
        st_ino: int,
        test_hook: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._path = canonical_path
        self._fd = fd
        self._st_dev = st_dev
        self._st_ino = st_ino
        self._closed = False
        self._test_hook = test_hook

    @property
    def fd(self) -> int:
        if self._closed:
            raise RunnerError(
                ErrorCode.INTERNAL_HARNESS_ERROR, "owned run root is closed"
            )
        return self._fd

    @property
    def canonical_path(self) -> Path:
        return self._path

    def test_event(self, event: str, **details: Any) -> None:
        """Invoke a deterministic harness-only lifecycle hook.

        Production callers never install this hook.  Permanent tests use it
        to place a race at an exact lifecycle boundary without weakening the
        descriptor-anchored write implementation.
        """
        if self._test_hook is not None:
            self._test_hook(event, dict(details))

    @property
    def st_dev(self) -> int:
        return self._st_dev

    @property
    def st_ino(self) -> int:
        return self._st_ino

    def _verify_root_fd(self) -> None:
        try:
            current = os.fstat(self._fd)
        except OSError as exc:
            raise RunnerError(
                ErrorCode.INTERNAL_HARNESS_ERROR,
                "owned run-root descriptor is invalid",
            ) from exc
        if (current.st_dev, current.st_ino) != (self._st_dev, self._st_ino):
            raise RunnerError(
                ErrorCode.INTERNAL_HARNESS_ERROR,
                "owned run-root identity changed",
            )
        if not stat.S_ISDIR(current.st_mode):
            raise RunnerError(
                ErrorCode.INTERNAL_HARNESS_ERROR,
                "owned run-root is not a directory",
            )

    def _open_parent_chain(
        self, parts: tuple[str, ...], *, create_missing: bool
    ) -> tuple[int, str, list[int]]:
        """Open parent directories anchored to the held root fd.

        Returns (parent_fd, final_name, owned_fds_to_close_except_root).
        The root fd itself is never closed here.
        """
        self._verify_root_fd()
        if self._test_hook is not None:
            self._test_hook("after_authorization", {"relative_parts": parts})
        if len(parts) == 1:
            return self._fd, parts[0], []
        opened: list[int] = []
        current_fd = self._fd
        try:
            for part in parts[:-1]:
                if self._test_hook is not None:
                    self._test_hook("before_walk_step", {"part": part})
                try:
                    next_fd = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=current_fd,
                    )
                except FileNotFoundError:
                    if not create_missing:
                        raise RunnerError(
                            ErrorCode.INTERNAL_HARNESS_ERROR,
                            "parent directory is missing",
                            part=part,
                        )
                    try:
                        os.mkdir(part, 0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise RunnerError(
                            ErrorCode.INTERNAL_HARNESS_ERROR,
                            "directory creation failed",
                            part=part,
                        ) from exc
                    try:
                        next_fd = os.open(
                            part,
                            os.O_RDONLY
                            | os.O_DIRECTORY
                            | os.O_NOFOLLOW
                            | os.O_CLOEXEC,
                            dir_fd=current_fd,
                        )
                    except OSError as exc:
                        raise RunnerError(
                            ErrorCode.INTERNAL_HARNESS_ERROR,
                            "directory open failed after creation",
                            part=part,
                        ) from exc
                except OSError as exc:
                    # ELOOP means symlink encountered -> fail closed (ROOTFD-07).
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "ancestor is not an authorized directory",
                        part=part,
                    ) from exc
                try:
                    child_st = os.fstat(next_fd)
                except OSError as exc:
                    os.close(next_fd)
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "directory stat failed",
                        part=part,
                    ) from exc
                if not stat.S_ISDIR(child_st.st_mode):
                    os.close(next_fd)
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "ancestor is not a directory",
                        part=part,
                    )
                # lstat-equivalent check: O_NOFOLLOW open already rejects
                # symlinks; additionally verify via dir_fd lstat identity.
                try:
                    lstat = os.stat(
                        part, dir_fd=current_fd, follow_symlinks=False
                    )
                except OSError as exc:
                    os.close(next_fd)
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "ancestor stat failed",
                        part=part,
                    ) from exc
                if stat.S_ISLNK(lstat.st_mode):
                    os.close(next_fd)
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "ancestor was replaced by symlink",
                        part=part,
                    )
                if (lstat.st_dev, lstat.st_ino) != (
                    child_st.st_dev,
                    child_st.st_ino,
                ):
                    os.close(next_fd)
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "descriptor identity mismatch",
                        part=part,
                    )
                opened.append(next_fd)
                current_fd = next_fd
                if self._test_hook is not None:
                    self._test_hook("after_walk_step", {"part": part})
            return current_fd, parts[-1], opened
        except BaseException:
            for owned in reversed(opened):
                try:
                    os.close(owned)
                except OSError:
                    pass
            raise

    def mkdir_rel(self, relative: str) -> None:
        parts = _split_lexical_relative(relative)
        parent_fd, final_name, opened = self._open_parent_chain(
            parts, create_missing=True
        )
        try:
            if self._test_hook is not None:
                self._test_hook(
                    "before_mkdir", {"parent_fd": parent_fd, "name": final_name}
                )
            try:
                lstat = os.stat(
                    final_name, dir_fd=parent_fd, follow_symlinks=False
                )
                if stat.S_ISDIR(lstat.st_mode):
                    return
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "target already exists and is not a directory",
                    path=relative,
                )
            except FileNotFoundError:
                pass
            try:
                os.mkdir(final_name, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                try:
                    lstat = os.stat(
                        final_name, dir_fd=parent_fd, follow_symlinks=False
                    )
                    if not stat.S_ISDIR(lstat.st_mode):
                        raise RunnerError(
                            ErrorCode.INTERNAL_HARNESS_ERROR,
                            "target exists and is not a directory",
                            path=relative,
                        )
                except OSError as exc:
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "directory verification failed",
                        path=relative,
                    ) from exc
            except OSError as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "directory creation failed",
                    path=relative,
                ) from exc
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
        finally:
            for owned in reversed(opened):
                try:
                    os.close(owned)
                except OSError:
                    pass

    def atomic_create_bytes_rel(
        self,
        relative: str,
        payload: bytes,
        *,
        mode: int = 0o600,
    ) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise RunnerError(
                ErrorCode.INTERNAL_HARNESS_ERROR, "payload must be bytes"
            )
        parts = _split_lexical_relative(relative)
        parent_fd, final_name, opened = self._open_parent_chain(
            parts, create_missing=True
        )
        try:
            if self._test_hook is not None:
                self._test_hook(
                    "before_write", {"parent_fd": parent_fd, "name": final_name}
                )
            # Fail closed if target already exists (create-once), without
            # following symlinks.
            try:
                os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
                raise RunnerError(
                    ErrorCode.INTEGRITY_MISMATCH,
                    "authoritative artifact already exists",
                    path=relative,
                )
            except FileNotFoundError:
                pass
            except RunnerError:
                raise
            except OSError as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "target stat failed",
                    path=relative,
                ) from exc
            temp_name = f".{final_name}.tmp-{os.getpid()}"
            # Remove stale temp from our own pid if present (same pid reuse).
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            try:
                temp_fd = os.open(temp_name, flags, mode, dir_fd=parent_fd)
            except OSError as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "durable evidence write failed",
                    path=relative,
                ) from exc
            try:
                with os.fdopen(temp_fd, "wb", closefd=True) as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                if self._test_hook is not None:
                    self._test_hook(
                        "after_write_before_link",
                        {"parent_fd": parent_fd, "name": final_name},
                    )
                try:
                    os.link(
                        temp_name,
                        final_name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise RunnerError(
                        ErrorCode.INTEGRITY_MISMATCH,
                        "authoritative artifact already exists",
                        path=relative,
                    ) from exc
                except OSError as exc:
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "atomic publication failed",
                        path=relative,
                    ) from exc
                try:
                    os.fsync(parent_fd)
                except OSError as exc:
                    raise RunnerError(
                        ErrorCode.INTERNAL_HARNESS_ERROR,
                        "directory fsync failed",
                        path=relative,
                    ) from exc
            finally:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
        finally:
            for owned in reversed(opened):
                try:
                    os.close(owned)
                except OSError:
                    pass

    def atomic_create_json_rel(self, relative: str, value: Any) -> None:
        self.atomic_create_bytes_rel(relative, canonical_json_bytes(value))

    def assert_public_binding(self) -> None:
        """Prove the public run-root pathname still names the held inode.

        Contract (fail closed):
        - public run-root path exists;
        - final component is not a symlink;
        - opening the public path with O_DIRECTORY|O_NOFOLLOW succeeds;
        - fstat(public_fd).st_dev/st_ino == held (dev, ino).

        A renamed held directory plus a newly-created unrelated directory
        at the old pathname MUST fail.  Symlink replacement, deletion, or
        restoration with a different inode MUST fail.  No FD is leaked.
        """
        if self._closed:
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "owned run root is closed; public binding cannot hold",
            )
        # lstat without following the final component: symlink => fail.
        try:
            public_lstat = os.lstat(self._path)
        except OSError as exc:
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "public run-root pathname is missing",
            ) from exc
        if stat.S_ISLNK(public_lstat.st_mode):
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "public run-root final component is a symlink",
            )
        if not stat.S_ISDIR(public_lstat.st_mode):
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "public run-root is not a directory",
            )
        try:
            public_fd = os.open(
                str(self._path),
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as exc:
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "public run-root cannot be opened without following symlinks",
            ) from exc
        try:
            try:
                public_st = os.fstat(public_fd)
            except OSError as exc:
                raise RunnerError(
                    ErrorCode.INTEGRITY_MISMATCH,
                    "public run-root stat failed",
                ) from exc
            if not stat.S_ISDIR(public_st.st_mode):
                raise RunnerError(
                    ErrorCode.INTEGRITY_MISMATCH,
                    "public run-root is not a directory",
                )
            if (public_st.st_dev, public_st.st_ino) != (
                self._st_dev,
                self._st_ino,
            ):
                raise RunnerError(
                    ErrorCode.INTEGRITY_MISMATCH,
                    "public run-root pathname no longer names the held inode",
                    held_dev=self._st_dev,
                    held_ino=self._st_ino,
                    public_dev=public_st.st_dev,
                    public_ino=public_st.st_ino,
                )
            # Race check: lstat identity must match the opened directory
            # identity; otherwise the pathname raced between lstat/open.
            if (public_lstat.st_dev, public_lstat.st_ino) != (
                public_st.st_dev,
                public_st.st_ino,
            ):
                raise RunnerError(
                    ErrorCode.INTEGRITY_MISMATCH,
                    "public run-root raced during binding verification",
                )
            # Held descriptor itself must still name the same inode.
            self._verify_root_fd()
        finally:
            try:
                os.close(public_fd)
            except OSError:
                pass

    def check_public_binding(self) -> bool:
        """Non-raising binding probe (True iff binding holds)."""
        try:
            self.assert_public_binding()
            return True
        except RunnerError:
            return False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                os.close(self._fd)
            except OSError:
                pass

    def __enter__(self) -> "OwnedRunRoot":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


RunRootHandle = OwnedRunRoot


def open_owned_run_root(
    disposable_root: Path,
    *,
    test_hook: Callable[[str, dict[str, Any]], None] | None = None,
) -> OwnedRunRoot:
    """Open a durable capability for an already-validated run root."""
    raw = Path(disposable_root)
    try:
        root_fd = os.open(
            str(raw),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID,
            "run root cannot be opened as a directory descriptor",
        ) from exc
    try:
        root_st = os.fstat(root_fd)
    except OSError as exc:
        try:
            os.close(root_fd)
        except OSError:
            pass
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, "run root stat failed"
        ) from exc
    if not stat.S_ISDIR(root_st.st_mode):
        try:
            os.close(root_fd)
        except OSError:
            pass
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, "run root is not a directory"
        )
    try:
        canonical = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        try:
            os.close(root_fd)
        except OSError:
            pass
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, "run root cannot be resolved"
        ) from exc
    return OwnedRunRoot(
        canonical_path=canonical,
        fd=root_fd,
        st_dev=root_st.st_dev,
        st_ino=root_st.st_ino,
        test_hook=test_hook,
    )


def atomic_create_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    """Create authoritative evidence once, durably, without replacement."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.parent / f".{path.name}.tmp-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    try:
        descriptor = os.open(temp, flags, mode)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temp, path)
            except FileExistsError as exc:
                raise RunnerError(
                    ErrorCode.INTEGRITY_MISMATCH,
                    "authoritative artifact already exists",
                    path=str(path),
                ) from exc
            _fsync_directory(path.parent)
        finally:
            if temp.exists():
                temp.unlink()
    except RunnerError:
        raise
    except OSError as exc:
        raise RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR,
            "durable evidence write failed",
            path=str(path),
        ) from exc


def atomic_create_json(path: Path, value: Any) -> None:
    atomic_create_bytes(path, canonical_json_bytes(value))


def _reject_nonfinite_constant(value: str) -> Any:
    raise RunnerError(
        ErrorCode.INVALID_MANIFEST,
        "non-finite JSON constant is forbidden",
        constant=value,
    )


def _reject_nonfinite_float(value: str) -> float:
    """Strict parse_float hook rejecting overflow to non-finite (1e999)."""
    try:
        parsed = float(value)
    except ValueError as exc:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "JSON numeric value is malformed",
            value=value,
        ) from exc
    if not math.isfinite(parsed):
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "non-finite JSON numeric value is forbidden",
            value=value,
        )
    return parsed


def _assert_all_finite(value: Any) -> None:
    """Reject any parsed float that is NaN/Infinity (nested structures)."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "non-finite JSON numeric value is forbidden",
            )
    elif isinstance(value, dict):
        for item in value.values():
            _assert_all_finite(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _assert_all_finite(item)


def strict_json_loads(text: str) -> Any:
    try:
        parsed = json.loads(
            text,
            parse_constant=_reject_nonfinite_constant,
            parse_float=_reject_nonfinite_float,
        )
    except RunnerError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "JSON input is unreadable or malformed",
        ) from exc
    _assert_all_finite(parsed)
    return parsed


def load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "JSON input is unreadable or malformed",
            path=str(path),
        ) from exc
    try:
        return strict_json_loads(text)
    except RunnerError as exc:
        exc.details.setdefault("path", str(path))
        raise


@dataclasses.dataclass(frozen=True)
class RunPlan:
    run_id: str
    candidate_sha: str
    candidate_tree: str
    environment_id: str
    campaign_kind: str
    static_manifest_hashes: Mapping[str, str]
    seed: int
    budgets: Mapping[str, int | float]
    run_root: str
    scenario_selection: tuple[str, ...]
    started_at: str
    tool_hashes: Mapping[str, str]
    fixture_hashes: Mapping[str, str]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "RunPlan":
        required = {field.name for field in dataclasses.fields(cls)}
        if set(raw) != required:
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "run plan fields are not exact",
                missing=sorted(required - set(raw)),
                extra=sorted(set(raw) - required),
            )
        string_fields = (
            "run_id",
            "candidate_sha",
            "candidate_tree",
            "environment_id",
            "campaign_kind",
            "run_root",
            "started_at",
        )
        if any(not isinstance(raw[key], str) or not raw[key] for key in string_fields):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "run plan string field is empty or malformed",
            )
        if isinstance(raw["seed"], bool) or not isinstance(raw["seed"], int):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "run plan seed must be an integer"
            )
        for key in (
            "static_manifest_hashes",
            "budgets",
            "tool_hashes",
            "fixture_hashes",
        ):
            if not isinstance(raw[key], dict):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST, f"{key} must be an object"
                )
        selection = raw["scenario_selection"]
        if not isinstance(selection, list) or any(
            not isinstance(item, str) or not item for item in selection
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "scenario_selection must be an array of IDs"
            )
        return cls(**{**raw, "scenario_selection": tuple(selection)})

    def to_dict(self) -> dict[str, Any]:
        value = dataclasses.asdict(self)
        value["scenario_selection"] = list(self.scenario_selection)
        return value


@dataclasses.dataclass(frozen=True)
class BudgetLimits:
    wall_seconds: float
    scenarios: int = 0
    executions: int = 0
    mutations: int = 0
    provider_calls: int = 0
    retries: int = 0
    fallbacks: int = 0
    corrections: int = 0
    evidence_bytes: int = 0

    def __post_init__(self) -> None:
        for field in dataclasses.fields(self):
            value = getattr(self, field.name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or value < 0
            ):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "budget must be non-negative",
                    budget=field.name,
                )
            if isinstance(value, float) and not math.isfinite(value):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "budget must be finite",
                    budget=field.name,
                )
        wall = self.wall_seconds
        if isinstance(wall, float) and not math.isfinite(wall):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "budget must be finite",
                budget="wall_seconds",
            )
        if self.wall_seconds <= 0:
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "wall budget must be positive"
            )


class BudgetEngine:
    """One monotonic, non-resetting budget ledger for a campaign."""

    _KINDS = {
        "scenarios",
        "executions",
        "mutations",
        "provider_calls",
        "retries",
        "fallbacks",
        "corrections",
        "evidence_bytes",
    }

    def __init__(
        self, limits: BudgetLimits, *, clock: Callable[[], float] = time.monotonic
    ):
        self.limits = limits
        self._clock = clock
        self.started = clock()
        self.deadline = self.started + limits.wall_seconds
        self.consumed = {kind: 0 for kind in self._KINDS}
        self.reservations: list[dict[str, Any]] = []

    def check_wall(self) -> None:
        if self._clock() >= self.deadline:
            raise RunnerError(
                ErrorCode.BUDGET_EXHAUSTED, "global wall-clock deadline exhausted"
            )

    def remaining_wall(self) -> float:
        return max(0.0, self.deadline - self._clock())

    def reserve(self, kind: str, amount: int = 1, *, action_id: str) -> dict[str, Any]:
        self.check_wall()
        if (
            kind not in self._KINDS
            or isinstance(amount, bool)
            or not isinstance(amount, int)
            or amount <= 0
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "invalid budget reservation",
                kind=kind,
                amount=amount,
            )
        limit = getattr(self.limits, kind)
        if limit <= 0 or self.consumed[kind] + amount > limit:
            code = (
                ErrorCode.PROVIDER_BUDGET_EXHAUSTED
                if kind == "provider_calls"
                else ErrorCode.BUDGET_EXHAUSTED
            )
            raise RunnerError(
                code,
                "budget exhausted before action launch",
                kind=kind,
                action_id=action_id,
            )
        self.consumed[kind] += amount
        row = {
            "sequence": len(self.reservations) + 1,
            "kind": kind,
            "amount": amount,
            "action_id": action_id,
            "consumed": self.consumed[kind],
            "limit": limit,
        }
        self.reservations.append(row)
        return dict(row)

    def snapshot(self) -> dict[str, Any]:
        return {
            "limits": dataclasses.asdict(self.limits),
            "consumed": dict(sorted(self.consumed.items())),
            "reservations": list(self.reservations),
            "started_monotonic": self.started,
            "deadline_monotonic": self.deadline,
        }


@dataclasses.dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    process_cleanup_verified: bool


def _terminate_exact_observations(observations: Iterable[Any]) -> None:
    """Best-effort cleanup using pidfd-pinned identities from H1 snapshots."""
    for observation in observations:
        details = observation.details
        try:
            expected_pid = int(details["pid"])
            current = process_identity(expected_pid)
            if (
                current.start_time != details.get("start_time")
                or current.boot_id != details.get("boot_id")
                or current.pgid != details.get("pgid")
                or current.sid != details.get("sid")
            ):
                continue
            descriptor = os.pidfd_open(expected_pid, 0)
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        except (AttributeError, KeyError, OSError, TypeError, ValueError):
            continue


_SUBREAPER_ENSURED: bool | None = None


_SUBREAPER_REFCOUNT = 0
_SUBREAPER_LOCK = threading.Lock()
_SUBREAPER_PRIOR: int | None = None


def _get_child_subreaper() -> int | None:
    """Query PR_GET_CHILD_SUBREAPER; returns 0/1 or None if unavailable."""
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_GET_CHILD_SUBREAPER = 37
        current = ctypes.c_int(0)
        result = libc.prctl(
            PR_GET_CHILD_SUBREAPER,
            ctypes.byref(current),
            0,
            0,
            0,
        )
        if result != 0:
            return None
        return int(current.value)
    except Exception:
        return None


def _set_child_subreaper(enabled: bool) -> bool:
    """Set or clear child-subreaper state; returns success."""
    global _SUBREAPER_ENSURED
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_CHILD_SUBREAPER = 36
        result = libc.prctl(PR_SET_CHILD_SUBREAPER, 1 if enabled else 0, 0, 0, 0)
        ok = result == 0
        _SUBREAPER_ENSURED = ok and enabled
        if not enabled and ok:
            _SUBREAPER_ENSURED = False
        return ok
    except Exception:
        _SUBREAPER_ENSURED = False
        return False


def _ensure_child_subreaper() -> bool:
    """Make this process a child subreaper so daemonized leaks reparent here.

    Scoped to owned executions via refcount: callers must pair each ensure
    with a clear so unrelated suites (watchdog/safety) observe default
    reparenting to init after the owned scope ends.

    Host state preservation: on the 0->1 transition the pre-existing
    PR_GET_CHILD_SUBREAPER value is stored; on the 1->0 transition that
    exact prior value is restored (0=>0, 1=>1).  Refcount and prior-state
    are guarded by a lock so nested/concurrent scopes never disable the
    subreaper while another scope remains active.
    """
    global _SUBREAPER_ENSURED, _SUBREAPER_REFCOUNT, _SUBREAPER_PRIOR
    with _SUBREAPER_LOCK:
        if _SUBREAPER_REFCOUNT > 0:
            _SUBREAPER_REFCOUNT += 1
            return True
        # Outermost entry: capture host prior state first.
        prior = _get_child_subreaper()
        _SUBREAPER_PRIOR = prior
        if prior == 1:
            # Already a subreaper: just take a refcount, no prctl needed.
            _SUBREAPER_REFCOUNT = 1
            _SUBREAPER_ENSURED = True
            return True
        ok = _set_child_subreaper(True)
        if ok:
            _SUBREAPER_REFCOUNT = 1
        else:
            # If prctl failed, do not hold a scope; clear saved prior.
            _SUBREAPER_PRIOR = None
        return ok


def _clear_child_subreaper() -> bool:
    """Release one owned scope; restore original host state when outermost ends."""
    global _SUBREAPER_REFCOUNT, _SUBREAPER_PRIOR
    with _SUBREAPER_LOCK:
        if _SUBREAPER_REFCOUNT <= 0:
            # A release without a successful acquire is a strict no-op.  In
            # particular it must never clear a host-owned subreaper setting.
            return True
        _SUBREAPER_REFCOUNT -= 1
        if _SUBREAPER_REFCOUNT != 0:
            return True
        # Outermost exit: restore exactly the captured prior state.
        prior = _SUBREAPER_PRIOR
        _SUBREAPER_PRIOR = None
        if prior is None:
            # Prior query unavailable: fall back to disabling (legacy).
            return _set_child_subreaper(False)
        if prior == 1:
            # Host was already a subreaper: ensure still enabled.
            current = _get_child_subreaper()
            if current == 1:
                return True
            return _set_child_subreaper(True)
        return _set_child_subreaper(False)


@contextlib.contextmanager
def child_subreaper_scope() -> Iterable[bool]:
    """Acquire/release exactly one child-subreaper ownership reference."""
    acquired = _ensure_child_subreaper()
    try:
        yield acquired
    finally:
        if acquired:
            _clear_child_subreaper()


def _proc_start_time(pid: int) -> int | None:
    try:
        identity = process_identity(pid)
        return identity.start_time
    except Exception:
        return None


def _is_descendant_of(pid: int, ancestor: int, *, max_depth: int = 64) -> bool:
    """Walk /proc ppid chain to prove ancestry without trusting names."""
    current = pid
    for _ in range(max_depth):
        if current == ancestor:
            return True
        try:
            identity = process_identity(current)
        except Exception:
            return False
        parent = identity.ppid
        if parent is None:
            return False
        if parent == ancestor:
            return True
        if parent <= 1:
            return False
        current = parent
    return False


def _collect_owned_survivors(
    leader: Any, *, caller_pid: int, leader_start: int | None
) -> list[int]:
    """Find live survivors owned by one execution, including setsid escapes.

    Uses exact PID identity, ppid ancestry, and subreaper reparenting.
    Never claims foreign processes: a candidate must have started at or
    after the leader and either descend from the leader/caller or match
    the leader's session context with valid boot/start identity.
    """
    survivors: dict[int, bool] = {}
    try:
        leader_pid = int(getattr(leader, "pid", -1))
    except Exception:
        leader_pid = -1
    leader_boot = getattr(leader, "boot_id", None)
    leader_pgid = getattr(leader, "pgid", None)
    leader_sid = getattr(leader, "sid", None)
    # Snapshot all processes once.
    all_pids: list[int] = []
    try:
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                all_pids.append(int(entry.name))
    except OSError:
        return []
    for pid in all_pids:
        if pid == caller_pid or pid == leader_pid:
            continue
        try:
            current = process_identity(pid)
        except Exception:
            continue
        # PID reuse / wrong start-time / wrong boot guards.
        if leader_boot is not None and current.boot_id is not None:
            if current.boot_id != leader_boot:
                continue
        if leader_start is not None and current.start_time is not None:
            if current.start_time < leader_start:
                continue
        elif leader_start is None:
            continue
        # Zombies owned by us are still leaks (must be reaped / FAIL).
        is_zombie = current.state == "Z"
        # Direct ancestry via leader or via subreaper caller (ppid == caller
        # with fresh start_time). No gating on current subreaper state: without
        # subreaper orphans reparent to init (ppid 1) and are naturally
        # excluded; with subreaper they reparent here and are claimed.
        owned_by_ancestry = _is_descendant_of(pid, leader_pid) or (
            current.ppid == caller_pid
            and current.start_time is not None
            and leader_start is not None
            and current.start_time >= leader_start
        )
        # Session-context match (non-setsid survivors).
        owned_by_session = (
            leader_pgid is not None
            and leader_sid is not None
            and current.pgid == leader_pgid
            and current.sid == leader_sid
        )
        if owned_by_ancestry or owned_by_session or is_zombie and owned_by_ancestry:
            # For zombies, require ancestry (reparented zombies go to
            # subreaper/caller, hence ppid == caller).
            if is_zombie and not owned_by_ancestry and not owned_by_session:
                continue
            survivors[pid] = True
    # Also include exact-identity live leader children via descendants scan.
    try:
        from tests.prod_readiness_support import descendants_of as _descendants_of

        for child in _descendants_of(leader_pid):
            survivors[child.pid] = True
        for child in _descendants_of(caller_pid):
            try:
                current = process_identity(child.pid)
            except Exception:
                continue
            if leader_start is not None and current.start_time is not None:
                if current.start_time >= leader_start:
                    survivors[child.pid] = True
    except Exception:
        pass
    return sorted(survivors)


def _bounded_drain(
    process: subprocess.Popen[str], *, absolute_deadline: float
) -> tuple[str, str]:
    """Drain pipes with an absolute deadline; never wait forever for EOF.

    Uses nonblocking reads with select so a descendant holding the pipe
    cannot cause indefinite/uncaught blocking.
    """
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    try:
        stdout_fd = process.stdout.fileno() if process.stdout is not None else None
        stderr_fd = process.stderr.fileno() if process.stderr is not None else None
    except Exception:
        stdout_fd = None
        stderr_fd = None
    if stdout_fd is None or stderr_fd is None:
        # Fallback: bounded communicate.
        remaining = max(0.0, absolute_deadline - time.monotonic())
        try:
            return process.communicate(timeout=max(0.1, remaining))
        except subprocess.TimeoutExpired as exc:
            return (
                (exc.stdout or "") if isinstance(exc.stdout, str) else "",
                (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            )
    # Set nonblocking.
    for fd in (stdout_fd, stderr_fd):
        try:
            os.set_blocking(fd, False)
        except Exception:
            pass
    selector = selectors.DefaultSelector()
    try:
        if process.stdout is not None:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        if process.stderr is not None:
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        stdout_open = process.stdout is not None
        stderr_open = process.stderr is not None
        while stdout_open or stderr_open:
            remaining = absolute_deadline - time.monotonic()
            if remaining <= 0:
                break
            # If process exited and no data ready, do a short poll then stop.
            events = selector.select(timeout=min(0.05, remaining))
            if not events:
                if process.poll() is not None:
                    # One more nonblocking attempt, then give up waiting
                    # for EOF held by surviving descendants.
                    for _ in range(2):
                        for key in list(selector.get_map().values()):
                            try:
                                data = os.read(key.fileobj.fileno(), 65536)
                                if not data:
                                    try:
                                        selector.unregister(key.fileobj)
                                    except Exception:
                                        pass
                                    if key.data == "stdout":
                                        stdout_open = False
                                    else:
                                        stderr_open = False
                                else:
                                    text = data.decode("utf-8", errors="replace")
                                    if key.data == "stdout":
                                        stdout_chunks.append(text)
                                    else:
                                        stderr_chunks.append(text)
                            except (BlockingIOError, OSError):
                                pass
                    # Do not loop forever: pipe held by survivor => stop.
                    break
                continue
            for key, _mask in events:
                try:
                    data = os.read(key.fileobj.fileno(), 65536)
                except (BlockingIOError, OSError):
                    continue
                if not data:
                    try:
                        selector.unregister(key.fileobj)
                    except Exception:
                        pass
                    if key.data == "stdout":
                        stdout_open = False
                    else:
                        stderr_open = False
                else:
                    text = data.decode("utf-8", errors="replace")
                    if key.data == "stdout":
                        stdout_chunks.append(text)
                    else:
                        stderr_chunks.append(text)
    finally:
        try:
            selector.close()
        except Exception:
            pass
    return "".join(stdout_chunks), "".join(stderr_chunks)


def run_owned_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    environment: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run one command in an owned session and prove descendant cleanup.

    Guarantees:
    - stdout/stderr collection has an absolute deadline (no unbounded
      communicate waiting for pipe EOF held by descendants);
    - surviving owned descendants make cleanup verification false;
    - no unrelated PID signaling (exact pidfd-pinned identities only);
    - setsid() descendants are still detected via subreaper + ancestry.
    """
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise RunnerError(ErrorCode.INVALID_MANIFEST, "timeout must be numeric")
    if not math.isfinite(float(timeout)) or float(timeout) <= 0:
        raise RunnerError(ErrorCode.INVALID_MANIFEST, "timeout must be finite")
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise RunnerError(ErrorCode.INVALID_MANIFEST, "command must be non-empty argv")
    with child_subreaper_scope():
        return _run_owned_command_in_scope(
            command, cwd=cwd, timeout=float(timeout), environment=environment
        )


def _run_owned_command_in_scope(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    environment: Mapping[str, str] | None,
) -> CommandResult:
    """Implementation for :func:`run_owned_command` under an acquired scope."""
    caller_pid = os.getpid()
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR,
            "owned command executable is missing",
            executable=Path(command[0]).name,
        ) from exc
    except OSError as exc:
        raise RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR,
            "owned command could not be launched",
            error=type(exc).__name__,
        ) from exc
    try:
        identity = process_identity(process.pid)
    except Exception as exc:
        try:
            process.kill()
        except Exception:
            pass
        raise RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR, "owned process identity unavailable"
        ) from exc
    leader_start = identity.start_time
    timed_out = False
    stdout = ""
    stderr = ""
    try:
        try:
            stdout, stderr = process.communicate(timeout=float(timeout))
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            # Preserve partial output if provided.
            if isinstance(exc.stdout, str):
                stdout = exc.stdout
            if isinstance(exc.stderr, str):
                stderr = exc.stderr
            try:
                terminate_owned_process_group(process, identity)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
            # Bounded drain: never wait forever for EOF.
            drained_stdout, drained_stderr = _bounded_drain(
                process, absolute_deadline=time.monotonic() + 5.0
            )
            stdout += drained_stdout
            stderr += drained_stderr
            # Ensure process reaped with bounded wait.
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except Exception:
                    pass
                try:
                    process.wait(timeout=2)
                except Exception:
                    pass
    except RunnerError:
        raise
    except Exception as exc:
        try:
            process.kill()
        except Exception:
            pass
        raise RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR,
            "owned command execution failed",
            error=type(exc).__name__,
        ) from exc
    # Detect survivors: snapshot-based (non-setsid) + ancestry/subreader
    # (setsid/daemonized). Do NOT trust executor self-report alone.
    survivors: set[int] = set(_collect_owned_survivors(identity, caller_pid=caller_pid, leader_start=leader_start))
    try:
        snapshot = capture_resource_snapshot(owner_identities=(identity,))
        for leak in snapshot.unexpected_leaks:
            try:
                survivors.add(int(leak.details.get("pid")))
            except Exception:
                pass
    except Exception:
        # Snapshot failure is itself a leak uncertainty -> fail closed.
        return CommandResult(
            tuple(command), process.returncode, stdout, stderr, timed_out, False
        )
    if survivors:
        # Attempt exact-identity cleanup, then re-verify.
        try:
            snapshot2 = capture_resource_snapshot(owner_identities=(identity,))
            _terminate_exact_observations(tuple(snapshot2.unexpected_leaks))
        except Exception:
            pass
        for pid in sorted(survivors):
            try:
                current = process_identity(pid)
                if (
                    current.start_time is not None
                    and leader_start is not None
                    and current.start_time >= leader_start
                    and current.boot_id == identity.boot_id
                ):
                    try:
                        descriptor = os.pidfd_open(pid, 0)
                    except (AttributeError, OSError):
                        continue
                    try:
                        # Revalidate before signaling.
                        rechecked = process_identity(pid)
                        if (
                            rechecked.start_time == current.start_time
                            and rechecked.boot_id == current.boot_id
                        ):
                            try:
                                signal.pidfd_send_signal(
                                    descriptor, signal.SIGKILL
                                )
                            except OSError:
                                pass
                    finally:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
            except Exception:
                continue
        deadline = time.monotonic() + 3
        still_alive: list[int] = []
        while time.monotonic() < deadline:
            still_alive = []
            for pid in sorted(survivors):
                try:
                    current = process_identity(pid)
                    # Zombie owned by us still counts as leak until reaped.
                    # If parent is us (subreaper), try to reap via waitpid.
                    if current.state == "Z":
                        try:
                            waited, _ = os.waitpid(pid, os.WNOHANG)
                            if waited == 0:
                                still_alive.append(pid)
                        except ChildProcessError:
                            pass
                        except OSError:
                            still_alive.append(pid)
                    else:
                        # Verify still same identity.
                        if (
                            current.boot_id == identity.boot_id
                            and current.start_time is not None
                            and leader_start is not None
                            and current.start_time >= leader_start
                        ):
                            still_alive.append(pid)
                except Exception:
                    continue
            if not still_alive:
                break
            time.sleep(0.02)
        # Final check: any remaining owned survivor => verified False.
        # Also re-scan via ancestry to catch reparented stragglers.
        rescan = _collect_owned_survivors(
            identity, caller_pid=caller_pid, leader_start=leader_start
        )
        live_rescan: list[int] = []
        for pid in rescan:
            try:
                current = process_identity(pid)
                if current.state == "Z":
                    try:
                        waited, _ = os.waitpid(pid, os.WNOHANG)
                        if waited != 0:
                            continue
                    except ChildProcessError:
                        continue
                    except OSError:
                        pass
                    live_rescan.append(pid)
                else:
                    live_rescan.append(pid)
            except Exception:
                continue
        # Fail closed: ANY owned leak detected during execution makes
        # verification false, even if cleanup subsequently killed it. A
        # leaky command must never report verified True (otherwise provider
        # PASS would hide the leak). Survivors still alive also False.
        if survivors or still_alive or live_rescan:
            return CommandResult(
                tuple(command), process.returncode, stdout, stderr, timed_out, False
            )
    return CommandResult(
        tuple(command), process.returncode, stdout, stderr, timed_out, True
    )


def _overlap(first: Path, second: Path) -> bool:
    return (
        first == second or first.is_relative_to(second) or second.is_relative_to(first)
    )


def validate_external_run_root(
    run_root: Path,
    canonical_repo: Path,
    *,
    source_directories: Sequence[Path] = (),
    must_be_empty: bool = True,
) -> ContainmentPolicy:
    """Prove a run root is physical, absolute, external, and unambiguous."""
    raw = Path(run_root)
    if not raw.is_absolute() or any(part == ".." for part in raw.parts):
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID,
            "run root must be absolute without parent traversal",
        )
    if raw.is_symlink():
        raise RunnerError(ErrorCode.RUN_ROOT_INVALID, "run root may not be a symlink")
    try:
        root = raw.resolve(strict=True)
        canonical = canonical_repo.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID,
            "run root or canonical repository cannot be resolved",
        ) from exc
    if not root.is_dir():
        raise RunnerError(ErrorCode.RUN_ROOT_INVALID, "run root must be a directory")
    protected = [canonical, *registered_worktrees(canonical)]
    common_raw = subprocess.run(
        ["git", "-C", str(canonical), "rev-parse", "--git-common-dir"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()
    common = Path(common_raw)
    protected.append(
        (canonical / common).resolve() if not common.is_absolute() else common.resolve()
    )
    protected.extend(Path(item).resolve(strict=True) for item in source_directories)
    if any(_overlap(root, item) for item in protected):
        code = (
            ErrorCode.CANONICAL_TARGET_REFUSED
            if any(
                _overlap(root, item)
                for item in protected[: 3 + len(registered_worktrees(canonical))]
            )
            else ErrorCode.RUN_ROOT_INVALID
        )
        raise RunnerError(
            code, "run root overlaps a protected path", run_root=str(root)
        )
    configured_raw = os.environ.get(RUN_ROOT_ENV)
    if not configured_raw:
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID,
            f"{RUN_ROOT_ENV} must name the external parent run root",
        )
    configured_path = Path(configured_raw)
    if not configured_path.is_absolute() or configured_path.is_symlink():
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID,
            f"{RUN_ROOT_ENV} must be an absolute physical directory",
        )
    try:
        configured = configured_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, f"{RUN_ROOT_ENV} cannot be resolved"
        ) from exc
    if root.parent != configured or not root.name:
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID,
            f"run root must be exactly {RUN_ROOT_ENV}/<run_id>",
            configured_root=str(configured),
            run_root=str(root),
        )
    if must_be_empty and any(root.iterdir()):
        raise RunnerError(
            ErrorCode.RUN_ROOT_INVALID, "run root must be newly created or empty"
        )
    try:
        root.chmod(0o700)
        return ContainmentPolicy.create(root, canonical)
    except HarnessSafetyError as exc:
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET, "containment policy rejected run root"
        ) from exc


def initialize_run_root(
    run_root: Path,
    canonical_repo: Path,
    *,
    source_directories: Sequence[Path] = (),
    test_hook: Callable[[str, dict[str, Any]], None] | None = None,
) -> ContainmentPolicy:
    policy = validate_external_run_root(
        run_root, canonical_repo, source_directories=source_directories
    )
    owned: OwnedRunRoot | None = None
    try:
        owned = open_owned_run_root(policy.disposable_root, test_hook=test_hook)
        for name in RUN_LAYOUT:
            owned.mkdir_rel(name)
    finally:
        if owned is not None:
            owned.close()
    return policy


def initialize_owned_run_root(
    run_root: Path,
    canonical_repo: Path,
    *,
    source_directories: Sequence[Path] = (),
    test_hook: Callable[[str, dict[str, Any]], None] | None = None,
) -> tuple[ContainmentPolicy, OwnedRunRoot]:
    """Validate then return both the policy and a held descriptor capability.

    Callers MUST use the returned OwnedRunRoot for all authoritative writes
    and MUST close it (or use it as a context manager). The file descriptor
    pins the originally authorized directory inode; pathname renames or
    symlink swaps after authorization cannot redirect descriptor-anchored
    writes.
    """
    policy = validate_external_run_root(
        run_root, canonical_repo, source_directories=source_directories
    )
    owned = open_owned_run_root(policy.disposable_root, test_hook=test_hook)
    try:
        for name in RUN_LAYOUT:
            owned.mkdir_rel(name)
    except BaseException:
        owned.close()
        raise
    # Attach handle for convenience; runners should use the explicit handle.
    object.__setattr__(policy, "_owned_handle", owned)  # type: ignore[attr-defined]
    return policy, owned


def persist_run_plan(
    policy: ContainmentPolicy,
    raw_plan: Mapping[str, Any],
    *,
    expected_campaign_kind: str,
    owned: OwnedRunRoot | None = None,
) -> RunPlan:
    """Validate and durably freeze a campaign's shared plan before execution."""
    plan = RunPlan.from_dict(raw_plan)
    if plan.campaign_kind != expected_campaign_kind:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "run plan campaign kind differs from runner",
            expected=expected_campaign_kind,
            actual=plan.campaign_kind,
        )
    if plan.run_id != policy.disposable_root.name:
        raise RunnerError(ErrorCode.INVALID_MANIFEST, "run ID differs from run root")
    try:
        planned_root = Path(plan.run_root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST, "planned run root is invalid"
        ) from exc
    if planned_root != policy.disposable_root:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST, "planned run root differs from actual run root"
        )
    if owned is not None:
        owned.atomic_create_json_rel(
            "manifest/run-plan.json", plan.to_dict()
        )
    else:
        atomic_create_json(
            policy.disposable_root / "manifest" / "run-plan.json", plan.to_dict()
        )
    return plan


def budget_limits_from_plan(plan: RunPlan) -> BudgetLimits:
    allowed = {field.name for field in dataclasses.fields(BudgetLimits)}
    if set(plan.budgets) != allowed:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "run plan budgets must contain the exact common budget fields",
            missing=sorted(allowed - set(plan.budgets)),
            extra=sorted(set(plan.budgets) - allowed),
        )
    return BudgetLimits(**plan.budgets)


def freeze_run_plan(
    policy: ContainmentPolicy,
    raw_plan: Mapping[str, Any] | None,
    *,
    expected_campaign_kind: str,
    default_limits: BudgetLimits,
    seed: int,
    scenario_selection: Sequence[str],
    tool_paths: Sequence[Path] = (),
    fixture_paths: Sequence[Path] = (),
    owned: OwnedRunRoot | None = None,
) -> RunPlan:
    """Freeze an explicit Stage B plan or a fully populated implementation plan."""
    if raw_plan is None:
        raw_plan = {
            "run_id": policy.disposable_root.name,
            "candidate_sha": git_output(
                policy.canonical_repo, "rev-parse", "HEAD"
            ).strip(),
            "candidate_tree": git_output(
                policy.canonical_repo, "rev-parse", "HEAD^{tree}"
            ).strip(),
            "environment_id": f"python-{sys.version_info.major}.{sys.version_info.minor}-{sys.platform}",
            "campaign_kind": expected_campaign_kind,
            "static_manifest_hashes": {},
            "seed": seed,
            "budgets": dataclasses.asdict(default_limits),
            "run_root": str(policy.disposable_root),
            "scenario_selection": list(scenario_selection),
            "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tool_hashes": {
                str(path): sha256_path(path) for path in sorted(tool_paths, key=str)
            },
            "fixture_hashes": {
                str(path): sha256_path(path) for path in sorted(fixture_paths, key=str)
            },
        }
    else:
        # Strict Stage B plan budgets: reject non-finite numbers early,
        # including JSON NaN/Infinity that strict_json_loads already blocks
        # for file-loaded plans but may appear in programmatically built dicts.
        budgets = raw_plan.get("budgets")
        if isinstance(budgets, dict):
            for key, value in budgets.items():
                if isinstance(value, bool):
                    raise RunnerError(
                        ErrorCode.INVALID_MANIFEST,
                        "budget must be non-negative",
                        budget=key,
                    )
                if isinstance(value, float) and not math.isfinite(value):
                    raise RunnerError(
                        ErrorCode.INVALID_MANIFEST,
                        "budget must be finite",
                        budget=key,
                    )
    return persist_run_plan(
        policy, raw_plan, expected_campaign_kind=expected_campaign_kind, owned=owned
    )


def git_output(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if process.returncode:
        raise RunnerError(
            ErrorCode.INTERNAL_HARNESS_ERROR,
            "git inspection failed",
            args=list(args),
            stderr=process.stderr,
        )
    return process.stdout


def canonical_state(repo: Path) -> dict[str, Any]:
    tracked = git_output(repo, "ls-files", "-s").encode()
    staged = git_output(repo, "diff", "--cached", "--binary").encode()
    unstaged = git_output(repo, "diff", "--binary").encode()
    untracked = sorted(
        line[3:]
        for line in git_output(
            repo, "status", "--porcelain=v1", "--untracked-files=all"
        ).splitlines()
        if line.startswith("?? ")
    )
    return {
        "head": git_output(repo, "rev-parse", "HEAD").strip(),
        "tree": git_output(repo, "rev-parse", "HEAD^{tree}").strip(),
        "semantic_index_sha256": sha256_bytes(tracked),
        "tracked_state_sha256": sha256_bytes(
            git_output(
                repo, "status", "--porcelain=v1", "--untracked-files=no"
            ).encode()
        ),
        "staged_sha256": sha256_bytes(staged),
        "unstaged_sha256": sha256_bytes(unstaged),
        "untracked": untracked,
        "worktrees": [str(item) for item in registered_worktrees(repo)],
    }


_SECRET_NAME = re.compile(r"(?:^|_)(?:TOKEN|API_KEY|SECRET|PASSWORD)$", re.IGNORECASE)
_BEARER = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+")
_NAMED_SECRET = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|API_KEY|SECRET|PASSWORD))\s*([:=])\s*([^\s,;]+)"
)
# Lowercase CLI flags: --token VALUE, --token=VALUE, --api-key, etc.
_FLAG_SECRET = re.compile(
    r"(?i)(--?(?:token|api[-_]?key|secret|password|authorization))(=)([^\s,;]+)"
)
_FLAG_NAMES = frozenset(
    {
        "--token",
        "--api-key",
        "--api_key",
        "--secret",
        "--password",
        "--authorization",
        "-t",
        "--auth",
        "--bearer",
    }
)


def redact_text(text: str, *, known_secrets: Iterable[str] = ()) -> str:
    if not isinstance(text, str):
        raise RunnerError(
            ErrorCode.SECRET_REDACTION_FAILED, "redaction input is not text"
        )
    secrets = tuple(known_secrets)
    result = _BEARER.sub(r"\1[REDACTED]", text)
    result = _NAMED_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", result
    )
    for secret in sorted(
        {value for value in secrets if isinstance(value, str) and value},
        key=len,
        reverse=True,
    ):
        result = result.replace(secret, "[REDACTED]")
    for secret in secrets:
        if secret and secret in result:
            raise RunnerError(
                ErrorCode.SECRET_REDACTION_FAILED, "secret remained after redaction"
            )
    return result


def redacted_environment_metadata(
    environment: Mapping[str, str],
    *,
    allowlist: Iterable[str] = ("PATH", "LANG", "LC_ALL", "TZ"),
) -> dict[str, str]:
    allowed = set(allowlist)
    output: dict[str, str] = {}
    for key in sorted(environment):
        if _SECRET_NAME.search(key) or key.upper() == "AUTHORIZATION":
            output[key] = "[REDACTED]"
        elif key in allowed:
            output[key] = environment[key]
    return output


def collect_known_secrets(environment: Mapping[str, str]) -> list[str]:
    """Collect secret values using the same knowledge as stdout/stderr."""
    import re as _re

    known: list[str] = []
    for key, value in environment.items():
        if not isinstance(value, str) or not value:
            continue
        if key.upper() == "AUTHORIZATION" or _re.search(
            r"(?:^|_)(?:TOKEN|API_KEY|SECRET|PASSWORD)$", key, _re.IGNORECASE
        ):
            known.append(value)
    return known


def redact_argv(
    command: Sequence[str], *, known_secrets: Iterable[str] = ()
) -> list[str]:
    """Redact secret-bearing argv using the same knowledge as text/env.

    Covers known secret values, *_TOKEN/*_API_KEY/*_SECRET/*_PASSWORD,
    AUTHORIZATION/Bearer, KEY=value, --token VALUE and --token=VALUE
    (including punctuation-adjacent values). Ordinary args are retained.
    Raises RunnerError on redaction failure so campaigns cannot PASS.
    """
    if not command or any(
        not isinstance(part, str) or not part for part in command
    ):
        raise RunnerError(
            ErrorCode.SECRET_REDACTION_FAILED,
            "redaction input command is malformed",
        )
    secrets = tuple(known_secrets)
    redacted: list[str] = []
    redact_next = False
    for part in command:
        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
            continue
        lowered = part.lower()
        if lowered in _FLAG_NAMES:
            # Flag itself is not secret, but its value (next argv) is.
            redacted.append(part)
            redact_next = True
            continue
        value = part
        try:
            value = _BEARER.sub(r"\1[REDACTED]", value)
            value = _NAMED_SECRET.sub(
                lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value
            )
            value = _FLAG_SECRET.sub(r"\1\2[REDACTED]", value)
        except Exception as exc:
            raise RunnerError(
                ErrorCode.SECRET_REDACTION_FAILED, "argv redaction failed"
            ) from exc
        for secret in sorted(
            {s for s in secrets if isinstance(s, str) and s},
            key=len,
            reverse=True,
        ):
            if secret in value:
                value = value.replace(secret, "[REDACTED]")
        redacted.append(value)
    if redact_next:
        # Trailing flag without value: nothing to redact, keep as-is.
        pass
    # Fail closed: no known secret may survive byte-for-byte.
    for secret in secrets:
        if secret:
            for element in redacted:
                if secret in element:
                    raise RunnerError(
                        ErrorCode.SECRET_REDACTION_FAILED,
                        "secret remained after argv redaction",
                    )
    return redacted


def stable_error_code(exc: BaseException) -> ErrorCode:
    """Map operational failures to stable machine-readable codes."""
    if isinstance(exc, RunnerError):
        return exc.code
    if isinstance(exc, FileNotFoundError):
        return ErrorCode.MUTANT_INVALID
    if isinstance(exc, subprocess.TimeoutExpired):
        return ErrorCode.BUDGET_EXHAUSTED
    if isinstance(exc, (TimeoutError,)):
        return ErrorCode.BUDGET_EXHAUSTED
    return ErrorCode.INTERNAL_HARNESS_ERROR


def evidence_size(root: Path) -> int:
    return sum(
        path.stat().st_size
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def seal_artifacts(
    root: Path,
    relative_paths: Sequence[str],
    *,
    candidate_sha: str,
    candidate_tree: str,
    run_id: str,
) -> dict[str, Any]:
    entries = []
    for relative in sorted(set(relative_paths)):
        path = root / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or not path.resolve().is_relative_to(root.resolve())
        ):
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "artifact is missing, linked, or external",
                path=relative,
            )
        entries.append(
            {
                "path": relative,
                "sha256": sha256_path(path),
                "bytes": path.stat().st_size,
            }
        )
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "candidate_sha": candidate_sha,
        "candidate_tree": candidate_tree,
        "artifacts": entries,
    }
    atomic_create_json(root / "integrity" / "evidence-manifest.json", manifest)
    return manifest


def sha256_owned_rel(owned: OwnedRunRoot, relative: str) -> str:
    """Hash a file anchored to the held run-root fd (swap-proof)."""
    parts = _split_lexical_relative(relative)
    parent_fd, final_name, opened = owned._open_parent_chain(
        parts, create_missing=False
    )
    try:
        try:
            fd = os.open(
                final_name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "artifact is missing or linked",
                path=relative,
            ) from exc
        try:
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
            return digest.hexdigest()
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    finally:
        for owned_fd in reversed(opened):
            try:
                os.close(owned_fd)
            except OSError:
                pass


def finalize_integrity(
    root: Path,
    *,
    evidence_manifest: Mapping[str, Any],
    assessment_paths: Sequence[str],
    owned: OwnedRunRoot | None = None,
) -> dict[str, Any]:
    if owned is not None:
        evidence_digest = sha256_owned_rel(
            owned, "integrity/evidence-manifest.json"
        )
        assessment = {
            relative: sha256_owned_rel(owned, relative)
            for relative in sorted(assessment_paths)
        }
    else:
        evidence_path = root / "integrity" / "evidence-manifest.json"
        assessment = {
            relative: sha256_path(root / relative)
            for relative in sorted(assessment_paths)
        }
        evidence_digest = sha256_path(evidence_path)
    final = {
        "schema_version": 1,
        "evidence_manifest_sha256": evidence_digest,
        "assessment_sha256": assessment,
    }
    if owned is not None:
        owned.atomic_create_json_rel("integrity/final-integrity.json", final)
        digest = sha256_owned_rel(owned, "integrity/final-integrity.json")
        owned.atomic_create_bytes_rel(
            "integrity/final-integrity.sha256",
            (digest + "  final-integrity.json\n").encode(),
        )
    else:
        final_path = root / "integrity" / "final-integrity.json"
        atomic_create_json(final_path, final)
        atomic_create_bytes(
            root / "integrity" / "final-integrity.sha256",
            (sha256_path(final_path) + "  final-integrity.json\n").encode(),
        )
    return final


def seal_artifacts_owned(
    owned: OwnedRunRoot,
    root: Path,
    relative_paths: Sequence[str],
    *,
    candidate_sha: str,
    candidate_tree: str,
    run_id: str,
) -> dict[str, Any]:
    """Descriptor-anchored seal: hash via paths, publish via held fd."""
    entries = []
    for relative in sorted(set(relative_paths)):
        path = root / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or not path.resolve().is_relative_to(root.resolve())
        ):
            raise RunnerError(
                ErrorCode.INTEGRITY_MISMATCH,
                "artifact is missing, linked, or external",
                path=relative,
            )
        entries.append(
            {
                "path": relative,
                "sha256": sha256_path(path),
                "bytes": path.stat().st_size,
            }
        )
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "candidate_sha": candidate_sha,
        "candidate_tree": candidate_tree,
        "artifacts": entries,
    }
    owned.atomic_create_json_rel("integrity/evidence-manifest.json", manifest)
    return manifest


_ALLOWED_DIAGNOSTIC_BASENAMES = frozenset(
    {
        "queue-state.json",
        "budget-state.json",
        "diagnostic.json",
        "current.json",
    }
)


def _inventory_regular_files(root: Path) -> tuple[list[str], bool]:
    """Inventory physical regular files; returns (relatives, has_symlink)."""
    relatives: list[str] = []
    has_symlink = False
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames):
            candidate = current / name
            try:
                if os.path.islink(candidate):
                    has_symlink = True
                    try:
                        dirnames.remove(name)
                    except ValueError:
                        pass
            except OSError:
                continue
        for name in filenames:
            candidate = current / name
            try:
                if os.path.islink(candidate):
                    has_symlink = True
                    continue
            except OSError:
                continue
            # Exclude ephemeral pycache outside integrity relevance.
            try:
                relative = candidate.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                has_symlink = True
                continue
            if "__pycache__" in Path(relative).parts:
                continue
            if relative.endswith(".pyc"):
                continue
            relatives.append(relative)
    return sorted(relatives), has_symlink


def verify_final_integrity(root: Path) -> bool:
    try:
        evidence = load_json(root / "integrity" / "evidence-manifest.json")
        final = load_json(root / "integrity" / "final-integrity.json")
        expected_line = (
            (root / "integrity" / "final-integrity.sha256")
            .read_text(encoding="ascii")
            .split()[0]
        )
        if sha256_path(root / "integrity" / "final-integrity.json") != expected_line:
            return False
        if (
            sha256_path(root / "integrity" / "evidence-manifest.json")
            != final["evidence_manifest_sha256"]
        ):
            return False
        expected_files: set[str] = set()
        for entry in evidence["artifacts"]:
            if sha256_path(root / entry["path"]) != entry["sha256"]:
                return False
            expected_files.add(str(entry["path"]))
        for relative, digest in final["assessment_sha256"].items():
            if sha256_path(root / relative) != digest:
                return False
            expected_files.add(str(relative))
        expected_files.update(
            {
                "integrity/evidence-manifest.json",
                "integrity/final-integrity.json",
                "integrity/final-integrity.sha256",
            }
        )
        # Bind to the expected sealed file set: any new JSON (including
        # uppercase), non-JSON authoritative file, or symlink in
        # authoritative/assessment/integrity-relevant dirs invalidates.
        actual_files, has_symlink = _inventory_regular_files(root)
        if has_symlink:
            return False
        for relative in actual_files:
            if relative in expected_files:
                continue
            basename = Path(relative).name
            # Explicitly allowed diagnostics only.
            if basename in _ALLOWED_DIAGNOSTIC_BASENAMES:
                continue
            # Any other file in authoritative/assessment/integrity scope
            # invalidates integrity (new JSON, uppercase JSON, non-JSON,
            # unexpected symlink already handled).
            parts = Path(relative).parts
            if parts and parts[0] in (
                "assessment",
                "integrity",
                "evidence",
                "manifest",
                "mutation",
                "stress",
                "soak",
                "providers",
                "suites",
            ):
                return False
            # Files in other layout dirs (sandboxes, etc.) are execution
            # scratch; still require exact binding for assessment/integrity.
            # For strictness, any unlisted file in sealed scope fails.
            # Sandbox scratch is allowed to exist (worker dirs) only if
            # under sandboxes/; otherwise fail.
            if parts and parts[0] == "sandboxes":
                continue
            return False
        return True
    except (OSError, KeyError, IndexError, TypeError, RunnerError):
        return False


def command_hash(command: Sequence[str]) -> str:
    return sha256_bytes(canonical_json_bytes(list(command)))


__all__ = [
    "BudgetEngine",
    "BudgetLimits",
    "ContainmentPolicy",
    "CommandResult",
    "ErrorCode",
    "OwnedRunRoot",
    "RUN_LAYOUT",
    "RUN_ROOT_ENV",
    "RunPlan",
    "RunRootHandle",
    "RunnerError",
    "SignalSentinel",
    "atomic_create_bytes",
    "atomic_create_json",
    "budget_limits_from_plan",
    "canonical_state",
    "child_subreaper_scope",
    "capture_resource_snapshot",
    "collect_known_secrets",
    "command_hash",
    "evidence_size",
    "finalize_integrity",
    "freeze_run_plan",
    "hash_paths",
    "initialize_owned_run_root",
    "initialize_run_root",
    "load_json",
    "open_owned_run_root",
    "persist_run_plan",
    "redact_argv",
    "redact_text",
    "redacted_environment_metadata",
    "run_owned_command",
    "seal_artifacts",
    "seal_artifacts_owned",
    "sha256_path",
    "stable_error_code",
    "strict_json_loads",
    "validate_external_run_root",
    "verify_final_integrity",
]
