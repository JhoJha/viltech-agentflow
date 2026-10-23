"""Test-only support for PROD-READINESS durable-boundary and safety tests.

Nothing in this module is imported by production code.  Destructive helpers
require an explicit disposable root and exact Linux process identity.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from unittest import mock


CRASH_BOUNDARIES = (
    "before_authoritative_write",
    "after_write_before_durability",
    "after_durable_completion",
    "after_durable_artifact_before_next_boundary",
)
LINUX_PROC_ROOT = Path("/proc")


class HarnessSafetyError(RuntimeError):
    """The requested harness operation could not be proven safe."""


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode:
        raise HarnessSafetyError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def registered_worktrees(repo: Path) -> tuple[Path, ...]:
    paths = []
    for line in _git(repo.resolve(), "worktree", "list", "--porcelain").splitlines():
        if line.startswith("worktree "):
            paths.append(Path(line[9:]).resolve())
    return tuple(sorted(paths, key=str))


def _destructive_overlap(first: Path, second: Path) -> bool:
    """True when two resolved paths destructively overlap in either direction."""
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def _unlink_dir_contents_fd(
    dir_fd: int,
    protected_dev_ino: set[tuple[int, int]],
    hook: Callable[[str, dict[str, Any]], None] | None = None,
) -> None:
    """Recursively remove directory contents anchored entirely to held dir_fd."""
    if hook is not None:
        hook("before_child_traversal", {"dir_fd": dir_fd})
    try:
        names = os.listdir(dir_fd)
    except OSError as exc:
        raise HarnessSafetyError(f"DIR_TRAVERSAL_FAILED: {exc}") from exc
    for name in names:
        if hook is not None:
            hook("before_child_stat", {"dir_fd": dir_fd, "name": name})
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise HarnessSafetyError(f"DESTRUCTIVE_TARGET_UNREADABLE: {exc}") from exc

        if stat.S_ISDIR(st.st_mode):
            if hook is not None:
                hook("before_child_open", {"dir_fd": dir_fd, "name": name})
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=dir_fd,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise HarnessSafetyError(f"DESTRUCTIVE_TARGET_CHANGED: {exc}") from exc
            try:
                child_st = os.fstat(child_fd)
                if (child_st.st_dev, child_st.st_ino) != (st.st_dev, st.st_ino):
                    raise HarnessSafetyError("DESCRIPTOR_IDENTITY_MISMATCH")
                if (child_st.st_dev, child_st.st_ino) in protected_dev_ino:
                    raise HarnessSafetyError("DESTRUCTIVE_TARGET_PROTECTED")
                _unlink_dir_contents_fd(child_fd, protected_dev_ino, hook)
            finally:
                os.close(child_fd)
            if hook is not None:
                hook("before_rmdir", {"dir_fd": dir_fd, "name": name})
            try:
                os.rmdir(name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise HarnessSafetyError(f"DESTRUCTIVE_RMDIR_FAILED: {exc}") from exc
        else:
            # Symlink, regular file, FIFO, socket: NEVER follow symlink!
            if hook is not None:
                hook("before_unlink", {"dir_fd": dir_fd, "name": name})
            try:
                os.unlink(name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise HarnessSafetyError(f"DESTRUCTIVE_UNLINK_FAILED: {exc}") from exc


@dataclass(frozen=True)
class _DestructiveTarget:
    """One authorized target representation shared with descriptor traversal."""

    canonical: Path
    relative_parts: tuple[str, ...]


@dataclass(frozen=True)
class ContainmentPolicy:
    disposable_root: Path
    canonical_repo: Path
    canonical_git_common_dir: Path
    registered_real_worktrees: tuple[Path, ...]
    protected_dev_ino: frozenset[tuple[int, int]] = field(default_factory=frozenset)
    _test_hook: Any = field(default=None, repr=False, compare=False)

    @classmethod
    def create(cls, disposable_root: Path, canonical_repo: Path) -> "ContainmentPolicy":
        root = disposable_root.resolve(strict=True)
        canonical = canonical_repo.resolve(strict=True)
        common_raw = Path(_git(canonical, "rev-parse", "--git-common-dir"))
        common = (
            common_raw.resolve(strict=True)
            if common_raw.is_absolute()
            else (canonical / common_raw).resolve(strict=True)
        )
        real = registered_worktrees(canonical)
        protected = (canonical, common, *real)
        if any(_destructive_overlap(root, item) for item in protected):
            raise HarnessSafetyError("DISPOSABLE_ROOT_PROTECTED")
        dev_inos = set()
        for item in protected:
            try:
                st = os.stat(item)
                dev_inos.add((st.st_dev, st.st_ino))
            except OSError:
                pass
        return cls(root, canonical, common, real, frozenset(dev_inos))

    def set_test_hook(
        self, hook: Callable[[str, dict[str, Any]], None] | None
    ) -> None:
        object.__setattr__(self, "_test_hook", hook)

    def _current_protected_dev_ino(self) -> set[tuple[int, int]]:
        dev_inos = set(self.protected_dev_ino)
        for item in (
            self.canonical_repo,
            self.canonical_git_common_dir,
            *self.registered_real_worktrees,
            *registered_worktrees(self.canonical_repo),
        ):
            try:
                st = os.stat(item)
                dev_inos.add((st.st_dev, st.st_ino))
            except OSError:
                pass
        return dev_inos

    def _normalize_destructive_target(
        self, target: Path, *, allow_root: bool = False
    ) -> _DestructiveTarget:
        """Interpret relative targets only against the disposable root.

        The returned lexical components are the exact components later used
        by descriptor traversal.  Process CWD is never consulted.
        """
        target_path = Path(target)
        raw_parts = target_path.parts
        if not raw_parts or target_path == Path("."):
            raise HarnessSafetyError("DESTRUCTIVE_TARGET_IS_DISPOSABLE_ROOT")
        if any(part == ".." for part in raw_parts):
            raise HarnessSafetyError("DESTRUCTIVE_TARGET_PARENT_TRAVERSAL")

        root = self.disposable_root
        if target_path.is_absolute():
            lexical_target = Path(os.path.normpath(os.fspath(target_path)))
            if lexical_target != root and not lexical_target.is_relative_to(root):
                raise HarnessSafetyError("DESTRUCTIVE_TARGET_OUTSIDE_DISPOSABLE_ROOT")
            relative = lexical_target.relative_to(root)
        else:
            relative = Path(os.path.normpath(os.fspath(target_path)))
            lexical_target = root / relative

        parts = relative.parts
        if not parts or parts == (".",) or any(part in {"", ".", ".."} for part in parts):
            if allow_root and parts in {(), (".",)}:
                parts = ()
            else:
                raise HarnessSafetyError("DESTRUCTIVE_TARGET_IS_DISPOSABLE_ROOT")

        candidate = lexical_target.resolve(strict=False)
        if candidate == root and not allow_root:
            raise HarnessSafetyError("DESTRUCTIVE_TARGET_IS_DISPOSABLE_ROOT")
        if candidate != root and not candidate.is_relative_to(root):
            raise HarnessSafetyError("DESTRUCTIVE_TARGET_OUTSIDE_DISPOSABLE_ROOT")
        protected = (
            self.canonical_repo,
            self.canonical_git_common_dir,
            *self.registered_real_worktrees,
            *registered_worktrees(self.canonical_repo),
        )
        if any(_destructive_overlap(candidate, item) for item in protected):
            raise HarnessSafetyError("DESTRUCTIVE_TARGET_PROTECTED")
        # Every existing parent is resolved above.  This additionally rejects a
        # not-yet-existing child whose closest existing parent aliases outside.
        parent = lexical_target
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        resolved_parent = parent.resolve(strict=True)
        if resolved_parent != root and not resolved_parent.is_relative_to(root):
            raise HarnessSafetyError("DESTRUCTIVE_PARENT_ESCAPES_DISPOSABLE_ROOT")
        return _DestructiveTarget(candidate, tuple(parts))

    def require_owned_target(self, target: Path, *, allow_root: bool = False) -> Path:
        """Prove that a root-relative or absolute target is disposable."""
        return self._normalize_destructive_target(target, allow_root=allow_root).canonical

    def remove_owned(self, target: Path) -> None:
        """Safely remove an owned target using descriptor-anchored deletion."""
        # Normalize and authorize once. Descriptor traversal consumes these
        # same immutable root-relative components even if CWD later changes.
        normalized = self._normalize_destructive_target(target)
        if self._test_hook is not None:
            self._test_hook(
                "after_authorization",
                {
                    "target": normalized.canonical,
                    "relative_parts": normalized.relative_parts,
                },
            )

        parts = normalized.relative_parts

        protected_dev_ino = self._current_protected_dev_ino()

        if self._test_hook is not None:
            self._test_hook("before_open_root", {"target": normalized.canonical})

        try:
            root_fd = os.open(
                str(self.disposable_root),
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as exc:
            raise HarnessSafetyError(f"DISPOSABLE_ROOT_UNREADABLE: {exc}") from exc

        opened_fds = [root_fd]
        try:
            root_st = os.fstat(root_fd)
            if (root_st.st_dev, root_st.st_ino) in protected_dev_ino:
                raise HarnessSafetyError("DISPOSABLE_ROOT_PROTECTED")

            # Step: walk intermediate ancestors using O_DIRECTORY | O_NOFOLLOW
            current_fd = root_fd
            for part in parts[:-1]:
                if self._test_hook is not None:
                    self._test_hook("before_walk_step", {"part": part, "current_fd": current_fd})
                try:
                    next_fd = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=current_fd,
                    )
                except FileNotFoundError:
                    # Intermediate ancestor already removed
                    return
                except OSError as exc:
                    raise HarnessSafetyError(f"DESTRUCTIVE_TARGET_CHANGED: {exc}") from exc
                opened_fds.append(next_fd)
                next_st = os.fstat(next_fd)
                if (next_st.st_dev, next_st.st_ino) in protected_dev_ino:
                    raise HarnessSafetyError("DESTRUCTIVE_TARGET_PROTECTED")
                current_fd = next_fd

            parent_fd = current_fd
            final_name = parts[-1]

            if self._test_hook is not None:
                self._test_hook("after_parent_fd", {"parent_fd": parent_fd, "final_name": final_name})
                self._test_hook("before_target_stat", {"parent_fd": parent_fd, "final_name": final_name})

            # Inspect final target relative to held parent descriptor
            try:
                target_lstat = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            except OSError as exc:
                raise HarnessSafetyError(f"DESTRUCTIVE_TARGET_UNREADABLE: {exc}") from exc

            if stat.S_ISLNK(target_lstat.st_mode) or stat.S_ISREG(target_lstat.st_mode):
                if self._test_hook is not None:
                    self._test_hook("before_unlink", {"parent_fd": parent_fd, "name": final_name})
                try:
                    os.unlink(final_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise HarnessSafetyError(f"DESTRUCTIVE_UNLINK_FAILED: {exc}") from exc
                return

            if stat.S_ISDIR(target_lstat.st_mode):
                if self._test_hook is not None:
                    self._test_hook("before_target_open", {"parent_fd": parent_fd, "final_name": final_name})
                try:
                    target_fd = os.open(
                        final_name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent_fd,
                    )
                except FileNotFoundError:
                    return
                except OSError as exc:
                    raise HarnessSafetyError(f"DESTRUCTIVE_TARGET_CHANGED: {exc}") from exc
                opened_fds.append(target_fd)
                target_st = os.fstat(target_fd)
                if (target_st.st_dev, target_st.st_ino) != (target_lstat.st_dev, target_lstat.st_ino):
                    raise HarnessSafetyError("DESCRIPTOR_IDENTITY_MISMATCH")
                if (target_st.st_dev, target_st.st_ino) in protected_dev_ino:
                    raise HarnessSafetyError("DESTRUCTIVE_TARGET_PROTECTED")

                if self._test_hook is not None:
                    self._test_hook("after_target_open", {"target_fd": target_fd, "final_name": final_name})

                # Recursively delete contents relative to held descriptor
                _unlink_dir_contents_fd(target_fd, protected_dev_ino, self._test_hook)

                opened_fds.remove(target_fd)
                os.close(target_fd)

                if self._test_hook is not None:
                    self._test_hook("before_rmdir", {"parent_fd": parent_fd, "name": final_name})
                try:
                    os.rmdir(final_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    raise HarnessSafetyError(f"DESTRUCTIVE_RMDIR_FAILED: {exc}") from exc
                return

            raise HarnessSafetyError("DESTRUCTIVE_TARGET_UNEXPECTED_TYPE")
        finally:
            for fd in reversed(opened_fds):
                try:
                    os.close(fd)
                except OSError:
                    pass


def _read_boot_id() -> str | None:
    try:
        return (LINUX_PROC_ROOT / "sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return None


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    ppid: int | None
    pgid: int | None
    sid: int | None
    start_time: int | None
    state: str | None
    boot_id: str | None
    fd_count: int | None
    thread_count: int | None
    measurement: str = "linux-/proc"


def process_identity(pid: int) -> ProcessIdentity:
    """Capture exact process identity. Linux-only fields are explicitly marked."""
    stat_path = LINUX_PROC_ROOT / str(pid) / "stat"
    raw = stat_path.read_text(encoding="utf-8", errors="replace")
    end = raw.rfind(")")
    fields = raw[end + 1 :].split() if end >= 0 else []
    if len(fields) < 20:
        raise HarnessSafetyError(f"malformed {stat_path}")
    try:
        state = fields[0]
        ppid = int(fields[1])
        pgid = int(fields[2])
        sid = int(fields[3])
        start_time = int(fields[19])
    except ValueError as exc:
        raise HarnessSafetyError(f"invalid {stat_path}") from exc
    try:
        fd_count = sum(1 for _ in (LINUX_PROC_ROOT / str(pid) / "fd").iterdir())
    except OSError:
        fd_count = None
    try:
        thread_count = sum(1 for _ in (LINUX_PROC_ROOT / str(pid) / "task").iterdir())
    except OSError:
        thread_count = None
    return ProcessIdentity(
        pid, ppid, pgid, sid, start_time, state, _read_boot_id(), fd_count, thread_count
    )


def same_process(expected: ProcessIdentity) -> bool:
    try:
        current = process_identity(expected.pid)
    except (FileNotFoundError, ProcessLookupError, HarnessSafetyError):
        return False
    return (
        current.start_time == expected.start_time
        and current.boot_id == expected.boot_id
        and current.pgid == expected.pgid
        and current.sid == expected.sid
    )


def _all_processes() -> tuple[ProcessIdentity, ...]:
    result = []
    if not LINUX_PROC_ROOT.is_dir():
        return ()
    for entry in LINUX_PROC_ROOT.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            result.append(process_identity(int(entry.name)))
        except (FileNotFoundError, ProcessLookupError, PermissionError, HarnessSafetyError):
            continue
    return tuple(sorted(result, key=lambda item: item.pid))


def _scan_processes_with_uncertainty() -> tuple[tuple[ProcessIdentity, ...], bool]:
    """Scan /proc, reporting whether ownership-relevant data was unreadable.

    Returns (processes, had_persistent_uncertainty).  Transient disappearance
    (FileNotFoundError/ProcessLookupError) is not uncertainty; malformed stat
    or persistently unreadable owner identity data is.
    """
    result: list[ProcessIdentity] = []
    persistent_uncertainty = False
    try:
        entries = list(LINUX_PROC_ROOT.iterdir())
    except OSError:
        # Cannot even enumerate /proc: callers fail closed when ownership is
        # expected.  Report uncertainty so an apparently clean result is not
        # returned.
        return (), True
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            result.append(process_identity(int(entry.name)))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, HarnessSafetyError, OSError):
            persistent_uncertainty = True
            continue
    return tuple(sorted(result, key=lambda item: item.pid)), persistent_uncertainty


def _coerce_owner_identity(value: Any) -> ProcessIdentity | None:
    if isinstance(value, ProcessIdentity):
        return value
    if isinstance(value, dict):
        try:
            return ProcessIdentity(
                pid=int(value["pid"]),
                ppid=int(value["ppid"]) if value.get("ppid") is not None else None,
                pgid=int(value["pgid"]) if value.get("pgid") is not None else None,
                sid=int(value["sid"]) if value.get("sid") is not None else None,
                start_time=int(value["start_time"]) if value.get("start_time") is not None else None,
                state=value.get("state"),
                boot_id=value.get("boot_id"),
                fd_count=value.get("fd_count"),
                thread_count=value.get("thread_count"),
            )
        except (KeyError, TypeError, ValueError):
            return None
    return None


def _matches_owned_execution(member: ProcessIdentity, leader: ProcessIdentity) -> bool:
    """Match a live /proc member to a durable owned execution identity.

    Numeric PGID alone is never sufficient: the session, boot, and
    start-time context must also agree where available.
    """
    if leader.pgid is None or leader.sid is None:
        return False
    if member.pgid != leader.pgid or member.sid != leader.sid:
        return False
    if leader.boot_id is not None and member.boot_id is not None:
        if member.boot_id != leader.boot_id:
            return False
    if leader.start_time is not None and member.start_time is not None:
        # Members of the owned execution start at or after the leader.
        # An older foreign process that coincidentally reuses the numeric
        # PGID/SID must not be claimed.
        if member.start_time < leader.start_time:
            return False
    return True


DEFAULT_EXECUTION_SCOPE = "single-test-execution"
_DURABLE_PROCESS_REGISTRY: dict[str, list[ProcessIdentity]] = {}


def register_owned_process(
    identity: ProcessIdentity | int | dict[str, Any],
    *,
    owner_scope: str = DEFAULT_EXECUTION_SCOPE,
) -> ProcessIdentity:
    """Explicit durable member-identity registry for owned processes."""
    if not isinstance(owner_scope, str) or not owner_scope:
        raise HarnessSafetyError("PROC_OWNER_SCOPE_MALFORMED")
    if isinstance(identity, int):
        proc_id = process_identity(identity)
    else:
        coerced = _coerce_owner_identity(identity)
        if coerced is None:
            raise HarnessSafetyError("PROC_OWNER_IDENTITY_MALFORMED")
        proc_id = coerced
    if proc_id.start_time is None or not proc_id.boot_id:
        raise HarnessSafetyError("PROC_OWNER_IDENTITY_MALFORMED")
    _DURABLE_PROCESS_REGISTRY.setdefault(owner_scope, []).append(proc_id)
    return proc_id


def clear_owned_process_registry(
    owner_scope: str = DEFAULT_EXECUTION_SCOPE,
) -> None:
    """Clear only one execution's durable ownership records."""
    _DURABLE_PROCESS_REGISTRY.pop(owner_scope, None)


def descendants_of(pid: int) -> tuple[ProcessIdentity, ...]:
    processes, uncertain = _scan_processes_with_uncertainty()
    if uncertain:
        raise HarnessSafetyError("PROC_OWNER_IDENTITY_UNREADABLE")
    children: dict[int, list[ProcessIdentity]] = {}
    for item in processes:
        if item.ppid is not None:
            children.setdefault(item.ppid, []).append(item)
    found: list[ProcessIdentity] = []
    pending = [pid]
    while pending:
        parent = pending.pop()
        for child in children.get(parent, []):
            found.append(child)
            pending.append(child.pid)
    return tuple(sorted(found, key=lambda item: item.pid))


@dataclass(frozen=True)
class ResourceObservation:
    kind: str
    identity: str
    classification: str
    details: dict[str, Any]


@dataclass(frozen=True)
class ResourceSnapshot:
    linux_proc_available: bool
    processes: tuple[ResourceObservation, ...]
    owned_process_groups: tuple[int, ...]
    write_leases: tuple[ResourceObservation, ...]
    worktrees: tuple[ResourceObservation, ...]
    declared_directories: tuple[ResourceObservation, ...]

    @property
    def unexpected_leaks(self) -> tuple[ResourceObservation, ...]:
        return tuple(
            item
            for group in (
                self.processes,
                self.write_leases,
                self.worktrees,
                self.declared_directories,
            )
            for item in group
            if item.classification == "UNEXPECTED_LEAK"
        )


def capture_resource_snapshot(
    *,
    owner_pids: Iterable[int] = (),
    owner_identities: Iterable[Any] = (),
    source_repo: Path | None = None,
    fixture_manifest: dict[str, Any] | None = None,
    owner_scope: str = DEFAULT_EXECUTION_SCOPE,
) -> ResourceSnapshot:
    """Observe only; this function never sends signals or removes resources.

    Owned processes remain discoverable via durable execution identity
    (exact PID/start-time/boot identity or PGID/SID context). Callers that
    need post-exit accounting must pass the leader's previously captured
    identity through ``owner_identities``; numeric PGID/SID reuse without
    matching session/start-time context is never claimed.
    """
    if not LINUX_PROC_ROOT.is_dir():
        raise HarnessSafetyError("PROC_UNAVAILABLE")
    manifest = fixture_manifest or {}
    # Support the manifest-carried durable identity contract as well: an
    # execution that is still expected to be owned may declare its leader
    # identities explicitly so post-exit descendants stay discoverable.
    manifest_identities = manifest.get("owner_identities", [])
    if not isinstance(manifest_identities, list):
        manifest_identities = []
    process_map: dict[int, ProcessIdentity] = {}
    owned_leaders: list[ProcessIdentity] = []
    persistent_owner_error = False
    for pid in sorted(set(owner_pids)):
        try:
            identity = process_identity(pid)
        except (FileNotFoundError, ProcessLookupError):
            # Confirmed disappearance of a previously terminal/quiescent
            # process is representable as clean when no owned descendant
            # remains (checked below); it is not a persistent read failure.
            continue
        except HarnessSafetyError:
            # Required process stat exists but cannot be parsed: fail closed.
            raise
        except (PermissionError, OSError) as exc:
            raise HarnessSafetyError(f"PROC_OWNER_IDENTITY_UNREADABLE: {pid}") from exc
        process_map[identity.pid] = identity
        owned_leaders.append(identity)
        try:
            for child in descendants_of(identity.pid):
                process_map[child.pid] = child
        except HarnessSafetyError:
            raise
        except (PermissionError, OSError) as exc:
            raise HarnessSafetyError(f"PROC_OWNER_IDENTITY_UNREADABLE: {pid}") from exc
        except (FileNotFoundError, ProcessLookupError):
            pass
    scoped_registry = list(_DURABLE_PROCESS_REGISTRY.get(owner_scope, ()))
    for raw in list(owner_identities) + list(manifest_identities) + scoped_registry:
        coerced = _coerce_owner_identity(raw)
        if coerced is None:
            raise HarnessSafetyError("PROC_OWNER_IDENTITY_MALFORMED")
        if coerced.pgid is None or coerced.sid is None:
            raise HarnessSafetyError("PROC_OWNER_IDENTITY_MALFORMED")
        owned_leaders.append(coerced)
        # If the process is still alive with the exact immutable identity,
        # retain ownership even if it escaped PGID/SID via setsid().
        try:
            live = process_identity(coerced.pid)
        except (FileNotFoundError, ProcessLookupError):
            live = None
        except HarnessSafetyError:
            raise
        except (PermissionError, OSError) as exc:
            raise HarnessSafetyError(f"PROC_OWNER_IDENTITY_UNREADABLE: {coerced.pid}") from exc
        if live is not None and (
            live.start_time == coerced.start_time
            and live.boot_id == coerced.boot_id
        ):
            process_map[live.pid] = live
            try:
                for child in descendants_of(live.pid):
                    process_map[child.pid] = child
            except HarnessSafetyError:
                raise
            except (PermissionError, OSError) as exc:
                raise HarnessSafetyError(
                    f"PROC_OWNER_IDENTITY_UNREADABLE: {live.pid}"
                ) from exc
            except (FileNotFoundError, ProcessLookupError):
                pass
    # Durable group scan: find members matching any owned execution identity
    # even when the leader PID no longer exists (reparented descendants).
    scanned: tuple[ProcessIdentity, ...] = ()
    scan_uncertain = False
    if owned_leaders:
        try:
            scanned, scan_uncertain = _scan_processes_with_uncertainty()
        except HarnessSafetyError:
            raise
        except (PermissionError, OSError) as exc:
            raise HarnessSafetyError("PROC_OWNER_IDENTITY_UNREADABLE") from exc
        if scan_uncertain or persistent_owner_error:
            raise HarnessSafetyError("PROC_OWNER_IDENTITY_UNREADABLE")
        for member in scanned:
            for leader in owned_leaders:
                if _matches_owned_execution(member, leader):
                    process_map.setdefault(member.pid, member)
                    break
    expected_processes = set(manifest.get("expected_preserved_processes", []))
    process_rows = tuple(
        ResourceObservation(
            "process",
            str(pid),
            "EXPECTED_PRESERVED" if pid in expected_processes else "UNEXPECTED_LEAK",
            asdict(process_map[pid]),
        )
        for pid in sorted(process_map)
    )
    groups = tuple(
        sorted(
            {
                item.details["pgid"]
                for item in process_rows
                if item.details["pgid"] is not None
            }
        )
    )

    expected_worktrees = {
        str(Path(path).resolve(strict=False))
        for path in manifest.get("expected_preserved_worktrees", [])
    }
    declared_worktrees = {
        str(Path(path).resolve(strict=False)) for path in manifest.get("worktrees", [])
    }
    owned_roots = tuple(
        Path(path).resolve(strict=False)
        for key in ("owned_roots", "temp_directories", "run_directories")
        for path in manifest.get(key, [])
    )
    observed_worktrees: list[ResourceObservation] = []
    if source_repo is not None:
        for path in registered_worktrees(source_repo):
            path_text = str(path)
            if path.resolve() == source_repo.resolve():
                continue
            owned = path_text in declared_worktrees or path_text in expected_worktrees or any(
                path == root or path.is_relative_to(root) for root in owned_roots
            )
            classification = (
                "EXPECTED_PRESERVED"
                if path_text in expected_worktrees
                else "UNEXPECTED_LEAK"
                if owned
                else "OBSERVED_UNOWNED"
            )
            observed_worktrees.append(
                ResourceObservation("worktree", path_text, classification, {"exists": path.exists()})
            )

    expected_leases = {
        str(Path(path).resolve(strict=False)) for path in manifest.get("expected_preserved_leases", [])
    }
    lease_rows = []
    for raw in sorted(manifest.get("write_leases", []), key=str):
        path = Path(raw).resolve(strict=False)
        if not path.exists():
            continue
        classification = (
            "EXPECTED_PRESERVED" if str(path) in expected_leases else "UNEXPECTED_LEAK"
        )
        lease_rows.append(
            ResourceObservation("write_lease", str(path), classification, {"exists": True})
        )

    expected_dirs = {
        str(Path(path).resolve(strict=False)) for path in manifest.get("expected_preserved_directories", [])
    }
    dir_rows = []
    for kind in ("temp_directories", "run_directories"):
        for raw in sorted(manifest.get(kind, []), key=str):
            path = Path(raw).resolve(strict=False)
            classification = (
                "EXPECTED_PRESERVED"
                if str(path) in expected_dirs
                else "OBSERVED_DECLARED"
            )
            dir_rows.append(
                ResourceObservation(kind[:-3], str(path), classification, {"exists": path.exists()})
            )
    return ResourceSnapshot(
        LINUX_PROC_ROOT.is_dir(),
        process_rows,
        groups,
        tuple(lease_rows),
        tuple(sorted(observed_worktrees, key=lambda item: item.identity)),
        tuple(dir_rows),
    )


@dataclass(frozen=True)
class CrashResult:
    scenario_id: str
    child_pid: int
    child_identity: dict[str, Any]
    selected_boundary: str
    phase: str
    returncode: int
    exit_code: int | None
    signal: int | None
    artifact_paths: tuple[str, ...]
    hashes: dict[str, str | None]
    seed: int
    durability_acknowledged: bool
    descendant_identities_before_kill: tuple[dict[str, Any], ...]
    active_descendants_after_wait: tuple[int, ...]

    def logical_result(self) -> dict[str, Any]:
        """Stable replay oracle excluding OS-assigned identities and paths."""
        return {
            "scenario_id": self.scenario_id,
            "selected_boundary": self.selected_boundary,
            "phase": self.phase,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "hash_present": {
                Path(key).name: value is not None for key, value in self.hashes.items()
            },
            "seed": self.seed,
            "durability_acknowledged": self.durability_acknowledged,
            "active_descendants_after_wait": bool(self.active_descendants_after_wait),
        }


def _read_event(fd: int, timeout: float) -> dict[str, Any]:
    selector = selectors.DefaultSelector()
    selector.register(fd, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise HarnessSafetyError("CRASH_CHILD_EVENT_TIMEOUT")
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = os.read(fd, 1)
            if not chunk:
                raise HarnessSafetyError("CRASH_CHILD_EVENT_EOF")
            data.extend(chunk)
    finally:
        selector.close()
    try:
        value = json.loads(data)
    except json.JSONDecodeError as exc:
        raise HarnessSafetyError("CRASH_CHILD_EVENT_MALFORMED") from exc
    if not isinstance(value, dict):
        raise HarnessSafetyError("CRASH_CHILD_EVENT_MALFORMED")
    return value


def terminate_owned_process_group(
    proc: subprocess.Popen[Any], expected: ProcessIdentity, *, sig: signal.Signals = signal.SIGKILL
) -> None:
    """Signal a group only after revalidating its exact recorded leader identity."""
    if proc.pid != expected.pid:
        raise HarnessSafetyError("PROCESS_HANDLE_IDENTITY_MISMATCH")
    if expected.pgid != expected.pid or expected.sid != expected.pid:
        raise HarnessSafetyError("PROCESS_NOT_ISOLATED_GROUP_LEADER")
    if not same_process(expected):
        raise HarnessSafetyError("PROCESS_IDENTITY_CHANGED")
    members = [
        item
        for item in _all_processes()
        if item.pgid == expected.pgid and item.sid == expected.sid and item.state != "Z"
    ]
    if not any(item.pid == expected.pid and item.start_time == expected.start_time for item in members):
        raise HarnessSafetyError("PROCESS_LEADER_NOT_REVALIDATED")
    pinned: list[tuple[int, ProcessIdentity]] = []
    try:
        for member in members:
            try:
                pidfd = os.pidfd_open(member.pid, 0)
            except (AttributeError, OSError) as exc:
                raise HarnessSafetyError("PROCESS_IDENTITY_PIN_FAILED") from exc
            pinned.append((pidfd, member))
        # Signal only pidfd-pinned members whose immutable identity and owned
        # session/group still match. No numeric group-wide signal is used.
        for pidfd, member in pinned:
            try:
                current = process_identity(member.pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if (
                current.start_time != member.start_time
                or current.boot_id != member.boot_id
                or current.pgid != expected.pgid
                or current.sid != expected.sid
            ):
                raise HarnessSafetyError("PROCESS_MEMBER_IDENTITY_CHANGED")
            try:
                signal.pidfd_send_signal(pidfd, sig)
            except (AttributeError, OSError) as exc:
                raise HarnessSafetyError("PROCESS_SIGNAL_FAILED") from exc
    finally:
        for pidfd, _member in pinned:
            os.close(pidfd)


class CrashDriver:
    def __init__(self, policy: ContainmentPolicy, *, timeout: float = 10.0):
        self.policy = policy
        self.timeout = timeout

    def run(
        self,
        scenario_id: str,
        boundary: str,
        *,
        seed: int = 0,
        writer: str = "atomic_json_fsync",
        spawn_descendant: bool = False,
    ) -> CrashResult:
        if boundary not in CRASH_BOUNDARIES:
            raise ValueError(f"unknown crash boundary: {boundary}")
        if writer not in {"atomic_json", "atomic_json_fsync"}:
            raise ValueError(f"unknown writer: {writer}")
        scenario = self.policy.require_owned_target(
            self.policy.disposable_root / "scenarios" / scenario_id
        )
        scenario.mkdir(parents=True, exist_ok=False)
        authoritative = scenario / "authoritative.json"
        diagnostic = scenario / "diagnostic.json"
        record_path = scenario / "crash-result.json"
        event_r, event_w = os.pipe()
        gate_r, gate_w = os.pipe()
        script = Path(__file__).resolve()
        argv = [
            sys.executable,
            str(script),
            "--crash-child",
            "--root",
            str(scenario),
            "--scenario-id",
            scenario_id,
            "--boundary",
            boundary,
            "--writer",
            writer,
            "--seed",
            str(seed),
            "--event-fd",
            str(event_w),
            "--gate-fd",
            str(gate_r),
        ]
        if spawn_descendant:
            argv.append("--spawn-descendant")
        proc = subprocess.Popen(
            argv,
            cwd=self.policy.disposable_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(event_w, gate_r),
            start_new_session=True,
        )
        os.close(event_w)
        os.close(gate_r)
        expected: ProcessIdentity | None = None
        descendants_before_kill: tuple[ProcessIdentity, ...] = ()
        try:
            expected = process_identity(proc.pid)
            event = _read_event(event_r, self.timeout)
            if event.get("phase") != boundary or event.get("pid") != proc.pid:
                raise HarnessSafetyError(f"unexpected crash checkpoint: {event!r}")
            # Current crash scenarios can create only the direct helper below;
            # it never calls setsid(). Prove that every live descendant still
            # shares the pinned crash leader's group/session before signaling.
            # A future escaping topology must add scoped durable registration.
            descendants_before_kill = descendants_of(proc.pid)
            escaped = tuple(
                item.pid
                for item in descendants_before_kill
                if item.pgid != expected.pgid or item.sid != expected.sid
            )
            if escaped:
                raise HarnessSafetyError(
                    f"UNREGISTERED_ESCAPED_CRASH_DESCENDANT: {escaped}"
                )
            terminate_owned_process_group(proc, expected)
            returncode = proc.wait(timeout=self.timeout)
        except BaseException:
            if expected is not None and proc.poll() is None:
                with contextlib.suppress(HarnessSafetyError, ProcessLookupError):
                    terminate_owned_process_group(proc, expected)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=self.timeout)
            raise
        finally:
            os.close(event_r)
            os.close(gate_w)

        survivors = tuple(
            item.pid
            for item in _all_processes()
            if item.pgid == expected.pgid and item.sid == expected.sid and item.state != "Z"
        )
        if survivors:
            raise HarnessSafetyError(f"UNACCOUNTED_ACTIVE_DESCENDANT: {survivors}")
        paths = (str(authoritative), str(diagnostic), str(record_path))
        hashes = {
            str(path): sha256_path(path) if path.is_file() else None
            for path in (authoritative, diagnostic)
        }
        result = CrashResult(
            scenario_id=scenario_id,
            child_pid=proc.pid,
            child_identity=asdict(expected),
            selected_boundary=boundary,
            phase=boundary,
            returncode=returncode,
            exit_code=returncode if returncode >= 0 else None,
            signal=-returncode if returncode < 0 else None,
            artifact_paths=paths,
            hashes=hashes,
            seed=seed,
            durability_acknowledged=boundary
            in {"after_durable_completion", "after_durable_artifact_before_next_boundary"},
            descendant_identities_before_kill=tuple(
                asdict(item) for item in descendants_before_kill
            ),
            active_descendants_after_wait=survivors,
        )
        # The parent records the observation only after the killed group is
        # proven quiet. This record is harness evidence, never product evidence.
        record_path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n")
        return result


class SignalSentinel:
    """Unrelated cooperative child that records caught signals and exits by pipe."""

    def __init__(self, policy: ContainmentPolicy, name: str = "unrelated-sentinel"):
        import secrets as _secrets

        self.policy = policy
        self.name = name
        self.events_path = policy.require_owned_target(
            policy.disposable_root / "sentinels" / f"{name}.jsonl"
        )
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        # Bind evidence to this sentinel instance: a fresh event file plus a
        # unique run token included in every child event.  Stale events from
        # prior runs cannot fail a fresh sentinel, and foreign PID/token
        # events are never attributed to this instance.  Truncation only
        # touches this sentinel's own file, never unrelated evidence.
        self.run_token = _secrets.token_hex(16)
        try:
            with self.events_path.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {"kind": "INIT", "pid": os.getpid(), "token": self.run_token}
                    )
                    + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise HarnessSafetyError(f"SENTINEL_EVENT_INIT_FAILED: {exc}") from exc
        self._control_r, self._control_w = os.pipe()
        code = (
            "import json,os,select,signal,sys\n"
            "path=sys.argv[1]; fd=int(sys.argv[2]); token=sys.argv[3]\n"
            "def emit(kind,num=None):\n"
            " f=open(path,'a',encoding='utf-8'); f.write(json.dumps({'kind':kind,'signal':num,'pid':os.getpid(),'token':token})+'\\n'); f.flush(); os.fsync(f.fileno()); f.close()\n"
            "def caught(num,frame): emit('SIGNAL',num)\n"
            "for n in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGUSR1): signal.signal(n,caught)\n"
            "emit('READY'); print('READY',flush=True)\n"
            "while True:\n"
            " ready,_,_=select.select([fd],[],[])\n"
            " if os.read(fd,1)==b'Q': emit('CLEAN_EXIT'); break\n"
        )
        self.proc = subprocess.Popen(
            [sys.executable, "-c", code, str(self.events_path), str(self._control_r), self.run_token],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            pass_fds=(self._control_r,),
            start_new_session=True,
        )
        os.close(self._control_r)
        ready = self.proc.stdout.readline().strip() if self.proc.stdout is not None else ""
        if ready != "READY":
            raise HarnessSafetyError("SENTINEL_DID_NOT_START")
        self.identity = process_identity(self.proc.pid)

    def events(self) -> tuple[dict[str, Any], ...]:
        rows = []
        if self.events_path.is_file():
            try:
                content = self.events_path.read_text(encoding="utf-8")
            except OSError as exc:
                raise HarnessSafetyError(f"SENTINEL_EVENT_READ_FAILED: {exc}") from exc
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise HarnessSafetyError("SENTINEL_EVIDENCE_UNCERTAIN") from exc
        return tuple(rows)

    def _is_current_instance_event(self, row: dict[str, Any]) -> bool:
        token = row.get("token")
        pid = row.get("pid")
        # Events carrying an explicit foreign token/PID belong to another
        # instance and must not be attributed here.  Legacy events without
        # binding are treated conservatively as current-instance so a real
        # signal is never missed (fail closed).
        if token is not None and token != self.run_token:
            return False
        if pid is not None and pid != self.proc.pid:
            return False
        return True

    def signal_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            row
            for row in self.events()
            if row.get("kind") == "SIGNAL" and self._is_current_instance_event(row)
        )

    def assert_untouched(self) -> None:
        if self.proc.poll() is not None:
            raise AssertionError(f"sentinel exited unexpectedly: {self.proc.returncode}")
        if not same_process(self.identity):
            raise AssertionError("sentinel identity changed")
        if self.signal_events():
            raise AssertionError(f"sentinel received signal: {self.signal_events()!r}")

    def close(self) -> None:
        if self.proc.poll() is None:
            with contextlib.suppress(BrokenPipeError):
                os.write(self._control_w, b"Q")
            self.proc.wait(timeout=5)
        os.close(self._control_w)
        if self.proc.stdout is not None:
            self.proc.stdout.close()
        if self.proc.stderr is not None:
            self.proc.stderr.close()

    def __enter__(self) -> "SignalSentinel":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


def authoritative_json(path: Path) -> dict[str, Any] | None:
    """Return a complete authoritative object; diagnostics are never accepted."""
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("authority") != "AUTHORITATIVE":
        return None
    if value.get("status") != "COMPLETED":
        return None
    return value


def _child_emit(fd: int, phase: str) -> None:
    payload = json.dumps({"phase": phase, "pid": os.getpid()}, sort_keys=True).encode() + b"\n"
    os.write(fd, payload)


def _crash_child(args: argparse.Namespace) -> int:
    # Import here so the ordinary test support import has no dependency on
    # production internals. The child executes the real production writer.
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    import agentflow  # pylint: disable=import-outside-toplevel

    root = Path(args.root).resolve(strict=True)
    artifact = root / "authoritative.json"
    diagnostic = root / "diagnostic.json"
    diagnostic.write_text(
        json.dumps(
            {
                "authority": "DIAGNOSTIC",
                "status": "COMPLETED",
                "scenario_id": args.scenario_id,
                "seed": args.seed,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    descendants = []
    if args.spawn_descendant:
        descendants.append(
            subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(3600)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        )

    def checkpoint(phase: str) -> None:
        if phase != args.boundary:
            return
        _child_emit(args.event_fd, phase)
        # Only an explicit parent release may continue execution. Normal crash
        # tests SIGKILL the group, so this read never returns.
        if os.read(args.gate_fd, 1) != b"C":
            os._exit(125)

    checkpoint("before_authoritative_write")
    original_replace = os.replace
    original_fsync_directory = agentflow.fsync_directory

    def replace(source: str | bytes | Path, target: str | bytes | Path) -> None:
        original_replace(source, target)
        if Path(target).resolve(strict=False) == artifact:
            checkpoint("after_write_before_durability")

    def fsync_directory(path: Path) -> None:
        original_fsync_directory(path)
        if Path(path).resolve(strict=False) == root:
            checkpoint("after_durable_completion")

    payload = {
        "authority": "AUTHORITATIVE",
        "status": "COMPLETED",
        "scenario_id": args.scenario_id,
        "seed": args.seed,
    }
    with mock.patch.object(agentflow.os, "replace", side_effect=replace), mock.patch.object(
        agentflow, "fsync_directory", side_effect=fsync_directory
    ):
        getattr(agentflow, args.writer)(artifact, payload)
    checkpoint("after_durable_artifact_before_next_boundary")
    return 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crash-child", action="store_true")
    parser.add_argument("--root")
    parser.add_argument("--scenario-id")
    parser.add_argument("--boundary", choices=CRASH_BOUNDARIES)
    parser.add_argument("--writer", choices=("atomic_json", "atomic_json_fsync"))
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--event-fd", type=int)
    parser.add_argument("--gate-fd", type=int)
    parser.add_argument("--spawn-descendant", action="store_true")
    return parser.parse_args(argv)


if __name__ == "__main__":
    parsed = _parse_args(sys.argv[1:])
    if not parsed.crash_child:
        raise SystemExit("test support is not a user CLI")
    raise SystemExit(_crash_child(parsed))
