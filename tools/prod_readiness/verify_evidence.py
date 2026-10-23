#!/usr/bin/env python3
"""Read-only cross-artifact verifier for PROD-READINESS evidence.

The verifier never repairs, creates, removes, or normalizes supplied evidence.
Its manifest is intentionally small: ``run-manifest.json`` identifies the run,
candidate, required paths, and immutable artifacts with their SHA-256 digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


MANIFEST_NAME = "run-manifest.json"
# Explicit diagnostic contract for sealed bundles: only these basenames may
# appear as unlisted JSON.  Every other .json file in a sealed bundle must be
# a listed authoritative artifact; unfamiliar basenames are never inferred as
# non-authoritative.
DIAGNOSTIC_NAMES = {"queue-state.json", "budget-state.json", "diagnostic.json", "current.json"}
KNOWN_AUTHORITATIVE_NAMES = {
    "queue-plan.json",
    "queue-started.json",
    "item-started.json",
    "item-terminal.json",
    "final.json",
    "workspace.json",
    "preservation.json",
    "scenario-terminal.json",
}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str | None
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    status: str = "PASS"
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)
    checked_artifacts: list[str] = field(default_factory=list)
    candidate_sha: str | None = None
    run_id: str | None = None

    def error(
        self, code: str, path: str | None, message: str, **details: Any
    ) -> None:
        self.errors.append(ValidationIssue(code, path, message, details))
        self.status = "FAIL"

    def warning(
        self, code: str, path: str | None, message: str, **details: Any
    ) -> None:
        self.warnings.append(ValidationIssue(code, path, message, details))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "errors": [asdict(item) for item in self.errors],
            "warnings": [asdict(item) for item in self.warnings],
            "checked_artifacts": sorted(set(self.checked_artifacts)),
            "candidate_sha": self.candidate_sha,
            "run_id": self.run_id,
        }


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _looks_truncated(text: str, exc: json.JSONDecodeError) -> bool:
    stripped = text.rstrip()
    if not stripped:
        return True
    if exc.pos >= max(0, len(text) - 1):
        return True
    message = exc.msg.lower()
    if "unterminated" in message:
        return True
    # JSON evidence is object/array shaped. An unclosed delimiter is a strong,
    # deterministic truncation signal; malformed tokens remain EV-02.
    stack: list[str] = []
    quoted = False
    escaped = False
    pairs = {"}": "{", "]": "["}
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char in "{[":
            stack.append(char)
        elif char in "}]":
            if not stack or stack[-1] != pairs[char]:
                return False
            stack.pop()
    return quoted or bool(stack)


def _resolve_internal_reference(root: Path, raw: Any) -> tuple[Path | None, str | None]:
    """Strict reference resolver rejecting absolute paths, .., symlink escapes."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "reference must be a non-empty path string"
    raw_str = raw.strip()
    if raw_str.startswith("/") or Path(raw_str).is_absolute():
        return None, "reference must be relative, absolute paths are forbidden"
    parts = Path(raw_str).parts
    if any(part == ".." for part in parts):
        return None, "reference contains forbidden '..' traversal"
    full_path = root / raw_str
    try:
        resolved = full_path.resolve(strict=False)
        root_resolved = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"reference cannot be safely resolved: {exc}"
    if resolved != root_resolved and not resolved.is_relative_to(root_resolved):
        return None, "reference escapes evidence root"
    try:
        cur = root
        for part in parts:
            cur = cur / part
            if cur.is_symlink():
                target = cur.resolve(strict=False)
                if target != root_resolved and not target.is_relative_to(root_resolved):
                    return None, "symlink reference escapes evidence root"
    except (OSError, RuntimeError, ValueError):
        pass
    return full_path, None


def _artifact_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root).as_posix()
    except ValueError:
        return str(path.resolve(strict=False))


def _is_authoritative_path(relative: str) -> bool:
    path = Path(relative)
    if path.name in KNOWN_AUTHORITATIVE_NAMES:
        return True
    if "transitions" in path.parts and path.suffix == ".json":
        return True
    return path.name.endswith("-terminal.json") or path.name.endswith("-started.json")


def _is_queue_final_document(
    relative: str, entry: dict[str, Any] | None, document: Any
) -> bool:
    """Recognize a listed queue final by content or declared semantic kind."""
    if not isinstance(document, dict):
        return False
    kind = str((entry or {}).get("kind", "")).lower()
    return "completed_items" in document or "queue-final" in kind


def _is_program_final_document(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and isinstance(document.get("run_id"), str)
        and isinstance(document.get("program_id"), str)
        and "verdict" in document
        and "completed_items" not in document
    )


def _canonical_logical_marker(
    relative: str, entry: dict[str, Any] | None, document: Any
) -> tuple[str, str] | None:
    """Map an evidence document to its canonical logical marker class.

    Duplicate immutable logical markers are detected by semantic contract,
    not by filename or manifest ``kind``.  Equivalent terminal contracts for
    the same logical object may not coexist under alternate names/kinds.
    """
    if not isinstance(document, dict):
        return None
    # Queue final check
    if _is_queue_final_document(relative, entry, document) and isinstance(
        document.get("queue_run_id"), str
    ):
        return ("queue-final", str(document["queue_run_id"]))
    # Program final check
    if _is_program_final_document(document):
        return ("program-final", f"{document['run_id']}:{document['program_id']}")
    item_id = document.get("item_id")
    if isinstance(item_id, str) and item_id:
        # An item terminal contract carries its program outcome; any file
        # with that shape is the same logical marker regardless of filename
        # (``item-terminal.json`` vs ``terminal-alt.json``) or ``kind``.
        if isinstance(document.get("program_outcome"), dict):
            return ("item-terminal", item_id)
        # An item start contract carries the start marker for the item.
        entry_kind = str((entry or {}).get("kind", ""))
        name = Path(relative).name
        if (
            "start" in entry_kind.lower()
            or "start" in name.lower()
            or isinstance(document.get("run_id"), str)
        ):
            return ("item-started", item_id)
        return None
    scenario_id = document.get("scenario_id")
    if isinstance(scenario_id, str) and scenario_id:
        entry_kind = str((entry or {}).get("kind", ""))
        name = Path(relative).name
        if (
            "terminal" in entry_kind.lower()
            or "terminal" in name.lower()
            or isinstance(document.get("program_outcome"), dict)
            or "status" in document
        ):
            return ("scenario-terminal", scenario_id)
    return None


class EvidenceVerifier:
    def __init__(
        self,
        root: Path,
        *,
        expected_candidate_sha: str | None = None,
        require_sealed: bool = True,
    ):
        self.root = root.resolve(strict=False)
        self.expected_candidate_sha = expected_candidate_sha
        self.require_sealed = require_sealed
        self.result = ValidationResult()
        self.documents: dict[str, Any] = {}
        self.entries: list[dict[str, Any]] = []
        self.entry_by_path: dict[str, dict[str, Any]] = {}

    def _scan_physical_tree(self) -> tuple[list[Path], list[Path]]:
        """Walk physical evidence tree without following symlinks.

        Returns (json_files, all_files).
        Reports EV-17 on any directory or file symlink.
        """
        json_files: list[Path] = []
        all_files: list[Path] = []
        import stat as _stat

        for dirpath, dirnames, filenames in os.walk(str(self.root), followlinks=False):
            current_dir = Path(dirpath)
            for d in list(dirnames):
                dir_path = current_dir / d
                try:
                    st = os.lstat(dir_path)
                except OSError as exc:
                    self.result.error(
                        "EV-06",
                        _artifact_relative(self.root, dir_path),
                        f"unreadable directory: {exc}",
                    )
                    dirnames.remove(d)
                    continue
                if _stat.S_ISLNK(st.st_mode):
                    self.result.error(
                        "EV-17",
                        _artifact_relative(self.root, dir_path),
                        "symlinked directory is forbidden in sealed evidence",
                    )
                    dirnames.remove(d)

            for f in filenames:
                file_path = current_dir / f
                try:
                    st = os.lstat(file_path)
                except OSError as exc:
                    self.result.error(
                        "EV-06",
                        _artifact_relative(self.root, file_path),
                        f"unreadable file: {exc}",
                    )
                    continue
                if _stat.S_ISLNK(st.st_mode):
                    self.result.error(
                        "EV-17",
                        _artifact_relative(self.root, file_path),
                        "symlinked file is forbidden in sealed evidence",
                    )
                    continue
                all_files.append(file_path)
                if f.lower().endswith(".json"):
                    json_files.append(file_path)

        json_files.sort(key=lambda p: str(p))
        all_files.sort(key=lambda p: str(p))
        return json_files, all_files

    def verify(self) -> ValidationResult:
        if not self.root.is_dir():
            self.result.error("EV-01", str(self.root), "evidence directory is missing")
            return self.result
        if self.root.is_symlink():
            self.result.error("EV-17", str(self.root), "evidence root must not be a symlink")
            return self.result
        manifest_path = self.root / MANIFEST_NAME
        manifest = self._read_json(manifest_path, required=True)
        if not isinstance(manifest, dict):
            return self.result
        self.result.run_id = self._string_or_none(manifest.get("run_id"))
        self.result.candidate_sha = self._string_or_none(manifest.get("candidate_sha"))
        self._validate_manifest_shape(manifest)

        json_paths, _all_files = self._scan_physical_tree()

        self._load_declared_artifacts(manifest)
        self._check_manifest_listing(manifest, json_paths)
        self._check_diagnostic_object_types()
        self._check_queue_final_identity(manifest)
        self._check_candidate_identity(manifest)
        self._check_cross_ids(manifest)
        self._check_references(manifest)
        self._check_terminal_contracts(manifest)
        self._check_human_gates()
        self._check_reservations()
        self._check_diagnostic_leading()
        self._check_queue_order(manifest)
        self.result.checked_artifacts = sorted(set(self.result.checked_artifacts))
        self.result.errors.sort(key=lambda item: (item.code, item.path or "", item.message))
        self.result.warnings.sort(key=lambda item: (item.code, item.path or "", item.message))
        self.result.status = "FAIL" if self.result.errors else "PASS"
        return self.result

    @staticmethod
    def _string_or_none(value: Any) -> str | None:
        return value if isinstance(value, str) and value else None

    def _read_json(self, path: Path, *, required: bool = False) -> Any:
        relative = _artifact_relative(self.root, path)
        if not path.is_file():
            if required:
                self.result.error("EV-01", relative, "required artifact is missing")
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            self.result.error("EV-02", relative, f"artifact is unreadable: {exc}")
            return None
        self.result.checked_artifacts.append(relative)
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            code = "EV-03" if _looks_truncated(text, exc) else "EV-02"
            label = "truncated" if code == "EV-03" else "malformed"
            self.result.error(code, relative, f"{label} JSON", line=exc.lineno, column=exc.colno)
            return None
        except RecursionError:
            self.result.error("EV-02", relative, "JSON nesting exceeds safe parser depth")
            return None
        self.documents[relative] = value
        return value

    def _validate_manifest_shape(self, manifest: dict[str, Any]) -> None:
        for key in ("run_id", "candidate_sha", "required_artifacts", "artifacts"):
            if key not in manifest:
                self.result.error("EV-01", MANIFEST_NAME, f"manifest field {key!r} is missing")
        if not isinstance(manifest.get("required_artifacts"), list):
            self.result.error("EV-02", MANIFEST_NAME, "required_artifacts must be an array")
        if not isinstance(manifest.get("artifacts"), list):
            self.result.error("EV-02", MANIFEST_NAME, "artifacts must be an array")
        sealed = manifest.get("sealed") is True or (
            isinstance(manifest.get("sealed_at"), str) and bool(manifest.get("sealed_at"))
        )
        if self.require_sealed and not sealed:
            self.result.error(
                "EV-01",
                MANIFEST_NAME,
                "release verification requires manifest sealing metadata ('sealed' or 'sealed_at')",
            )
        if self.expected_candidate_sha is not None and manifest.get("candidate_sha") != self.expected_candidate_sha:
            self.result.error(
                "EV-07",
                MANIFEST_NAME,
                "candidate SHA differs from the independently expected SHA",
                expected=self.expected_candidate_sha,
                actual=manifest.get("candidate_sha"),
            )

    def _load_declared_artifacts(self, manifest: dict[str, Any]) -> None:
        required = manifest.get("required_artifacts", [])
        required_set = {item for item in required if isinstance(item, str)}
        for raw in required:
            path, problem = _resolve_internal_reference(self.root, raw)
            if problem or path is None:
                self.result.error("EV-06", MANIFEST_NAME, problem or "bad required reference", reference=raw)
                continue
            if not path.is_file():
                self.result.error("EV-01", str(raw), "required artifact is missing")

        combined: list[tuple[Any, bool]] = []
        combined.extend(
            (item, False)
            for item in (
                manifest.get("artifacts", [])
                if isinstance(manifest.get("artifacts"), list)
                else []
            )
        )
        static_inputs = manifest.get("static_inputs", [])
        if isinstance(static_inputs, list):
            combined.extend((item, True) for item in static_inputs)
        logical_markers: dict[tuple[str, str], str] = {}
        for index, (raw, is_static_input) in enumerate(combined):
            if not isinstance(raw, dict):
                self.result.error("EV-02", MANIFEST_NAME, "artifact entry must be an object", index=index)
                continue
            relative = raw.get("path")
            path, problem = _resolve_internal_reference(self.root, relative)
            if problem or path is None or Path(str(relative)).is_absolute():
                self.result.error("EV-06", MANIFEST_NAME, problem or "artifact path must be relative", reference=relative)
                continue
            relative = Path(str(relative)).as_posix()
            entry = dict(raw)
            entry["_index"] = index
            self.entries.append(entry)
            if relative in self.entry_by_path:
                self.result.error("EV-05", relative, "artifact path is declared more than once")
            else:
                self.entry_by_path[relative] = entry
            immutable = entry.get("immutable", True)
            logical_id = entry.get("logical_id")
            kind = entry.get("kind", Path(relative).name)
            if immutable is True and isinstance(logical_id, str):
                marker = (str(kind), logical_id)
                if marker in logical_markers:
                    self.result.error(
                        "EV-05",
                        relative,
                        "duplicate immutable logical marker",
                        first=logical_markers[marker],
                        kind=kind,
                        logical_id=logical_id,
                    )
                else:
                    logical_markers[marker] = relative
            if is_static_input:
                document = None
                if not path.is_file():
                    self.result.error("EV-01", relative, "declared static input is missing")
                else:
                    self.result.checked_artifacts.append(relative)
            else:
                document = self._read_json(path, required=relative in required_set)
            expected_digest = entry.get("sha256")
            if (
                not isinstance(expected_digest, str)
                or len(expected_digest) != 64
                or any(char not in "0123456789abcdef" for char in expected_digest.lower())
            ):
                self.result.error("EV-04", relative, "declared SHA-256 is missing or malformed")
            elif path.is_file():
                try:
                    actual = sha256_path(path)
                except OSError as exc:
                    self.result.error("EV-04", relative, f"artifact cannot be hashed: {exc}")
                else:
                    if actual != expected_digest:
                        self.result.error(
                            "EV-04", relative, "artifact SHA-256 mismatch", expected=expected_digest, actual=actual
                        )
            if document is not None:
                self._check_inferred_duplicate(relative, document, logical_markers)

    def _check_inferred_duplicate(
        self, relative: str, document: Any, seen: dict[tuple[str, str], str]
    ) -> None:
        if not isinstance(document, dict):
            return
        name = Path(relative).name
        if name not in {"item-started.json", "item-terminal.json", "scenario-terminal.json"}:
            return
        logical = document.get("item_id") or document.get("scenario_id")
        if not isinstance(logical, str):
            return
        marker = (name, logical)
        first = seen.get(marker)
        if first is not None and first != relative:
            self.result.error(
                "EV-05", relative, "duplicate immutable logical marker", first=first, logical_id=logical
            )
        else:
            seen[marker] = relative

    def _check_manifest_listing(
        self, manifest: dict[str, Any], json_paths: list[Path]
    ) -> None:
        listed = set(self.entry_by_path)
        sealed = manifest.get("sealed") is True or isinstance(manifest.get("sealed_at"), str)

        for path in json_paths:
            relative = _artifact_relative(self.root, path)
            if relative == MANIFEST_NAME:
                continue
            is_diag = Path(relative).name in DIAGNOSTIC_NAMES
            if is_diag:
                # Permitted diagnostic: parse and validate even if unlisted
                if relative not in self.documents:
                    doc = self._read_json(path, required=False)
                    if doc is not None:
                        self.documents[relative] = doc
                continue
            if relative in listed:
                continue
            if sealed:
                # Sealed completeness: every .json must be either a listed
                # authoritative artifact or an explicitly allowed diagnostic.
                # No heuristic inference of "non-authoritative" is permitted.
                self.result.error(
                    "EV-16", relative, "unexpected JSON artifact exists after sealing"
                )
                continue
            if _is_authoritative_path(relative) and relative not in listed:
                code = "EV-16" if sealed else "EV-15"
                message = (
                    "unexpected authoritative artifact exists after sealing"
                    if sealed
                    else "authoritative artifact is not listed in manifest"
                )
                self.result.error(code, relative, message)
        self._check_canonical_logical_duplicates(json_paths)

    def _check_diagnostic_object_types(self) -> None:
        """Allowlisted diagnostics must always be JSON objects."""
        for relative, document in self.documents.items():
            if Path(relative).name in DIAGNOSTIC_NAMES and not isinstance(document, dict):
                self.result.error(
                    "EV-02", relative, "diagnostic JSON must be an object"
                )

    def _check_queue_final_identity(self, manifest: dict[str, Any]) -> None:
        """Every listed queue final has one explicit sealed-run identity."""
        expected = manifest.get("queue_run_id")
        for relative, document in self.documents.items():
            entry = self.entry_by_path.get(relative)
            if entry is None or not _is_queue_final_document(relative, entry, document):
                continue
            queue_run_id = document.get("queue_run_id")
            if not isinstance(queue_run_id, str) or not queue_run_id:
                self.result.error(
                    "EV-08", relative, "queue final queue_run_id is missing or malformed"
                )
                continue
            if not isinstance(expected, str) or not expected or queue_run_id != expected:
                self.result.error(
                    "EV-08",
                    relative,
                    "queue final queue_run_id differs from sealed run identity",
                    expected=expected,
                    actual=queue_run_id,
                )

    def _check_canonical_logical_duplicates(self, json_paths: list[Path]) -> None:
        """Detect duplicate logical markers by semantic contract.

        Two files carrying equivalent terminal contracts for the same logical
        object (same item/scenario id with the same contract shape) may not
        coexist under alternate filenames or manifest kinds.  Harmless
        duplicate references to the same exact physical artifact are exempt.
        """
        seen: dict[tuple[str, str], tuple[str, Any]] = {}
        # Listed documents first, using both manifest entry and content shape.
        for relative, document in list(self.documents.items()):
            entry = self.entry_by_path.get(relative)
            marker = _canonical_logical_marker(relative, entry, document)
            if marker is None:
                continue
            first = seen.get(marker)
            if first is None:
                seen[marker] = (relative, document)
                continue
            first_rel, _first_doc = first
            if first_rel == relative:
                continue
            try:
                same_physical = (self.root / first_rel).resolve(
                    strict=False
                ) == (self.root / relative).resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                same_physical = False
            if same_physical:
                continue
            self.result.error(
                "EV-05",
                relative,
                "duplicate immutable logical marker",
                first=first_rel,
                logical_class=marker[0],
                logical_id=marker[1],
            )
        # Unlisted JSON files on disk may also duplicate a listed logical
        # marker under an alternate name (e.g. terminal-alt.json).
        for path in json_paths:
            try:
                relative = _artifact_relative(self.root, path)
            except ValueError:
                continue
            if relative == MANIFEST_NAME or relative in self.documents:
                continue
            if Path(relative).name in DIAGNOSTIC_NAMES:
                continue
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            marker = _canonical_logical_marker(relative, None, document)
            if marker is None:
                continue
            first = seen.get(marker)
            if first is None:
                seen[marker] = (relative, document)
                continue
            first_rel, _first_doc = first
            if first_rel == relative:
                continue
            try:
                same_physical = (self.root / first_rel).resolve(
                    strict=False
                ) == (self.root / relative).resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                same_physical = False
            if same_physical:
                continue
            self.result.error(
                "EV-05",
                relative,
                "duplicate immutable logical marker",
                first=first_rel,
                logical_class=marker[0],
                logical_id=marker[1],
            )

    def _candidate_values(self) -> Iterable[tuple[str, Any]]:
        for relative, document in self.documents.items():
            if not isinstance(document, dict):
                continue
            for key in ("candidate_sha", "candidate_commit", "baseline_commit"):
                if key in document:
                    yield relative, document[key]
            if Path(relative).name == "queue-plan.json":
                for index, item in enumerate(document.get("items", [])) if isinstance(document.get("items"), list) else ():
                    if isinstance(item, dict):
                        for key in ("candidate_sha", "candidate_commit", "baseline_commit"):
                            if key in item:
                                yield f"{relative}#items[{index}].{key}", item[key]
            outcome = document.get("program_outcome")
            if isinstance(outcome, dict):
                for key in ("candidate_sha", "candidate_commit", "baseline_commit"):
                    if key in outcome:
                        yield f"{relative}#program_outcome.{key}", outcome[key]
            if _is_queue_final_document(
                relative, self.entry_by_path.get(relative), document
            ):
                for index, item in enumerate(document.get("completed_items", [])) if isinstance(document.get("completed_items"), list) else ():
                    if isinstance(item, dict):
                        for key in ("candidate_sha", "candidate_commit", "baseline_commit"):
                            if key in item:
                                yield f"{relative}#completed_items[{index}].{key}", item[key]

    def _check_candidate_identity(self, manifest: dict[str, Any]) -> None:
        expected = manifest.get("candidate_sha")
        if not isinstance(expected, str) or not expected:
            self.result.error("EV-07", MANIFEST_NAME, "manifest candidate SHA is missing")
            return
        for relative, value in self._candidate_values():
            if value not in (None, "") and value != expected:
                self.result.error(
                    "EV-07", relative, "candidate SHA mismatch", expected=expected, actual=value
                )
        expected_tree = manifest.get("candidate_tree")
        if expected_tree is not None:
            if not isinstance(expected_tree, str) or not expected_tree:
                self.result.error("EV-07", MANIFEST_NAME, "candidate tree identity is malformed")
            else:
                for relative, document in self.documents.items():
                    if not isinstance(document, dict):
                        continue
                    if (
                        "candidate_tree" in document
                        and document["candidate_tree"] != expected_tree
                    ):
                        self.result.error(
                            "EV-07",
                            relative,
                            "candidate tree identity mismatch",
                            expected=expected_tree,
                            actual=document["candidate_tree"],
                        )
                    outcome = document.get("program_outcome")
                    if (
                        isinstance(outcome, dict)
                        and "candidate_tree" in outcome
                        and outcome["candidate_tree"] != expected_tree
                    ):
                        self.result.error(
                            "EV-07",
                            f"{relative}#program_outcome",
                            "candidate tree identity mismatch in program outcome",
                            expected=expected_tree,
                            actual=outcome["candidate_tree"],
                        )

    def _check_cross_ids(self, manifest: dict[str, Any]) -> None:
        root_expected = {
            key: manifest.get(key)
            for key in ("run_id", "queue_id", "queue_run_id", "program_id", "task_id")
            if isinstance(manifest.get(key), str)
        }
        queue_plan = next(
            (doc for rel, doc in self.documents.items() if Path(rel).name == "queue-plan.json" and isinstance(doc, dict)),
            None,
        )
        plan_items: dict[str, dict[str, Any]] = {}
        if queue_plan is not None:
            for item in queue_plan.get("items", []) if isinstance(queue_plan.get("items"), list) else []:
                if isinstance(item, dict) and isinstance(item.get("item_id"), str):
                    plan_items[item["item_id"]] = item
        for relative, document in self.documents.items():
            if relative == MANIFEST_NAME or not isinstance(document, dict):
                continue
            name = Path(relative).name
            for key, expected in root_expected.items():
                if key in document and document[key] != expected:
                    # Program run_id normally differs from queue_run_id. Only
                    # compare fields with the same explicit semantic name.
                    if key == "run_id" and isinstance(manifest.get("queue_id"), str):
                        continue
                    self.result.error(
                        "EV-08", relative, f"{key} mismatch", expected=expected, actual=document[key]
                    )
            item_id = document.get("item_id")
            if isinstance(item_id, str) and plan_items:
                plan = plan_items.get(item_id)
                if plan is None:
                    self.result.error("EV-08", relative, "item_id is absent from queue plan", item_id=item_id)
                else:
                    for key in ("program_id", "task_id"):
                        expected = None
                        nested = plan.get("program" if key == "program_id" else "task")
                        if isinstance(nested, dict):
                            expected = nested.get(key)
                        if key in document and expected is not None and document[key] != expected:
                            self.result.error(
                                "EV-08", relative, f"{key} mismatch", expected=expected, actual=document[key]
                            )
            if name == "item-terminal.json":
                outcome = document.get("program_outcome")
                if isinstance(outcome, dict):
                    for key in ("program_id", "task_id", "run_id"):
                        if key in document and outcome.get(key) != document.get(key):
                            self.result.error("EV-08", relative, f"terminal/outcome {key} mismatch")
                    if isinstance(item_id, str) and item_id in plan_items:
                        plan = plan_items[item_id]
                        for key, container in (("program_id", "program"), ("task_id", "task")):
                            nested = plan.get(container)
                            expected = nested.get(key) if isinstance(nested, dict) else None
                            if expected is not None and outcome.get(key) != expected:
                                self.result.error(
                                    "EV-08",
                                    relative,
                                    f"program outcome/plan {key} mismatch",
                                    expected=expected,
                                    actual=outcome.get(key),
                                )
                    starts = [
                        candidate
                        for candidate_relative, candidate in self.documents.items()
                        if Path(candidate_relative).name == "item-started.json"
                        and isinstance(candidate, dict)
                        and candidate.get("item_id") == item_id
                    ]
                    if starts and starts[0].get("run_id") != outcome.get("run_id"):
                        self.result.error("EV-08", relative, "item start/terminal run_id mismatch")

    def _check_references(self, manifest: dict[str, Any]) -> None:
        references: list[tuple[str, Any, str | None]] = []
        for raw in manifest.get("references", []) if isinstance(manifest.get("references"), list) else []:
            references.append((MANIFEST_NAME, raw, None))
        for entry in self.entries:
            for raw in entry.get("references", []) if isinstance(entry.get("references"), list) else []:
                references.append((str(entry.get("path")), raw, None))
        for relative, document in self.documents.items():
            if not isinstance(document, dict):
                continue
            outcome = document.get("program_outcome")
            candidates = [document, outcome] if isinstance(outcome, dict) else [document]
            for value in candidates:
                for key in ("final_path", "preservation_evidence_path", "run_dir", "execution_repo"):
                    raw = value.get(key)
                    if raw not in (None, ""):
                        references.append((relative, raw, key))
        for source, raw, field_name in references:
            path, problem = _resolve_internal_reference(self.root, raw)
            if problem or path is None or not path.exists():
                self.result.error(
                    "EV-06", source, "broken required reference", field=field_name, reference=raw, reason=problem
                )
                continue
            relative = _artifact_relative(self.root, path)
            sealed = manifest.get("sealed") is True or (
                isinstance(manifest.get("sealed_at"), str)
                and bool(manifest.get("sealed_at"))
            )
            if (
                sealed
                and path.is_file()
                and relative != MANIFEST_NAME
                and relative not in self.entry_by_path
            ):
                self.result.error(
                    "EV-16",
                    relative,
                    "referenced authoritative artifact is not listed in sealed manifest",
                    source=source,
                    field=field_name,
                )

    def _find_document_for_reference(self, raw: Any) -> tuple[str | None, Any]:
        path, problem = _resolve_internal_reference(self.root, raw)
        if problem or path is None:
            return None, None
        relative = _artifact_relative(self.root, path)
        if relative in self.entry_by_path and relative in self.documents:
            return relative, self.documents[relative]
        return relative, None

    def _check_terminal_contracts(self, manifest: dict[str, Any]) -> None:
        for relative, final in list(self.documents.items()):
            if not _is_program_final_document(final):
                continue
            required = ("run_id", "program_id", "task_id", "verdict", "status", "human_gate")
            missing = [key for key in required if key not in final]
            if missing:
                self.result.error(
                    "EV-13", relative, "program final lacks terminal contract fields", missing=missing
                )
            if final.get("verdict") == "HUMAN_GATE":
                if final.get("status") != "SUCCESS" or final.get("human_gate") is not True:
                    self.result.error("EV-09", relative, "invalid Human Gate program final")
            elif final.get("human_gate") is True:
                self.result.error("EV-09", relative, "non-Human-Gate program final claims human_gate")
        for relative, terminal in list(self.documents.items()):
            if Path(relative).name != "item-terminal.json" or not isinstance(terminal, dict):
                continue
            outcome = terminal.get("program_outcome")
            if not isinstance(outcome, dict):
                self.result.error("EV-13", relative, "item terminal has no program outcome")
                continue
            required = (
                "run_id",
                "program_id",
                "task_id",
                "verdict",
                "status",
                "human_gate",
                "outcome_class",
                "final_path",
                "final_sha256",
                "process_quiescence",
            )
            missing = [key for key in required if key not in outcome]
            if missing:
                self.result.error(
                    "EV-13", relative, "program outcome lacks terminal contract fields", missing=missing
                )
            if outcome.get("process_quiescence") != "PROVEN":
                self.result.error("EV-13", relative, "program process quiescence is not proven")
            if outcome.get("preservation_status") == "PROVEN" and not outcome.get(
                "preservation_evidence_path"
            ):
                self.result.error("EV-13", relative, "proven preservation lacks evidence reference")
            final_rel, final = self._find_document_for_reference(outcome.get("final_path"))
            if not isinstance(final, dict):
                self.result.error("EV-13", relative, "item terminal has no valid program final")
                continue
            digest = outcome.get("final_sha256")
            final_path, _ = _resolve_internal_reference(self.root, outcome.get("final_path"))
            digest_valid = (
                isinstance(digest, str)
                and len(digest) == 64
                and all(char in "0123456789abcdef" for char in digest.lower())
            )
            if not digest_valid:
                self.result.error("EV-04", relative, "program final SHA-256 is malformed")
            elif final_path is not None and final_path.is_file():
                try:
                    actual = sha256_path(final_path)
                except OSError as exc:
                    self.result.error("EV-04", final_rel, f"program final cannot be hashed: {exc}")
                else:
                    if actual != digest:
                        self.result.error("EV-04", final_rel, "program final digest mismatch", expected=digest, actual=actual)
            for key in ("run_id", "program_id", "task_id", "verdict", "status", "human_gate"):
                if final.get(key) != outcome.get(key):
                    code = "EV-08" if key in {"run_id", "program_id", "task_id"} else "EV-09"
                    self.result.error(code, relative, f"program outcome/final {key} mismatch")
            if "final" in outcome and outcome.get("final") != final:
                self.result.error("EV-09", relative, "embedded program final differs from referenced final")
            if outcome.get("verdict") == "HUMAN_GATE":
                if outcome.get("human_gate") is not True or outcome.get("status") != "SUCCESS" or outcome.get("outcome_class") != "HUMAN_GATE":
                    self.result.error("EV-09", relative, "invalid Human Gate terminal contract")
            elif outcome.get("human_gate") is True:
                self.result.error("EV-09", relative, "non-Human-Gate verdict claims human_gate")
            if outcome.get("outcome_class") == "HUMAN_GATE" and outcome.get("verdict") != "HUMAN_GATE":
                self.result.error("EV-09", relative, "Human Gate outcome class has non-Human-Gate verdict")

    def _queue_final_documents(self) -> Iterable[tuple[str, dict[str, Any]]]:
        for relative, document in self.documents.items():
            entry = self.entry_by_path.get(relative)
            if entry is not None and _is_queue_final_document(relative, entry, document):
                yield relative, document

    def _terminal_by_item(self) -> dict[str, tuple[str, dict[str, Any]]]:
        result = {}
        for relative, document in self.documents.items():
            if Path(relative).name == "item-terminal.json" and isinstance(document, dict):
                item_id = document.get("item_id")
                if isinstance(item_id, str):
                    result[item_id] = (relative, document)
        return result

    def _check_human_gates(self) -> None:
        terminals = self._terminal_by_item()
        for relative, final in self._queue_final_documents():
            completed = {
                item.get("item_id"): item
                for item in final.get("completed_items", [])
                if isinstance(item, dict) and isinstance(item.get("item_id"), str)
            }
            for gate in final.get("pending_human_gates", []) if isinstance(final.get("pending_human_gates"), list) else []:
                item_id = gate.get("item_id") if isinstance(gate, dict) else None
                summary = completed.get(item_id)
                terminal = terminals.get(item_id)
                outcome = terminal[1].get("program_outcome") if terminal else None
                valid = (
                    isinstance(summary, dict)
                    and summary.get("outcome_class") == "HUMAN_GATE"
                    and summary.get("verdict") == "HUMAN_GATE"
                    and isinstance(outcome, dict)
                    and outcome.get("outcome_class") == "HUMAN_GATE"
                    and outcome.get("human_gate") is True
                )
                if not valid:
                    self.result.error(
                        "EV-10", relative, "Human Gate reference targets a non-Human-Gate item", item_id=item_id
                    )
            pending_ids = {
                item.get("item_id")
                for item in final.get("pending_human_gates", [])
                if isinstance(item, dict) and isinstance(item.get("item_id"), str)
            }
            completed_gate_ids = {
                item_id
                for item_id, summary in completed.items()
                if summary.get("outcome_class") == "HUMAN_GATE"
            }
            if pending_ids != completed_gate_ids:
                self.result.error(
                    "EV-09",
                    relative,
                    "pending Human Gate set differs from completed Human Gate set",
                    pending=sorted(pending_ids),
                    completed=sorted(completed_gate_ids),
                )
            if final.get("verdict") == "HUMAN_GATES_READY" and (
                final.get("status") != "SUCCESS"
                or not completed
                or completed_gate_ids != set(completed)
            ):
                self.result.error("EV-09", relative, "invalid HUMAN_GATES_READY queue contract")
            for item_id, summary in completed.items():
                terminal = terminals.get(item_id)
                if terminal is None:
                    self.result.error("EV-09", relative, "queue final completion lacks item terminal", item_id=item_id)
                    continue
                outcome = terminal[1].get("program_outcome", {})
                for key in (
                    "verdict",
                    "status",
                    "outcome_class",
                    "run_id",
                    "program_id",
                    "task_id",
                    "final_sha256",
                    "baseline_commit",
                ):
                    if key in summary and summary.get(key) != outcome.get(key):
                        code = "EV-08" if key in {"run_id", "program_id", "task_id"} else "EV-09"
                        self.result.error(code, relative, f"queue summary/terminal {key} mismatch", item_id=item_id)

    def _check_reservations(self) -> None:
        started: dict[tuple[Any, Any], dict[str, Any]] = {}
        for relative, doc in self.documents.items():
            if not isinstance(doc, dict) or "transitions" not in Path(relative).parts:
                continue
            if Path(relative).stem.endswith("-started"):
                key = (doc.get("logical_invocation"), doc.get("attempt"))
                if key in started:
                    self.result.error("EV-05", relative, "duplicate immutable attempt marker")
                started[key] = doc
        for relative, state in self.documents.items():
            if Path(relative).name != "budget-state.json" or not isinstance(state, dict):
                continue
            used = state.get("used")
            reservations = state.get("reservations")
            if not isinstance(used, dict) or not isinstance(reservations, list):
                self.result.error("EV-11", relative, "budget counters/reservations are malformed")
                continue
            expected = {
                "model_calls": len(reservations),
                "retries": sum(isinstance(item, dict) and item.get("attempt") == "RETRY" for item in reservations),
                "fallbacks": sum(isinstance(item, dict) and item.get("attempt") == "FALLBACK" for item in reservations),
                "corrections": sum(isinstance(item, dict) and item.get("correction_start") is True for item in reservations),
            }
            for key, count in expected.items():
                if used.get(key) != count:
                    self.result.error(
                        "EV-11", relative, f"{key} counter/reservation inconsistency", expected=count, actual=used.get(key)
                    )
            ids = [item.get("reservation_id") for item in reservations if isinstance(item, dict)]
            if ids != list(range(1, len(ids) + 1)):
                self.result.error("EV-11", relative, "reservation IDs are not contiguous and unique")
            for item in reservations:
                if not isinstance(item, dict):
                    self.result.error("EV-11", relative, "reservation is malformed")
                    continue
                key = (item.get("logical_invocation"), item.get("attempt"))
                marker = started.get(key)
                if marker is not None and marker.get("reservation_id") != item.get("reservation_id"):
                    self.result.error("EV-11", relative, "attempt marker/reservation mismatch")
            reservation_keys = {
                (item.get("logical_invocation"), item.get("attempt"))
                for item in reservations
                if isinstance(item, dict)
            }
            unexpected_markers = sorted(
                repr(key) for key in set(started).difference(reservation_keys)
            )
            if unexpected_markers:
                self.result.error(
                    "EV-11",
                    relative,
                    "immutable attempt marker has no reservation",
                    markers=unexpected_markers,
                )

    def _check_diagnostic_leading(self) -> None:
        terminals = self._terminal_by_item()
        terminal_ids = set(terminals)
        started_attempts = {
            (doc.get("logical_invocation"), doc.get("attempt"))
            for relative, doc in self.documents.items()
            if isinstance(doc, dict)
            and "transitions" in Path(relative).parts
            and Path(relative).stem.endswith("-started")
        }
        # Immutable start markers by item, plus plan order for current-item
        # validation.  Diagnostic state must not invent a current item.
        starts_by_item: dict[str, tuple[str, dict[str, Any]]] = {}
        for rel, doc in self.documents.items():
            if (
                isinstance(doc, dict)
                and isinstance(doc.get("item_id"), str)
                and _canonical_logical_marker(rel, self.entry_by_path.get(rel), doc)
                == ("item-started", doc["item_id"])
            ):
                starts_by_item.setdefault(doc["item_id"], (rel, doc))
        plan_ids: list[str] = []
        for rel, doc in self.documents.items():
            if Path(rel).name == "queue-plan.json" and isinstance(doc, dict):
                items = doc.get("items")
                if isinstance(items, list):
                    plan_ids = [
                        item.get("item_id")
                        for item in items
                        if isinstance(item, dict) and isinstance(item.get("item_id"), str)
                    ]
                break
        for relative, state in self.documents.items():
            if not isinstance(state, dict) or Path(relative).name not in DIAGNOSTIC_NAMES:
                continue
            completed = state.get("completed_item_ids", [])
            if isinstance(completed, list):
                ahead = sorted(item for item in completed if item not in terminal_ids)
                if ahead:
                    self.result.error(
                        "EV-12", relative, "diagnostic state leads immutable item terminals", item_ids=ahead
                    )
                lagging = sorted(item for item in terminal_ids if item not in completed)
                if lagging:
                    self.result.warning(
                        "EV-W01",
                        relative,
                        "diagnostic state lags immutable item terminals",
                        item_ids=lagging,
                    )
            reservations = state.get("reservations", [])
            if isinstance(reservations, list):
                ahead = [
                    (item.get("logical_invocation"), item.get("attempt"))
                    for item in reservations
                    if isinstance(item, dict)
                    and (item.get("logical_invocation"), item.get("attempt")) not in started_attempts
                ]
                if ahead:
                    self.result.error(
                        "EV-12", relative, "diagnostic reservations lead immutable attempt evidence", reservations=ahead
                    )
            if state.get("status") in {"SUCCESS", "COMPLETED"}:
                has_queue_final = any(True for _ in self._queue_final_documents())
                if not has_queue_final:
                    self.result.error("EV-12", relative, "diagnostic completion leads authoritative final")
            current = state.get("current_item_id")
            if current is not None:
                self._check_diagnostic_current_item(
                    relative, current, plan_ids, terminals, starts_by_item
                )

    def _check_diagnostic_current_item(
        self,
        relative: str,
        current: Any,
        plan_ids: list[str],
        terminals: dict[str, tuple[str, dict[str, Any]]],
        starts_by_item: dict[str, tuple[str, dict[str, Any]]],
    ) -> None:
        """Validate diagnostic current_item_id against immutable evidence."""
        if not isinstance(current, str) or not current:
            self.result.error(
                "EV-12", relative, "diagnostic current item is malformed", current_item_id=current
            )
            return
        if plan_ids and current not in plan_ids:
            self.result.error(
                "EV-12",
                relative,
                "diagnostic current item is absent from immutable queue plan",
                current_item_id=current,
            )
            return
        if current not in starts_by_item:
            self.result.error(
                "EV-12",
                relative,
                "diagnostic current item lacks an immutable start marker",
                current_item_id=current,
            )
        if plan_ids and current in plan_ids:
            position = plan_ids.index(current)
            for prior in plan_ids[:position]:
                if prior not in terminals:
                    self.result.error(
                        "EV-12",
                        relative,
                        "diagnostic current item precedes immutable prior terminal",
                        current_item_id=current,
                        prior_item_id=prior,
                    )
            # Ordering must be valid: prior terminals precede current start.
            if current in starts_by_item:
                start_sequence = self._sequence(*starts_by_item[current])
                for prior in plan_ids[:position]:
                    if prior not in terminals:
                        continue
                    terminal_sequence = self._sequence(*terminals[prior])
                    if terminal_sequence is None or start_sequence is None:
                        self.result.error(
                            "EV-12",
                            relative,
                            "diagnostic current item lacks authoritative sequence evidence",
                            current_item_id=current,
                        )
                        break
                    if start_sequence[0] <= terminal_sequence[0]:
                        self.result.error(
                            "EV-12",
                            relative,
                            "diagnostic current item evidence precedes prior item terminal",
                            current_item_id=current,
                            prior_item_id=prior,
                        )
                        break

    def _sequence(self, relative: str, document: dict[str, Any]) -> tuple[int, str] | None:
        entry = self.entry_by_path.get(relative, {})
        value = entry.get("sequence", document.get("evidence_sequence"))
        if isinstance(value, int) and not isinstance(value, bool):
            return value, "sequence"
        # A sealed manifest's ordered immutable list is itself authoritative
        # ordering evidence. It avoids filesystem timestamp inference.
        index = entry.get("_index")
        return (index, "manifest_order") if isinstance(index, int) else None

    def _check_queue_order(self, manifest: dict[str, Any]) -> None:
        plans = [
            doc for relative, doc in self.documents.items()
            if Path(relative).name == "queue-plan.json" and isinstance(doc, dict)
        ]
        if not plans:
            return
        items = plans[0].get("items")
        if not isinstance(items, list):
            return
        starts: dict[str, tuple[str, dict[str, Any]]] = {}
        terminals = self._terminal_by_item()
        for relative, doc in self.documents.items():
            if Path(relative).name == "item-started.json" and isinstance(doc, dict) and isinstance(doc.get("item_id"), str):
                starts[doc["item_id"]] = (relative, doc)
        ordered_ids = [item.get("item_id") for item in items if isinstance(item, dict)]
        for previous, current in zip(ordered_ids, ordered_ids[1:]):
            if current not in starts:
                continue
            if previous not in terminals:
                self.result.error(
                    "EV-14", starts[current][0], "next item started before prior item terminal exists", prior_item_id=previous
                )
                continue
            terminal_sequence = self._sequence(*terminals[previous])
            start_sequence = self._sequence(*starts[current])
            if terminal_sequence is None or start_sequence is None:
                self.result.error("EV-14", starts[current][0], "queue order lacks authoritative sequence evidence")
            elif start_sequence[0] <= terminal_sequence[0]:
                self.result.error(
                    "EV-14",
                    starts[current][0],
                    "next item evidence precedes prior item terminal",
                    prior_item_id=previous,
                    prior_sequence=terminal_sequence[0],
                    next_sequence=start_sequence[0],
                )


def verify_evidence(
    evidence_dir: str | os.PathLike[str],
    *,
    expected_candidate_sha: str | None = None,
    require_sealed: bool = True,
) -> dict[str, Any]:
    """Validate an external evidence directory without mutating it."""
    return EvidenceVerifier(
        Path(evidence_dir),
        expected_candidate_sha=expected_candidate_sha,
        require_sealed=require_sealed,
    ).verify().to_dict()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("--expected-candidate-sha")
    parser.add_argument(
        "--in-progress",
        action="store_true",
        help="Allow in-progress unsealed verification without required sealing metadata",
    )
    args = parser.parse_args(argv)
    result = verify_evidence(
        args.evidence_dir,
        expected_candidate_sha=args.expected_candidate_sha,
        require_sealed=not args.in_progress,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
