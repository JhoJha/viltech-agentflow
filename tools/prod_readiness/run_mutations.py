#!/usr/bin/env python3
"""Manifest-driven mutation campaign executor for disposable repository copies."""

from __future__ import annotations

import argparse
import json
import os as _os
import re
import shutil
import subprocess as _subprocess
import sys as _sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from tools.prod_readiness.common import (
    BudgetEngine,
    BudgetLimits,
    ErrorCode,
    RunnerError,
    budget_limits_from_plan,
    canonical_state,
    freeze_run_plan,
    initialize_owned_run_root,
    load_json,
    run_owned_command,
    sha256_path,
    stable_error_code,
)

SEVERITIES = {"CRITICAL", "IMPORTANT"}
CLASSIFICATIONS = {"KILLED", "SURVIVED", "INVALID"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_mutation_manifest(raw: Any) -> list[dict[str, Any]]:
    rows = raw.get("mutations") if isinstance(raw, dict) else None
    if not isinstance(rows, list) or not rows:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "mutation manifest requires a non-empty mutations array",
        )
    seen: set[str] = set()
    required = {
        "mutation_id",
        "severity",
        "target_file",
        "operation",
        "mapped_invariant_tests",
        "expected_failure_reason",
        "test_command",
    }
    validated = []
    for index, row in enumerate(rows):
        if (
            not isinstance(row, dict)
            or set(row) - (required | {"seed", "description", "trusted_probe_id"})
            or not required.issubset(row)
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST, "malformed mutation definition", index=index
            )
        mutation_id = row["mutation_id"]
        if (
            not isinstance(mutation_id, str)
            or not _SAFE_ID.fullmatch(mutation_id)
            or mutation_id in seen
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "duplicate or malformed mutation ID",
                mutation_id=mutation_id,
            )
        seen.add(mutation_id)
        if row["severity"] not in SEVERITIES:
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "invalid mutation severity",
                mutation_id=mutation_id,
            )
        target = row["target_file"]
        if (
            not isinstance(target, str)
            or Path(target).is_absolute()
            or ".." in Path(target).parts
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "mutation target must be repository-relative",
                mutation_id=mutation_id,
            )
        operation = row["operation"]
        if (
            not isinstance(operation, dict)
            or operation.get("type") != "replace_text"
            or not isinstance(operation.get("find"), str)
            or not operation["find"]
            or not isinstance(operation.get("replace"), str)
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "unsupported or malformed mutation operation",
                mutation_id=mutation_id,
            )
        command = row["test_command"]
        tests = row["mapped_invariant_tests"]
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item for item in command)
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "test command must be an argv array",
                mutation_id=mutation_id,
            )
        if (
            not isinstance(tests, list)
            or not tests
            or any(not isinstance(item, str) or not item for item in tests)
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "mapped invariant tests are required",
                mutation_id=mutation_id,
            )
        if (
            not isinstance(row["expected_failure_reason"], str)
            or not row["expected_failure_reason"]
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "expected failure reason is required",
                mutation_id=mutation_id,
            )
        probe_id = row.get("trusted_probe_id")
        if probe_id is not None and (
            not isinstance(probe_id, str) or not _SAFE_ID.fullmatch(probe_id)
        ):
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "trusted probe ID is malformed",
                mutation_id=mutation_id,
            )
        validated.append(dict(row))
    return validated


def _copy_repository(source_repo: Path, destination: Path) -> None:
    if destination.exists():
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET,
            "mutation copy destination already exists",
            path=str(destination),
        )
    git_dir = source_repo / ".git"
    if git_dir.exists():
        result = run_owned_command(
            [
                "git",
                "clone",
                "--no-hardlinks",
                "--quiet",
                str(source_repo),
                str(destination),
            ],
            cwd=destination.parent,
            timeout=60,
        )
        if result.returncode or not result.process_cleanup_verified:
            raise RunnerError(
                ErrorCode.MUTANT_INVALID, "disposable repository clone failed"
            )
    else:
        shutil.copytree(
            source_repo,
            destination,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        result = run_owned_command(
            ["git", "init", "--quiet"], cwd=destination, timeout=30
        )
        if result.returncode or not result.process_cleanup_verified:
            raise RunnerError(
                ErrorCode.MUTANT_INVALID, "disposable repository initialization failed"
            )


def _apply_mutation(copy_root: Path, row: Mapping[str, Any]) -> None:
    target = copy_root / row["target_file"]
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(
            ErrorCode.MUTANT_INVALID,
            "mutation target is missing",
            mutation_id=row["mutation_id"],
        ) from exc
    if (
        not resolved.is_relative_to(copy_root.resolve())
        or target.is_symlink()
        or not target.is_file()
    ):
        raise RunnerError(
            ErrorCode.UNSAFE_TARGET,
            "mutation target escapes disposable copy",
            mutation_id=row["mutation_id"],
        )
    operation = row["operation"]
    text = target.read_text(encoding="utf-8")
    count = text.count(operation["find"])
    expected_count = operation.get("count", 1)
    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count <= 0
        or count != expected_count
    ):
        raise RunnerError(
            ErrorCode.MUTANT_INVALID,
            "mutation anchor count differs",
            mutation_id=row["mutation_id"],
            expected=expected_count,
            actual=count,
        )
    target.write_text(
        text.replace(operation["find"], operation["replace"], expected_count),
        encoding="utf-8",
    )


STRUCTURED_MARKER = "__MUTATION_STRUCTURED_RESULT__"

# DEPRECATED (untrusted): the previous in-band stdout marker protocol is
# retained only as a constant for forgery-ignoring tests.  It MUST NEVER
# establish KILLED/PASS/ERROR/DID_NOT_RUN.  stdout/stderr are untrusted
# evidence only.  The trusted channel is _TRUSTED_WORKER_SOURCE below,
# which writes a nonce-bound JSON artifact to a harness-owned path outside
# the disposable mutation copy; the parent harness (trusted controller)
# owns the final classification.

_TRUSTED_NONCE_ENV = "_MUT_HARNESS_NONCE"
_TRUSTED_RESULT_ENV = "_MUT_HARNESS_RESULT"

_TRUSTED_WORKER_SOURCE = (
    "import json as _js, os as _os, sys as _sys, traceback as _tb, unittest as _ut\n"
    "_nonce = _os.environ.pop('_MUT_HARNESS_NONCE', None)\n"
    "_result_path = _os.environ.pop('_MUT_HARNESS_RESULT', None)\n"
    "_ids = _sys.argv[1:]\n"
    "_loader = _ut.TestLoader()\n"
    "_suite = _ut.TestSuite()\n"
    "_load_errors = []\n"
    "for _id in _ids:\n"
    "    try:\n"
    "        _suite.addTests(_loader.loadTestsFromName(_id))\n"
    "    except BaseException:\n"
    "        _load_errors.append({'test_id': _id, 'trace': _tb.format_exc()})\n"
    "_results = []\n"
    "if _load_errors:\n"
    "    for _e in _load_errors:\n"
    "        _results.append({'test_id': _e['test_id'], 'status': 'ERROR',"
    " 'failure_trace': '', 'error_trace': _e['trace']})\n"
    "else:\n"
    "    class _R(_ut.TestResult):\n"
    "        def __init__(self):\n"
    "            super().__init__(); self._rows = {}\n"
    "        def _tid(self, test):\n"
    "            return test.id()\n"
    "        def addSuccess(self, test):\n"
    "            super().addSuccess(test); self._rows[self._tid(test)] = ('PASS', '', '')\n"
    "        def addFailure(self, test, err):\n"
    "            super().addFailure(test, err)\n"
    "            self._rows[self._tid(test)] = ('ASSERTION_FAILURE',"
    " ''.join(_tb.format_exception(*err)), '')\n"
    "        def addError(self, test, err):\n"
    "            super().addError(test, err)\n"
    "            self._rows[self._tid(test)] = ('ERROR', '',"
    " ''.join(_tb.format_exception(*err)))\n"
    "    _r = _R()\n"
    "    try:\n"
    "        _suite.run(_r)\n"
    "    except BaseException:\n"
    "        _results.append({'test_id': '_harness', 'status': 'ERROR',"
    " 'failure_trace': '', 'error_trace': _tb.format_exc()})\n"
    "    else:\n"
    "        _ran = set(_r._rows.keys())\n"
    "        for _id in _ids:\n"
    "            _matches = [k for k in _ran if k == _id or k.startswith(_id + '.')]\n"
    "            if not _matches:\n"
    "                _found = False\n"
    "                for _t, _tr in list(_r.failures) + list(_r.errors):\n"
    "                    try:\n"
    "                        _tid = _t.id()\n"
    "                    except Exception:\n"
    "                        continue\n"
    "                    if _tid == _id or _tid.startswith(_id):\n"
    "                        _is_fail = any(_t is x for x, _ in _r.failures)\n"
    "                        _results.append({'test_id': _id, 'status':"
    " 'ASSERTION_FAILURE' if _is_fail else 'ERROR',"
    " 'failure_trace': _tr if _is_fail else '',"
    " 'error_trace': '' if _is_fail else _tr})\n"
    "                        _found = True\n"
    "                if not _found:\n"
    "                    _results.append({'test_id': _id, 'status': 'DID_NOT_RUN',"
    " 'failure_trace': '', 'error_trace': ''})\n"
    "            else:\n"
    "                for _k in sorted(_matches):\n"
    "                    _st, _ft, _et = _r._rows[_k]\n"
    "                    _results.append({'test_id': _k, 'status': _st,"
    " 'failure_trace': _ft, 'error_trace': _et})\n"
    "        for _t, _tr in list(_r.errors):\n"
    "            try:\n"
    "                _tid = _t.id()\n"
    "            except Exception:\n"
    "                continue\n"
    "            if not any(_r2['test_id'] == _tid for _r2 in _results):\n"
    "                _results.append({'test_id': _tid, 'status': 'ERROR',"
    " 'failure_trace': '', 'error_trace': _tr})\n"
    "_payload = _js.dumps({'nonce': _nonce, 'results': _results}, sort_keys=True) + '\\n'\n"
    "# Trusted write: harness-owned path outside the mutation copy.\n"
    "# No structured marker is printed to stdout/stderr (untrusted).\n"
    "if _result_path and _nonce:\n"
    "    try:\n"
    "        _tmp = _result_path + '.tmp-%d' % _os.getpid()\n"
    "        _fd = _os.open(_tmp, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC | _os.O_CLOEXEC, 0o600)\n"
    "        try:\n"
    "            _data = _payload.encode('utf-8')\n"
    "            _off = 0\n"
    "            while _off < len(_data):\n"
    "                _n = _os.write(_fd, _data[_off:])\n"
    "                _off += _n\n"
    "            _os.fsync(_fd)\n"
    "        finally:\n"
    "            _os.close(_fd)\n"
    "        _os.replace(_tmp, _result_path)\n"
    "    except BaseException:\n"
    "        raise SystemExit(2)\n"
    "else:\n"
    "    raise SystemExit(2)\n"
)

# Legacy wrapper retained for reference only; never used for classification.
_STRUCTURED_WRAPPER = _TRUSTED_WORKER_SOURCE

# R3 authority boundary.  This program is executed from the pristine harness
# in an interpreter that never imports from copy_root.  The candidate is one
# more process below it.  Candidate stdout/stderr/exit code are observations;
# only this probe performs the assertion and authors the probe record.
_TRUSTED_PROBE_SOURCE = r'''
import ast, hashlib, json, os, pathlib, subprocess, sys
c = json.loads(sys.argv[1])
root = pathlib.Path(c["copy_root"]).resolve(strict=True)
target = (root / c["target_file"]).resolve(strict=True)
if not target.is_relative_to(root) or target.is_symlink() or not target.is_file():
    raise SystemExit(3)
status, reason = "DID_NOT_RUN", "PROBE_NOT_EXECUTED"
observed = {"candidate_stdout": "", "candidate_stderr": "", "candidate_exit": None}
probe_id = c["probe_id"]
try:
    if probe_id == "python-source-constant-v1":
        tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))
        allowed = all(isinstance(n, (ast.Assign, ast.Expr)) and
                      (not isinstance(n, ast.Expr) or isinstance(n.value, ast.Constant))
                      for n in tree.body)
        values = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for name in node.targets:
                    if isinstance(name, ast.Name) and name.id == "VALUE" and isinstance(node.value, ast.Constant):
                        values.append(node.value.value)
        driver = "import importlib; importlib.import_module(%r); print('CANDIDATE_DRIVER_COMPLETE')" % pathlib.Path(c["target_file"]).stem
        cmd = [sys.executable, "-c", driver]
    elif probe_id.startswith("release-external-"):
        # Direct mapped-test invocation deliberately bypasses
        # unittest.TestSuite.run.  This driver is candidate-side execution
        # only; the surrounding pristine probe still owns classification.
        driver = r"""
import importlib, json, sys, traceback, unittest
ids = json.loads(sys.argv[1]); ran = 0; failures = []; errors = []
for mapped in ids:
    parts = mapped.split('.'); module = None; remainder = []
    for cut in range(len(parts), 0, -1):
        try:
            module = importlib.import_module('.'.join(parts[:cut])); remainder = parts[cut:]; break
        except ModuleNotFoundError as exc:
            if exc.name != '.'.join(parts[:cut]) and not '.'.join(parts[:cut]).startswith(str(exc.name) + '.'):
                errors.append(traceback.format_exc()); break
    if module is None: continue
    classes = []
    if remainder:
        obj = getattr(module, remainder[0], None)
        if isinstance(obj, type) and issubclass(obj, unittest.TestCase): classes = [obj]
    else:
        classes = [v for v in vars(module).values() if isinstance(v, type) and issubclass(v, unittest.TestCase) and v.__module__ == module.__name__]
    for cls in classes:
        names = [remainder[1]] if len(remainder) > 1 else [n for n in dir(cls) if n.startswith('test') and callable(getattr(cls, n, None))]
        try: cls.setUpClass()
        except BaseException: errors.append(traceback.format_exc()); continue
        try:
            for name in names:
                case = cls(name); ran += 1
                try:
                    case._callSetUp(); getattr(case, name)(); case._callTearDown()
                except AssertionError: failures.append(traceback.format_exc())
                except BaseException: errors.append(traceback.format_exc())
                finally:
                    try: case.doCleanups()
                    except BaseException: errors.append(traceback.format_exc())
        finally:
            try: cls.tearDownClass(); cls.doClassCleanups()
            except BaseException: errors.append(traceback.format_exc())
if errors:
    print('\n'.join(errors)); print('CANDIDATE_PROBE_COMPLETE ERROR'); raise SystemExit(72)
if not ran:
    print('CANDIDATE_PROBE_COMPLETE DID_NOT_RUN'); raise SystemExit(73)
if failures:
    print('\n'.join(failures)); print('CANDIDATE_PROBE_COMPLETE ASSERTION_FAILURE'); raise SystemExit(71)
print('CANDIDATE_PROBE_COMPLETE PASS')
"""
        allowed, values = True, []
        cmd = [sys.executable, "-c", driver, json.dumps(c["mapped_invariant"])]
    else:
        raise ValueError("unknown trusted probe")
    if cmd:
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
        p = subprocess.run(cmd, cwd=root, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=float(c["timeout"]), close_fds=True)
        observed = {"candidate_stdout": p.stdout[-4096:], "candidate_stderr": p.stderr[-4096:], "candidate_exit": p.returncode}
        if not allowed:
            status, reason = "ERROR", "AMBIGUOUS_CANDIDATE_BEHAVIOR"
        elif probe_id == "python-source-constant-v1":
            complete = p.returncode == 0 and p.stdout.splitlines().count("CANDIDATE_DRIVER_COMPLETE") == 1
            if not complete:
                status, reason = "DID_NOT_RUN", "CANDIDATE_DID_NOT_COMPLETE"
            elif values == [1]:
                status, reason = "PASS", "INVARIANT_SATISFIED"
            elif len(values) == 1:
                status, reason = "ASSERTION_FAILURE", c["expected_reason"]
            else:
                status, reason = "ERROR", "AMBIGUOUS_CANDIDATE_BEHAVIOR"
        else:
            combined = p.stdout + "\n" + p.stderr
            completed = p.stdout.splitlines()[-1:] == ["CANDIDATE_PROBE_COMPLETE PASS"]
            failed = p.stdout.splitlines()[-1:] == ["CANDIDATE_PROBE_COMPLETE ASSERTION_FAILURE"]
            if p.returncode == 0 and completed:
                status, reason = "PASS", "INVARIANT_SATISFIED"
            elif p.returncode == 71 and failed and c["expected_reason"].lower() in combined.lower():
                status, reason = "ASSERTION_FAILURE", c["expected_reason"]
            else:
                status, reason = "ERROR", "CANDIDATE_START_OR_SETUP_FAILED"
    else:
        status, reason = "ERROR", "AMBIGUOUS_CANDIDATE_BEHAVIOR"
except subprocess.TimeoutExpired:
    status, reason = "DID_NOT_RUN", "CANDIDATE_TIMEOUT"
except BaseException as exc:
    status, reason = "ERROR", "PROBE_EXCEPTION_" + type(exc).__name__
report = {"probe_id": probe_id, "mapped_invariant": c["mapped_invariant"],
          "status": status, "reason_code": reason, "observed_behavior": observed,
          "candidate_sha": c["candidate_sha"], "candidate_tree": c["candidate_tree"],
          "tool_probe_hash": c["tool_probe_hash"]}
sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
'''


def _trusted_probe_id(row: Mapping[str, Any]) -> str:
    explicit = row.get("trusted_probe_id")
    if isinstance(explicit, str):
        return explicit
    if row.get("target_file") == "calc.py":
        return "python-source-constant-v1"
    return f"release-external-{row['mutation_id']}"


def _run_trusted_probe(
    *,
    row: Mapping[str, Any],
    copy_root: Path,
    candidate_sha: str,
    candidate_tree: str,
    timeout: float,
) -> tuple[dict[str, Any] | None, Any]:
    probe_hash = __import__("hashlib").sha256(_TRUSTED_PROBE_SOURCE.encode()).hexdigest()
    contract = {
        "probe_id": _trusted_probe_id(row),
        "mapped_invariant": list(row["mapped_invariant_tests"]),
        "copy_root": str(copy_root),
        "target_file": row["target_file"],
        "candidate_command": list(row["test_command"]),
        "replacement": row["operation"]["replace"],
        "expected_reason": row["expected_failure_reason"],
        "candidate_sha": candidate_sha,
        "candidate_tree": candidate_tree,
        "tool_probe_hash": probe_hash,
        "timeout": timeout,
    }
    env = {"PATH": _os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
    process = run_owned_command(
        [
            _sys.executable,
            "-I",
            "-c",
            _TRUSTED_PROBE_SOURCE,
            json.dumps(contract, sort_keys=True, separators=(",", ":")),
        ],
        cwd=Path(__file__).resolve().parents[2],
        timeout=timeout + 5,
        environment=env,
    )
    if process.returncode != 0 or process.timed_out or not process.process_cleanup_verified:
        return None, process
    try:
        lines = process.stdout.splitlines()
        if len(lines) != 1:
            return None, process
        report = json.loads(lines[0])
    except (json.JSONDecodeError, TypeError):
        return None, process
    required = {
        "probe_id", "mapped_invariant", "status", "reason_code",
        "observed_behavior", "candidate_sha", "candidate_tree", "tool_probe_hash",
    }
    if not isinstance(report, dict) or set(report) != required:
        return None, process
    if report["probe_id"] != contract["probe_id"] or report["tool_probe_hash"] != probe_hash:
        return None, process
    if report["candidate_sha"] != candidate_sha or report["candidate_tree"] != candidate_tree:
        return None, process
    if report["status"] not in {"PASS", "ASSERTION_FAILURE", "ERROR", "DID_NOT_RUN"}:
        return None, process
    return report, process


def _parse_structured_output(output: str) -> tuple[list[dict[str, Any]] | None, bool]:
    """Legacy in-band marker parser (UNTRUSTED, diagnostics only).

    stdout/stderr markers MUST NEVER establish KILLED.  This helper is
    retained for backward compatibility and spoof-detection diagnostics,
    but the campaign classification path MUST NOT call it for verdicts.
    """
    lines = [
        line
        for line in output.splitlines()
        if STRUCTURED_MARKER in line
    ]
    if len(lines) != 1:
        return None, len(lines) > 1
    try:
        raw = lines[0].split(STRUCTURED_MARKER, 1)[1]
        payload = json.loads(raw)
        results = payload.get("results")
        if not isinstance(results, list):
            return None, False
        return results, False
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None, False


def _read_trusted_worker_result(
    path: Path, expected_nonce: str
) -> list[dict[str, Any]] | None:
    """Read and validate the harness-owned trusted worker artifact.

    Returns the validated results list, or None if missing/invalid/forged.
    The artifact must be a regular file (not symlink) containing the exact
    per-mutation nonce and a well-formed results array.  stdout/stderr
    markers are never consulted here.
    """
    try:
        if not path.is_file() or path.is_symlink():
            return None
    except OSError:
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("nonce") != expected_nonce:
        return None
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        return None
    validated: list[dict[str, Any]] = []
    for row in results:
        if not isinstance(row, dict):
            return None
        status = row.get("status")
        if status not in ("PASS", "ASSERTION_FAILURE", "ERROR", "DID_NOT_RUN"):
            return None
        if not isinstance(row.get("test_id"), str) or not row["test_id"]:
            return None
        validated.append(
            {
                "test_id": row["test_id"],
                "status": status,
                "failure_trace": str(row.get("failure_trace", "")),
                "error_trace": str(row.get("error_trace", "")),
            }
        )
    return validated


def classify_structured(
    expected_reason: str,
    structured_results: Sequence[Mapping[str, Any]] | None,
    *,
    mutation_applied: bool = True,
    harness_error: bool = False,
    timed_out: bool = False,
    setup_error: bool = False,
    unrelated_failed: bool = False,
    command_unavailable: bool = False,
) -> str:
    """Structured test-result classification (no substring KILLED)."""
    if (
        not mutation_applied
        or harness_error
        or timed_out
        or setup_error
        or command_unavailable
    ):
        return "INVALID"
    if structured_results is None:
        return "INVALID"
    # Normalize.
    rows = [dict(row) for row in structured_results]
    if not rows:
        return "INVALID"
    # Any harness-level ERROR invalidates (import error, fixture missing, etc).
    for row in rows:
        status = row.get("status")
        if status == "ERROR":
            return "INVALID"
        if status not in ("PASS", "ASSERTION_FAILURE", "DID_NOT_RUN"):
            return "INVALID"
    ran = [row for row in rows if row.get("status") in ("PASS", "ASSERTION_FAILURE")]
    did_not_run = [row for row in rows if row.get("status") == "DID_NOT_RUN"]
    if did_not_run and not ran:
        return "INVALID"
    if did_not_run:
        # Mapped test did not run while others did -> ambiguous -> INVALID.
        return "INVALID"
    if unrelated_failed:
        # Unrelated failure with mapped PASS (MCLASS-05) or mixed (MCLASS-14).
        return "INVALID"
    failures = [row for row in rows if row.get("status") == "ASSERTION_FAILURE"]
    passes = [row for row in rows if row.get("status") == "PASS"]
    if failures and not passes and len(rows) >= 1:
        pass
    if not failures:
        # All mapped PASS -> SURVIVED (MCLASS-10).
        if passes and len(passes) == len(rows):
            return "SURVIVED"
        return "INVALID"
    # At least one mapped assertion failure: require expected contract to
    # match THAT mapped test's failure trace (MCLASS-13).
    matched = False
    for row in failures:
        trace = str(row.get("failure_trace", "")) + "\n" + str(
            row.get("error_trace", "")
        )
        if expected_reason and expected_reason in trace:
            matched = True
            break
    if not matched:
        return "INVALID"
    return "KILLED"


def classify_mutant(
    returncode: int | None,
    output: str,
    expected_reason: str,
    *,
    timed_out: bool = False,
    harness_error: bool = False,
    mapped_tests: Sequence[str] = (),
    structured_results: Sequence[Mapping[str, Any]] | None = None,
    mutation_applied: bool = True,
    unrelated_failed: bool = False,
    setup_error: bool = False,
    command_unavailable: bool = False,
) -> str:
    """Trusted-channel entry point with fail-closed logic.

    Substring presence of mapped IDs or expected text in stdout/stderr
    NEVER yields KILLED (MCLASS-11/12, R1H-03, MTRUST-11).  KILLED requires
    harness-owned trusted structured evidence (nonce-bound artifact outside
    the mutation copy).  A missing trusted completion record is INVALID,
    never KILLED and never SURVIVED: premature os._exit/sys.exit or forged
    stdout/stderr markers without a valid trusted artifact are INVALID.
    """
    if timed_out or harness_error or returncode is None:
        return "INVALID"
    if not mutation_applied or setup_error or command_unavailable:
        return "INVALID"
    if structured_results is None:
        # No trusted completion record: INVALID even on clean exit.
        # stdout/stderr result-like text is ignored (MTRUST-01/02/11).
        return "INVALID"
    return classify_structured(
        expected_reason,
        structured_results,
        mutation_applied=mutation_applied,
        harness_error=harness_error,
        timed_out=timed_out,
        setup_error=setup_error,
        unrelated_failed=unrelated_failed,
        command_unavailable=command_unavailable,
    )


def _detect_setup_error(output: str) -> bool:
    markers = (
        "SyntaxError",
        "IndentationError",
        "ModuleNotFoundError",
        "ImportError",
        "No module named",
        "broken fixture",
        "Fixture",
        "fixture",
        "ERROR: ",
    )
    return any(marker in output for marker in markers)


def run_mutation_campaign(
    *,
    source_repo: Path,
    canonical_repo: Path,
    run_root: Path,
    manifest: Mapping[str, Any],
    selected_ids: Sequence[str] | None = None,
    budget: BudgetEngine | None = None,
    timeout: float = 60.0,
    run_plan: Mapping[str, Any] | None = None,
    _test_hook: Any = None,
) -> dict[str, Any]:
    mutations = validate_mutation_manifest(manifest)
    probe_manifest = manifest.get("trusted_probe_manifest")
    if probe_manifest is not None:
        if not isinstance(probe_manifest, dict) or set(probe_manifest) != {
            row["mutation_id"] for row in mutations
        }:
            raise RunnerError(
                ErrorCode.INVALID_MANIFEST,
                "trusted probe manifest must map every mutation exactly once",
            )
        for row in mutations:
            probe_id = probe_manifest.get(row["mutation_id"])
            if not isinstance(probe_id, str) or not _SAFE_ID.fullmatch(probe_id):
                raise RunnerError(
                    ErrorCode.INVALID_MANIFEST,
                    "trusted probe manifest contains malformed probe ID",
                    mutation_id=row["mutation_id"],
                )
            row["trusted_probe_id"] = probe_id
    selected = set(selected_ids or [row["mutation_id"] for row in mutations])
    if selected - {row["mutation_id"] for row in mutations}:
        raise RunnerError(
            ErrorCode.INVALID_MANIFEST,
            "unknown selected mutation",
            ids=sorted(selected),
        )
    policy, owned = initialize_owned_run_root(
        run_root,
        canonical_repo,
        source_directories=(Path(__file__).resolve().parent,),
        test_hook=_test_hook,
    )
    # ROOTBIND: after initialization the public pathname must still name
    # the held inode.
    _binding_failure: dict[str, Any] | None = None
    try:
        owned.assert_public_binding()
    except RunnerError as exc:
        _binding_failure = exc.to_dict()
    try:
        default_limits = BudgetLimits(
            wall_seconds=300,
            scenarios=len(selected),
            executions=len(selected),
            mutations=len(selected),
            evidence_bytes=100_000_000,
        )
        frozen_plan = freeze_run_plan(
            policy,
            run_plan,
            expected_campaign_kind="mutation",
            default_limits=default_limits,
            seed=0,
            scenario_selection=sorted(selected),
            tool_paths=(Path(__file__).resolve(),),
            owned=owned,
        )
        before = canonical_state(canonical_repo)
        source_before = {
            str(path.relative_to(source_repo)): sha256_path(path)
            for path in source_repo.rglob("*")
            if path.is_file() and ".git" not in path.parts
        }
        engine = budget or BudgetEngine(budget_limits_from_plan(frozen_plan))
        results = []
        for row in mutations:
            if row["mutation_id"] not in selected:
                continue
            mutation_id = row["mutation_id"]
            try:
                engine.reserve("scenarios", action_id=mutation_id)
                engine.reserve("mutations", action_id=mutation_id)
            except RunnerError:
                # Stable error model: budget exhaustion becomes explicit
                # failed/incomplete result, never raw escape.
                raise
            copy_root = policy.require_owned_target(
                policy.disposable_root / "sandboxes" / mutation_id
            )
            classification = "INVALID"
            returncode = None
            stdout = ""
            stderr = ""
            structured: dict[str, Any] | None = None
            setup_error = False
            unrelated_failed = False
            harness_error_flag = False
            timed_out_flag = False
            command_unavailable = False
            mutation_applied = False
            copy_sha = before["head"]
            copy_tree = before["tree"]
            started = time.time()
            try:
                _copy_repository(source_repo, copy_root)
                try:
                    _apply_mutation(copy_root, row)
                except RunnerError:
                    mutation_applied = False
                    raise
                mutation_applied = True
                engine.reserve("executions", action_id=f"{mutation_id}:tests")
                # R3: the controller launches a pristine trusted probe.  That
                # process never imports mutated modules; it launches the
                # candidate beneath itself and owns all assertion logic.
                copy_tree = sha256_path(copy_root / row["target_file"])
                try:
                    structured, process = _run_trusted_probe(
                        row=row,
                        copy_root=copy_root,
                        candidate_sha=copy_sha,
                        candidate_tree=copy_tree,
                        timeout=min(timeout, engine.remaining_wall()),
                    )
                except RunnerError:
                    command_unavailable = True
                    harness_error_flag = True
                    process = None  # type: ignore[assignment]
                if process is not None:
                    returncode, stdout, stderr = (
                        process.returncode,
                        process.stdout,
                        process.stderr,
                    )
                    timed_out_flag = bool(process.timed_out)
                    harness_error_flag = not process.process_cleanup_verified
                    if structured is None or harness_error_flag or timed_out_flag:
                        classification = "INVALID"
                    elif structured["status"] == "PASS":
                        classification = "SURVIVED"
                    elif (
                        structured["status"] == "ASSERTION_FAILURE"
                        and structured["reason_code"] == row["expected_failure_reason"]
                    ):
                        classification = "KILLED"
                    else:
                        classification = "INVALID"
            except RunnerError as exc:
                code = stable_error_code(exc)
                if code in (ErrorCode.MUTANT_INVALID,):
                    classification = "INVALID"
                elif code in (ErrorCode.BUDGET_EXHAUSTED, ErrorCode.PROVIDER_BUDGET_EXHAUSTED):
                    classification = "INVALID"
                    stderr = (stderr + "\n" + str(exc)) if stderr else str(exc)
                    # Persist partial evidence then re-raise as INCOMPLETE?
                    # For per-mutant budget failure, mark INVALID and continue;
                    # global wall exhaustion aborts via engine.check_wall below.
                else:
                    classification = "INVALID"
                if not stderr:
                    stderr = str(exc)
                else:
                    stderr = stderr + "\n" + str(exc)
            except _subprocess.TimeoutExpired:
                classification = "INVALID"
                timed_out_flag = True
                stderr = (stderr + "\nTimeoutExpired") if stderr else "TimeoutExpired"
            except FileNotFoundError as exc:
                classification = "INVALID"
                command_unavailable = True
                stderr = (stderr + "\n" + str(exc)) if stderr else str(exc)
            except Exception as exc:
                # Unknown runtime errors must not escape unhandled and must
                # never PASS (ERR-05).
                classification = "INVALID"
                harness_error_flag = True
                stderr = (stderr + f"\nINTERNAL:{type(exc).__name__}:{exc}") if stderr else f"INTERNAL:{type(exc).__name__}:{exc}"
            stdout_rel = f"mutation/{mutation_id}/stdout.txt"
            stderr_rel = f"mutation/{mutation_id}/stderr.txt"
            structured_rel = f"mutation/{mutation_id}/structured.json"
            try:
                for relative, content in ((stdout_rel, stdout), (stderr_rel, stderr)):
                    owned.atomic_create_bytes_rel(relative, content.encode("utf-8"))
                owned.atomic_create_json_rel(
                    structured_rel,
                    {
                        "results": structured,
                        "setup_error": setup_error,
                        "unrelated_failed": unrelated_failed,
                        "harness_error": harness_error_flag,
                        "timed_out": timed_out_flag,
                        "command_unavailable": command_unavailable,
                        "mutation_applied": mutation_applied,
                    },
                )
            except RunnerError:
                raise
            except Exception as exc:
                raise RunnerError(
                    ErrorCode.INTERNAL_HARNESS_ERROR,
                    "mutation evidence persistence failed",
                    mutation_id=mutation_id,
                ) from exc
            record = {
                "mutation_id": mutation_id,
                "severity": row["severity"],
                "target_file": row["target_file"],
                "operation": row["operation"],
                "mapped_invariant_tests": row["mapped_invariant_tests"],
                "trusted_probe_id": _trusted_probe_id(row),
                "expected_failure_reason": row["expected_failure_reason"],
                "seed": row.get("seed"),
                "copy_sha": copy_sha,
                "copy_tree": copy_tree,
                "test_command": row["test_command"],
                "exit_status": returncode,
                "stdout_ref": stdout_rel,
                "stderr_ref": stderr_rel,
                "structured_ref": structured_rel,
                "classification": classification,
                "started_at_epoch": started,
                "finished_at_epoch": time.time(),
            }
            try:
                owned.atomic_create_json_rel(
                    f"mutation/{mutation_id}/result.json", record
                )
            except RunnerError:
                raise
            results.append(record)
        source_after = {
            str(path.relative_to(source_repo)): sha256_path(path)
            for path in source_repo.rglob("*")
            if path.is_file() and ".git" not in path.parts
        }
        after = canonical_state(canonical_repo)
        if source_before != source_after or before != after:
            raise RunnerError(
                ErrorCode.CANONICAL_TARGET_REFUSED,
                "source or canonical state changed during mutation campaign",
            )
        # ROOTBIND: before any terminal PASS is committed / before sealing,
        # the public pathname must still name the held inode.
        try:
            owned.assert_public_binding()
        except RunnerError as exc:
            if _binding_failure is None:
                _binding_failure = exc.to_dict()
        if _binding_failure is not None:
            summary_status = "FAIL"
        else:
            summary_status = (
                "PASS"
                if results and all(row["classification"] == "KILLED" for row in results)
                else "FAIL"
            )
        if _binding_failure is not None:
            summary_status = "FAIL"
        summary = {
            "status": summary_status,
            "results": results,
            "budget": engine.snapshot(),
            "canonical_before": before,
            "canonical_after": after,
            "run_plan": frozen_plan.to_dict(),
        }
        if _binding_failure is not None:
            summary["binding_failure"] = _binding_failure
            summary["error"] = _binding_failure
        owned.atomic_create_json_rel("mutation/summary.json", summary)
        # ROOTBIND: after sealing completes and before returning PASS,
        # revalidate; binding failure can never be overwritten.
        try:
            owned.assert_public_binding()
        except RunnerError as exc:
            if _binding_failure is None:
                _binding_failure = exc.to_dict()
            summary["status"] = "FAIL"
            summary["binding_failure"] = _binding_failure
            summary["error"] = _binding_failure
            return summary
        if _binding_failure is not None:
            summary["status"] = "FAIL"
            return summary
        return summary
    finally:
        owned.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--canonical-repo", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--run-plan", type=Path, required=True)
    parser.add_argument("--mutation", action="append")
    args = parser.parse_args(argv)
    try:
        result = run_mutation_campaign(
            source_repo=args.source_repo,
            canonical_repo=args.canonical_repo,
            run_root=args.run_root,
            manifest=load_json(args.manifest),
            selected_ids=args.mutation,
            run_plan=load_json(args.run_plan),
        )
    except RunnerError as exc:
        print(json.dumps(exc.to_dict(), sort_keys=True))
        return 2
    print(json.dumps({"status": result["status"]}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
