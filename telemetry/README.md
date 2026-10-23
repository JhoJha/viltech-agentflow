# VilTech Telemetry V0 — durable human + external evidence (append-only)

Telemetry observes. It never controls. No routing, no scoring, no automation.

## What lives here

`v1/events/<event_id>.json` — one JSON file per event. Two types:

- `human_gate`: a human adjudication (`accepted_as_is`, `accepted_with_changes`,
  `rejected`, `superseded`). The decision arrives **only** via an explicit
  `--decision` flag. `final.json: HUMAN_GATE` means "reached the gate", never
  "accepted". There is no `--from-final` and there never will be in V0.
- `external_execution`: a minimal stub for work done outside AgentFlow
  (who / model / roles / timing / outcome / usage-if-reported).

`v1/schemas/*.schema.json` — contract, documentation, versioning. Enforcement
lives in hand-rolled Python validators inside `telemetry.py` (stdlib only,
same pattern as `validate_task`/`result_valid` in `agentflow.py`). No JSON
Schema engine, no new dependencies.

## Meaning of `decision_source: "human"` / `attestation_source: "human"`

It means: "this record was declared explicitly through the CLI by the
operator." It is provenance, **not** cryptographically authenticated human
identity. `actor` is a short logical alias (e.g. `human-operator`), never
autodetected from USER/UID/home paths, never IAM.

## Rules

- Append-only: create new files, never edit or delete. Corrections are NEW
  events with `supersedes_event_id`. Re-running the same content creates a
  new visible event (V0 promises no idempotency).
- UTC everywhere (`...Z`). `event_id` is `<UTC>Z-<6hex>` and equals the filename.
- Artifact citations are `{run_id, relpath, sha256}` with `relpath` relative
  to `runs/<run_id>/` (no absolutes, no `..`, no symlinks, regular files only).
  A `runs/<run_id>` root that is itself a symlink is rejected outright, so a
  planted link can never be used to hash files outside `runs/`.
- Prior events used for `supersedes_event_id` must be regular files
  physically contained in `v1/events/`, never symlinks (a linked
  `<event_id>.json` is rejected and nothing is published).
- Environment provenance (`environment.models_sha256`,
  `environment.agentflow_sha256`) is best-effort evidence, never a gate: if a
  base file cannot be hashed the event is still recorded with that field as
  `null` plus a visible `stderr` warning. `null` means "provenance
  unavailable/degraded", never "provenance verified" — no hash is ever
  invented.
- Privacy: no prompts, outputs, code, diffs, stdout/stderr, JSONL, tracebacks,
  tokens, credentials, or PII. `note` ≤ 2000 chars, `summary` ≤ 500 chars;
  high-confidence secret shapes reject the write (never silently redacted).
- Cost semantics: `provider_reported` = the provider billed it;
  `harness_estimated` = a harness/catalog number (e.g. OpenCode catalog cost),
  NOT real economic cost; `unavailable` = unknown. Codex usage today is
  `unavailable`. Never invent precision.

## Retention (until TEL-002)

Do NOT prune or rotate `runs/`: raw token/cost usage lives in
`*-output.jsonl` and only exists when the execution completed. Timeout/crash
may lose `output.jsonl` by current runtime design — in that case usage is
`unavailable`, which is honest data, not a bug to fix here.

## Tracking

`telemetry/v1/events/` is designed to be tracked/durable (small,
irreplaceable human/external evidence). `runs/` and `.locks/` keep their
current ephemeral policy. No commit is made by the tooling itself.

## task_class convention (optional, open vocabulary)

Task packets may carry a short kebab-case `task_class` (e.g. `lease-fix`,
`harness`, `migration`, `e2e-spec`, `review-only`, `telemetry`). It passes
through to `task.json` untouched. No closed enum; `unknown` allowed; never
infer it from `risk`/`objective`; never rewrite history. Mappings live in
future analytics, not in stored records.

## Usage

```bash
python3 telemetry.py gate --task <task-id> [--run <run-id>] --actor <alias> \
  --decision accepted_as_is|accepted_with_changes|rejected|superseded \
  [--decided-at <UTC-Z>] [--artifact <run:relpath> ...] [--supersedes <event-id>] [--note ...]

python3 telemetry.py external --actor <alias> [--task <task-id>] \
  --actor-kind model|human|tool --roles architect,worker \
  --provider <p> --model <id> [--variant <v>] [--session-type ...] \
  [--timing-source ...] [--started-at ...Z] [--finished-at ...Z] \
  [--verdict ...] [--summary ...] [--token-source ...] [--tokens-in N ...] \
  [--cost-source ...] [--cost-value X --currency USD] [--note ...]
```

## Verify (TEL-001-R2, read-only)

```bash
python3 telemetry.py verify
```

`verify` inspects the whole `v1/events/` store and never modifies
anything: no new events, no renames, no deletions, no repairs, no cache,
no locks, no state files. Exit `0` means the store is verifiable (WARNINGs
allowed); exit `2` means at least one integrity/validation ERROR.

Structured entry point for reuse (TUI / TEL-002 later):

```python
report = telemetry.verify_event_store()
text = telemetry.format_verify_report(report)
```

`report` is a plain dict (`files_scanned`, `events_parsed`,
`human_gate`, `external_execution`, `errors`, `warnings`,
`exact_semantic_duplicates`, `degraded_provenance`,
`broken_supersession_refs`, `artifact_warnings`, `findings`, `ok`);
each finding carries `severity` (`ERROR`/`WARNING`), a stable `code`,
`file`, `event_id`, and `detail`.

Checks: regular-file trust without following symlinks (`EVENT_SYMLINK`,
`EVENT_NOT_REGULAR`, `UNEXPECTED_FILE`); JSON parseability
(`JSON_INVALID`, scan continues past bad files);
filename == `<event_id>.json` (`EVENT_ID_FILENAME_MISMATCH`);
strict `telemetry_version` (`UNSUPPORTED_VERSION`; only exact int `1`
counts, `true`/`1.0` rejected); authoritative
Python validation per event type (`EVENT_INVALID`, including unhashable
`task_id` shapes and non-finite/huge numerics — one bad event never
aborts the scan); supersession
integrity (`SUPERSESSION_INVALID`); null environment provenance as honest
data (`DEGRADED_PROVENANCE` WARNING); conservative exact semantic
duplicates grouped by type/task with only `event_id`/`recorded_at`
excluded (`EXACT_SEMANTIC_DUPLICATE` WARNING, never auto-fixed);
artifact refs re-checked with existing trust logic — structurally unsafe
refs are `ARTIFACT_INVALID` ERROR while a sound ref whose backing file
is missing or currently unreadable (`PermissionError`/`OSError` on
read/hash) is `ARTIFACT_UNAVAILABLE` WARNING; JSON strings that can never
name a file (NUL bytes, lone surrogates) are structurally unsafe
(`ARTIFACT_INVALID`), symlink loops on the artifact path
(self-referential or multi-node cycles, including the `RuntimeError`
some Python versions raise from path resolution instead of `OSError`)
are structurally unsafe (`ARTIFACT_INVALID`, never "historical
unavailable"), and JSON that exceeds safe parse depth
(`RecursionError`) is `JSON_INVALID` — in all cases the scan continues
past the bad event without traceback; stored `sha256` is
compared read-only against current file content, mismatch is
`ARTIFACT_HASH_MISMATCH` ERROR (expected/actual hashes reported, never
repaired, never rewritten).

Report rendering is total over JSON string content: lone surrogates
that reach findings are escaped at display time (valid Unicode is left
untouched, stored evidence is never rewritten), so printing the report
to UTF-8 stdout cannot crash — exit codes stay semantic (`0` for
warnings-only, `2` when ERRORs exist). Writer text that is not valid
UTF-8 (`actor`, `note`, `summary`, ...) is rejected with a controlled
error before anything is written: no partial event, no traceback.
