# VilTech AgentFlow V0

AgentFlow V0 is a small local coordinator for implementation workers, deterministic validators, and independent read-only review. A standalone program stops at a human gate; AUTONOMY-001 can run a bounded sequential queue of independent programs and collect multiple pending human gates. It is not a service, dashboard, deployment system, parallel scheduler, DAG engine, adaptive router, or long-term memory.

## Architecture

- `agentflow.py`: baseline guard, exclusive local write lease, CLI invocation, validator runner, reviewer/correction loop, and final result.
- `config/models.json`: real discovered harness/model IDs, variants, and transparent routing order.
- `prompts/`: worker and reviewer contracts.
- `opencode/agents/`: OpenCode permission profiles; the reviewer has no edit or shell permission.
- `schemas/`: human-readable task/result contracts.
- `tasks/`: task packets. `runs/`: timestamped evidence, raw machine output, validator results, and `final.json`.

Only Python 3 stdlib and the installed `git`, `opencode`, and/or `codex` CLIs are required.

## Safety contract

Before delegation, AgentFlow records repo, branch, HEAD, dirty/untracked paths, hashes of pre-existing changes, and `git diff --check`. Declared baseline drift stops the run. A per-repo atomic lock permits one writer. After every worker call, AgentFlow rejects changes outside `allowed_paths`. Reviewers run without a write lease because their profile is read-only, and any observed repo change also aborts.

AgentFlow never offers commit, push, PR, merge, deploy, DB mutation, Alembic upgrade/downgrade, production, or real Meta operations. Git destructive commands are forbidden in prompts and OpenCode permissions. Deterministic validator PASS requires an observed zero exit code.

## Use

```bash
python agentflow.py inspect
python agentflow.py models
python -m unittest discover -s tests -v
python agentflow.py run tasks/example.json
python agentflow.py program run programs/example.json
python agentflow.py queue run path/to/queue.json
```

A task supplies an absolute repo, expected baseline, allowed paths, objective/invariants, validators, optional `preferred_worker`/`preferred_reviewer`, and a correction cap from 0 to 2. For HIGH/CRITICAL tasks, independent review is mandatory and must use a different model family.

### Finding Pipeline Runner v0

`python3 agentflow.py finding run <finding.json>` executes one strict frozen
finding through the existing A-mode Program runner, then validates the exact
reviewed candidate and stops at a finding `HUMAN_GATE`. Each invocation creates
a unique attempt under `runs/findings/`, even when the logical `finding_id` is
reused. Use `python3 agentflow.py finding status <finding-run-id>` for
read-only status and `python3 agentflow.py finding resume <finding-run-id>` only
for safe completed boundaries. Both report success only after durable finding
terminal evidence verifies.

Finding v0 does not use queue `ExecutionControl`. Its candidate manifest binds
the detached registered worktree, frozen HEAD, semantic Git index, and every
filesystem entry other than that worktree's Git administrative metadata.
Broader validators run under a candidate `WriteLease`; any candidate mutation,
including ignored files, stops the finding. The final result grants no authority
to commit, push, open a PR, merge, or deploy.

Runs end with `HUMAN_GATE` on success or a fail-closed code such as `BASELINE_DRIFT`, `WRITE_LEASE_CONFLICT`, `VALIDATOR_FAILED`, `INVALID_MODEL_OUTPUT`, `REVIEW_RETRY_CAP`, or `CONTROL_PLANE_MUTATED`.

## Trusted control-plane invariant (F-04)

For each logical run AgentFlow captures the protected control plane once
before untrusted execution and keeps that baseline immutable. It is
verified before every model invocation, after every model invocation
(including failure paths, before any retry/fallback/correction), and
again immediately before `HUMAN_GATE`.

Protected set (always rooted at the running AgentFlow `ROOT`, never
`exec_repo`): all `*.py` files directly under `ROOT` (including
`agentflow.py`; catches `sitecustomize.py`-style runtime injection),
`prompts/**`, `opencode/**` (excluding `node_modules/**` and
`__pycache__/**`), `config/models.json`, and `schemas/result.schema.json`.
The manifest never follows symlinks and detects content changes, additions,
deletions, file/directory replacement, and symlink introduction/replacement/target changes.

Any difference fails closed as `CONTROL_PLANE_MUTATED`: no retry, no
fallback, no correction, no reviewer/adjudicator progression, and no
`HUMAN_GATE`. The verdict is queue-fatal. Legitimate AgentFlow
self-modification must use isolation (a detached candidate worktree);
non-isolated modification of protected `ROOT` files is fatal even when
the path would otherwise be allowed by the task.

Each OpenCode process receives a fresh copy of `ROOT/opencode` at
`runs/<run>/runtime/<invocation-id>/opencode-config`. Its path is recorded
in the invocation JSON as `runtime_config_dir`. OpenCode may create its own
runtime files there; the copy stays under `runs/` as diagnostic evidence.
AgentFlow rejects symlinks and special entries in the trusted source config
before launching OpenCode, and the runtime path must be outside the target
repository and protected source tree. Direct writes to `ROOT/opencode` still
trigger F-04.

### Durable poison ledger (future-run invariant)

Same-run detection alone is not enough: a worker that mutated the
control plane and was stopped leaves the poisoned state on disk, and a
later logical run would otherwise capture it as a fresh trusted
baseline. Whenever AgentFlow itself observes `CONTROL_PLANE_MUTATED`,
it durably records the post-mutation manifest (content-bound: the full
file map plus its canonical manifest digest) in a coordinator-written
poison ledger at `.locks/control-plane-poison.json` (atomic write with
fsync, deduplicated, bounded to the 32 most recent entries).

At every logical-run start, after the run baseline manifest is computed
but before any worktree creation or model invocation, the manifest is
compared against the ledger. A match fails closed as
`CONTROL_PLANE_MUTATED` (`status: STOPPED`, `human_gate: false`, no
model/worktree/retry/fallback/correction). Standalone `invoke_model`
calls (without an outer logical-run owner) also execute the durable
poison gate inside a bounded ownership scope: one immutable baseline
per logical invocation, poison check before untrusted execution,
cleanup after completion or `BaseException`, and no stale trust
inheritance from unrelated later calls. Legitimate pre-existing
control-plane state that is not in the ledger remains allowed,
regardless of Git HEAD; the per-run immutable baseline semantics are
unchanged. The ledger lives under `.locks`, which is not part of the
protected manifest, so recording cannot recursively trigger detection.
A ledger that exists but cannot be safely parsed or verified (including
entries whose stored evidence fails digest verification) fails closed as
`CONTROL_PLANE_MUTATED`; malformed durable poison evidence is never
treated as "no poison". Poison-ledger updates are cross-process safe:
the entire read-modify-write is protected by an OS advisory lock
(`fcntl.flock`) with deterministic lock lifetime, so concurrent
detections cannot lose an entry.

## AUTONOMY-001 sequential program queues

`queue run` validates and freezes the entire queue before it creates queue evidence, starts the wall clock, creates a worktree, or invokes a model. Queue documents are strict (`schemas/queue.schema.json`), contain 1..8 uniquely identified items, and supply queue-wide limits for wall-clock seconds, physical model calls, retries, fallbacks, and correction starts. Every referenced task must enable isolation and name an explicit resolvable baseline commit. Each program receives its own detached worktree pinned to that preflight baseline; candidates are preserved for human review and are never committed, published, merged, deployed, or automatically cleaned up.

```json
{
  "queue_id": "release-prep",
  "items": [
    {"item_id": "api", "program": "api-program.json"},
    {"item_id": "docs", "program": "docs-program.json"}
  ],
  "budgets": {
    "wall_clock_seconds": 7200,
    "model_calls": 24,
    "retries": 2,
    "fallbacks": 2,
    "corrections": 2
  },
  "recovery": {
    "fallback_profiles": {
      "architect": "architect_adjudicator",
      "worker": "fallback_long_context",
      "reviewer": "independent_reviewer"
    }
  }
}
```

Recovery is per logical invocation: `PRIMARY`, at most one same-profile `RETRY`, then at most one explicitly configured `FALLBACK`; quota/model-unavailable failures skip retry. Every physical launch consumes a durably reserved model call. Recovery is forbidden after a writer leaves any workspace delta, and provider routing relies only on structured error codes—not prose. Native timeout wins over inactivity detection, which wins over the queue deadline at the same observation.

Queue evidence lives under `runs/queues/<queue-run>/`: frozen `queue-plan.json`, `queue-started.json`, diagnostic `queue-state.json` and `budget-state.json`, per-item start/terminal markers and immutable attempt transitions, then `final.json`. Only `item-terminal.json` proves item completion. `HUMAN_GATE` continues to the next item; isolated program-local failures also continue. Budget exhaustion, preservation/process uncertainty, and safety/controller failures stop the queue without creating false markers for later items. There is no resume or automatic reconciliation.

## Model roles and changes

The current roles are listed by `python agentflow.py models`: DeepSeek V4.1 Flash Max is primary, Codex Luna Max is co-champion, MiMo V2.5 is volume, GLM-5.3-Flash Max is independent reviewer, Qwen3.8 Flash xhigh is fallback, Terra High is controller, Terra Max is premium escalation, Sol High is a Codex architect/adjudicator option, and Muse Spark 1.3 Contributor High is the verified OpenCode program architect. IDs and variants are separate fields because that is how the installed CLIs invoke them.

To add or disable a model, edit only `config/models.json` after confirming the exact ID/variant with the relevant installed CLI. Do not infer names.

## Model output-inactivity watchdog (WATCHDOG-001A, opt-in)

Model supervision is opt-in and model-only. Without extra configuration,
existing behavior is preserved exactly: only the absolute
`model_timeout_seconds` deadline applies.

To arm output-inactivity detection, set a task-level integer threshold:

```json
{
  "model_timeout_seconds": 3600,
  "model_inactivity_timeout_seconds": 300
}
```

Rules:

- Absent `model_inactivity_timeout_seconds`: watchdog disabled.
- Present: must be an integer (`true`/`false` rejected), greater than 0, and
  strictly less than the effective `model_timeout_seconds`. Violations fail
  task validation with `INVALID_TASK`.
- One threshold applies to all model roles (worker, reviewer, architect,
  adjudicator). Git, validators, and ordinary subprocesses are never
  supervised and never watched.
- A stall means the leader is still alive and no non-empty stdout or stderr
  bytes were observed for the threshold (monotonic clock, raw bytes, either
  pipe counts). The policy is armed immediately before supervision entry, so
  worker registration and GO latency consume neither the absolute nor the
  inactivity budget.
- Absolute timeout always wins: if both become due in the same controller
  iteration, `PROCESS_TIMEOUT` is reported, and continuous activity never
  extends the absolute deadline.
- A stalled leader is terminated with the existing controlled-group
  termination, then reported as `STALL_DETECTED`. A leader that already
  exited is never misclassified as a stall. Termination or cleanup trouble
  stays authoritative `INTERNAL_ERROR`.
- Before `STALL_DETECTED` or `PROCESS_TIMEOUT` leaves `invoke_model`,
  evidence is persisted to `<role>-cycle-<n>-failure.json` (failure code,
  absolute timeout, inactivity threshold, observed inactivity duration,
  stdout/stderr byte counts, return code when available, and lossy-decoded
  partial output). `final.json` remains authoritative for the run outcome
  and existing workspace preservation is reused unchanged.

## PROGRAM-001B sequential subtasks (opt-in)

Set `max_subtasks` (exact integer 1..4, hard maximum 4) in `program.json`
to run sequential subtasks. Absence preserves PROGRAM-001A behavior
exactly. B-mode requires `task.isolation.enabled == true` and uses one
shared detached execution worktree for the entire program.

The architect returns a COMPLETE plan plus `subtasks`: a non-empty
ordered array where each item has EXACTLY `subtask_id`
(`[a-z0-9][a-z0-9._-]{0,63}`, unique), `objective`, `allowed_paths`
(subset of parent scope), `invariants`, and `expected_outputs`. Unknown
fields (including `repo`, `risk`, `validators`, `forbidden_actions`,
`isolation`, timeouts, `max_corrections`, `dependencies`, nested
subtasks, routing, worker profile) are rejected.

Each child inherits repo (execution worktree), risk, exact parent
validators, unchanged `forbidden_actions`, parent+child invariants, and
model/watchdog timeouts. Child scope is the delta since that child's
durable start baseline; parent scope is the accumulated delta since the
original program baseline. Both are enforced after worker AND after
validators (validator writes count as child mutations). Continuity
requires child N to start exactly from child N-1's durable end baseline,
else `PROGRAM_WORKSPACE_DRIFT`. Durable `program-plan.json`,
`program-state.json`, and `subtasks/<ordinal>-<id>/` (`subtask.json`,
`started.json`, `worker-cycle-0-invocation.json` /
`worker-cycle-0-result.json` (the result embeds the validator status
mapping), `validators-cycle-0.json` (full validator results written by
`run_validators` when validators run), `completed.json` OR `failed.json`)
use `atomic_json_fsync` except the invocation/result and
`validators-cycle-0.json` artifacts, which use `atomic_json`;
`completed.json` is immutable and is the only completion point. After
all children, an
integrated review/adjudication runs, with at most ONE program-level
correction inside parent scope, full validators, final review, proven
preservation (`WORKSPACE_PRESERVATION_FAILED` without `HUMAN_GATE`), and
primary-failure precedence over later preservation failures.

## Terra/Sol operation

Terra High normally validates or creates a task packet, runs the three CLI commands above, reads `runs/<run>/final.json`, and escalates discrepancies. Sol High is reserved for architecture, CRITICAL work, difficult conflicts, security-sensitive judgment, and changes to AgentFlow itself. Neither controller should bypass the final human gate.
