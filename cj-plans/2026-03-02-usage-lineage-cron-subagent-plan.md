# Usage lineage plan: cron + subagent token attribution

Date: 2026-03-02
Mode: full feature slice
Priorities: accuracy/no double-counting, default-on rollout, no realtime (manual refresh)

## Goal

Show exactly where tokens come from in Usage dashboard, including:

- cron jobs/runs
- subagent spawns
- lineage back to root session

## Non-goals

- no push/streaming realtime
- no new token accounting source

## Invariants (accuracy)

1. Transcript-derived usage remains single source of truth for token totals.
2. Cron run logs are metadata enrichment only (job/run linkage), never additive token source.
3. Any missing linkage metadata must degrade to `unknown`, never inferred totals.

## Data model additions

### `sessions.usage` entry extensions

Add to `SessionUsageEntry` (`src/gateway/server-methods/usage.ts`, `ui/src/ui/usage-types.ts`):

- `kind: "main" | "subagent" | "cron" | "cron-run" | "other"`
- `lineage?: {`
  - `parentSessionKey?: string`
  - `rootSessionKey?: string`
  - `path?: string[]` (root -> current)
  - `depth?: number`
  - `cycleDetected?: boolean`
  - `}`
- `subagent?: { depth?: number; spawnedBy?: string }`
- `cron?: { jobId?: string; runId?: string; matchedRunLog?: boolean; runTs?: number }`

### aggregate extensions

Add to `SessionsUsageAggregates`:

- `byKind: Array<{ kind: string; totals: ... }>`
- `byCronJob: Array<{ jobId: string; totals: ...; runs: number }>`
- `byRootSession: Array<{ rootSessionKey: string; totals: ...; sessions: number }>`

## Backend plan

### 1) Lineage resolver utility

Create utility (new file under `src/gateway/server-methods/` or `src/infra/`):

- input: session key + session store map
- output: parent/root/path/depth/cycle
- unbounded traversal with:
  - visited set cycle guard
  - max-hop safety hard cap (internal fail-safe, e.g. 10k) with `cycleDetected`/`truncated`

### 2) Session classification

Classify `kind` by key + entry metadata:

- cron run: `agent:*:cron:<jobId>:run:<runId>`
- cron base: `agent:*:cron:<jobId>`
- subagent: `subagent:` prefix or `spawnedBy` present
- main/other fallback

### 3) Cron enrichment

Use cron run logs (`src/cron/run-log.ts`) to enrich session rows:

- map by `sessionKey` and/or `sessionId` + `jobId`
- attach `cron.jobId`, `cron.runId`, run timestamp, `matchedRunLog`
- never add run-log usage into totals

### 4) Aggregate builders

Build new aggregates from already computed per-session usage totals:

- byKind
- byCronJob
- byRootSession

### 5) Protocol/type updates

Update shared/client types:

- `ui/src/ui/usage-types.ts`
- `ui/src/ui/types.ts` re-exports if needed

## UI plan

### 1) Session list row metadata

In Usage list (`ui/src/ui/views/usage-render-overview.ts`):

- add badges: `cron`, `cron-run`, `subagent dN`, `main`
- add compact lineage text: `root -> ... -> current` (truncated middle for long paths)
- add cron badge detail: `job:<id>`

### 2) Filters/query terms

Extend usage query parser (`ui/src/ui/views/usage-query.ts`, helpers):

- `kind:cron|cron-run|subagent|main`
- `cron:<jobId>`
- `root:<sessionKey-fragment>`
- `has:lineage-cycle`

### 3) Detail panel lineage card

In session detail (`ui/src/ui/views/usage-render-details.ts`):

- lineage card with full path
- parent/root quick links where resolvable
- cron linkage card (job id, run id, matched log)

### 4) Top-level insights

In overview cards:

- top cron jobs by tokens
- subagent vs non-subagent token split
- top roots by tokens

## Testing plan

### Backend

- `src/gateway/server-methods/usage.sessions-usage.test.ts`
  - returns lineage fields for spawned chains
  - cycle handling (A->B->A)
  - cron job/run extraction
  - run-log enrichment present/absent behavior
  - aggregate correctness vs known fixtures
- new utility tests for lineage traversal edge cases

### UI

- `ui/src/ui/controllers/usage.node.test.ts` (shape handling)
- usage view tests for badges/filter behavior
- query parser tests for new tokens

### Safety tests

- assert totals unchanged before/after enrichment for same transcript fixture
- assert no duplicate token accumulation when run log usage exists

## Migration/compat

- Fields are additive and optional.
- Old UI should keep working if backend updated first.
- New UI should tolerate missing lineage fields.

## Rollout

- default on
- staged by merge order:
  1. backend + tests
  2. UI wiring + tests
  3. polish docs

## Implementation sequence (atomic commits)

1. backend lineage utility + tests
2. `sessions.usage` payload fields + aggregate fields + tests
3. cron run-log enrichment + tests
4. shared/ui types update
5. usage list badges + lineage row + tests
6. query filter extensions + tests
7. detail panel lineage + cron cards + tests
8. overview aggregate cards + tests
9. lint/typecheck/test sweep

## Commands for validation

- `pnpm tsgo`
- `pnpm check`
- `pnpm test -- src/gateway/server-methods/usage.sessions-usage.test.ts`
- `pnpm test -- ui/src/ui/controllers/usage.node.test.ts`
- targeted usage view tests

## Open questions (resolved via interview)

- scope: full slice ✅
- priority: accuracy ✅
- cron linkage: session key + run logs enrichment ✅
- lineage traversal: unbounded + cycle guard ✅
- realtime: no ✅
- rollout: default on ✅
