# Usage lineage v1 (lean)

Date: 2026-03-02
Supersedes: `2026-03-02-usage-lineage-cron-subagent-plan.md`

## Goal

Show where tokens come from in Usage dashboard: cron jobs, subagents, main sessions.

## Invariants

1. Transcript-derived usage = single source of truth for token totals.
2. Cron run logs = metadata enrichment only, never additive token source.
3. Missing linkage → `unknown` kind, never inferred totals.

## Scope

### In (v1)

- `kind` field on `SessionUsageEntry`: `"main" | "subagent" | "cron" | "cron-run" | "other"`
- `subagentDepth` on subagent sessions
- `parentSessionKey` from `SessionEntry.spawnedBy` (preferred) or key parsing fallback
- `cron` metadata: `{ jobId, runId, matchedRunLog, runTs }` from run-log join
- `aggregates.byKind` aggregate
- UI: kind badges on session rows + byKind summary card
- Tests: kind classification, cron enrichment join, totals-unchanged guard

### Deferred

- Full lineage traversal / cycle detection
- `byRootSession` aggregate
- Query grammar expansion (`kind:`, `root:`, `has:lineage-cycle`)
- Detail panel lineage card
- `path[]` / `rootSessionKey` fields

## Existing infrastructure (no new files needed for classification)

- `src/sessions/session-key-utils.ts`:
  - `isCronRunSessionKey()` — `cron:<id>:run:<id>` pattern
  - `isCronSessionKey()` — `cron:` prefix
  - `isSubagentSessionKey()` — `subagent:` prefix
  - `getSubagentDepth()` — counts `:subagent:` segments
- `src/config/sessions/types.ts`: `SessionEntry.spawnedBy?: string`
- `src/cron/run-log.ts`: `CronRunLogEntry` has `sessionKey`, `sessionId`, `jobId`

## Data model changes

### `SessionUsageEntry` additions (src/gateway/server-methods/usage.ts)

```ts
kind: "main" | "subagent" | "cron" | "cron-run" | "other";
subagentDepth?: number;
parentSessionKey?: string;
cron?: {
  jobId?: string;
  runId?: string;
  matchedRunLog?: boolean;
  runTs?: number;
};
```

### `SessionsUsageAggregates` addition

```ts
byKind: Array<{ kind: string; totals: CostUsageSummary["totals"] }>;
```

## Implementation plan

### 1. Add kind classification in sessions.usage handler

In the existing `for (const merged of limitedEntries)` loop:

```ts
import {
  isCronRunSessionKey,
  isCronSessionKey,
  isSubagentSessionKey,
  getSubagentDepth,
} from "../../sessions/session-key-utils.js";

const kind = isCronRunSessionKey(merged.key)
  ? "cron-run"
  : isCronSessionKey(merged.key)
    ? "cron"
    : isSubagentSessionKey(merged.key)
      ? "subagent"
      : "main";

const subagentDepth = kind === "subagent" ? getSubagentDepth(merged.key) : undefined;
const parentSessionKey =
  merged.storeEntry?.spawnedBy ?? resolveThreadParentSessionKey(merged.key) ?? undefined;
```

### 2. Cron run-log enrichment

Before the main loop, load cron run logs and build a lookup map:

```ts
// Build sessionKey → CronRunLogEntry map from run logs
const cronRunLogMap = await buildCronRunLogMap(config);

// In the loop, for cron/cron-run sessions:
const cronMeta = cronRunLogMap.get(merged.key) ?? cronRunLogMap.get(merged.sessionId);
```

Parse `jobId` and `runId` from session key for cron-run sessions:

- Key pattern: `agent:<agentId>:cron:<jobId>:run:<runId>`

### 3. byKind aggregate

Add `byKindMap` alongside existing `byAgentMap`, `byChannelMap`:

```ts
const byKindMap = new Map<string, CostUsageSummary["totals"]>();
// In loop: merge totals into byKindMap.get(kind)
```

### 4. UI: kind badges

In `ui/src/ui/views/usage-render-overview.ts`, add badge next to session label:

- `[cron]`, `[cron-run]`, `[sub:d2]`, no badge for main
- Use existing badge/tag styling pattern

### 5. UI: byKind summary

In usage overview, add a compact breakdown card showing token/cost split by kind.

## Testing

### Backend tests (`usage.sessions-usage.test.ts`)

1. **Kind classification**: mock sessions with cron/subagent/main keys → assert correct `kind`
2. **Cron enrichment**: mock run log entries → assert `cron.jobId`, `matchedRunLog`
3. **Totals guard**: assert `totals` unchanged before/after adding kind + cron fields
4. **parentSessionKey**: test spawnedBy preference over key parsing

### UI tests

1. Badge rendering for each kind
2. byKind card with fixture data

## Commit sequence

1. Backend: kind + parentSessionKey + subagentDepth on SessionUsageEntry + byKind aggregate + tests
2. Backend: cron run-log enrichment + tests
3. UI types: update shared types
4. UI: kind badges + byKind card + tests
