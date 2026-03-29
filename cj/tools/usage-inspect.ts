#!/usr/bin/env bun
/**
 * Usage inspection CLI — wraps openclaw gateway RPC for agent-friendly usage queries.
 *
 * Usage:
 *   bun cj/tools/usage-inspect.ts summary [--days N]
 *   bun cj/tools/usage-inspect.ts sessions [--days N] [--limit N] [--sort cost|tokens|recent] [--agent ID] [--model PATTERN] [--kind main|cron|subagent]
 *   bun cj/tools/usage-inspect.ts session <key>
 *   bun cj/tools/usage-inspect.ts search <query> [--days N] [--limit N]
 */

import { callGateway } from "../../src/gateway/call.js";
import { GATEWAY_CLIENT_MODES, GATEWAY_CLIENT_NAMES } from "../../src/utils/message-channel.js";

const rpc = async (method: string, params?: Record<string, unknown>) =>
  callGateway({
    method,
    params,
    timeoutMs: 30_000,
    clientName: GATEWAY_CLIENT_NAMES.CLI,
    mode: GATEWAY_CLIENT_MODES.CLI,
  });

function daysToDateRange(days: number): { startDate: string; endDate: string } {
  const end = new Date();
  const start = new Date(end.getTime() - (days - 1) * 86400000);
  const fmtDate = (d: Date) => d.toISOString().slice(0, 10);
  return { startDate: fmtDate(start), endDate: fmtDate(end) };
}

const fmt = {
  usd: (n: number) => `$${n.toFixed(4)}`,
  tokens: (n: number) =>
    n >= 1_000_000
      ? `${(n / 1_000_000).toFixed(1)}M`
      : n >= 1_000
        ? `${(n / 1_000).toFixed(1)}K`
        : String(n),
  pct: (n: number) => `${n.toFixed(1)}%`,
  dur: (ms: number) => {
    if (ms < 1000) return `${Math.round(ms)}ms`;
    if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60_000).toFixed(1)}m`;
  },
};

function parseArgs() {
  const args = process.argv.slice(2);
  const cmd = args[0] ?? "summary";
  const flags: Record<string, string> = {};
  const positional: string[] = [];

  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      flags[key] = args[i + 1] ?? "true";
      i++;
    } else {
      positional.push(args[i]);
    }
  }

  return { cmd, flags, positional };
}

async function summary(days: number) {
  const result = (await rpc("usage.cost", { days })) as any;
  const { totals, daily } = result;

  console.log(`\n📊 Usage Summary (last ${days} days)\n`);
  console.log(`  Total Cost:   ${fmt.usd(totals.totalCost)}`);
  console.log(`  Total Tokens: ${fmt.tokens(totals.totalTokens)}`);
  console.log(`  Input:        ${fmt.tokens(totals.input)} (${fmt.usd(totals.inputCost)})`);
  console.log(`  Output:       ${fmt.tokens(totals.output)} (${fmt.usd(totals.outputCost)})`);
  console.log(`  Cache Read:   ${fmt.tokens(totals.cacheRead)} (${fmt.usd(totals.cacheReadCost)})`);
  console.log(
    `  Cache Write:  ${fmt.tokens(totals.cacheWrite)} (${fmt.usd(totals.cacheWriteCost)})`,
  );

  if (daily?.length) {
    console.log(`\n  Daily breakdown (recent):`);
    const recent = daily.slice(-7);
    for (const d of recent) {
      const bar = "█".repeat(
        Math.min(40, Math.round((d.totalCost / (totals.totalCost / days)) * 10)),
      );
      console.log(
        `    ${d.date}  ${fmt.usd(d.totalCost).padStart(10)}  ${fmt.tokens(d.totalTokens).padStart(8)}  ${bar}`,
      );
    }
  }
}

async function sessions(opts: {
  days: number;
  limit: number;
  sort: string;
  agent?: string;
  model?: string;
  kind?: string;
}) {
  const result = (await rpc("sessions.usage", {
    ...daysToDateRange(opts.days),
    limit: Math.min(opts.limit * 3, 200), // over-fetch for filtering
  })) as any;

  let entries: any[] = result.sessions ?? [];

  if (opts.agent) {
    entries = entries.filter((s: any) => s.agentId?.includes(opts.agent));
  }
  if (opts.kind) {
    entries = entries.filter((s: any) => s.kind === opts.kind);
  }
  if (opts.model) {
    const pat = opts.model.toLowerCase();
    entries = entries.filter((s: any) =>
      s.usage?.modelUsage?.some(
        (m: any) =>
          (m.model ?? "").toLowerCase().includes(pat) ||
          (m.provider ?? "").toLowerCase().includes(pat),
      ),
    );
  }

  if (opts.sort === "cost") {
    entries.sort((a: any, b: any) => (b.usage?.totalCost ?? 0) - (a.usage?.totalCost ?? 0));
  } else if (opts.sort === "tokens") {
    entries.sort((a: any, b: any) => (b.usage?.totalTokens ?? 0) - (a.usage?.totalTokens ?? 0));
  }

  entries = entries.slice(0, opts.limit);

  console.log(`\n📋 Sessions (${entries.length} shown, ${opts.sort} sort)\n`);

  const { totals, aggregates } = result;

  if (aggregates?.byAgent?.length) {
    console.log("  By Agent:");
    for (const a of aggregates.byAgent) {
      console.log(
        `    ${a.agentId.padEnd(20)} ${fmt.usd(a.totals.totalCost).padStart(10)}  ${fmt.tokens(a.totals.totalTokens).padStart(8)}`,
      );
    }
    console.log();
  }

  if (aggregates?.byModel?.length) {
    console.log("  By Model:");
    for (const m of aggregates.byModel.slice(0, 5)) {
      console.log(
        `    ${(m.provider + "/" + m.model).padEnd(40)} ${fmt.usd(m.totals.totalCost).padStart(10)}  ${fmt.tokens(m.totals.totalTokens).padStart(8)}`,
      );
    }
    console.log();
  }

  if (aggregates?.byKind?.length) {
    console.log("  By Kind:");
    for (const k of aggregates.byKind) {
      console.log(
        `    ${k.kind.padEnd(15)} ${fmt.usd(k.totals.totalCost).padStart(10)}  ${fmt.tokens(k.totals.totalTokens).padStart(8)}`,
      );
    }
    console.log();
  }

  console.log("  Sessions:");
  for (const s of entries) {
    const u = s.usage;
    if (!u) continue;
    const label = s.label ? ` (${s.label})` : "";
    const model = u.modelUsage?.[0]?.model ?? s.model ?? "";
    const date = new Date(s.updatedAt).toISOString().slice(0, 16);
    console.log(
      `    ${date}  ${s.kind.padEnd(10)} ${fmt.usd(u.totalCost).padStart(10)}  ${fmt.tokens(u.totalTokens).padStart(8)}  ${model.slice(0, 25).padEnd(25)}  ${(s.agentId ?? "").slice(0, 15)}${label}`,
    );
  }

  console.log(`\n  Totals: ${fmt.usd(totals.totalCost)}  ${fmt.tokens(totals.totalTokens)}`);
}

async function sessionDetail(key: string) {
  const result = (await rpc("sessions.usage", { key, limit: 1 })) as any;
  const session = result.sessions?.[0];
  if (!session) {
    console.error(`Session not found: ${key}`);
    process.exit(1);
  }

  const u = session.usage;
  console.log(`\n🔍 Session: ${key}\n`);
  if (session.label) console.log(`  Label:    ${session.label}`);
  console.log(`  Kind:     ${session.kind}`);
  console.log(`  Agent:    ${session.agentId ?? "unknown"}`);
  console.log(`  Channel:  ${session.channel ?? "unknown"}`);
  if (session.model) console.log(`  Model:    ${session.model}`);
  console.log(`  Updated:  ${new Date(session.updatedAt).toISOString()}`);

  if (u) {
    console.log(`\n  Cost:     ${fmt.usd(u.totalCost)}`);
    console.log(`  Tokens:   ${fmt.tokens(u.totalTokens)}`);
    console.log(`  Input:    ${fmt.tokens(u.input)} (${fmt.usd(u.inputCost)})`);
    console.log(`  Output:   ${fmt.tokens(u.output)} (${fmt.usd(u.outputCost)})`);
    console.log(`  Cache R:  ${fmt.tokens(u.cacheRead)} (${fmt.usd(u.cacheReadCost)})`);
    console.log(`  Cache W:  ${fmt.tokens(u.cacheWrite)} (${fmt.usd(u.cacheWriteCost)})`);

    if (u.durationMs) console.log(`  Duration: ${fmt.dur(u.durationMs)}`);

    if (u.messageCounts) {
      const mc = u.messageCounts;
      console.log(
        `\n  Messages: ${mc.total} (user: ${mc.user}, assistant: ${mc.assistant}, tools: ${mc.toolCalls}, errors: ${mc.errors})`,
      );
    }

    if (u.modelUsage?.length) {
      console.log("\n  Models:");
      for (const m of u.modelUsage) {
        console.log(
          `    ${(m.provider + "/" + m.model).padEnd(40)} ${fmt.usd(m.totals.totalCost).padStart(10)}  calls: ${m.count}`,
        );
      }
    }

    if (u.toolUsage?.tools?.length) {
      console.log(
        `\n  Tools (${u.toolUsage.uniqueTools} unique, ${u.toolUsage.totalCalls} calls):`,
      );
      for (const t of u.toolUsage.tools.slice(0, 10)) {
        console.log(`    ${t.name.padEnd(30)} ${String(t.count).padStart(5)}`);
      }
    }

    if (u.latency) {
      console.log(
        `\n  Latency:  avg ${fmt.dur(u.latency.avgMs)}, p95 ${fmt.dur(u.latency.p95Ms)}, min ${fmt.dur(u.latency.minMs)}, max ${fmt.dur(u.latency.maxMs)}`,
      );
    }
  }
}

async function search(query: string, days: number, limit: number) {
  const result = (await rpc("sessions.usage", { ...daysToDateRange(days), limit: 200 })) as any;
  const q = query.toLowerCase();

  const matches = (result.sessions ?? [])
    .filter((s: any) => {
      const fields = [
        s.key,
        s.label,
        s.sessionId,
        s.agentId,
        s.channel,
        s.model,
        s.kind,
        ...(s.usage?.modelUsage ?? []).map((m: any) => `${m.provider}/${m.model}`),
      ].filter(Boolean);
      return fields.some((f: string) => f.toLowerCase().includes(q));
    })
    .slice(0, limit);

  console.log(`\n🔎 Search: "${query}" (${matches.length} matches)\n`);

  for (const s of matches) {
    const u = s.usage;
    const cost = u ? fmt.usd(u.totalCost) : "n/a";
    const tokens = u ? fmt.tokens(u.totalTokens) : "n/a";
    const date = new Date(s.updatedAt).toISOString().slice(0, 16);
    const label = s.label ? ` (${s.label})` : "";
    console.log(
      `  ${date}  ${cost.padStart(10)}  ${tokens.padStart(8)}  ${s.kind.padEnd(10)}  ${(s.agentId ?? "").slice(0, 15)}${label}`,
    );
    console.log(`    key: ${s.key}`);
  }
}

async function jsonOutput(method: string, params?: Record<string, unknown>) {
  const result = await rpc(method, params);
  console.log(JSON.stringify(result, null, 2));
}

async function main() {
  const { cmd, flags, positional } = parseArgs();
  const days = Number(flags.days ?? 7);
  const limit = Number(flags.limit ?? 20);
  const isJson = "json" in flags;

  try {
    if (isJson) {
      switch (cmd) {
        case "summary":
          await jsonOutput("usage.cost", { days });
          break;
        case "sessions":
          await jsonOutput("sessions.usage", { ...daysToDateRange(days), limit });
          break;
        case "session":
          await jsonOutput("sessions.usage", { key: positional[0], limit: 1 });
          break;
        default:
          console.error(`Unknown command: ${cmd}`);
          process.exit(1);
      }
      return;
    }

    switch (cmd) {
      case "summary":
        await summary(days);
        break;
      case "sessions":
        await sessions({
          days,
          limit,
          sort: flags.sort ?? "cost",
          agent: flags.agent,
          model: flags.model,
          kind: flags.kind,
        });
        break;
      case "session":
        if (!positional[0]) {
          console.error("Usage: session <key>");
          process.exit(1);
        }
        await sessionDetail(positional[0]);
        break;
      case "search":
        if (!positional[0]) {
          console.error("Usage: search <query>");
          process.exit(1);
        }
        await search(positional[0], days, limit);
        break;
      case "help":
        console.log(`
Usage: bun cj/tools/usage-inspect.ts <command> [options]

Commands:
  summary              Aggregate cost/token summary
  sessions             List sessions with usage breakdown
  session <key>        Detailed view of a single session
  search <query>       Search sessions by key, label, agent, model, etc.
  help                 Show this help

Options:
  --days N             Lookback window (default: 7)
  --limit N            Max results (default: 20)
  --sort cost|tokens|recent  Sort sessions (default: cost)
  --agent ID           Filter by agent ID
  --model PATTERN      Filter by model name
  --kind TYPE          Filter by kind (main|cron|cron-run|subagent|other)
  --json               Output raw JSON
`);
        break;
      default:
        console.error(`Unknown command: ${cmd}. Run 'help' for usage.`);
        process.exit(1);
    }
  } catch (err: any) {
    console.error(`Error: ${err.message ?? err}`);
    process.exit(1);
  }
}

main();
