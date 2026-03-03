import { describe, expect, it } from "vitest";
import {
  buildByKindInsightRows,
  getSessionKindBadgeLabel,
} from "./usage-render-overview.ts";
import type { UsageAggregates, UsageSessionEntry } from "./usageTypes.ts";

describe("getSessionKindBadgeLabel", () => {
  const baseSession: UsageSessionEntry = {
    key: "agent:main:test",
    kind: "main",
    usage: null,
  };

  it("renders expected badges", () => {
    expect(getSessionKindBadgeLabel(baseSession)).toBeUndefined();
    expect(getSessionKindBadgeLabel({ ...baseSession, kind: "cron" })).toBe("[cron]");
    expect(getSessionKindBadgeLabel({ ...baseSession, kind: "cron-run" })).toBe("[cron-run]");
    expect(getSessionKindBadgeLabel({ ...baseSession, kind: "subagent", subagentDepth: 2 })).toBe(
      "[sub:d2]",
    );
    expect(getSessionKindBadgeLabel({ ...baseSession, kind: "other" })).toBe("[other]");
  });
});

describe("buildByKindInsightRows", () => {
  it("builds cost/token rows from byKind aggregates", () => {
    const aggregates = {
      byKind: [
        {
          kind: "cron-run",
          totals: {
            input: 0,
            output: 0,
            cacheRead: 0,
            cacheWrite: 0,
            totalTokens: 123,
            totalCost: 1.5,
            inputCost: 0,
            outputCost: 0,
            cacheReadCost: 0,
            cacheWriteCost: 0,
            missingCostEntries: 0,
          },
        },
      ],
    } as UsageAggregates;

    expect(buildByKindInsightRows(aggregates)).toEqual([
      {
        label: "cron-run",
        value: "$1.50",
        sub: "123",
      },
    ]);
  });
});
