import { describe, expect, it } from "vitest";
import {
  normalizePluginsConfig,
  resolveEffectiveEnableState,
  resolveEnableState,
} from "./config-state.js";

describe("normalizePluginsConfig", () => {
  it("uses default memory slot when not specified", () => {
    const result = normalizePluginsConfig({});
    expect(result.slots.memory).toBe("memory-core");
  });

  it("respects explicit memory slot value", () => {
    const result = normalizePluginsConfig({
      slots: { memory: "custom-memory" },
    });
    expect(result.slots.memory).toBe("custom-memory");
  });

  it("disables memory slot when set to 'none' (case insensitive)", () => {
    expect(
      normalizePluginsConfig({
        slots: { memory: "none" },
      }).slots.memory,
    ).toBeNull();
    expect(
      normalizePluginsConfig({
        slots: { memory: "None" },
      }).slots.memory,
    ).toBeNull();
  });

  it("trims whitespace from memory slot value", () => {
    const result = normalizePluginsConfig({
      slots: { memory: "  custom-memory  " },
    });
    expect(result.slots.memory).toBe("custom-memory");
  });

  it("uses default when memory slot is empty string", () => {
    const result = normalizePluginsConfig({
      slots: { memory: "" },
    });
    expect(result.slots.memory).toBe("memory-core");
  });

  it("uses default when memory slot is whitespace only", () => {
    const result = normalizePluginsConfig({
      slots: { memory: "   " },
    });
    expect(result.slots.memory).toBe("memory-core");
  });
});

describe("resolveEffectiveEnableState", () => {
  function resolveBundledTelegramState(config: Parameters<typeof normalizePluginsConfig>[0]) {
    const normalized = normalizePluginsConfig(config);
    return resolveEffectiveEnableState({
      id: "telegram",
      origin: "bundled",
      config: normalized,
      rootConfig: {
        channels: {
          telegram: {
            enabled: true,
          },
        },
      },
    });
  }

  it("enables bundled channels when channels.<id>.enabled=true", () => {
    const state = resolveBundledTelegramState({
      enabled: true,
    });
    expect(state).toEqual({ enabled: true });
  });

  it("keeps explicit plugin-level disable authoritative", () => {
    const state = resolveBundledTelegramState({
      enabled: true,
      entries: {
        telegram: {
          enabled: false,
        },
      },
    });
    expect(state).toEqual({ enabled: false, reason: "disabled in config" });
  });
});

describe("resolveEnableState", () => {
  it("enables memory slot plugin even when not in allowlist", () => {
    const normalized = normalizePluginsConfig({
      enabled: true,
      allow: ["telegram", "voice-call"],
    });
    expect(normalized.slots.memory).toBe("memory-core");
    const state = resolveEnableState("memory-core", "bundled", normalized);
    expect(state).toEqual({ enabled: true });
  });

  it("still blocks memory slot plugin when explicitly denied", () => {
    const normalized = normalizePluginsConfig({
      enabled: true,
      deny: ["memory-core"],
    });
    const state = resolveEnableState("memory-core", "bundled", normalized);
    expect(state).toEqual({ enabled: false, reason: "blocked by denylist" });
  });
});
