import { describe, expect, it } from "vitest";
import { visibleNavigation } from "./AttackDefenseApp";
import { orderAndDedupe } from "./useLiveEvents";
import {
  isConnectionDegraded, nextBackoff, parseFlagBatch, patchStageIndex,
  scoreboardDisclosure,
} from "./uiLogic";

describe("role-aware live fire UI", () => {
  it("hides unauthorized navigation instead of disabling it", () => {
    expect(visibleNavigation("competitor")).toContain("Attack Console");
    expect(visibleNavigation("competitor")).not.toContain("Round Control");
    expect(visibleNavigation("operator")).toContain("Evidence");
    expect(visibleNavigation("operator")).not.toContain("Attack Console");
    expect(visibleNavigation("observer")).toEqual([
      "Live Overview", "Scoreboard", "Match Timeline", "Service Status", "Major Events",
    ]);
  });

  it("validates and bounds local flag batches", () => {
    const valid = "FLAG{abcdefghijklmnopqrstuvwxyz012345}";
    const result = parseFlagBatch(`${valid}\ninvalid`);
    expect(result).toEqual([{ flag: valid, valid: true }, { flag: "invalid", valid: false }]);
    expect(parseFlagBatch(new Array(30).fill(valid).join(" "))).toHaveLength(20);
  });

  it("deduplicates and orders out-of-order stream events", () => {
    const events = orderAndDedupe([
      { event_id: "old", category: "system", type: "round", result: "ok", timestamp: 1 },
      { event_id: "new", category: "system", type: "round", result: "ok", timestamp: 2 },
      { event_id: "old", category: "system", type: "round", result: "ok", timestamp: 1 },
    ]);
    expect(events.map((event) => event.event_id)).toEqual(["new", "old"]);
  });

  it("uses bounded exponential reconnect and stale state", () => {
    expect(nextBackoff(1000)).toBe(2000);
    expect(nextBackoff(20_000)).toBe(30_000);
    expect(isConnectionDegraded("live", 10_000, 20_000)).toBe(false);
    expect(isConnectionDegraded("live", 1_000, 20_000)).toBe(true);
    expect(isConnectionDegraded("degraded", 20_000, 20_000)).toBe(true);
  });

  it("maps patch pipeline and public scoreboard disclosure", () => {
    expect(patchStageIndex("deployed")).toBe(8);
    expect(patchStageIndex("rollback")).toBe(7);
    expect(scoreboardDisclosure({
      view: "public", delay_rounds: 3, scoreboard: [],
    })).toBe("PUBLIC SCORE — DELAYED BY 3 ROUNDS");
  });
});
