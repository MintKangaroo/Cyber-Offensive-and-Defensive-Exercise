import { describe, it, expect } from "vitest";
import { relativeTime, severityTone } from "./severity";
import type { Severity } from "./api/types";

describe("severityTone maps 5 levels to distinct design-system tones", () => {
  it("keeps every level distinguishable", () => {
    const levels: Severity[] = ["critical", "high", "medium", "low", "info"];
    const tones = levels.map(severityTone);
    expect(tones).toEqual([
      "critical",
      "warning",
      "intelligence",
      "operational",
      "neutral",
    ]);
    expect(new Set(tones).size).toBe(5);
  });
});

describe("relativeTime (Korean units, never negative)", () => {
  it("formats and clamps", () => {
    expect(relativeTime(5)).toBe("5초 전");
    expect(relativeTime(90)).toBe("1분 전");
    expect(relativeTime(3600)).toBe("1시간 전");
    expect(relativeTime(-4)).toBe("0초 전");
  });
});
