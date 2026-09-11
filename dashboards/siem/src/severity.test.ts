import { describe, it, expect } from "vitest";
import {
  SEVERITY_LABEL,
  parseMitre,
  relativeTime,
  severityLabel,
  severityTone,
} from "./severity";

describe("severity mapping preserves detection semantics", () => {
  it("keeps the exact 5-level labels", () => {
    expect(SEVERITY_LABEL).toEqual({
      0: "INFO",
      1: "LOW",
      2: "MEDIUM",
      3: "HIGH",
      4: "CRITICAL",
    });
    expect(severityLabel(4)).toBe("CRITICAL");
    expect(severityLabel(99)).toBe("99"); // unknown falls back to the number
  });

  it("maps each numeric level to a distinct design-system tone", () => {
    const tones = [0, 1, 2, 3, 4].map(severityTone);
    expect(tones).toEqual([
      "neutral",
      "operational",
      "intelligence",
      "warning",
      "critical",
    ]);
    expect(new Set(tones).size).toBe(5); // all distinguishable
    expect(severityTone(7)).toBe("neutral"); // unknown → neutral, never crashes
  });
});

describe("relativeTime (Korean units, never negative)", () => {
  it("formats seconds, minutes and hours", () => {
    expect(relativeTime(5)).toBe("5초 전");
    expect(relativeTime(125)).toBe("2분 전");
    expect(relativeTime(7200)).toBe("2시간 전");
  });
  it("clamps negatives to zero", () => {
    expect(relativeTime(-10)).toBe("0초 전");
  });
});

describe("parseMitre defensively reads the JSON string field", () => {
  it("parses a JSON array", () => {
    expect(parseMitre('["T1190","T1059"]')).toEqual(["T1190", "T1059"]);
  });
  it("returns [] for invalid or non-array JSON", () => {
    expect(parseMitre("not json")).toEqual([]);
    expect(parseMitre('{"a":1}')).toEqual([]);
    expect(parseMitre("")).toEqual([]);
  });
});
