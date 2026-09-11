import { describe, it, expect } from "vitest";
import { difficultyTone, eventLabel, eventTone, isActiveIncident } from "./helpers";

describe("difficultyTone maps each level to a distinct tone", () => {
  it("covers easy/medium/hard/insane", () => {
    const tones = ["easy", "medium", "hard", "insane"].map(difficultyTone);
    expect(tones).toEqual(["healthy", "warning", "critical", "intelligence"]);
    expect(new Set(tones).size).toBe(4);
    expect(difficultyTone("weird")).toBe("neutral");
  });
});

describe("eventTone classifies attack vs defensive events", () => {
  it("reds attacks, greens defenses, neutrals the rest", () => {
    expect(eventTone("asset_compromised")).toBe("critical");
    expect(eventTone("flag_exfiltrated")).toBe("critical");
    expect(eventTone("red_objective_success")).toBe("critical");
    expect(eventTone("blue_detection_success")).toBe("healthy");
    expect(eventTone("asset_recovered")).toBe("healthy");
    expect(eventTone("blue_patch_verified")).toBe("healthy");
    expect(eventTone("stage_completed")).toBe("neutral");
  });
});

describe("isActiveIncident counts in-progress attacks", () => {
  it("matches compromise/attack/exfil only", () => {
    expect(isActiveIncident("red_attack_started")).toBe(true);
    expect(isActiveIncident("asset_compromised")).toBe(true);
    expect(isActiveIncident("flag_exfiltrated")).toBe(true);
    expect(isActiveIncident("blue_detection_success")).toBe(false);
    expect(isActiveIncident("stage_completed")).toBe(false);
  });
});

describe("eventLabel keeps the Korean labels with a fallback", () => {
  it("translates known types and passes through unknown", () => {
    expect(eventLabel("red_attack_started")).toBe("공격 개시");
    expect(eventLabel("blue_detection_success")).toBe("탐지 성공");
    expect(eventLabel("mystery_event")).toBe("mystery_event");
  });
});
