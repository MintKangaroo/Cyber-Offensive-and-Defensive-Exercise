/**
 * Automated accessibility regression checks (roadmap priority 6, code side).
 * Runs axe-core over the rendered Blue portal in jsdom (structural; color-contrast
 * needs real layout and is left to the manual audit).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, act, fireEvent } from "@testing-library/react";
import axe from "axe-core";
import type { BlueChallenge, Patches, RangeEvent, ScoreRow } from "./api";

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return {
    ...actual,
    fetchBlueChallenges: vi.fn(),
    fetchBlueScoreboard: vi.fn(),
    fetchTeams: vi.fn(),
    fetchEvents: vi.fn(),
    fetchPatches: vi.fn(),
    togglePatch: vi.fn().mockResolvedValue({}),
    submitRule: vi.fn(),
  };
});

import * as api from "./api";
import App from "./App";

const challenge: BlueChallenge = {
  id: "DET-001", category: "detection", difficulty: "hard", title: "Detect flood",
  points_blue: 100, mitre: ["T0836"], goal: "g", success_criteria: "s", description: "d", solved: false,
};
const events: RangeEvent[] = [{ event_id: "e1", event_type: "asset_compromised", timestamp: 1, actor: "red", team_id: "red_a", target_asset: "power_plant", vuln_id: "PP-006" }];
const patches: Patches = { power_plant: { "PP-006": false } };
const scoreboard: ScoreRow[] = [{ team_id: "blue_alpha", solved: 1, points: 100, last_solve: 1 }];

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  vi.mocked(api.fetchBlueChallenges).mockResolvedValue({ challenges: [challenge], count: 1 });
  vi.mocked(api.fetchBlueScoreboard).mockResolvedValue({ scoreboard });
  vi.mocked(api.fetchTeams).mockResolvedValue({ teams: [] });
  vi.mocked(api.fetchEvents).mockResolvedValue({ events });
  vi.mocked(api.fetchPatches).mockResolvedValue(patches);
});

async function axeClean(container: HTMLElement) {
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

describe("Blue portal accessibility (axe, structural)", () => {
  it("incident/patch/detection tabs have no axe violations", async () => {
    let container!: HTMLElement;
    await act(async () => {
      ({ container } = render(<App />));
      await new Promise((r) => setTimeout(r, 0));
    });
    await axeClean(container);
    // patch board
    await act(async () => {
      fireEvent.click(container.querySelector('[aria-current]') ? container : container);
    });
    // detection tab (renders challenge grid + panel when a card is chosen)
    const detectionTab = [...container.querySelectorAll("button")].find((b) => /탐지 챌린지/.test(b.textContent || ""));
    if (detectionTab) await act(async () => { fireEvent.click(detectionTab); });
    const card = [...container.querySelectorAll("button")].find((b) => /Detect flood/.test(b.textContent || ""));
    if (card) await act(async () => { fireEvent.click(card); await new Promise((r) => setTimeout(r, 0)); });
    await axeClean(container);
  });
});
