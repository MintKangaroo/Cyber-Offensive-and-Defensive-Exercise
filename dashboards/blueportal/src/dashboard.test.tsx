import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
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

const challenge = (over: Partial<BlueChallenge> = {}): BlueChallenge => ({
  id: "DET-001",
  category: "detection",
  difficulty: "hard",
  title: "Detect Modbus write flood",
  points_blue: 100,
  mitre: ["T0836"],
  goal: "Write a rule that flags the attack",
  success_criteria: "Match attack, ignore normal",
  description: "power_plant setpoint tampering",
  solved: false,
  ...over,
});

const events: RangeEvent[] = [
  { event_id: "e1", event_type: "asset_compromised", timestamp: 1, actor: "red", team_id: "red_a", target_asset: "power_plant", vuln_id: "PP-006" },
];
const patches: Patches = { power_plant: { "PP-006": false } };
const scoreboard: ScoreRow[] = [{ team_id: "blue_alpha", solved: 1, points: 100, last_solve: 1 }];

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  vi.mocked(api.fetchBlueChallenges).mockResolvedValue({ challenges: [challenge()], count: 1 });
  vi.mocked(api.fetchBlueScoreboard).mockResolvedValue({ scoreboard });
  vi.mocked(api.fetchTeams).mockResolvedValue({ teams: [] });
  vi.mocked(api.fetchEvents).mockResolvedValue({ events });
  vi.mocked(api.fetchPatches).mockResolvedValue(patches);
});

describe("Blue portal — defensive workflows preserved", () => {
  it("renders the incident feed with a translated attack label", async () => {
    render(<App />);
    await screen.findByText("자산 침해"); // asset_compromised label
    // attack event carries the critical tone class
    expect(document.querySelector(".bp-event.cr-tone-critical")).toBeTruthy();
  });

  it("toggles a patch with the audit reason", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /패치 보드/ }));
    const patchBtn = await screen.findByRole("button", { name: "patch" });
    fireEvent.click(patchBtn);
    await waitFor(() =>
      expect(api.togglePatch).toHaveBeenCalledWith(
        "power_plant",
        "PP-006",
        true,
        "blue portal patch",
      ),
    );
  });

  it("opens a detection challenge and submits a Sigma rule", async () => {
    vi.mocked(api.submitRule).mockResolvedValue({
      passed: true,
      points_awarded: 100,
      already_solved: false,
      detail: "matched attack, no false positives",
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /탐지 챌린지/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Detect Modbus write flood/ }));

    const editor = await screen.findByLabelText("탐지 규칙 YAML");
    expect(editor).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "규칙 제출" }));
    await waitFor(() =>
      expect(api.submitRule).toHaveBeenCalledWith("DET-001", "blue_alpha", expect.any(String)),
    );
    await screen.findByText(/정답! \+100pt/);
  });
});
