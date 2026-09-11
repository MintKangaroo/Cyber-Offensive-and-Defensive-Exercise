import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { AttackSurface, AttackTarget, MatchState, Session } from "./api";

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return {
    ...actual,
    login: vi.fn(),
    getState: vi.fn(),
    getAttackSurface: vi.fn(),
    getScoreboard: vi.fn(),
    sendTargetRequest: vi.fn(),
    submitCapturedFlag: vi.fn(),
  };
});

import * as api from "./api";
import App from "./App";
import { GuidedMode } from "./GuidedMode";

const session: Session = { access_token: "tok", role: "red", team_id: "team01", match_id: "m1" };
const target: AttackTarget = {
  team_id: "team02", team: "Team 02", team_slug: "team-02",
  service_id: "svc-notes", service: "Vulnerable Notes", service_slug: "vulnerable-notes",
  scheme: "http", public_port: 9102,
};
const state: MatchState = {
  id: "m1", name: "Demo Match", status: "running", round: 3, server_time: 0,
  team: { id: "team01", name: "Team 01" },
};
const surface: AttackSurface = {
  teams: [], services: [], targets: [target], disclosure: "public",
};

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  vi.mocked(api.getState).mockResolvedValue(state);
  vi.mocked(api.getAttackSurface).mockResolvedValue(surface);
  vi.mocked(api.getScoreboard).mockResolvedValue({ scoreboard: [] });
});

describe("Red portal login gate", () => {
  it("logs in and validates the A/D participant session", async () => {
    vi.mocked(api.login).mockResolvedValue(session);
    render(<App />);
    expect(screen.getByRole("heading", { name: "Red Operations Login" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "ENTER ATTACK PLANE" }));
    await waitFor(() => expect(api.login).toHaveBeenCalled());
    // after login the attack plane header appears
    await screen.findByText("RED OPERATIONS");
  });
});

describe("Red portal mode toggle (beginner vs advanced workbench)", () => {
  it("switches from guided mode to the raw request workbench", async () => {
    localStorage.setItem("redportal_ad_session", JSON.stringify(session));
    render(<App />);
    // beginner is default → guided mode present, no raw request form
    await screen.findByText("RED OPERATIONS");
    expect(screen.queryByRole("button", { name: "SEND TO LIVE SERVICE" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "고급(워크벤치)" }));
    // advanced → workbench send button + flag submission appear
    await screen.findByRole("button", { name: "SEND TO LIVE SERVICE" });
    expect(screen.getByRole("button", { name: "SUBMIT TO GAME ENGINE" })).toBeInTheDocument();
    // hidden-information framing preserved
    expect(screen.getByText("AUTHORIZED TARGETS")).toBeInTheDocument();
  });
});

describe("GuidedMode runs real requests step by step", () => {
  it("registers via the live target on the first step", async () => {
    vi.mocked(api.sendTargetRequest).mockResolvedValue({
      status: 200, elapsed_ms: 12, headers: "", body: '{"ok":true}',
    });
    render(<GuidedMode target={target} session={session} onFlagAccepted={() => {}} />);
    // first step action button (mission-defined) is present
    const stepButton = await screen.findByRole("button", { name: /계정 생성 \(Register\)/ });
    fireEvent.click(stepButton);
    await waitFor(() =>
      expect(api.sendTargetRequest).toHaveBeenCalledWith(
        target, "POST", "/api/register", "", expect.any(String),
      ),
    );
  });
});
