/**
 * Automated accessibility regression checks (roadmap priority 6, code side).
 * Runs axe-core over the Red portal login and the logged-in workbench in jsdom
 * (structural; color-contrast needs real layout and is left to the manual audit).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, act } from "@testing-library/react";
import axe from "axe-core";
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

const session: Session = { access_token: "t", role: "red", team_id: "team01", match_id: "m1" };
const target: AttackTarget = {
  team_id: "team02", team: "Team 02", team_slug: "t2", service_id: "svc", service: "Vulnerable Notes",
  service_slug: "vulnerable-notes", scheme: "http", public_port: 9102,
};
const state: MatchState = { id: "m1", name: "Demo", status: "running", round: 2, server_time: 0, team: { id: "team01", name: "T1" } };
const surface: AttackSurface = { teams: [], services: [], targets: [target], disclosure: "public" };

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  vi.mocked(api.getState).mockResolvedValue(state);
  vi.mocked(api.getAttackSurface).mockResolvedValue(surface);
  vi.mocked(api.getScoreboard).mockResolvedValue({ scoreboard: [] });
});

async function render_and_axe(setup?: () => void) {
  setup?.();
  let container!: HTMLElement;
  await act(async () => {
    ({ container } = render(<App />));
    await new Promise((r) => setTimeout(r, 0));
  });
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

describe("Red portal accessibility (axe, structural)", () => {
  it("login screen has no axe violations", () => render_and_axe());
  it("logged-in guided workbench (two labelled asides) has no axe violations", () =>
    render_and_axe(() => localStorage.setItem("redportal_ad_session", JSON.stringify(session))));
});
