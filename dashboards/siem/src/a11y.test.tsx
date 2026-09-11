/**
 * Automated accessibility regression checks (roadmap priority 6, code side).
 * Runs axe-core over the rendered SIEM views in jsdom. This complements — does not
 * replace — a manual keyboard/screen-reader audit; color-contrast (which needs real
 * layout) is left to the manual pass and disabled here.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, act } from "@testing-library/react";
import axe from "axe-core";

vi.mock("./api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api/client")>();
  return {
    ...actual,
    search: vi.fn().mockResolvedValue({ total: 0, returned: 0, events: [] }),
    fetchAlerts: vi.fn().mockResolvedValue({
      alerts: [{
        id: "A1", rule_id: "R1", title: "Unauthorized write", severity: 4,
        mitre: '["T0836"]', status: "open", timestamp: Date.now() / 1000 - 10,
        detail: "power_plant", matched_event: "E1",
      }],
    }),
    updateAlertStatus: vi.fn(),
    fetchSourceHealth: vi.fn().mockResolvedValue({
      sources: { suricata: { last_seen: 1, lines_ingested: 5, parse_errors: 0, status: "green", seconds_since_last: 3 } },
    }),
    fetchAttackCoverage: vi.fn().mockResolvedValue({ technique_coverage: { T1190: ["r1"] }, total_rules: 9 }),
    useAlertStream: () => ({ connected: true }),
  };
});

import App from "./App";
import { AlertsView } from "./components/Alerts/AlertsView";
import { AttackCoverageView } from "./components/AttackCoverage/AttackCoverageView";
import { SourceHealth } from "./components/SourceHealth/SourceHealth";

async function noViolations(ui: React.ReactElement) {
  let container!: HTMLElement;
  await act(async () => {
    ({ container } = render(ui));
    await new Promise((r) => setTimeout(r, 0)); // let polling resolve
  });
  const results = await axe.run(container, {
    rules: { "color-contrast": { enabled: false } },
  });
  const summary = results.violations.map((v) => `${v.id}: ${v.help}`);
  expect(summary).toEqual([]);
}

beforeEach(() => vi.clearAllMocks());

describe("SIEM accessibility (axe, structural)", () => {
  it("App shell + Discover has no axe violations", () => noViolations(<App />));
  it("Alerts view has no axe violations", () => noViolations(<AlertsView />));
  it("Coverage view has no axe violations", () => noViolations(<AttackCoverageView />));
  it("Source health has no axe violations", () => noViolations(<SourceHealth />));
});
