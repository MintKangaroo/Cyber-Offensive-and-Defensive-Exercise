/**
 * Automated accessibility regression checks (roadmap priority 6, code side).
 * Runs axe-core over the rendered EDR views in jsdom (structural checks; color-contrast
 * needs real layout and is left to the manual audit). Complements, not replaces, a
 * manual keyboard/screen-reader review.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, act } from "@testing-library/react";
import axe from "axe-core";
import type { Alert, Host, ProcessNode } from "./api/types";

vi.mock("./api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api/client")>();
  return {
    ...actual,
    fetchHosts: vi.fn().mockResolvedValue([]),
    fetchProcessTree: vi.fn().mockResolvedValue([]),
    fetchAlerts: vi.fn().mockResolvedValue([]),
    isolateHost: vi.fn(),
    unisolateHost: vi.fn(),
    killProcess: vi.fn(),
    useEdrAlertStream: () => ({ connected: true }),
  };
});

import App from "./App";
import { HostList } from "./components/HostList";
import { AlertsPanel } from "./components/AlertsPanel";
import { ProcessTree } from "./components/ProcessTree";

const host: Host = { asset: "power_plant", status: "online", last_seen: 1, process_count: 12, isolated: true };
const alert: Alert = {
  id: "AL1", asset: "power_plant", rule_id: "R", rule_name: "Reverse shell",
  severity: "critical", pid: 42, cmdline: "nc", timestamp: Date.now() / 1000, detail: "uvicorn→sh→nc",
};
const tree: ProcessNode[] = [{
  asset: "power_plant", pid: 1, ppid: 0, name: "uvicorn", cmdline: "uvicorn app",
  create_time: 0, username: "root", connections: "[]",
  children: [{ asset: "power_plant", pid: 42, ppid: 1, name: "nc", cmdline: "nc -e",
    create_time: 0, username: "root", connections: "[]", children: [] }],
}];

async function noViolations(ui: React.ReactElement) {
  let container!: HTMLElement;
  await act(async () => {
    ({ container } = render(ui));
    await new Promise((r) => setTimeout(r, 0));
  });
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

beforeEach(() => vi.clearAllMocks());

describe("EDR accessibility (axe, structural)", () => {
  it("App three-pane shell has no axe violations", () => noViolations(<App />));
  it("Host list (selected + isolated + confirm) has no axe violations", () =>
    noViolations(<HostList hosts={[host]} selectedAsset="power_plant" onSelectAsset={() => {}} onActionDone={() => {}} />));
  it("Alerts panel has no axe violations", () =>
    noViolations(<AlertsPanel alerts={[alert]} onKillDone={() => {}} />));
  it("Process tree has no axe violations", () =>
    noViolations(<ProcessTree tree={tree} flaggedPids={new Set([42])} alertsByPid={new Map([[42, [alert]]])} onSelectPid={() => {}} selectedPid={null} />));
});
