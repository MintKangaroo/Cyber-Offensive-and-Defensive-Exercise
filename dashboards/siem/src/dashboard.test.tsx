import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { Alert } from "./api/types";

// Mock only the network layer; keep the real usePolling hook so the tests
// exercise the actual data flow. useAlertStream is stubbed (no WebSocket in jsdom).
vi.mock("./api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api/client")>();
  return {
    ...actual,
    search: vi.fn(),
    fetchAlerts: vi.fn(),
    updateAlertStatus: vi.fn().mockResolvedValue(undefined),
    fetchSourceHealth: vi.fn(),
    fetchAttackCoverage: vi.fn(),
    useAlertStream: () => ({ connected: true }),
  };
});

import * as client from "./api/client";
import { AlertsView } from "./components/Alerts/AlertsView";
import { Discover } from "./components/Discover/Discover";
import { AttackCoverageView } from "./components/AttackCoverage/AttackCoverageView";
import { SourceHealth } from "./components/SourceHealth/SourceHealth";

const alert = (over: Partial<Alert> = {}): Alert => ({
  id: "A1",
  rule_id: "ICS-MODBUS-WRITE",
  title: "Unauthorized setpoint write",
  severity: 4,
  mitre: '["T0836"]',
  status: "open",
  timestamp: Date.now() / 1000 - 30,
  detail: "power_plant register 40001",
  matched_event: "E1",
  ...over,
});

beforeEach(() => vi.clearAllMocks());

describe("AlertsView — detection lifecycle preserved", () => {
  it("shows the open count and acks/closes through the status API", async () => {
    vi.mocked(client.fetchAlerts).mockResolvedValue({ alerts: [alert()] });
    render(<AlertsView />);

    await screen.findByText("Unauthorized setpoint write");
    expect(screen.getByText("1 open")).toBeInTheDocument();
    // CRITICAL severity chip carries the critical tone class.
    expect(document.querySelector(".siem-sev.cr-tone-critical")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "확인" }));
    await waitFor(() =>
      expect(client.updateAlertStatus).toHaveBeenCalledWith("A1", "ack"),
    );
  });

  it("hides the ack button once acknowledged", async () => {
    vi.mocked(client.fetchAlerts).mockResolvedValue({
      alerts: [alert({ id: "A2", status: "ack" })],
    });
    render(<AlertsView />);
    await screen.findByText("Unauthorized setpoint write");
    expect(screen.queryByRole("button", { name: "확인" })).toBeNull();
    expect(screen.getByRole("button", { name: "종결" })).toBeInTheDocument();
  });

  it("hides the close button and dims the row once closed", async () => {
    vi.mocked(client.fetchAlerts).mockResolvedValue({
      alerts: [alert({ id: "A3", status: "closed" })],
    });
    render(<AlertsView />);
    await screen.findByText("Unauthorized setpoint write");
    expect(screen.queryByRole("button", { name: "종결" })).toBeNull();
    expect(document.querySelector(".siem-alert")).toHaveStyle({ opacity: "0.5" });
  });

  it("renders the empty state when there are no detections", async () => {
    vi.mocked(client.fetchAlerts).mockResolvedValue({ alerts: [] });
    render(<AlertsView />);
    await screen.findByText("탐지된 알림 없음");
  });
});

describe("Discover — search filters preserved", () => {
  it("sends the selected severity threshold and limit", async () => {
    vi.mocked(client.search).mockResolvedValue({
      total: 1,
      returned: 1,
      events: [
        {
          event_id: "E1",
          timestamp: "2026-09-11T00:00:00Z",
          ingested_at: "",
          source_type: "suricata",
          source_ip: null,
          host: null,
          asset: "power_plant",
          severity: 3,
          category: "ids",
          action: null,
          src: null,
          dst: null,
          signature: null,
          mitre: ["T1190"],
          trace_id: null,
          vuln_id: null,
          team_id: null,
          message: "ET EXPLOIT attempt",
          tags: [],
        },
      ],
    });
    render(<Discover />);
    // initial empty state
    expect(screen.getByText("검색 결과 없음")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("전문 검색어"), {
      target: { value: "exploit" },
    });
    fireEvent.change(screen.getByLabelText("심각도 필터"), {
      target: { value: "3" },
    });
    fireEvent.click(screen.getByRole("button", { name: "검색" }));

    await screen.findByText("ET EXPLOIT attempt");
    expect(client.search).toHaveBeenCalledWith({
      text: "exploit",
      source_type: undefined,
      severity_min: 3,
      limit: 200,
    });
    // HIGH severity chip
    expect(document.querySelector(".siem-sev.cr-tone-warning")).toBeTruthy();
  });
});

describe("AttackCoverageView — coverage counts preserved", () => {
  it("shows rule counts per technique and total rules", async () => {
    vi.mocked(client.fetchAttackCoverage).mockResolvedValue({
      technique_coverage: { T1190: ["r1", "r2"], T0836: ["r3"] },
      total_rules: 9,
    });
    render(<AttackCoverageView />);
    await screen.findByText("T1190");
    expect(screen.getByText("2개 규칙")).toBeInTheDocument();
    expect(screen.getByText("1개 규칙")).toBeInTheDocument();
    expect(screen.getByText("9 rules loaded")).toBeInTheDocument();
  });
});

describe("SourceHealth — status semantics preserved", () => {
  it("marks green sources healthy and red sources critical", async () => {
    vi.mocked(client.fetchSourceHealth).mockResolvedValue({
      sources: {
        suricata: {
          last_seen: 1,
          lines_ingested: 10,
          parse_errors: 0,
          status: "green",
          seconds_since_last: 5,
        },
        zeek: {
          last_seen: null,
          lines_ingested: 0,
          parse_errors: 2,
          status: "red",
          seconds_since_last: null,
        },
      },
    });
    render(<SourceHealth />);
    await screen.findByText("suricata");
    expect(document.querySelector(".siem-dot.cr-tone-healthy")).toBeTruthy();
    expect(document.querySelector(".siem-dot.cr-tone-critical")).toBeTruthy();
    expect(screen.getByText("없음")).toBeInTheDocument(); // null seconds
  });
});
