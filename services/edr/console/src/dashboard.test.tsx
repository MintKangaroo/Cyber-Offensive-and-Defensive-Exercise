import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import type { Alert, Host, ProcessNode } from "./api/types";

vi.mock("./api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api/client")>();
  return {
    ...actual,
    isolateHost: vi.fn().mockResolvedValue(undefined),
    unisolateHost: vi.fn().mockResolvedValue(undefined),
    killProcess: vi
      .fn()
      .mockResolvedValue({ command_id: "cmd12345678", warning: null }),
  };
});

import * as client from "./api/client";
import { HostList } from "./components/HostList";
import { AlertsPanel } from "./components/AlertsPanel";
import { ProcessTree } from "./components/ProcessTree";

const host = (over: Partial<Host> = {}): Host => ({
  asset: "power_plant",
  status: "online",
  last_seen: 1,
  process_count: 12,
  isolated: false,
  ...over,
});

const alert = (over: Partial<Alert> = {}): Alert => ({
  id: "AL1",
  asset: "power_plant",
  rule_id: "EDR-REVSHELL",
  rule_name: "Reverse shell spawned",
  severity: "critical",
  pid: 4242,
  cmdline: "nc -e /bin/sh",
  timestamp: Date.now() / 1000 - 10,
  detail: "uvicorn → sh → nc",
  ...over,
});

beforeEach(() => vi.clearAllMocks());

describe("HostList — containment requires a reason and calls the API", () => {
  it("isolates a host through the confirm flow", async () => {
    render(
      <HostList
        hosts={[host()]}
        selectedAsset="power_plant"
        onSelectAsset={() => {}}
        onActionDone={() => {}}
      />,
    );
    // Korean asset label is shown
    expect(screen.getByText("발전소 / SCADA")).toBeInTheDocument();
    // online host → healthy dot
    expect(document.querySelector(".edr-dot.cr-tone-healthy")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /호스트 격리/ }));
    const confirm = screen.getByRole("button", { name: "격리 확인" });
    expect(confirm).toBeDisabled(); // reason required
    fireEvent.change(screen.getByLabelText("격리 사유"), {
      target: { value: "lateral movement observed" },
    });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(client.isolateHost).toHaveBeenCalledWith(
        "power_plant",
        "lateral movement observed",
      ),
    );
  });

  it("shows the isolated badge and offers release", () => {
    render(
      <HostList
        hosts={[host({ isolated: true })]}
        selectedAsset="power_plant"
        onSelectAsset={() => {}}
        onActionDone={() => {}}
      />,
    );
    expect(screen.getByText("isolated")).toBeInTheDocument();
    expect(document.querySelector(".edr-dot.cr-tone-critical")).toBeTruthy();
    expect(
      screen.getByRole("button", { name: /격리 해제/ }),
    ).toBeInTheDocument();
  });
});

describe("AlertsPanel — kill process requires a reason", () => {
  it("kills a flagged process through the confirm flow", async () => {
    render(<AlertsPanel alerts={[alert()]} onKillDone={() => {}} />);
    // critical severity tone class on the card
    expect(document.querySelector(".edr-alert.cr-tone-critical")).toBeTruthy();
    expect(screen.getByText("Reverse shell spawned")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Kill Process \(pid 4242\)/ }));
    const confirm = screen.getByRole("button", { name: "Kill Process 확인" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText("프로세스 종료 사유"), {
      target: { value: "contain reverse shell" },
    });
    fireEvent.click(confirm);
    await waitFor(() =>
      expect(client.killProcess).toHaveBeenCalledWith(
        "power_plant",
        4242,
        "contain reverse shell",
      ),
    );
    await screen.findByText(/에이전트가 다음 폴링 주기에 실행/);
  });

  it("renders the empty state when there are no detections", () => {
    render(<AlertsPanel alerts={[]} onKillDone={() => {}} />);
    expect(screen.getByText("탐지된 알림 없음")).toBeInTheDocument();
  });
});

describe("ProcessTree — hierarchy and critical highlighting preserved", () => {
  const tree: ProcessNode[] = [
    {
      asset: "power_plant",
      pid: 1,
      ppid: 0,
      name: "uvicorn",
      cmdline: "uvicorn app:main",
      create_time: 0,
      username: "root",
      connections: "[]",
      children: [
        {
          asset: "power_plant",
          pid: 4242,
          ppid: 1,
          name: "nc",
          cmdline: "nc -e /bin/sh",
          create_time: 0,
          username: "root",
          connections: "[]",
          children: [],
        },
      ],
    },
  ];

  it("marks a critical-flagged process and renders the tree branch", () => {
    render(
      <ProcessTree
        tree={tree}
        flaggedPids={new Set([4242])}
        alertsByPid={new Map([[4242, [alert()]]])}
        onSelectPid={() => {}}
        selectedPid={null}
      />,
    );
    expect(screen.getByText("uvicorn")).toBeInTheDocument();
    const nc = screen.getByText("nc");
    expect(nc.className).toContain("edr-critical");
    expect(screen.getByText("flagged")).toBeInTheDocument();
    // pstree connector rendered for the child
    expect(screen.getByText(/└─|├─/)).toBeInTheDocument();
  });

  it("renders the empty state without a snapshot", () => {
    render(
      <ProcessTree
        tree={[]}
        flaggedPids={new Set()}
        alertsByPid={new Map()}
        onSelectPid={() => {}}
        selectedPid={null}
      />,
    );
    expect(screen.getByText("프로세스 정보 없음")).toBeInTheDocument();
  });
});
