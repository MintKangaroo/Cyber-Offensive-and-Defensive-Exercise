import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act, fireEvent } from "@testing-library/react";

// 네트워크(트윈 폴링/SSE)는 테스트에서 비활성 — 정적 데이터로 검증.
vi.mock("./api", () => ({
  fetchPowerTelemetry: vi.fn().mockResolvedValue(null),
  powerRegistersFromTelemetry: vi.fn(),
  executeStrike: vi.fn().mockResolvedValue(false),
  subscribeStream: vi.fn().mockReturnValue(() => {}),
}));

import App from "./App";

async function renderApp() {
  await act(async () => {
    render(<App />);
    await new Promise((r) => setTimeout(r, 0));
  });
}

beforeEach(() => vi.clearAllMocks());

describe("Live-Fire Ops console", () => {
  it("현황 아레나가 먼저 뜨고 타이머·시설 노드가 보인다", async () => {
    await renderApp();
    expect(screen.getByText(/국가 기반시설 공방 현황/)).toBeInTheDocument();
    expect(screen.getByText("Time Remaining")).toBeInTheDocument();
    expect(screen.getByText("Next Attack")).toBeInTheDocument();
    // 발전소 SIS 활성 타깃 노드
    expect(screen.getByRole("button", { name: /발전소 SIS/ })).toBeInTheDocument();
  });

  it("시설 노드를 누르면 그 시설 작전 콘솔로 드릴다운된다(발전소)", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /발전소 SIS/ }));
    });
    expect(screen.getByText(/THERMAL POWER PLANT/)).toBeInTheDocument();
    expect(screen.getByText("OT STRIKE MAP · 침투 작전도")).toBeInTheDocument();
    // 발전소 단선도 + 레지스터
    expect(screen.getByText(/발전 계통 단선도/)).toBeInTheDocument();
    expect(screen.getByText("TURBINE_RPM (cmd)")).toBeInTheDocument();
  });

  it("시설별로 스키매틱/자산이 바뀐다(병원 선택 시 환자 바이탈)", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /발전소 SIS/ }));
    });
    // 좌측 섹터 셀렉터에서 병원 선택
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /병원\s+PROBED/ }));
    });
    expect(screen.getByText(/HOSPITAL OT/)).toBeInTheDocument();
    expect(screen.getByText(/환자 안전 계통/)).toBeInTheDocument();
    expect(screen.getByText(/INFUSION_RATE/)).toBeInTheDocument();
  });
});
