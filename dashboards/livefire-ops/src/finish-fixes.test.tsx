import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act, fireEvent } from "@testing-library/react";
import { ARENA_NODES } from "./data";

// 네트워크(트윈 폴링/SSE) 비활성 — 정적(DEMO) 상태로 마감 결함 회귀를 검증.
vi.mock("./api", () => ({
  fetchPowerTelemetry: vi.fn().mockResolvedValue(null),
  fetchSectorTelemetry: vi.fn().mockResolvedValue(null),
  powerRegistersFromTelemetry: vi.fn(),
  registersFromSectorTelemetry: vi.fn(),
  sectorFootLine: vi.fn(),
  fmtClock: (s: number) => String(s),
  executeStep: vi.fn().mockResolvedValue({ ok: true, live: false }),
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

describe("마감 결함 회귀 (finish-reviewer)", () => {
  // 결함2: 상단 stat Attack/Defense 가 리더보드 me-row(150/60)와 어긋나던 문제(과거 0/40).
  it("콘솔 상단 Attack/Defense 가 리더보드 me-row 와 같은 값(DEMO)", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /발전소 SIS/ }));
    });
    const atkStat = screen.getByText("Attack").parentElement!;
    const defStat = screen.getByText("Defense").parentElement!;
    // 과거 모순값(0/40)이 아니라 리더보드 me-row 와 동일(150/60)
    expect(atkStat).toHaveTextContent("150");
    expect(defStat).toHaveTextContent("60");
    expect(atkStat).not.toHaveTextContent(/Attack0\b/);
    // 리더보드에도 같은 값이 떠서 상단 stat 과 1:1 일치(각각 2곳 이상 등장)
    expect(screen.getAllByText("150").length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("60").length).toBeGreaterThanOrEqual(2);
  });

  // 결함3: 아레나 노드가 좌/우 HUD 오버레이(타이머·스코어보드·Solve Log) 뒤에 가려지던 문제.
  //  Solve Log 패널이 우측(right:22px,width:300px)을 덮어 xPct>~77% 노드는 데스크톱에서 미도달.
  it("모든 아레나 시설 노드가 HUD 오버레이 열(좌<18%·우>76%) 밖에 위치", () => {
    for (const n of ARENA_NODES) {
      expect(n.xPct, `${n.id}(${n.label}) xPct=${n.xPct} 가 HUD 열과 겹침`).toBeGreaterThanOrEqual(18);
      expect(n.xPct, `${n.id}(${n.label}) xPct=${n.xPct} 가 Solve Log 패널과 겹침`).toBeLessThanOrEqual(76);
    }
    // 헤더 TARGETS 카운트와 실제 노드 수가 일치(도달 불가 노드 없음)
    expect(ARENA_NODES.length).toBe(18);
  });

  // 결함1: 아레나 오버레이 헤더의 ⟡(U+27E1)가 폰트에 없어 tofu 박스로 렌더되던 문제.
  it("아레나 헤더에 tofu 글리프(⟡)가 없고 브래킷 HUD 로 표기", async () => {
    await renderApp();
    expect(document.body.textContent ?? "").not.toContain("⟡");
    expect(screen.getByText(/LIVE FIRE CLOCK/)).toBeInTheDocument();
    expect(screen.getByText(/SOLVE LOG/)).toBeInTheDocument();
  });
});
