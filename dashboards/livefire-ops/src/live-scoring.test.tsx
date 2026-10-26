import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act, fireEvent } from "@testing-library/react";

// scores 토픽의 red/blue 듀얼리티(라이브 스코어보드·Solve Log)를 App 핸들러 수준에서 고정한다.
//  백엔드(scoring_engine)의 blue 가점 분기와 event_collector 의 scores 발행은
//  test_scoring_engine / test_scores_publish 가 보장한다. 여기서 닫는 갭은 프런트 배선:
//  "scores 프레임 actor!=='red' → DEFENSE 누적 + Solve Log 의 '방어' 측 항목".
//  이 라우팅이 끊기면 패치/탐지/복구(asset_recovered) 가 defense 열을 못 올린다(방어 라이브 E2E 로 실증).
const h = vi.hoisted(() => ({ onEvent: null as null | ((e: Record<string, unknown>) => void) }));

vi.mock("./api", () => ({
  fetchPowerTelemetry: vi.fn().mockResolvedValue(null),
  fetchSectorTelemetry: vi.fn().mockResolvedValue(null),
  powerRegistersFromTelemetry: vi.fn(),
  registersFromSectorTelemetry: vi.fn(),
  sectorFootLine: vi.fn(),
  fmtClock: (s: number) => String(s),
  executeStep: vi.fn().mockResolvedValue({ ok: true, live: false }),
  subscribeStream: (onEvent: (e: Record<string, unknown>) => void) => {
    h.onEvent = onEvent;      // 콘솔이 SSE 구독 시 등록하는 onEvent 를 포획
    return () => {};
  },
}));

import App from "./App";

const score = (actor: string, category: string, points: number) =>
  ({ topic: "scores", team_id: "default", actor, category, points });

async function renderApp() {
  await act(async () => {
    render(<App />);
    await new Promise((r) => setTimeout(r, 0));
  });
}

async function emit(e: Record<string, unknown>) {
  await act(async () => {
    h.onEvent!(e);
    await new Promise((r) => setTimeout(r, 0));
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  h.onEvent = null;
});

describe("라이브 채점 red/blue 듀얼리티 (scores 토픽)", () => {
  it("blue scores 프레임이 DEFENSE 열을, red 가 ATTACK 열을 올린다(콘솔 상단·리더보드)", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /발전소 SIS/ }));
    });
    expect(h.onEvent).toBeTruthy(); // 구독 등록 확인

    // red 공격 +100(objective), blue 방어 50(patch)+50(asset_recovered) = defense 100
    await emit(score("red", "objective", 100));
    await emit(score("blue", "patch_verified", 50));
    await emit(score("blue", "asset_recovered", 50));

    const atk = screen.getByText("Attack").parentElement!;
    const def = screen.getByText("Defense").parentElement!;
    expect(atk).toHaveTextContent("100");
    expect(def).toHaveTextContent("100");   // 과거엔 정적 60, 이제 라이브 blue 누적
    // 리더보드 me-row 가 상단 stat 과 동일한 atk/def 를 든다(각각 2곳 이상 등장)
    expect(screen.getAllByText("100").length).toBeGreaterThanOrEqual(2);
  });

  it("blue 는 Solve Log 에 '방어' 측, red 는 '공격' 측 항목으로 뜬다(아레나)", async () => {
    await renderApp(); // 아레나 뷰에서 시작
    expect(h.onEvent).toBeTruthy();

    await emit(score("red", "initial_access", 20));
    await emit(score("blue", "patch_verified", 50));

    // Solve Log 항목 텍스트(`<category> · +<pts>`)와 측(공격/방어) 라벨
    expect(screen.getByText(/patch_verified · \+50/)).toBeInTheDocument();
    expect(screen.getByText(/initial_access · \+20/)).toBeInTheDocument();
    expect(screen.getAllByText("방어").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("공격").length).toBeGreaterThanOrEqual(1);
  });

  it("blue 만 들어오면 ATTACK 0 · DEFENSE 가 오른다(duality 혼선 없음)", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /발전소 SIS/ }));
    });
    await emit(score("blue", "block_success", 30));

    const atk = screen.getByText("Attack").parentElement!;
    const def = screen.getByText("Defense").parentElement!;
    expect(def).toHaveTextContent("30");
    expect(atk).toHaveTextContent("0");   // blue 는 attack 에 새지 않는다
  });
});
