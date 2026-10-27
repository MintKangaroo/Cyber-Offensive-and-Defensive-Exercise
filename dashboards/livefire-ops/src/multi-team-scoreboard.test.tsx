import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act, fireEvent, within } from "@testing-library/react";

// 다팀(멀티 team_id) 스코어보드 라이브 회귀 — App 렌더 수준.
//  백엔드(scoring_engine)가 team_id 별로 점수를 분리하고 event_collector 가 team_id 를 실은 scores
//  프레임을 발행함은 2026-10-27 라이브로 실증: POST 2팀 → /scores {TEAM-02:{red:100}, default:{red:30,
//  blue:50}} · /scores/ranking [TEAM-02 100, default 80] · SSE 프레임이 팀별 team_id 분리.
//  buildScoreboard 의 순수 정렬은 scoreboard.test.tsx 가 고정한다. 여기서 닫는 갭은 "라이브 SSE 가
//  서로 다른 team_id 프레임을 흘릴 때 App 이 (1) 각 팀을 별 행으로 누적·랭크하고 (2) 다른 팀이
//  총점에서 앞서도 우리 팀(me) 행과 시설 상단 stat 이 그 팀 점수에 납치되지 않는지"다 —
//  live-scoring.test.tsx 는 team_id='default' 단일 팀만 봤다.
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
    h.onEvent = onEvent;
    return () => {};
  },
}));

import App from "./App";

// 실증한 라이브 분포: 우리팀(default) atk30/def50=80, 라이벌 TEAM-02 atk100=100(총점 앞섬).
const frame = (team_id: string, actor: string, category: string, points: number) =>
  ({ topic: "scores", team_id, actor, category, points });

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

async function emitTwoTeams() {
  await emit(frame("default", "red", "lateral_movement", 30));
  await emit(frame("default", "blue", "patch_verified", 50));
  await emit(frame("TEAM-02", "red", "objective", 100));
}

beforeEach(() => {
  vi.clearAllMocks();
  h.onEvent = null;
});

describe("다팀 스코어보드 라이브(scores 토픽, 서로 다른 team_id)", () => {
  it("아레나 리더보드가 두 팀을 별 행으로 누적하고 총점 내림차순 랭크(라이벌이 1위)", async () => {
    await renderApp(); // 아레나 뷰
    expect(h.onEvent).toBeTruthy();
    await emitTwoTeams();

    const board = screen.getByLabelText("스코어보드");
    const rival = within(board).getByText("TEAM-02").closest(".lbr")!;
    const me = within(board).getByText("RED · TEAM-01").closest(".lbr")!;

    // 라이벌 TEAM-02: rank 01 · score 100(우리팀 80 을 앞섬)
    expect(within(rival as HTMLElement).getByText("01")).toBeInTheDocument();
    expect(rival).toHaveTextContent("100");
    expect(rival).not.toHaveClass("me");       // 1위여도 '우리'가 아님

    // 우리팀 default: rank 02 · score 80 · me 하이라이트
    expect(within(me as HTMLElement).getByText("02")).toBeInTheDocument();
    expect(me).toHaveTextContent("80");
    expect(me).toHaveClass("me");
  });

  it("라이벌이 총점 1위여도 우리 시설 상단 stat 은 우리 팀 점수(30/50)로 남는다(납치 금지)", async () => {
    await renderApp();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /발전소 SIS/ }));
    });
    await emitTwoTeams();

    const atk = screen.getByText("Attack").parentElement!;
    const def = screen.getByText("Defense").parentElement!;
    expect(atk).toHaveTextContent("30");       // 우리팀(default) 공격 — TEAM-02 의 100 아님
    expect(def).toHaveTextContent("50");        // 우리팀 방어
    expect(atk).not.toHaveTextContent("100");   // 라이벌 점수가 상단 stat 에 새면 안 된다
  });

  it("Solve Log 가 양 팀의 어워드를 각자 팀 라벨로 보여준다", async () => {
    await renderApp();
    await emitTwoTeams();

    // TEAM-02 의 objective 어워드와 우리팀 patch_verified 어워드가 각자 팀 라벨로 뜬다
    expect(screen.getByText(/objective · \+100/)).toBeInTheDocument();
    expect(screen.getByText(/patch_verified · \+50/)).toBeInTheDocument();
    expect(screen.getByText(/lateral_movement · \+30/)).toBeInTheDocument();
    // 라이벌 팀 라벨(리더보드 + Solve Log 양쪽)과 우리 팀 라벨이 공존
    expect(screen.getAllByText("TEAM-02").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("RED · TEAM-01").length).toBeGreaterThanOrEqual(1);
  });
});
