import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act, within } from "@testing-library/react";

// 아레나 "LIVE FIRE CLOCK" 패널의 활동량 stat(Patch Count · 공격 · 방어) 라이브 회귀.
//  #144 가 정직하게 남긴 갭: 타이머/Solve Log/스코어보드는 라이브로 흘렀지만 patchCount/atkCount/
//  defCount 는 arenaData 가 덮지 않아 DEFAULT_ARENA 의 정적값(07/12/7)으로 떨어졌다 — 라이브파이어
//  콘솔이 '실시간 현황'을 자처하면서 세 숫자는 움직이지 않는 가짜였다. 이제 App 은 scores 어워드를
//  카테고리로 세어(atk=공격 어워드 수, def=방어 어워드 수, patch=patch_verified 수) 라이브로 채운다.
//  여기서 닫는 갭은 "(1) 라이브 어워드 전엔 정적 폴백, (2) scores 프레임이 흐르면 세 stat 이 실제
//  카운트로 바뀌고 정적값에 머무르지 않는다"다.
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

const frame = (actor: string, category: string, points: number, team_id = "default") =>
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

function clockPanel() {
  return screen.getByLabelText("라이브파이어 클럭");
}

beforeEach(() => {
  vi.clearAllMocks();
  h.onEvent = null;
});

describe("아레나 활동량 stat 라이브(Patch Count · 공격 · 방어)", () => {
  it("라이브 어워드가 오기 전엔 정적 폴백(07 / 공격 12 / 방어 7)", async () => {
    await renderApp();
    const panel = clockPanel();
    expect(within(panel).getByText("07")).toBeInTheDocument();       // DEFAULT_ARENA.patchCount
    expect(within(panel).getByText(/공격\s*12\b/)).toBeInTheDocument();
    expect(within(panel).getByText(/방어\s*7\b/)).toBeInTheDocument();
  });

  it("scores 어워드가 흐르면 세 stat 이 실제 카운트로 바뀐다(정적값 납치 금지)", async () => {
    await renderApp();
    expect(h.onEvent).toBeTruthy();
    // 공격 1, 방어 2(patch_verified 1 + detection_success 1) → patch=1, atk=1, def=2
    await emit(frame("red", "lateral_movement", 30));
    await emit(frame("blue", "patch_verified", 50));
    await emit(frame("blue", "detection_success", 20));

    const panel = clockPanel();
    expect(within(panel).getByText("01")).toBeInTheDocument();        // patch_verified 1건 → Patch Count 01
    expect(within(panel).getByText(/공격\s*1\b/)).toBeInTheDocument();  // 공격 어워드 1
    expect(within(panel).getByText(/방어\s*2\b/)).toBeInTheDocument();  // 방어 어워드 2
    // 정적 폴백값이 더는 보이지 않는다(가짜 숫자 잔존 금지)
    expect(within(panel).queryByText("07")).not.toBeInTheDocument();
    expect(within(panel).queryByText(/공격\s*12\b/)).not.toBeInTheDocument();
    expect(within(panel).queryByText(/방어\s*7\b/)).not.toBeInTheDocument();
  });

  it("patch_verified 가 아닌 방어 어워드는 Patch Count 를 올리지 않는다", async () => {
    await renderApp();
    // 방어 어워드지만 patch 가 아님(block_success) → def 1, patch 0
    await emit(frame("blue", "block_success", 30));
    const panel = clockPanel();
    expect(within(panel).getByText("00")).toBeInTheDocument();        // Patch Count 00 (patch_verified 없음)
    expect(within(panel).getByText(/방어\s*1\b/)).toBeInTheDocument();
    expect(within(panel).getByText(/공격\s*0\b/)).toBeInTheDocument();
  });
});
