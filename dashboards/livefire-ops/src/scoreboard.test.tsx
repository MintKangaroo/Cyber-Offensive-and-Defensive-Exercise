import { describe, it, expect, vi } from "vitest";

// App 이 import 하는 ./api 는 브라우저 전용(EventSource 등) — 순수 함수 테스트용으로 목.
vi.mock("./api", () => ({
  fetchPowerTelemetry: vi.fn(),
  fetchSectorTelemetry: vi.fn(),
  powerRegistersFromTelemetry: vi.fn(),
  registersFromSectorTelemetry: vi.fn(),
  sectorFootLine: vi.fn(),
  fmtClock: (s: number) => String(s),
  executeStep: vi.fn(),
  subscribeStream: vi.fn().mockReturnValue(() => {}),
}));

import { buildScoreboard } from "./App";

describe("buildScoreboard — 라이브 점수 분할", () => {
  it("라이브 행은 실제 atk/def 를 담는다(가짜 분할 금지)", () => {
    const rows = buildScoreboard({ default: { attack: 350, defense: 0 } });
    expect(rows).toHaveLength(1);
    const me = rows[0];
    expect(me.atk).toBe(350);        // 실제 공격 점수(과거엔 score/10=35 로 왜곡)
    expect(me.def).toBe(0);
    expect(me.score).toBe(350);
    expect(me.me).toBe(true);
  });

  it("여러 팀은 총점 내림차순으로 랭크", () => {
    const rows = buildScoreboard({
      default: { attack: 120, defense: 10 },
      "team-b": { attack: 200, defense: 0 },
    });
    expect(rows[0].score).toBe(200);
    expect(rows[0].atk).toBe(200);
    expect(rows[1].score).toBe(130);
    expect(rows[1].atk).toBe(120);
    expect(rows[1].def).toBe(10);
  });

  it("빈 집계는 정적 폴백(비어있지 않음)", () => {
    const rows = buildScoreboard({});
    expect(rows.length).toBeGreaterThan(0);
  });
});
