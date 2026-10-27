import { describe, it, expect, vi, afterEach } from "vitest";
import { executeStep } from "./api";
import { FACILITIES } from "./data";
import type { AttackStep } from "./types";

// 확장 섹터(lng/railway/airport/finance/factory) EXECUTE STRIKE 라이브 배선 회귀.
//  과거엔 generic() 시설의 attackChain 단계에 step.action 이 없어 EXECUTE STRIKE 가 서사 전용
//  ({live:false})이었다. 이제 각 섹터의 실제 트윈 HTTP 라우트를 action 으로 배선했다:
//    - 모든 통일 트윈: objective → POST /api/safety/override {override:true} (SIS BYPASS)
//    - datacenter_bms: lateral → POST /api/bacnet/write-property (실 BACnet WriteProperty)
//    - smart_factory : lateral → POST /api/mqtt/command        (실 MQTT Sparkplug DCMD)
//  이 라우트들은 실 트윈에서 2026-10-27 라이브로 도달 확인(override→interlock false, 도메인
//  라우트→실 프레임). 여기서 닫는 갭은 "data.ts 배선 → 실제 executeStep 이 그 트윈 라우트로
//  정확한 method/path/body 로 도달({live:true})" 하는지, 그리고 "트윈 없는 섹터(nuclear/telecom/
//  satellite)·URL 미주입 섹터는 호출 없이 서사({live:false})" 로 남는지다(허위 라이브 방지).
//  실제 executeStep + 실제 FACILITIES 카탈로그를 그대로 써서 배선 자체를 고정한다.

const BASE = "http://twin.local:1";

const step = (sector: string, phase: AttackStep["phase"]): AttackStep =>
  FACILITIES[sector].attackChain.find((s) => s.phase === phase)!;

function stubFetch() {
  const f = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
  vi.stubGlobal("fetch", f);
  return f;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("확장 섹터 EXECUTE STRIKE 라이브 배선", () => {
  // (섹터, 단계, 기대 method, 기대 path, 기대 body)
  const WIRED: [string, AttackStep["phase"], string, string, Record<string, unknown>][] = [
    ["lng", "objective", "POST", "/api/safety/override", { override: true }],
    ["railway", "objective", "POST", "/api/safety/override", { override: true }],
    ["airport", "objective", "POST", "/api/safety/override", { override: true }],
    ["finance", "objective", "POST", "/api/safety/override", { override: true }],
    ["factory", "objective", "POST", "/api/safety/override", { override: true }],
    ["finance", "lateral_movement", "POST", "/api/bacnet/write-property", { setpoint_c: 45 }],
    ["factory", "lateral_movement", "POST", "/api/mqtt/command", { value: 300 }],
  ];

  it.each(WIRED)("%s/%s → 실 트윈 라우트로 라이브 도달", async (sector, phase, method, path, body) => {
    vi.stubEnv(`VITE_TWIN_${sector.toUpperCase()}`, BASE);
    const f = stubFetch();
    const s = step(sector, phase);
    expect(s.action, `${sector}/${phase} 에 action 배선이 있어야`).toBeTruthy();

    const res = await executeStep(sector, s);
    expect(res).toEqual({ ok: true, live: true });
    expect(f).toHaveBeenCalledTimes(1);
    const [url, init] = f.mock.calls[0];
    expect(url).toBe(`${BASE}${path}`);
    expect(init.method).toBe(method);
    expect(JSON.parse(init.body)).toEqual(body);
  });

  it("objective 는 5개 확장 섹터 전부 SIS BYPASS 로 배선돼 있다", () => {
    for (const sector of ["lng", "railway", "airport", "finance", "factory"]) {
      const obj = step(sector, "objective");
      expect(obj.action?.path, sector).toBe("/api/safety/override");
    }
  });

  // 트윈이 없는 섹터는 라이브 배선을 넣지 않는다(허위 라이브 금지).
  it.each(["nuclear", "telecom", "satellite"])("%s(트윈 없음) → action 없음·호출 없음·서사", async (sector) => {
    vi.stubEnv(`VITE_TWIN_${sector.toUpperCase()}`, BASE); // URL 을 줘도
    const f = stubFetch();
    const obj = step(sector, "objective");
    expect(obj.action, `${sector} 는 통일 트윈이 없어 배선 금지`).toBeUndefined();

    const res = await executeStep(sector, obj);
    expect(res).toEqual({ ok: true, live: false });
    expect(f).not.toHaveBeenCalled();
  });

  it("URL 미주입(VITE_TWIN_* 없음) 섹터는 action 이 있어도 호출 없이 서사로 남는다", async () => {
    const f = stubFetch();                       // env 미설정
    const res = await executeStep("lng", step("lng", "objective"));
    expect(res).toEqual({ ok: true, live: false });
    expect(f).not.toHaveBeenCalled();
  });
});
