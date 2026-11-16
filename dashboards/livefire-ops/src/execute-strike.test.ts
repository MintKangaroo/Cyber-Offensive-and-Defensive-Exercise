import { describe, it, expect, vi, afterEach } from "vitest";
import { executeStep } from "./api";
import { FACILITIES } from "./data";
import type { AttackStep } from "./types";

// 확장 섹터(lng/railway/airport/finance/factory) EXECUTE STRIKE 라이브 배선 회귀.
//  과거엔 generic() 시설의 attackChain 단계에 step.action 이 없어 EXECUTE STRIKE 가 서사 전용
//  ({live:false})이었고, #150 에서 SIS BYPASS·합성 프레임까지만 배선됐다(ACTUAL 게이지 미구동).
//  이제 full-config 트윈과 동일한 2단 킬체인으로 **실 물리 파국**까지 연다:
//    - lateral_movement → POST /api/command {value}  (물리 cmd 레지스터 overdrive, redline 초과)
//    - objective        → POST /api/safety/override {override:true} (SIS BYPASS → 손상 누적·파국)
//    - finance/factory 의 privilege_escalation → 실 BACnet WriteProperty / MQTT Sparkplug(합성 프레임)
//  attach_modbus_ics 의 /api/command 는 airport_ot 실 트윈에서 2026-11-09 라이브로 파국 확인
//  (SIS 걸림=트립만, SIS 우회 후 cmd 90→actual 90>redline 50·damage 100·failed). 백엔드 계약은
//  tests/unit/test_twin_command_route.py 가 가드. 여기서 닫는 갭은 "data.ts 배선 → executeStep 이 그
//  트윈 라우트로 정확한 method/path/body 로 도달({live:true})", 그리고 "트윈 없는 섹터(nuclear/telecom/
//  satellite)·URL 미주입 섹터는 호출 없이 서사({live:false})" 다(허위 라이브 방지).
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
    // objective: SIS BYPASS (전 섹터)
    ["lng", "objective", "POST", "/api/safety/override", { override: true }],
    ["railway", "objective", "POST", "/api/safety/override", { override: true }],
    ["airport", "objective", "POST", "/api/safety/override", { override: true }],
    ["finance", "objective", "POST", "/api/safety/override", { override: true }],
    ["factory", "objective", "POST", "/api/safety/override", { override: true }],
    // lateral_movement: 물리 cmd overdrive(/api/command, redline 초과값) — 전 섹터
    ["lng", "lateral_movement", "POST", "/api/command", { value: 260 }],
    ["railway", "lateral_movement", "POST", "/api/command", { value: 160 }],
    ["airport", "lateral_movement", "POST", "/api/command", { value: 90 }],
    ["finance", "lateral_movement", "POST", "/api/command", { value: 48 }],
    ["factory", "lateral_movement", "POST", "/api/command", { value: 160 }],
    // privilege_escalation: 실 프로토콜 합성 프레임(finance/factory)
    ["finance", "privilege_escalation", "POST", "/api/bacnet/write-property", { setpoint_c: 45 }],
    ["factory", "privilege_escalation", "POST", "/api/mqtt/command", { value: 300 }],
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

  it("2단 킬체인: 5개 확장 섹터 전부 lateral=물리 cmd overdrive(/api/command) · objective=SIS BYPASS", () => {
    for (const sector of ["lng", "railway", "airport", "finance", "factory"]) {
      // lateral_movement 가 물리 cmd 를 redline 초과로 밀고(파국은 SIS 걸려 있는 동안 트립만),
      const lm = step(sector, "lateral_movement");
      expect(lm.action?.path, `${sector} lateral`).toBe("/api/command");
      expect(typeof (lm.action?.body as { value?: unknown })?.value, `${sector} overdrive value`).toBe("number");
      // objective 가 SIS 를 무력화해 비로소 손상이 누적된다(순서: chain 이 lateral→objective).
      const obj = step(sector, "objective");
      expect(obj.action?.path, `${sector} objective`).toBe("/api/safety/override");
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
