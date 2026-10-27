import { describe, it, expect, vi, afterEach } from "vitest";
import {
  registersFromSectorTelemetry,
  sectorFootLine,
  fetchSectorTelemetry,
  type SectorTelemetry,
} from "./api";

// 섹터 트윈 라이브 "연결"(텔레메트리 표시) 소비 쪽 회귀.
//  콘솔이 발전소 외 섹터(정유/공항/데이터센터/LNG/철도/스마트팩토리)를 라이브로 연결하는 길은
//  /api/telemetry(통일 규약)를 폴링 → fetchSectorTelemetry 로 파싱 → registersFromSectorTelemetry/
//  sectorFootLine 으로 렌더다(확장 섹터의 EXECUTE STRIKE 라이브 배선은 execute-strike.test.ts 가 가드).
//  트윈 쪽 계약은 tests/unit/test_twin_telemetry.py 가 섹터별로 고정한다. 여기서 닫는 갭은 그 payload 를
//  콘솔이 올바른 레지스터 행(cmd=SET, over-redline=O-LIMIT, damage=red, SIS 토글)으로 그려내는지다.

// 실측 payload: airport_ot /api/telemetry (MODBUS off 스냅샷, 2026-10-27 실 트윈에서 캡처).
const AIRPORT: SectorTelemetry = {
  asset: "airport_ot", cmd: 30, cmd_name: "FUEL_PRESSURE",
  actual: 30, actual_name: "HR2", damage: 0, interlock: true, failed: false, redline: 50,
  registers: [
    { addr: 0, name: "FUEL_PRESSURE", value: 30 },
    { addr: 1, name: "FUEL_FLOW", value: 40 },
  ],
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("섹터 트윈 라이브 연결 — 콘솔 텔레메트리 소비(registersFromSectorTelemetry)", () => {
  it("cmd 레지스터는 SET, SIS 코일 행이 추가된다(실측 airport payload)", () => {
    const rows = registersFromSectorTelemetry(AIRPORT);
    const fuel = rows.find((r) => r.name === "FUEL_PRESSURE")!;
    expect(fuel.state).toBe("SET");          // cmd_name === register.name → isCmd
    expect(fuel.addr).toBe("HR0");
    expect(rows.find((r) => r.name === "FUEL_FLOW")).toBeTruthy();
    // 콘솔이 통일 트윈에 항상 덧붙이는 SAFETY_INTERLOCK(coil0) 행
    const sis = rows.find((r) => r.name === "SAFETY_INTERLOCK")!;
    expect(sis.addr).toBe("coil0");
    expect(sis.value).toBe("ON");
    expect(sis.state).toBe("ARMED");
    expect(sis.tone).toBe("blue");
  });

  it("actual 이 redline 초과면 O-LIMIT(red), damage>0 는 red, SIS 해제는 BYPASS(red)", () => {
    // 공격이 물리 cmd 를 밀어 actual 이 redline 을 넘고 자산이 손상·SIS 가 해제된 라이브 상태.
    const hot: SectorTelemetry = {
      asset: "airport_ot", cmd: 90, cmd_name: "FUEL_PRESSURE",
      actual: 90, actual_name: "FUEL_PRESSURE", damage: 42, interlock: false, failed: false, redline: 50,
      registers: [
        { addr: 0, name: "FUEL_PRESSURE", value: 90 },   // actual_name == cmd_name == 이 레지스터
        { addr: 4, name: "DAMAGE", value: 42 },
      ],
    };
    const rows = registersFromSectorTelemetry(hot);
    const fuel = rows.find((r) => r.name === "FUEL_PRESSURE")!;
    expect(fuel.tone).toBe("red");
    expect(fuel.state).toBe("O-LIMIT");      // isActual && over
    expect(fuel.value).toContain("▲");
    const dmg = rows.find((r) => r.name === "DAMAGE")!;
    expect(dmg.tone).toBe("red");
    expect(dmg.state).toBe("▲");
    const sis = rows.find((r) => r.name === "SAFETY_INTERLOCK")!;
    expect(sis.value).toBe("OFF");
    expect(sis.state).toBe("BYPASS");
    expect(sis.tone).toBe("red");
  });

  it("sectorFootLine 이 actual/cmd/SIS/DAMAGE 를 하단 티커로 요약한다", () => {
    expect(sectorFootLine(AIRPORT)).toBe(
      "HR2 30 · FUEL_PRESSURE 30 · SIS ARMED · DAMAGE 0%");
    const failed = { ...AIRPORT, interlock: false, damage: 100, failed: true };
    expect(sectorFootLine(failed)).toContain("SIS BYPASS");
    expect(sectorFootLine(failed)).toContain("CATASTROPHIC_FAILURE");
  });
});

describe("fetchSectorTelemetry — 섹터 URL 해석 + 스키마 가드", () => {
  it("VITE_TWIN_<SECTOR> 주입 + 통일 payload → SectorTelemetry 로 파싱", async () => {
    vi.stubEnv("VITE_TWIN_AIRPORT", "http://twin.local:8206");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, json: async () => AIRPORT,
    }));
    const t = await fetchSectorTelemetry("airport");
    expect(t).not.toBeNull();
    expect(t!.cmd_name).toBe("FUEL_PRESSURE");
    expect(t!.registers).toHaveLength(2);
    expect(t!.interlock).toBe(true);
  });

  it("registers[] 없는 발전소 전용 스키마는 걸러 null(폴백) 처리한다", async () => {
    vi.stubEnv("VITE_TWIN_AIRPORT", "http://twin.local:8206");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, json: async () => ({ actual_rpm: 3600, cmd_rpm: 3600 }),  // 발전소 전용 스키마
    }));
    expect(await fetchSectorTelemetry("airport")).toBeNull();
  });

  it("URL 미해석 섹터(env 없음·비발전소)는 폴백(null) — 트윈 호출 없음", async () => {
    const f = vi.fn();
    vi.stubGlobal("fetch", f);
    expect(await fetchSectorTelemetry("railway")).toBeNull();
    expect(f).not.toHaveBeenCalled();
  });
});
