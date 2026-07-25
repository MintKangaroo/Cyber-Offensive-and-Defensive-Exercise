/**
 * ProcessImpact 순수 로직 유닛 테스트 (vitest, DOM 불필요)
 * =======================================================
 * 자산 상태 → 심각도 매핑, 정상↔사보타주 계기값 보간, 임팩트 게이지 폭, 섹터 데이터 무결성.
 */
import { describe, it, expect } from "vitest";
import { severityOf, reading, impactPct, SECTORS, type Sector } from "./ProcessImpact";

describe("severityOf", () => {
  it("자산 상태를 심각도로 매핑", () => {
    expect(severityOf("compromised")).toBe("critical");
    expect(severityOf("under_attack")).toBe("degraded");
    expect(severityOf("recovered")).toBe("restoring");
    expect(severityOf("secure")).toBe("nominal");
    expect(severityOf(undefined)).toBe("nominal");
  });
});

describe("reading (계기값 보간)", () => {
  const s: Sector = {
    asset: "x", label: "", metric: "", unit: "",
    nominal: 60, critical: 57.2, nominalMsg: "", criticalMsg: "",
  };
  it("nominal은 정상값", () => {
    expect(reading(s, "nominal")).toBeCloseTo(60);
  });
  it("critical은 사보타주값", () => {
    expect(reading(s, "critical")).toBeCloseTo(57.2);
  });
  it("degraded는 55% 지점으로 보간", () => {
    expect(reading(s, "degraded")).toBeCloseTo(60 + (57.2 - 60) * 0.55);
  });
  it("restoring은 25% 지점으로 보간", () => {
    expect(reading(s, "restoring")).toBeCloseTo(60 + (57.2 - 60) * 0.25);
  });
  it("증가형 지표(온도 22→41)도 방향 무관하게 보간", () => {
    const temp: Sector = { ...s, nominal: 22, critical: 41 };
    expect(reading(temp, "critical")).toBeCloseTo(41);
    expect(reading(temp, "nominal")).toBeCloseTo(22);
    expect(reading(temp, "degraded")).toBeGreaterThan(22);
    expect(reading(temp, "degraded")).toBeLessThan(41);
  });
});

describe("impactPct (게이지 폭)", () => {
  it("심각도가 높을수록 폭이 커진다(단조 증가)", () => {
    expect(impactPct("nominal")).toBeLessThan(impactPct("restoring"));
    expect(impactPct("restoring")).toBeLessThan(impactPct("degraded"));
    expect(impactPct("degraded")).toBeLessThan(impactPct("critical"));
    expect(impactPct("critical")).toBe(100);
  });
  it("모든 심각도가 0~100 범위", () => {
    for (const sev of ["nominal", "restoring", "degraded", "critical"] as const) {
      expect(impactPct(sev)).toBeGreaterThanOrEqual(0);
      expect(impactPct(sev)).toBeLessThanOrEqual(100);
    }
  });
});

describe("SECTORS 데이터 무결성", () => {
  it("10개 OT 섹터, asset 키 유니크", () => {
    expect(SECTORS).toHaveLength(10);
    const assets = SECTORS.map((s) => s.asset);
    expect(new Set(assets).size).toBe(10);
  });
  it("IT 자산(defense_network)은 물리 지표 없어 제외", () => {
    expect(SECTORS.find((s) => s.asset === "defense_network")).toBeUndefined();
  });
  it("모든 섹터가 필수 필드(label/metric/unit/메시지)를 가진다", () => {
    for (const s of SECTORS) {
      expect(s.label).toBeTruthy();
      expect(s.metric).toBeTruthy();
      expect(s.nominalMsg).toBeTruthy();
      expect(s.criticalMsg).toBeTruthy();
      expect(s.nominal).not.toBe(s.critical); // 정상≠사보타주여야 게이지가 의미
    }
  });
});
