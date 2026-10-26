import { describe, it, expect } from "vitest";
import { FACILITIES } from "./data";

// 2번째 섹터(상수도·병원) 풀 라이브 계약 회귀.
//  콘솔 attackChain 의 공격 엔드포인트는 실제 트윈 라우트(services/<sector>/main.py)와 일치해야
//  executeStep 이 라이브로 트윈을 구동한다. 경로가 트윈에 없는 값으로 드리프트하면(또는 step 이
//  action 없이 서사-전용으로 퇴화하면) 콘솔은 조용히 mock 으로 떨어진다 — 그걸 여기서 고정한다.
//
// 아래 allowlist 는 트윈 Vuln 라우트 + /api/safety/override(SIS) 를 코드에서 확인해 핀고정한 값.
//  services/water_utility/main.py / services/hospital_ot/main.py 와 1:1.
const TWIN_ENDPOINTS: Record<string, Set<string>> = {
  water: new Set([
    "POST /api/hmi/login",
    "POST /api/pump/control",
    "POST /api/dosing/chlorine",
    "POST /api/tank/setpoint",
    "POST /api/report/fetch",
    "POST /api/safety/override",
  ]),
  hospital: new Set([
    "GET /api/pacs/study",
    "GET /api/his/patient",
    "POST /api/device/infusion",
    "POST /api/dicom/store",
    "POST /api/nursecall/override",
    "POST /api/safety/override",
  ]),
};

describe("2번째 섹터 풀 라이브 계약 (상수도·병원)", () => {
  for (const sector of ["water", "hospital"] as const) {
    const facility = FACILITIES[sector];

    it(`${sector}: 콘솔 설정이 존재하고 킬체인이 비어있지 않다`, () => {
      expect(facility, `FACILITIES['${sector}'] 누락`).toBeTruthy();
      expect(facility.attackChain.length).toBeGreaterThanOrEqual(3);
    });

    it(`${sector}: 모든 킬체인 단계가 라이브(action method+path+body 완비)`, () => {
      for (const step of facility.attackChain) {
        expect(step.action, `${sector}/${step.id} 가 서사-전용(action 없음)`).toBeTruthy();
        expect(step.action!.method).toMatch(/^(GET|POST)$/);
        expect(step.action!.path).toMatch(/^\/api\//);
        expect(step.action!.body, `${sector}/${step.id} body 누락`).toBeTruthy();
      }
    });

    it(`${sector}: 모든 공격 엔드포인트가 실제 트윈 라우트와 일치(드리프트 차단)`, () => {
      const allow = TWIN_ENDPOINTS[sector];
      for (const step of facility.attackChain) {
        const sig = `${step.action!.method} ${step.action!.path}`;
        expect(allow.has(sig), `${sector}/${step.id}: '${sig}' 가 트윈에 없는 경로`).toBe(true);
      }
    });

    it(`${sector}: objective 단계가 SIS 무력화(/api/safety/override)로 물리 파국을 유발`, () => {
      const obj = facility.attackChain.find((s) => s.phase === "objective");
      expect(obj, `${sector} objective 단계 없음`).toBeTruthy();
      expect(obj!.action!.path).toBe("/api/safety/override");
    });
  }
});
