import { useMemo } from "react";
import { useRangeStore } from "../../store/rangeStore";
import type { AssetState, RangeEvent } from "../../api/types";

/**
 * ICS 물리 프로세스 임팩트 패널
 * ================================
 * 추상적인 자산 상태(secure/under_attack/compromised/recovered)를 각 ICS/OT 섹터의 **실제 물리
 * 프로세스 결과**로 번역해 보여준다 — "compromised"가 아니라 "계통 트립 / SIS 인터록 해제 /
 * CRAC 냉방 중단"처럼. 공방 훈련에서 사보타주가 물리 세계에 무엇을 의미하는지 직관적으로 전달.
 *
 * 데이터 소스: rangeStore.assetStates(이벤트로 파생) + 마지막 사보타주 이벤트(phase/vuln).
 * 별도 백엔드 없이 기존 이벤트 스트림만으로 동작(자기완결형).
 */

type Severity = "nominal" | "degraded" | "critical" | "restoring";

interface Sector {
  asset: string;
  label: string;      // 섹터명
  metric: string;     // 물리 지표명
  unit: string;
  nominal: number;    // 정상 판독값
  critical: number;   // 사보타주 시 판독값
  nominalMsg: string; // 정상 상태 설명
  criticalMsg: string; // 사보타주 결과 설명
}

// OT 물리 섹터만(사내망=IT는 물리 프로세스 지표가 없어 제외).
const SECTORS: Sector[] = [
  { asset: "power_plant", label: "전력망 SCADA", metric: "계통 주파수", unit: "Hz",
    nominal: 60.0, critical: 57.2, nominalMsg: "터빈 동기 · 계통 안정", criticalMsg: "보호계전 트립 · 주파수 붕괴" },
  { asset: "refinery_plant", label: "정유 DCS/SIS", metric: "반응기 압력", unit: "bar",
    nominal: 12.0, critical: 34.5, nominalMsg: "SIS 인터록 정상 · 압력 정격", criticalMsg: "SIS 인터록 해제 · 과압 폭주" },
  { asset: "smart_factory", label: "스마트팩토리", metric: "로봇셀 안전", unit: "%",
    nominal: 100, critical: 0, nominalMsg: "안전문 인터록 · 라인 정상", criticalMsg: "안전 오버라이드 · 셀 폭주" },
  { asset: "water_utility", label: "수도 정수", metric: "잔류 염소", unit: "ppm",
    nominal: 0.8, critical: 0.05, nominalMsg: "염소 투입 정상 · 수질 적합", criticalMsg: "투입 중단 · 수질 오염 위험" },
  { asset: "lng_terminal", label: "LNG 터미널", metric: "저장탱크 압력", unit: "kPa",
    nominal: 18.0, critical: 41.0, nominalMsg: "BOG 처리 · ESD 대기", criticalMsg: "ESD 무력화 · BOG 과압" },
  { asset: "railway_signaling", label: "철도 신호", metric: "폐색 안전", unit: "%",
    nominal: 100, critical: 0, nominalMsg: "ATP 정상 · 신호 정위", criticalMsg: "허용신호 위조 · 충돌 위험" },
  { asset: "airport_ot", label: "공항 OT", metric: "활주로 등화", unit: "%",
    nominal: 100, critical: 15, nominalMsg: "등화 · BHS 정상", criticalMsg: "등화 소등 · BHS 정지" },
  { asset: "datacenter_bms", label: "데이터센터 BMS", metric: "흡기 온도", unit: "℃",
    nominal: 22.0, critical: 41.0, nominalMsg: "CRAC 냉방 정상", criticalMsg: "냉방 오버라이드 · 과열" },
  { asset: "hospital_ot", label: "병원 OT", metric: "PACS 가용성", unit: "%",
    nominal: 100, critical: 20, nominalMsg: "PACS/HIS · 의료기기 정상", criticalMsg: "영상 가용성 붕괴" },
  { asset: "ground_station", label: "위성 지상국", metric: "TT&C 무결성", unit: "%",
    nominal: 100, critical: 10, nominalMsg: "커맨드 인증 · 링크 정상", criticalMsg: "커맨드 위조 · 자세 이상" },
];

function severityOf(state: AssetState | undefined): Severity {
  switch (state) {
    case "compromised": return "critical";
    case "under_attack": return "degraded";
    case "recovered": return "restoring";
    default: return "nominal";
  }
}

const SEV_STYLE: Record<Severity, { bar: string; text: string; badge: string; tag: string }> = {
  nominal:   { bar: "#34D399", text: "#34D399", badge: "border-[#34D399]/40 text-[#34D399]", tag: "정상" },
  degraded:  { bar: "#F5A623", text: "#F5A623", badge: "border-[#F5A623]/40 text-[#F5A623]", tag: "교란" },
  critical:  { bar: "#F43F5E", text: "#F43F5E", badge: "border-[#F43F5E]/50 text-[#F43F5E]", tag: "사보타주" },
  restoring: { bar: "#22D3EE", text: "#22D3EE", badge: "border-[#22D3EE]/40 text-[#22D3EE]", tag: "복구중" },
};

/** 정상→사보타주 사이 판독값을 심각도에 따라 보간해 계기값을 만든다. */
function reading(s: Sector, sev: Severity): number {
  const frac = sev === "critical" ? 1 : sev === "degraded" ? 0.55 : sev === "restoring" ? 0.25 : 0;
  return s.nominal + (s.critical - s.nominal) * frac;
}

/** 0(정상)~100(사보타주) 척도의 임팩트 게이지 폭. */
function impactPct(sev: Severity): number {
  return sev === "critical" ? 100 : sev === "degraded" ? 55 : sev === "restoring" ? 25 : 4;
}

function SectorRow({ sector, state, lastEvent }: { sector: Sector; state: AssetState; lastEvent?: RangeEvent }) {
  const sev = severityOf(state);
  const style = SEV_STYLE[sev];
  const val = reading(sector, sev);
  const decimals = Number.isInteger(sector.nominal) && Number.isInteger(sector.critical) ? 0 : 1;
  const msg = sev === "nominal" ? sector.nominalMsg
    : sev === "restoring" ? "블루팀 복구 진행 · 안정화 중"
    : sector.criticalMsg;

  return (
    <div className="border border-[#1E2A3F] rounded-md px-2.5 py-2 bg-[#111725]">
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono text-[11px] text-[#E8EDF5]">{sector.label}</span>
        <span className={`font-mono text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${style.badge}`}>
          {style.tag}
        </span>
      </div>
      <div className="flex items-baseline justify-between mb-1">
        <span className="font-mono text-[10px] text-[#6B7A99]">{sector.metric}</span>
        <span className="font-mono text-sm font-bold tabular-nums" style={{ color: style.text }}>
          {val.toFixed(decimals)}<span className="text-[9px] font-normal ml-0.5">{sector.unit}</span>
        </span>
      </div>
      {/* 임팩트 게이지 */}
      <div className="h-1.5 rounded-full bg-[#0A0E1A] overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700"
          style={{ width: `${impactPct(sev)}%`, backgroundColor: style.bar }} />
      </div>
      <div className="mt-1 font-mono text-[9px] text-[#6B7A99] leading-tight">
        {msg}
        {sev === "critical" && lastEvent?.phase ? ` · ${lastEvent.phase}` : ""}
      </div>
    </div>
  );
}

export function ProcessImpact() {
  const assetStates = useRangeStore((s) => s.assetStates);
  const events = useRangeStore((s) => s.events);

  // 각 자산의 마지막(최신) 이벤트 — critical 상세(phase) 표기용.
  const lastByAsset = useMemo(() => {
    const m = new Map<string, RangeEvent>();
    for (const e of events) {
      if (e.target_asset && !m.has(e.target_asset)) m.set(e.target_asset, e);
    }
    return m;
  }, [events]);

  const impacted = SECTORS.filter((s) => severityOf(assetStates[s.asset]) !== "nominal").length;

  return (
    <div className="p-3 flex flex-col gap-2" data-testid="process-impact">
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-widest text-[#6B7A99]">Process Impact</span>
        <span className="font-mono text-[10px] text-[#6B7A99]">
          영향 <span className={impacted > 0 ? "text-[#F43F5E]" : "text-[#34D399]"}>{impacted}</span>
          <span className="text-[#6B7A99]">/{SECTORS.length}</span>
        </span>
      </div>
      <div className="grid grid-cols-1 gap-1.5">
        {SECTORS.map((s) => (
          <SectorRow
            key={s.asset}
            sector={s}
            state={assetStates[s.asset] ?? "secure"}
            lastEvent={lastByAsset.get(s.asset)}
          />
        ))}
      </div>
      <div className="font-mono text-[9px] text-[#6B7A99] leading-tight">
        물리 지표는 자산 상태 기반 모사값(훈련 몰입용). 실제 프로세스 값 아님.
      </div>
    </div>
  );
}
