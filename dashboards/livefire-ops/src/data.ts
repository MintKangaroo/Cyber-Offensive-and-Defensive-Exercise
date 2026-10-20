// 실 트윈(services/<sector>/main.py)·shared/event_schema.py 에 근거한 카탈로그.
// 지어내지 않음: 자산명·프로토콜·포트·취약점ID·레지스터·점수는 코드에서 가져옴.
import type {
  ArenaNode,
  FacilityConfig,
  PhaseStep,
  RedPhase,
  ScoreRow,
  SolveEntry,
  StrikeLogEntry,
} from "./types";

// shared/event_schema.py RED_POINTS
export const PHASE_POINTS: Record<RedPhase, number> = {
  recon: 0,
  initial_access: 20,
  privilege_escalation: 30,
  lateral_movement: 30,
  data_exfiltration: 50,
  objective: 100,
  impact: 0,
};

export const PHASE_LABEL: Record<RedPhase, string> = {
  recon: "RECON",
  initial_access: "INITIAL ACCESS",
  privilege_escalation: "PRIV-ESC",
  lateral_movement: "LATERAL MOVEMENT",
  data_exfiltration: "EXFILTRATION",
  objective: "OBJECTIVE",
  impact: "IMPACT",
};

// ── 아레나(현황) 시설 노드 성좌 — 11 국가핵심기반 + 실 취약점 ──
export const ARENA_NODES: ArenaNode[] = [
  { id: "pp-sis", label: "발전소 SIS", code: "PP-005 · OBJECTIVE", sector: "power", xPct: 63, yPct: 46, status: "active" },
  { id: "pp-plc", label: "발전소 PLC", code: "PP-001/006", sector: "power", xPct: 53, yPct: 33, status: "engaged" },
  { id: "nuc", label: "원자력 RX-GW", code: "PATCHED", sector: "nuclear", xPct: 40, yPct: 30, status: "patched" },
  { id: "kpx", label: "전력거래소", code: "KPX · WEB-015", sector: "power", xPct: 70, yPct: 33, status: "engaged" },
  { id: "wtr", label: "상수도 배수", code: "WTR-002", sector: "water", xPct: 30, yPct: 40, status: "engaged" },
  { id: "lng", label: "LNG ESD", code: "LNG-001", sector: "lng", xPct: 47, yPct: 44, status: "engaged" },
  { id: "rwy", label: "철도 신호", code: "RWY-001", sector: "railway", xPct: 71, yPct: 62, status: "defended" },
  { id: "air", label: "공항 활주로", code: "AIR-001", sector: "airport", xPct: 22, yPct: 52, status: "engaged" },
  { id: "hsp-pump", label: "병원 주입펌프", code: "HSP-003", sector: "hospital", xPct: 36, yPct: 55, status: "engaged" },
  { id: "hsp-pacs", label: "병원 PACS", code: "HSP-001", sector: "hospital", xPct: 52, yPct: 58, status: "defended" },
  { id: "ref", label: "정유 SIS", code: "REF-002", sector: "lng", xPct: 68, yPct: 57, status: "engaged" },
  { id: "dcx", label: "데이터센터", code: "DCX-001", sector: "finance", xPct: 83, yPct: 55, status: "engaged" },
  { id: "gs", label: "위성 지상국", code: "GS-002", sector: "satellite", xPct: 28, yPct: 66, status: "engaged" },
  { id: "fac", label: "제조 PLC", code: "FAC-001", sector: "factory", xPct: 44, yPct: 69, status: "patched" },
  { id: "goose", label: "변전소 GOOSE", code: "SUBSTATION", sector: "power", xPct: 60, yPct: 70, status: "engaged" },
  { id: "fin", label: "금융 코어", code: "FIN", sector: "finance", xPct: 80, yPct: 68, status: "defended" },
  { id: "grid", label: "송전망 SCADA", code: "GRID-OPS", sector: "power", xPct: 50, yPct: 80, status: "engaged" },
  { id: "telco", label: "통신 5G 코어", code: "TELCO", sector: "telecom", xPct: 33, yPct: 80, status: "engaged" },
];

export const SCOREBOARD: ScoreRow[] = [
  { rank: 1, team: "RED · TEAM-01", score: 1500, me: true },
  { rank: 2, team: "TriStar Navigator", score: 1370 },
  { rank: 3, team: "codex-0001", score: 1251 },
  { rank: 4, team: "EQST", score: 1143 },
  { rank: 5, team: "로웬", score: 1086 },
];

export const SOLVE_LOG: SolveEntry[] = [
  { id: "s1", side: "attack", team: "RED·TEAM-01", text: "발전소 안전계통(PP-005) 무력화 성공 · +100", points: 100 },
  { id: "s2", side: "defense", team: "원자력", text: "RX-GW 취약점 패치 · 감점 방어" },
  { id: "s3", side: "attack", team: "TEAM-04", text: "상수도 배수지(WTR-002) 펌프 제어 탈취" },
  { id: "s4", side: "attack", team: "RED·TEAM-01", text: "발전소 PLC Modbus coil0 측면이동 · +30", points: 30 },
  { id: "s5", side: "defense", team: "철도 신호", text: "RWY-001 인터락 우회 차단" },
  { id: "s6", side: "attack", team: "TEAM-02", text: "병원 PACS(HSP-001) 영상 IDOR 열람" },
  { id: "s7", side: "attack", team: "RED·TEAM-01", text: "HMI 기본계정(PP-002) 초기 침투 · +20", points: 20 },
];

export const STRIKE_LOG: StrikeLogEntry[] = [
  { id: "k1", time: "41:12", phase: "objective", text: "SIS coil0 latch OFF · T0878", tag: "CRIT", current: true },
  { id: "k2", time: "40:58", phase: "objective", text: "safety/override · PP-005", tag: "+100" },
  { id: "k3", time: "39:03", phase: "lateral_movement", text: "modbus coil0 write · PP-006", tag: "+30" },
  { id: "k4", time: "36:40", phase: "initial_access", text: "HMI default creds · PP-002", tag: "+20" },
];

export function powerKillChain(): PhaseStep[] {
  return [
    { phase: "recon", label: "RECON", state: "done" },
    { phase: "initial_access", label: "INITIAL ACCESS", points: 20, state: "done" },
    { phase: "lateral_movement", label: "LATERAL MOVEMENT", points: 30, state: "done" },
    { phase: "objective", label: "OBJECTIVE", points: 100, state: "active" },
    { phase: "impact", label: "IMPACT", state: "todo" },
  ];
}

// ───────────────────────── 시설 콘솔 설정 ─────────────────────────
// 발전소: services/power_plant/main.py — Modbus HR0~4 / coil0, PP-001~007.
const POWER: FacilityConfig = {
  id: "power",
  name: "발전소",
  nameEn: "THERMAL POWER PLANT",
  meta: "SCADA / PLC · SEC-01/11 · 실 Modbus 502 · DNP3 20000",
  icon: "power",
  objective: "안전계통 무력화 → 터빈 과속 파국",
  objectivePoints: 100,
  schematic: "power-oneline",
  otNodes: [
    { id: "corp", name: "CORP GW", sub: "10.20.0.1 · IT 진입점", xPct: 15, yPct: 27, status: "owned" },
    { id: "hmi", name: "OPERATOR HMI", sub: "기본계정 로그인", xPct: 47, yPct: 28, status: "owned", protocols: ["HTTP"], vulns: ["PP-002"] },
    { id: "eng", name: "ENG WS", sub: "엔지니어링 WS", xPct: 30, yPct: 65, status: "owned", vulns: ["PP-003"] },
    { id: "hist", name: "HISTORIAN", sub: "역직렬화 RCE", xPct: 56, yPct: 69, status: "owned", vulns: ["PP-004"] },
    { id: "plc", name: "PLC · MODBUS", sub: "HR0 TURBINE_RPM", xPct: 74, yPct: 48, status: "owned", protocols: ["Modbus 502"], vulns: ["PP-001/006"] },
    { id: "sis", name: "SAFETY SIS", sub: "coil0 INTERLOCK", xPct: 87, yPct: 29, status: "target", vulns: ["PP-005", "PP-007"] },
  ],
  otEdges: [
    { from: "corp", to: "hmi" },
    { from: "hmi", to: "eng" },
    { from: "hmi", to: "hist" },
    { from: "hist", to: "plc" },
    { from: "eng", to: "plc" },
    { from: "plc", to: "sis", active: true },
  ],
  registersTitle: "PLC 레지스터 · LIVE (실 트윈)",
  registers: [
    { name: "TURBINE_RPM (cmd)", addr: "HR0", value: "5,600", state: "SET", tone: "red" },
    { name: "ACTUAL_RPM", addr: "HR2", value: "5,240 ▲", state: "O-SPD", tone: "red" },
    { name: "COOLANT_FLOW", addr: "HR1", value: "38 ▼", state: "LOW", tone: "red" },
    { name: "COOLANT_TEMP", addr: "HR3", value: "118°C", state: "HIGH", tone: "amber" },
    { name: "DAMAGE", addr: "HR4", value: "73%", state: "▲", tone: "red" },
    { name: "SAFETY_INTERLOCK", addr: "coil0", value: "OFF", state: "BYPASS", tone: "red" },
  ],
  services: [
    { name: "Modbus/TCP 502", state: "compromised" },
    { name: "DNP3 20000", state: "compromised" },
    { name: "IEC 60870-104", state: "up" },
    { name: "HMI HTTP 8002", state: "compromised" },
  ],
  exploit: { label: "coil0 → SIS OFF", detail: "Modbus FC5 · T0878" },
  strikeLog: [
    { id: "pp1", time: "41:12", phase: "objective", text: "SIS coil0 latch OFF · T0878", tag: "CRIT", current: true },
    { id: "pp2", time: "40:58", phase: "objective", text: "safety/override · PP-005", tag: "+100" },
    { id: "pp3", time: "39:03", phase: "lateral_movement", text: "modbus coil0 write · PP-006", tag: "+30" },
    { id: "pp4", time: "36:40", phase: "initial_access", text: "HMI default creds · PP-002", tag: "+20" },
  ],
  footLine: "00:41:12 · asset_compromised · power_plant · sustained_overspeed_sis_disabled · CRITICAL · phase=objective",
  // ★ 라이브 실행 체인 — 각 단계가 실제 발전소 트윈 엔드포인트를 순차 호출한다.
  attackChain: [
    { id: "pp-ia", phase: "initial_access", label: "HMI 기본계정 로그인", vuln: "PP-002", points: 20, action: { method: "POST", path: "/api/hmi/login", body: { username: "operator", password: "operator" } } },
    { id: "pp-lm1", phase: "lateral_movement", label: "PLC 터빈 RPM 명령 상향 → 5600", vuln: "PP-001", points: 30, action: { method: "POST", path: "/api/plc/write", body: { register: "TURBINE_RPM", value: 5600 } } },
    { id: "pp-lm2", phase: "lateral_movement", label: "냉각수 유량 차단 → 30", vuln: "PP-001", points: 30, action: { method: "POST", path: "/api/plc/write", body: { register: "COOLANT_FLOW", value: 30 } } },
    { id: "pp-obj", phase: "objective", label: "안전계통(SIS) 무력화 → 과속 파국", vuln: "PP-005", points: 100, action: { method: "POST", path: "/api/safety/override", body: { override: true } } },
  ],
};

// 병원: services/hospital_ot/main.py — PACS/HIS/의료기기 VLAN, HSP-001~005.
const HOSPITAL: FacilityConfig = {
  id: "hospital",
  name: "병원",
  nameEn: "HOSPITAL OT",
  meta: "PACS / HIS / 의료기기 VLAN · DICOM 104 · HL7 2575",
  icon: "hospital",
  objective: "주입펌프 무단제어 → 약물 과투여",
  objectivePoints: 100,
  schematic: "hospital-vitals",
  otNodes: [
    { id: "corp", name: "CORP GW", sub: "병원 IT 진입점", xPct: 15, yPct: 27, status: "owned" },
    { id: "his", name: "HIS", sub: "환자정보 SQLi", xPct: 44, yPct: 28, status: "owned", vulns: ["HSP-002"] },
    { id: "pacs", name: "PACS", sub: "영상 IDOR", xPct: 30, yPct: 65, status: "owned", protocols: ["DICOM"], vulns: ["HSP-001"] },
    { id: "vlan", name: "의료기기 VLAN", sub: "device segment", xPct: 56, yPct: 69, status: "owned" },
    { id: "pump", name: "주입펌프 PUMP-07", sub: "무단 제어", xPct: 74, yPct: 48, status: "owned", vulns: ["HSP-003"] },
    { id: "nurse", name: "NURSE CALL / BMS", sub: "알람 무력화", xPct: 87, yPct: 29, status: "target", vulns: ["HSP-005"] },
  ],
  otEdges: [
    { from: "corp", to: "his" },
    { from: "his", to: "pacs" },
    { from: "his", to: "vlan" },
    { from: "vlan", to: "pump" },
    { from: "pacs", to: "pump" },
    { from: "pump", to: "nurse", active: true },
  ],
  registersTitle: "의료기기 상태 · LIVE",
  registers: [
    { name: "INFUSION_RATE (PUMP-07)", addr: "mL/h", value: "900 ▲", state: "OVERDOSE", tone: "red" },
    { name: "PATIENT_HR", addr: "P001", value: "148 ▲", state: "TACHY", tone: "red" },
    { name: "SpO2", addr: "P001", value: "86% ▼", state: "LOW", tone: "red" },
    { name: "VENT_PRESSURE", addr: "VNT-2", value: "34", state: "HIGH", tone: "amber" },
    { name: "PACS STUDY", addr: "ST-1001", value: "EXPOSED", state: "IDOR", tone: "amber" },
    { name: "NURSE_CALL", addr: "ward-3", value: "MUTED", state: "SUPPRESSED", tone: "red" },
  ],
  services: [
    { name: "DICOM 104", state: "compromised" },
    { name: "HL7 2575", state: "compromised" },
    { name: "Device VLAN", state: "compromised" },
    { name: "HIS HTTP", state: "up" },
  ],
  exploit: { label: "주입펌프 과투여 주입", detail: "HSP-003 · device unauth" },
  strikeLog: [
    { id: "hs1", time: "22:40", phase: "lateral_movement", text: "의료기기 VLAN 피벗 · device segment", tag: "진행중", current: true },
    { id: "hs2", time: "21:18", phase: "lateral_movement", text: "PACS 영상 IDOR 열람 · HSP-001", tag: "+30" },
    { id: "hs3", time: "19:52", phase: "privilege_escalation", text: "HIS 환자정보 SQLi · HSP-002", tag: "+30" },
    { id: "hs4", time: "17:05", phase: "initial_access", text: "병원 IT 진입 · 기본계정", tag: "+20" },
  ],
  footLine: "22:40 · lateral_movement · hospital_ot · medical_device_vlan_pivot · HIGH · phase=lateral_movement",
  // 실 엔드포인트(VITE_TWIN_HOSPITAL 로 트윈 URL 주입 시 라이브).
  attackChain: [
    { id: "hs-ia", phase: "initial_access", label: "HIS 환자정보 SQLi", vuln: "HSP-002", points: 20, action: { method: "GET", path: "/api/his/patient", body: { id: "1 OR 1=1" } } },
    { id: "hs-lm1", phase: "lateral_movement", label: "PACS 영상 IDOR 열람", vuln: "HSP-001", points: 30, action: { method: "GET", path: "/api/pacs/study", body: { id: "ST-1001" } } },
    { id: "hs-lm2", phase: "lateral_movement", label: "주입펌프 과투여 설정 → RATE 900", vuln: "HSP-003", points: 30, action: { method: "POST", path: "/api/device/infusion", body: { device: "PUMP-07", rate: 900 } } },
    { id: "hs-obj", phase: "objective", label: "투약 안전인터록(SIS) 무력화 → 과투여 파국", vuln: "HSP-005", points: 100, action: { method: "POST", path: "/api/safety/override", body: { override: true } } },
  ],
};

// 상수도: services/water_utility/main.py — 정수/배수·펌프·염소, WTR-001~005.
const WATER: FacilityConfig = {
  id: "water",
  name: "상수도",
  nameEn: "WATER UTILITY",
  meta: "정수장 / 배수장 · SCADA Modbus",
  icon: "water",
  objective: "염소 과투입 + 배수지 범람",
  objectivePoints: 100,
  schematic: "water-process",
  otNodes: [
    { id: "corp", name: "CORP GW", sub: "IT 진입점", xPct: 15, yPct: 27, status: "owned" },
    { id: "hmi", name: "SCADA HMI", sub: "기본계정", xPct: 47, yPct: 28, status: "owned", vulns: ["WTR-003"] },
    { id: "pump", name: "PUMP INTAKE-1", sub: "펌프 제어", xPct: 30, yPct: 65, status: "owned", vulns: ["WTR-002"] },
    { id: "chlor", name: "CHLORINE DOSING", sub: "약품 주입", xPct: 60, yPct: 62, status: "owned", vulns: ["WTR-001"] },
    { id: "resv", name: "RESERVOIR", sub: "배수지 수위", xPct: 87, yPct: 40, status: "target", vulns: ["WTR-004"] },
  ],
  otEdges: [
    { from: "corp", to: "hmi" },
    { from: "hmi", to: "pump" },
    { from: "hmi", to: "chlor" },
    { from: "chlor", to: "resv", active: true },
  ],
  registersTitle: "공정 레지스터 · LIVE",
  registers: [
    { name: "CHLORINE_DOSE", addr: "DOS-1", value: "9.4 ▲", state: "OVERDOSE", tone: "red" },
    { name: "PUMP_SPEED (INTAKE-1)", addr: "PMP", value: "100%", state: "MAX", tone: "amber" },
    { name: "RESERVOIR_LEVEL", addr: "LVL", value: "104% ▲", state: "OVERFLOW", tone: "red" },
    { name: "FLOW_RATE", addr: "FLW", value: "high", state: "—", tone: "neutral" },
    { name: "PRESSURE", addr: "PRS", value: "surge", state: "HIGH", tone: "amber" },
  ],
  services: [
    { name: "Modbus/TCP", state: "compromised" },
    { name: "SCADA HMI", state: "compromised" },
    { name: "Historian", state: "up" },
  ],
  exploit: { label: "염소 과투입 주입", detail: "WTR-001 · dosing tamper" },
  strikeLog: [
    { id: "wt1", time: "33:02", phase: "lateral_movement", text: "염소 주입 조작 · WTR-001", tag: "진행중", current: true },
    { id: "wt2", time: "31:40", phase: "lateral_movement", text: "배수지 펌프 제어 탈취 · WTR-002", tag: "+30" },
    { id: "wt3", time: "29:15", phase: "initial_access", text: "SCADA HMI 기본계정 · WTR-003", tag: "+20" },
    { id: "wt4", time: "27:30", phase: "recon", text: "정수장 자산 매핑", tag: "—" },
  ],
  footLine: "33:02 · lateral_movement · water_utility · chlorine_overdose_reservoir_overflow · HIGH · phase=lateral_movement",
  // 실 엔드포인트(VITE_TWIN_WATER 로 트윈 URL 주입 시 라이브).
  attackChain: [
    { id: "wt-ia", phase: "initial_access", label: "SCADA HMI 기본계정", vuln: "WTR-003", points: 20, action: { method: "POST", path: "/api/hmi/login", body: { username: "operator", password: "operator" } } },
    { id: "wt-lm1", phase: "lateral_movement", label: "배수지 펌프 제어 탈취", vuln: "WTR-002", points: 30, action: { method: "POST", path: "/api/pump/control", body: { pump: "INTAKE-1", action: "stop" } } },
    { id: "wt-lm2", phase: "lateral_movement", label: "염소 과투입 주입", vuln: "WTR-001", points: 30, action: { method: "POST", path: "/api/dosing/chlorine", body: { ppm: 12 } } },
    { id: "wt-obj", phase: "objective", label: "투약 안전인터록(SIS) 무력화 → 급수 오염 파국", vuln: "WTR-001", points: 100, action: { method: "POST", path: "/api/safety/override", body: { override: true } } },
  ],
};

// 나머지 섹터 — 간소 설정(generic 스키매틱). 실 트윈 docstring 기반 식별자 유지.
function generic(
  id: FacilityConfig["id"],
  name: string,
  nameEn: string,
  meta: string,
  icon: FacilityConfig["icon"],
  objective: string,
  crown: { name: string; sub: string; vulns: string[] },
  services: FacilityConfig["services"],
  exploit: FacilityConfig["exploit"],
  registers: FacilityConfig["registers"],
): FacilityConfig {
  return {
    id, name, nameEn, meta, icon, objective, objectivePoints: 100,
    schematic: "generic",
    otNodes: [
      { id: "corp", name: "IT GW", sub: "진입점", xPct: 16, yPct: 28, status: "owned" },
      { id: "mid", name: "ENG / HMI", sub: "운영 콘솔", xPct: 48, yPct: 34, status: "owned" },
      { id: "ctrl", name: "CONTROL", sub: "제어 노드", xPct: 58, yPct: 68, status: "owned" },
      { id: "crown", name: crown.name, sub: crown.sub, xPct: 86, yPct: 32, status: "target", vulns: crown.vulns },
    ],
    otEdges: [
      { from: "corp", to: "mid" },
      { from: "mid", to: "ctrl" },
      { from: "ctrl", to: "crown", active: true },
    ],
    registersTitle: "제어 레지스터 · LIVE",
    registers,
    services,
    exploit,
    strikeLog: [
      { id: `${id}1`, time: "28:10", phase: "lateral_movement", text: `${crown.name} 제어 접근 · ${crown.vulns[0]}`, tag: "진행중", current: true },
      { id: `${id}2`, time: "26:30", phase: "privilege_escalation", text: "운영 콘솔 권한상승", tag: "+30" },
      { id: `${id}3`, time: "24:05", phase: "initial_access", text: "IT 진입 · 초기 침투", tag: "+20" },
      { id: `${id}4`, time: "22:00", phase: "recon", text: `${name} 자산 매핑`, tag: "—" },
    ],
    footLine: `28:10 · lateral_movement · ${id} · ${crown.vulns[0]} · phase=lateral_movement`,
    attackChain: [
      { id: `${id}-ia`, phase: "initial_access", label: "IT 진입 · 초기 침투", vuln: "INIT", points: 20 },
      { id: `${id}-pe`, phase: "privilege_escalation", label: "운영 콘솔 권한상승", vuln: "PRIV", points: 30 },
      { id: `${id}-lm`, phase: "lateral_movement", label: `${crown.name} 제어 접근`, vuln: crown.vulns[0], points: 30 },
      { id: `${id}-obj`, phase: "objective", label: objective, vuln: crown.vulns[0], points: 100 },
    ],
  };
}

const OTHERS: FacilityConfig[] = [
  generic("nuclear", "원자력", "NUCLEAR", "원자로 제어 · SIS", "nuclear", "원자로 안전계통 무력화",
    { name: "REACTOR SIS", sub: "안전 인터록", vulns: ["RX-SIS"] },
    [{ name: "OPC UA", state: "up" }, { name: "Modbus", state: "up" }],
    { label: "SIS bypass", detail: "4-eyes bypass" },
    [{ name: "RX_POWER", addr: "MWt", value: "nominal", state: "OK", tone: "blue" }, { name: "COOLANT", addr: "L", value: "nominal", state: "OK", tone: "blue" }]),
  generic("lng", "가스 · LNG", "LNG TERMINAL", "저장탱크 / BOG / ESD", "lng", "ESD 무력화 → 과압",
    { name: "ESD CONTROLLER", sub: "비상정지", vulns: ["LNG-001"] },
    [{ name: "Modbus", state: "compromised" }, { name: "F&G", state: "up" }],
    { label: "ESD trigger/bypass", detail: "LNG-001 · objective" },
    [{ name: "BOG_PRESSURE", addr: "BAR", value: "surge", state: "HIGH", tone: "red" }, { name: "TANK_LEVEL", addr: "%", value: "98", state: "HIGH", tone: "amber" }]),
  generic("railway", "철도 신호", "RAILWAY SIGNALING", "신호 / ATS / 연동장치", "railway", "신호 현시 위변조 → 충돌 위험",
    { name: "INTERLOCKING", sub: "연동장치", vulns: ["RWY-002"] },
    [{ name: "ATS", state: "compromised" }, { name: "CTC", state: "up" }],
    { label: "signal aspect override", detail: "RWY-001 · objective" },
    [{ name: "SIGNAL_S12", addr: "S12", value: "GREEN", state: "FORCED", tone: "red" }, { name: "ROUTE_R7", addr: "R7", value: "locked", state: "—", tone: "neutral" }]),
  generic("airport", "공항 OT", "AIRPORT OT", "BHS / 활주로등 / 연료", "airport", "활주로등 제어 탈취",
    { name: "RUNWAY LIGHTING", sub: "15L", vulns: ["AIR-001"] },
    [{ name: "BHS", state: "compromised" }, { name: "ATC Net", state: "up" }],
    { label: "runway lighting control", detail: "AIR-001" },
    [{ name: "RWY_15L_LIGHT", addr: "15L", value: "OFF", state: "FORCED", tone: "red" }, { name: "FUEL_VALVE", addr: "FV-3", value: "open", state: "—", tone: "amber" }]),
  generic("finance", "금융", "DATA CENTER BMS", "UPS / CRAC / 발전기", "finance", "CRAC 조작 → 과열 다운",
    { name: "CRAC-3", sub: "정밀공조", vulns: ["DCX-001"] },
    [{ name: "BMS", state: "compromised" }, { name: "DCIM", state: "up" }],
    { label: "CRAC setpoint tamper", detail: "DCX-001" },
    [{ name: "CRAC_SETPOINT", addr: "°C", value: "32 ▲", state: "OVERHEAT", tone: "red" }, { name: "UPS", addr: "%", value: "ok", state: "OK", tone: "blue" }]),
  generic("telecom", "통신", "TELCO 5G CORE", "5G 코어 / 전송", "telecom", "코어망 서비스 거부",
    { name: "5G CORE", sub: "AMF/SMF", vulns: ["TEL-CORE"] },
    [{ name: "N2/N3", state: "compromised" }, { name: "OAM", state: "up" }],
    { label: "core signaling flood", detail: "TEL-CORE" },
    [{ name: "SESSION_LOAD", addr: "%", value: "saturated", state: "DoS", tone: "red" }, { name: "LATENCY", addr: "ms", value: "high", state: "HIGH", tone: "amber" }]),
  generic("satellite", "위성", "GROUND STATION", "지상국 TT&C", "satellite", "TT&C 명령 탈취",
    { name: "TT&C UPLINK", sub: "명령 업링크", vulns: ["GS-002"] },
    [{ name: "Telemetry", state: "compromised" }, { name: "CCSDS", state: "up" }],
    { label: "attitude safety disable", detail: "GS-002 · CCSDS" },
    [{ name: "ATTITUDE_SAFE", addr: "ADCS", value: "DISABLED", state: "BYPASS", tone: "red" }, { name: "DOWNLINK", addr: "dB", value: "ok", state: "OK", tone: "blue" }]),
  generic("factory", "제조", "SMART FACTORY", "PLC / Robot / MES", "factory", "로봇 안전정지 무력화",
    { name: "ROBOT E-STOP", sub: "안전정지", vulns: ["FAC-004"] },
    [{ name: "Profinet", state: "compromised" }, { name: "MES", state: "up" }],
    { label: "robot E-stop override", detail: "FAC-002" },
    [{ name: "ROBOT_SPEED", addr: "R1", value: "max", state: "UNSAFE", tone: "red" }, { name: "ESTOP", addr: "—", value: "OFF", state: "BYPASS", tone: "red" }]),
];

export const FACILITIES: Record<string, FacilityConfig> = Object.fromEntries(
  [POWER, HOSPITAL, WATER, ...OTHERS].map((f) => [f.id, f]),
);

export const FACILITY_ORDER: FacilityConfig["id"][] = [
  "power", "nuclear", "water", "lng", "railway", "airport", "hospital", "finance", "telecom", "satellite", "factory",
];
