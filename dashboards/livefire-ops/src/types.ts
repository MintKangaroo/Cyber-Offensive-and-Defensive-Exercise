// 도메인 타입 — shared/event_schema.py 의 RedPhase/EventType 와 11 ICS 트윈에 대응.

/** shared/event_schema.py RedPhase (점수: data.ts PHASE_POINTS) */
export type RedPhase =
  | "recon"
  | "initial_access"
  | "privilege_escalation"
  | "lateral_movement"
  | "data_exfiltration"
  | "objective"
  | "impact";

export type NodeStatus = "locked" | "owned" | "target" | "held" | "patched";

/** 아레나(현황) 성좌의 시설 노드 */
export interface ArenaNode {
  id: string;
  label: string; // 한글 시설/자산명
  code: string; // 취약점/식별자 (PP-005 등)
  sector: SectorId;
  xPct: number;
  yPct: number;
  status: "engaged" | "defended" | "patched" | "active";
}

export type SectorId =
  | "power"
  | "nuclear"
  | "water"
  | "lng"
  | "railway"
  | "airport"
  | "hospital"
  | "finance"
  | "telecom"
  | "satellite"
  | "factory";

/** 시설 콘솔의 OT 침투맵 노드 */
export interface OtNode {
  id: string;
  name: string;
  sub: string;
  xPct: number;
  yPct: number;
  status: NodeStatus;
  protocols?: string[];
  vulns?: string[];
}

/** OT 맵의 엣지(측면이동 경로); active=현재 타격 아크 */
export interface OtEdge {
  from: string;
  to: string;
  active?: boolean;
}

/** 시설별 물리/자산 레지스터 테이블 행 */
export interface RegisterRow {
  name: string;
  addr: string;
  value: string;
  state: string;
  tone: "red" | "amber" | "blue" | "neutral";
}

export type ServiceState = "up" | "compromised" | "down";
export interface ServiceRow {
  name: string;
  state: ServiceState;
}

/** 시설별 물리 스키매틱 종류 — 발전소는 발전소답게, 병원은 병원답게 */
export type SchematicKind = "power-oneline" | "hospital-vitals" | "water-process" | "generic";

export interface FacilityConfig {
  id: SectorId;
  name: string; // 한글
  nameEn: string;
  meta: string; // 프로토콜/포트 등
  icon: IconKind;
  objective: string;
  objectivePoints: number;
  otNodes: OtNode[];
  otEdges: OtEdge[];
  schematic: SchematicKind;
  registersTitle: string;
  registers: RegisterRow[];
  services: ServiceRow[];
  exploit: { label: string; detail: string };
  strikeLog: StrikeLogEntry[]; // 시설별 스트라이크 로그(발전소 상수 재사용 금지)
  footLine: string; // 하단 티커의 시설별 활성 라인
  attackChain: AttackStep[]; // 킬체인 단계별 실행공격
}

/** 킬체인 실행 단계. action 이 있으면 실제 트윈 엔드포인트를 호출(발전소=라이브). */
export interface AttackStep {
  id: string;
  phase: RedPhase;
  label: string;
  vuln: string;
  points: number;
  action?: { method: "GET" | "POST"; path: string; body: Record<string, unknown> };
}

export type IconKind =
  | "power"
  | "nuclear"
  | "water"
  | "lng"
  | "railway"
  | "airport"
  | "hospital"
  | "finance"
  | "telecom"
  | "satellite"
  | "factory";

export interface SolveEntry {
  id: string;
  side: "attack" | "defense";
  team: string;
  text: string;
  points?: number;
}

export interface ScoreRow {
  rank: number;
  team: string;
  score: number;
  atk?: number; // 라이브 공격 점수(있으면 콘솔 리더보드가 실제값 표시)
  def?: number; // 라이브 방어 점수
  me?: boolean;
}

export interface StrikeLogEntry {
  id: string;
  time: string; // mm:ss
  phase: RedPhase;
  text: string;
  tag: string; // 점수/CRIT 표기
  current?: boolean;
}

export interface PhaseStep {
  phase: RedPhase;
  label: string;
  points?: number;
  state: "done" | "active" | "todo";
}

/** 발전소 라이브 물리 텔레메트리 (트윈 /api/telemetry) */
export interface PowerTelemetry {
  actual_rpm: number;
  cmd_rpm: number;
  coolant_flow: number;
  coolant_temp: number;
  damage: number;
  interlock: boolean; // SIS coil0
  failed: boolean;
}
