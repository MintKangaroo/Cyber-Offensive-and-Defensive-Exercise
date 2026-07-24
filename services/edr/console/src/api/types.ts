// EDR Backend API 응답 타입 (services/edr/api/main.py와 1:1 대응)

export type HostStatus = "online" | "offline";

export interface Host {
  asset: string;
  status: HostStatus;
  last_seen: number;
  process_count: number;
  isolated?: boolean; // Config Service의 quarantine 상태를 합쳐서 표시(프론트에서 별도 조회)
}

export interface ProcessNode {
  asset: string;
  pid: number;
  ppid: number;
  name: string;
  cmdline: string;
  create_time: number;
  username: string | null;
  connections: string; // 백엔드가 str(list)로 저장 - 파싱 필요
  children: ProcessNode[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Alert {
  id: string;
  asset: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  pid: number;
  cmdline: string;
  timestamp: number;
  detail: string;
}

export type KillCommandStatus = "pending" | "done" | "failed" | "rejected";

export interface KillCommand {
  id: string;
  asset: string;
  pid: number;
  reason: string;
  status: KillCommandStatus;
  requested_at: number;
  completed_at: number | null;
  result_detail: string | null;
}

export interface AuditEntry {
  audit_id: string;
  timestamp: number;
  actor: string;
  action: string;
  target: string;
  reason: string;
}

export interface WsAlertMessage {
  type: "alert";
  id: string;
  asset: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  pid: number;
  detail: string;
}
