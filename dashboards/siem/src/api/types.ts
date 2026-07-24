// SIEM API(services/siem/api/main.py) 응답 타입

export interface NormalizedEvent {
  event_id: string;
  timestamp: string;
  ingested_at: string;
  source_type: string;
  source_ip: string | null;
  host: string | null;
  asset: string | null;
  severity: number; // 0(info)~4(critical)
  category: string;
  action: string | null;
  src: { ip: string | null; port: number | null } | null;
  dst: { ip: string | null; port: number | null } | null;
  signature: string | null;
  mitre: string[];
  trace_id: string | null;
  vuln_id: string | null;
  team_id: string | null;
  message: string;
  tags: string[];
}

export interface Alert {
  id: string;
  rule_id: string;
  title: string;
  severity: number;
  mitre: string; // JSON 문자열(백엔드가 json.dumps로 저장) - 파싱 필요
  status: "open" | "ack" | "closed";
  timestamp: number;
  detail: string;
  matched_event: string;
}

export interface SourceHealthEntry {
  last_seen: number | null;
  lines_ingested: number;
  parse_errors: number;
  status: "green" | "red";
  seconds_since_last: number | null;
}

export interface Stats {
  events_by_source: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  top_signatures: { rule_id: string; title: string; c: number }[];
}

export interface AttackCoverage {
  technique_coverage: Record<string, string[]>; // technique_id -> rule_ids
  total_rules: number;
}

export const SEVERITY_LABEL: Record<number, string> = {
  0: "INFO",
  1: "LOW",
  2: "MEDIUM",
  3: "HIGH",
  4: "CRITICAL",
};
