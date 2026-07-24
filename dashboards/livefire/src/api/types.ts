// 백엔드 서비스 응답 타입(Event Collector/Scoring Engine/Config Service/Instructor API)

export type EventType =
  | "red_attack_started" | "red_objective_success"
  | "blue_patch_verified" | "blue_detection_success" | "blue_block_success"
  | "asset_compromised" | "asset_recovered" | "flag_exfiltrated"
  | "scenario_started" | "scenario_ended" | "score_updated"
  | "stage_completed" | "red_stealth_bonus" | "unmatched_detection";

export interface RangeEvent {
  event_id: string;
  event_type: EventType;
  timestamp: number;
  actor: "red" | "blue" | "system";
  team_id: string;
  scenario_id: string;
  target_asset: string;
  vuln_id?: string | null;
  phase?: string | null;
  trace_id?: string | null;
  matched_event_id?: string | null;
  challenge_id?: string | null;
  metadata: Record<string, unknown>;
}

export type AssetState = "secure" | "under_attack" | "compromised" | "recovered";
export const ASSETS = ["ground_station", "power_plant", "defense_network"] as const;
export type Asset = (typeof ASSETS)[number];

export interface TeamScore {
  red: number;
  blue: number;
}
export interface ScoresResponse {
  scenario_id: string;
  teams: Record<string, TeamScore>;
}

export interface Achievement {
  achievement_key: string;
  team_id: string;
  scenario_id: string;
  actor: string;
  category: string;
  points: number;
  source_event_id: string;
  created_at: number;
}

export interface PatchState {
  [vulnId: string]: boolean; // true = patched
}
export interface AllPatches {
  [asset: string]: PatchState;
}

export interface FlagEntry {
  vuln_id: string;
  asset: string;
  status: "safe" | "exfiltrated";
  last_event: RangeEvent;
}

export interface AuditEntry {
  audit_id?: string;
  timestamp: number;
  actor: string;
  action: string;
  target: string;
  reason: string;
}

export type Role = "red" | "blue" | "observer" | "instructor";
