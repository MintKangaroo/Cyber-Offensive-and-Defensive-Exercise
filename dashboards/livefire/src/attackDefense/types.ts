export type MatchMode = "exercise" | "attack_defense" | "hybrid_live_fire";
export type LiveRole = "competitor" | "operator" | "observer";
export type MatchStatus = "draft" | "running" | "paused" | "ended" | "failed";
export type ConnectionState = "connecting" | "live" | "degraded" | "offline";
export type AsyncState = "loading" | "empty" | "stale" | "degraded" | "unauthorized" | "error" | "reconnecting" | "normal";

export interface MatchState {
  id: string;
  name: string;
  mode: MatchMode;
  status: MatchStatus;
  starts_at: number | null;
  round: number;
  round_status?: string | null;
  round_ends_at?: number | null;
  server_time: number;
  team?: { id: string; name: string };
}

export interface ServiceInstance {
  id: string;
  service_id: string;
  service: string;
  team_id?: string;
  team_slug?: string;
  service_slug?: string;
  status: string;
  image_digest?: string | null;
  previous_image_digest?: string | null;
  last_health_at?: number | null;
  deployed_at?: number | null;
  updated_at: number;
  healthy?: number;
  degraded?: number;
  total?: number;
}

export interface ScoreRow {
  rank: number;
  team_id: string;
  team: string;
  slug: string;
  attack: number;
  defense: number;
  flag_defense: number;
  availability: number;
  detection: number;
  containment: number;
  recovery: number;
  incident_response: number;
  mission_inject: number;
  koth: number;
  stealth_attack: number;
  stealth_detection: number;
  penalty: number;
  adjustment: number;
  total: number;
  last_updated_round: number;
}

export interface KothHill {
  id: string;
  victim_team_id: string;
  victim_team: string;
  victim_team_slug: string;
  service_id: string;
  service: string;
  service_slug: string;
  status: "owned" | "unclaimed";
  owner_team_id?: string | null;
  owner_team?: string | null;
  owner_team_slug?: string | null;
  expires_after_round?: number | null;
  remaining_rounds: number;
  points_per_round: number;
  lease_sequence?: number;
  acquired_round?: number;
  acquired_at?: number;
}

export interface KothState {
  enabled: boolean;
  round: number;
  lease_rounds: number;
  points_per_round: number;
  score_weight: number;
  hills: KothHill[];
  disclosure: string;
}

export interface StealthIncident {
  id?: string;
  occurred_round?: number;
  occurred_sequence?: number;
  service_id: string;
  service?: string;
  service_slug?: string;
  status?: string;
  detected?: number;
  undetected?: number;
  total?: number;
  disclosed?: boolean;
  victim_team?: string;
  attacker_team?: string;
}

export interface StealthReport {
  id: string;
  round_id?: string;
  service_id: string;
  submitted_at: number;
  status?: string;
}

export interface StealthState {
  enabled: boolean;
  round: number;
  alert_delay_rounds: number;
  detection_window_rounds: number;
  attacker_undetected_points: number;
  defender_detection_points: number;
  incidents: StealthIncident[];
  reports: StealthReport[];
  disclosure: string;
}

export interface ScoreboardResponse {
  view: "public" | "operator";
  delay_rounds?: number;
  last_public_round?: number;
  provisional?: boolean;
  scoreboard: ScoreRow[];
}

export interface AttackSurface {
  teams: Array<{ id: string; name: string; slug: string }>;
  services: Array<{ id: string; name: string; slug: string }>;
  disclosure: string;
}

export interface PatchRecord {
  id: string;
  match_id: string;
  team_id?: string;
  service_id: string;
  image_reference: string;
  image_digest?: string | null;
  status: string;
  validation_result: Record<string, unknown>;
  submitted_at: number;
  validated_at?: number | null;
  deployed_at?: number | null;
}

export interface CaptureRecord {
  id: string;
  match_id: string;
  round_id?: string | null;
  round?: number | null;
  service_id?: string | null;
  service?: string | null;
  status: "available" | "withheld";
  available: boolean;
  captured_from: number;
  captured_until: number;
  release_at: number;
  packet_count: number;
  size_bytes: number;
  format: "pcap";
  privacy: string;
  raw_sha256?: string;
  sanitized_sha256?: string;
  source_size_bytes?: number;
  redaction_count?: number;
  address_count?: number;
  link_type?: number;
  sanitizer_version?: string;
}

export interface LiveEvent {
  event_id: string;
  category: "attack" | "defense" | "service" | "patch" | "score" | "system";
  type: string;
  result: string;
  timestamp: number;
  team_id?: string;
  service_id?: string;
  metadata?: Record<string, unknown>;
  scope?: "own_team";
}

export interface SubmissionResult {
  accepted: boolean;
  status: "accepted" | "rejected";
  score_delta?: number;
  reason?: "invalid_or_inactive";
}

export interface RuntimeSnapshot {
  state: MatchState | null;
  services: ServiceInstance[];
  scoreboard: ScoreboardResponse | null;
  attackSurface: AttackSurface | null;
  patches: PatchRecord[];
  captures: CaptureRecord[];
  koth: KothState | null;
  stealth: StealthState | null;
}

export const NAVIGATION: Record<LiveRole, string[]> = {
  competitor: [
    "Battle Overview", "Attack Console", "Defense Console", "Services",
    "Patches", "Captures", "Scoreboard", "Event Feed", "Team Settings",
  ],
  operator: [
    "Command Center", "Match Control", "Team Matrix", "Service Matrix",
    "Round Control", "Flag Operations", "Checker Operations", "Patch Review",
    "Scoring", "Evidence", "Infrastructure", "Observability",
  ],
  observer: ["Live Overview", "Scoreboard", "Match Timeline", "Service Status", "Major Events"],
};
