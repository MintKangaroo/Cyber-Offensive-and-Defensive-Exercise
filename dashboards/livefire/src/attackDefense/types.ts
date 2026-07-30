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
  penalty: number;
  adjustment: number;
  total: number;
  last_updated_round: number;
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
}

export const NAVIGATION: Record<LiveRole, string[]> = {
  competitor: [
    "Battle Overview", "Attack Console", "Defense Console", "Services",
    "Patches", "Scoreboard", "Event Feed", "Team Settings",
  ],
  operator: [
    "Command Center", "Match Control", "Team Matrix", "Service Matrix",
    "Round Control", "Flag Operations", "Checker Operations", "Patch Review",
    "Scoring", "Evidence", "Infrastructure", "Observability",
  ],
  observer: ["Live Overview", "Scoreboard", "Match Timeline", "Service Status", "Major Events"],
};
