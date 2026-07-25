// Range Control(8055) 클라이언트 — 교관 전용(#9 Match · #10 Reset · #11 Safety).
// 호스트는 페이지 로드 호스트를 따른다(WSL/Tailscale/localhost 자동).
const H = typeof window !== "undefined" ? window.location.hostname : "localhost";
export const RANGE = import.meta.env.VITE_RANGE_CONTROL_URL ?? `http://${H}:8055`;

export interface SafetyStatus {
  internet_egress: string;
  cross_team_traffic: string;
  docker_socket_exposure: string;
  active_emergency_stop: boolean;
  unauthorized_destination_attempts: number;
  paused_teams: string[];
  range_containment_score: string;
}
export interface Match {
  range_id: string; match_id: string;
  red_teams: string[]; blue_teams: string[]; twin_set: string[]; scenario_id: string;
}

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`${r.status}: ${(await r.text().catch(() => "")).slice(0, 160)}`);
  return r.json();
}
const auth = (token: string) => ({ Authorization: `Bearer ${token}`, "Content-Type": "application/json" });

export const fetchSafetyStatus = () => j<{ safety: SafetyStatus }>(`${RANGE}/safety/status`);
export const emergencyStop = (reason: string, token: string) =>
  j(`${RANGE}/safety/emergency-stop`, { method: "POST", headers: auth(token), body: JSON.stringify({ reason }) });
export const releaseEmergencyStop = (reason: string, token: string) =>
  j(`${RANGE}/safety/emergency-stop/release`, { method: "POST", headers: auth(token), body: JSON.stringify({ reason }) });
export const teamPause = (team_id: string, paused: boolean, token: string) =>
  j(`${RANGE}/safety/team-pause`, { method: "POST", headers: auth(token), body: JSON.stringify({ team_id, paused }) });

export const resetRange = (rangeId: string, reason: string, token: string) =>
  j(`${RANGE}/ranges/${encodeURIComponent(rangeId)}/reset`, { method: "POST", headers: auth(token), body: JSON.stringify({ reason }) });
export const verifyBaseline = (rangeId: string, token: string) =>
  j<{ passed: boolean; verdict: string; checks: Record<string, unknown> }>(
    `${RANGE}/ranges/${encodeURIComponent(rangeId)}/verify-baseline`, { method: "POST", headers: auth(token), body: "{}" });
export const snapshotRange = (rangeId: string, reason: string, token: string) =>
  j(`${RANGE}/ranges/${encodeURIComponent(rangeId)}/snapshot`, { method: "POST", headers: auth(token), body: JSON.stringify({ reason }) });

export const fetchMatches = () => j<{ matches: Match[]; count: number }>(`${RANGE}/matches`);
export const createMatch = (m: Partial<Match>, token: string) =>
  j(`${RANGE}/matches`, { method: "POST", headers: auth(token), body: JSON.stringify(m) });
