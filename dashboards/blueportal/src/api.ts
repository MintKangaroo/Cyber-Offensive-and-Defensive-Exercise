// Blue Portal 클라이언트. 백엔드 호스트는 페이지 로드 호스트를 따른다(WSL/Tailscale/localhost 자동).
const H = typeof window !== "undefined" ? window.location.hostname : "localhost";
export const PORTAL = import.meta.env.VITE_PORTAL_URL ?? `http://${H}:8060`;
export const CONFIG = import.meta.env.VITE_CONFIG_SERVICE_URL ?? `http://${H}:8030`;
export const EVENTS = import.meta.env.VITE_EVENT_COLLECTOR_URL ?? `http://${H}:8010`;

export interface BlueChallenge {
  id: string;
  category: string;
  difficulty: "easy" | "medium" | "hard" | "insane";
  title: string;
  points_blue: number;
  mitre: string[];
  goal: string;
  success_criteria: string;
  description: string;
  solved?: boolean;
}
export interface BlueSubmitResult {
  passed: boolean;
  points_awarded: number;
  already_solved: boolean;
  detail: string;
}
export interface ScoreRow { team_id: string; solved: number; points: number; last_solve: number; }
export interface RangeEvent {
  event_id: string; event_type: string; timestamp: number; actor: string;
  team_id: string; target_asset: string; vuln_id?: string | null; phase?: string | null;
}
export type Patches = Record<string, Record<string, boolean>>;

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`${r.status}: ${(await r.text().catch(() => "")).slice(0, 200)}`);
  return r.json();
}

export const fetchBlueChallenges = (team: string) =>
  j<{ challenges: BlueChallenge[]; count: number }>(`${PORTAL}/portal/blue/challenges?team_id=${encodeURIComponent(team)}`);
export const submitRule = (cid: string, team: string, rule_yaml: string) =>
  j<BlueSubmitResult>(`${PORTAL}/portal/blue/challenges/${cid}/submit`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ team_id: team, rule_yaml }),
  });
export const fetchBlueScoreboard = () => j<{ scoreboard: ScoreRow[] }>(`${PORTAL}/portal/blue/scoreboard`);
export const datasetUrl = (cid: string, which: "attack" | "normal") =>
  `${PORTAL}/portal/blue/challenges/${cid}/dataset?which=${which}`;

export const fetchEvents = (limit = 40) => j<{ events: RangeEvent[] }>(`${EVENTS}/events?limit=${limit}`);
// 패치 보드는 포털이 전체 취약점 카탈로그 + 라이브 상태를 병합해 제공(config_service 프록시).
export const fetchPatches = () => j<Patches>(`${PORTAL}/portal/blue/patches`);
export const togglePatch = (asset: string, vuln_id: string, patched: boolean, reason: string) =>
  j(`${PORTAL}/portal/blue/patch`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asset, vuln_id, patched, reason }),
  });
