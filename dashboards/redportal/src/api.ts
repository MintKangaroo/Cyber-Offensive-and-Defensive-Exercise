// Red Portal 백엔드(challenge_portal, 8060) 클라이언트.
// 백엔드 호스트는 페이지를 로드한 호스트를 따른다(WSL IP·Tailscale·localhost 자동 대응).
const H = typeof window !== "undefined" ? window.location.hostname : "localhost";
export const PORTAL = import.meta.env.VITE_PORTAL_URL ?? `http://${H}:8060`;

export interface Challenge {
  id: string;
  category: string;
  difficulty: "easy" | "medium" | "hard" | "insane";
  title: string;
  points_red: number;
  mitre: string[];
  goal: string;
  submit_fields: string[];
  description: string;
  artifacts: string[];
  has_artifact: boolean;
  gate: "artifact" | "service";
  solved?: boolean;
}

export interface SubmitResult {
  passed: boolean;
  points_awarded: number;
  grader_points: number;
  already_solved: boolean;
  detail: string;
}

export interface ScoreRow {
  team_id: string;
  solved: number;
  points: number;
  last_solve: number;
}

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`${r.status}: ${t.slice(0, 200)}`);
  }
  return r.json();
}

export async function fetchChallenges(teamId: string): Promise<{ challenges: Challenge[]; count: number }> {
  return j(`${PORTAL}/portal/challenges?team_id=${encodeURIComponent(teamId)}`);
}

export async function submitFlag(cid: string, teamId: string, fields: Record<string, string>): Promise<SubmitResult> {
  return j(`${PORTAL}/portal/challenges/${cid}/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ team_id: teamId, fields }),
  });
}

export async function fetchScoreboard(): Promise<{ scoreboard: ScoreRow[] }> {
  return j(`${PORTAL}/portal/scoreboard`);
}

export function artifactUrl(cid: string, teamId: string): string {
  return `${PORTAL}/portal/challenges/${cid}/artifact?team_id=${encodeURIComponent(teamId)}`;
}
