const host = typeof window !== "undefined" ? window.location.hostname : "localhost";
export const AD_API = import.meta.env.VITE_ATTACK_DEFENSE_API_URL ?? `http://${host}:8100`;
export const AUTH_API = import.meta.env.VITE_AUTH_API_URL ?? `http://${host}:8051`;

export interface Session {
  access_token: string;
  role: string;
  team_id: string;
  match_id: string;
}

export interface MatchState {
  id: string;
  name: string;
  status: string;
  round: number;
  round_status?: string | null;
  round_ends_at?: number | null;
  server_time: number;
  team: { id: string; name: string };
}

export interface AttackTarget {
  team_id: string;
  team: string;
  team_slug: string;
  service_id: string;
  service: string;
  service_slug: string;
  scheme: "http" | "https";
  public_port: number;
}

export interface AttackSurface {
  teams: Array<{ id: string; name: string; slug: string }>;
  services: Array<{ id: string; name: string; slug: string }>;
  targets: AttackTarget[];
  disclosure: string;
}

export interface ScoreRow {
  rank: number;
  team_id: string;
  team: string;
  attack: number;
  defense: number;
  availability: number;
  total: number;
}

async function request<T>(path: string, token = "", init?: RequestInit): Promise<T> {
  const response = await fetch(`${AD_API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${(await response.text().catch(() => "")).slice(0, 240)}`);
  }
  return response.json() as Promise<T>;
}

export async function login(username: string, password: string): Promise<Session> {
  const response = await fetch(`${AUTH_API}/auth/login`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error("로그인 정보를 확인하세요.");
  const session = await response.json() as Session;
  if (!session.team_id || !session.match_id) {
    throw new Error("A/D 경기 참가자 계정이 아닙니다.");
  }
  return session;
}

export const getState = (matchId: string, token: string) =>
  request<MatchState>(`/api/attack-defense/matches/${encodeURIComponent(matchId)}/state`, token);

export const getAttackSurface = (matchId: string, token: string) =>
  request<AttackSurface>(
    `/api/attack-defense/matches/${encodeURIComponent(matchId)}/attack-surface`, token,
  );

export const getScoreboard = (matchId: string) =>
  request<{ scoreboard: ScoreRow[] }>(
    `/api/attack-defense/matches/${encodeURIComponent(matchId)}/scoreboard`,
  );

export const submitCapturedFlag = (matchId: string, token: string, flag: string) =>
  request<{ accepted: boolean; status: string; score_delta?: number; reason?: string }>(
    `/api/attack-defense/matches/${encodeURIComponent(matchId)}/flags/submit`, token,
    { method: "POST", body: JSON.stringify({ flag }) },
  );

export function targetBaseUrl(target: AttackTarget): string {
  return `${target.scheme}://${host}:${target.public_port}`;
}

export async function sendTargetRequest(
  target: AttackTarget,
  method: string,
  path: string,
  bearer: string,
  body: string,
): Promise<{ status: number; elapsed_ms: number; headers: string; body: string }> {
  const started = performance.now();
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const response = await fetch(`${targetBaseUrl(target)}${normalizedPath}`, {
    method,
    headers: {
      ...(bearer.trim() ? { Authorization: `Bearer ${bearer.trim()}` } : {}),
      ...(body.trim() ? { "Content-Type": "application/json" } : {}),
    },
    body: ["GET", "HEAD"].includes(method) || !body.trim() ? undefined : body,
  });
  return {
    status: response.status,
    elapsed_ms: Math.round(performance.now() - started),
    headers: [...response.headers.entries()].map(([key, value]) => `${key}: ${value}`).join("\n"),
    body: await response.text(),
  };
}
