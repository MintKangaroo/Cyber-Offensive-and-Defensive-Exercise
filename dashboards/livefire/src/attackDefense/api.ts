import type {
  AttackSurface, LiveRole, MatchState, PatchRecord, ScoreboardResponse,
  ServiceInstance, SubmissionResult,
} from "./types";

const host = typeof window !== "undefined" ? window.location.hostname : "localhost";
const AD_API = import.meta.env.VITE_ATTACK_DEFENSE_API_URL ?? `http://${host}:8100`;
const AUTH_API = import.meta.env.VITE_AUTH_API_URL ?? `http://${host}:8051`;

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
    const message = await response.text().catch(() => "");
    const error = new Error(`${response.status} ${message}`) as Error & { status?: number };
    error.status = response.status;
    throw error;
  }
  return response.json() as Promise<T>;
}

export interface AttackDefenseApi {
  getState(matchId: string, role: LiveRole, token: string): Promise<MatchState>;
  getServices(matchId: string, role: LiveRole, token: string): Promise<ServiceInstance[]>;
  getScoreboard(matchId: string, role: LiveRole, token: string): Promise<ScoreboardResponse>;
  getAttackSurface(matchId: string, token: string): Promise<AttackSurface>;
  getPatches(matchId: string, role: LiveRole, token: string): Promise<PatchRecord[]>;
  submitFlag(matchId: string, token: string, flag: string): Promise<SubmissionResult>;
  submitPatch(matchId: string, serviceId: string, token: string, imageReference: string): Promise<PatchRecord>;
  operatorAction(matchId: string, action: string, token: string, reason: string): Promise<unknown>;
  operatorServiceAction(
    matchId: string, teamId: string, serviceId: string,
    action: "restart" | "rollback", token: string, reason: string,
  ): Promise<unknown>;
}

export const httpAttackDefenseApi: AttackDefenseApi = {
  getState(matchId, role, token) {
    if (role === "competitor") {
      return request(`/api/attack-defense/matches/${matchId}/state`, token);
    }
    return request(`/api/attack-defense/public/matches/${matchId}/state`, token);
  },
  async getServices(matchId, role, token) {
    if (role === "competitor") {
      const result = await request<{ services: ServiceInstance[] }>(
        `/api/attack-defense/matches/${matchId}/services/me`, token,
      );
      return result.services;
    }
    if (role === "operator") {
      const result = await request<{ services: ServiceInstance[] }>(
        `/api/attack-defense/operator/matches/${matchId}/services`, token,
      );
      return result.services;
    }
    const result = await request<{ services: ServiceInstance[] }>(
      `/api/attack-defense/public/matches/${matchId}/service-summary`,
    );
    return result.services;
  },
  getScoreboard(matchId, role, token) {
    const path = role === "operator"
      ? `/api/attack-defense/operator/matches/${matchId}/scoreboard`
      : `/api/attack-defense/matches/${matchId}/scoreboard`;
    return request(path, token);
  },
  getAttackSurface(matchId, token) {
    return request(`/api/attack-defense/matches/${matchId}/attack-surface`, token);
  },
  async getPatches(matchId, role, token) {
    const path = role === "operator"
      ? `/api/attack-defense/operator/matches/${matchId}/patches`
      : `/api/attack-defense/matches/${matchId}/patches`;
    const result = await request<{ patches: PatchRecord[] }>(path, token);
    return result.patches;
  },
  submitFlag(matchId, token, flag) {
    return request(`/api/attack-defense/matches/${matchId}/flags/submit`, token, {
      method: "POST", body: JSON.stringify({ flag }),
    });
  },
  submitPatch(matchId, serviceId, token, imageReference) {
    return request(
      `/api/attack-defense/matches/${matchId}/services/${serviceId}/patches`, token,
      { method: "POST", body: JSON.stringify({ image_reference: imageReference }) },
    );
  },
  operatorAction(matchId, action, token, reason) {
    const suffix = action === "finalize"
      ? "rounds/current/finalize"
      : action;
    return request(`/api/attack-defense/matches/${matchId}/${suffix}`, token, {
      method: "POST",
      body: action === "finalize" ? undefined : JSON.stringify({ reason }),
    });
  },
  operatorServiceAction(matchId, teamId, serviceId, action, token, reason) {
    return request(
      `/api/attack-defense/operator/matches/${matchId}/teams/${teamId}/services/${serviceId}/${action}`,
      token,
      { method: "POST", body: JSON.stringify({ reason }) },
    );
  },
};

export async function login(username: string, password: string) {
  const response = await fetch(`${AUTH_API}/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    credentials: "include", body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error("Invalid credentials");
  return response.json() as Promise<{
    role: string; team_id: string; match_id: string; access_token: string;
  }>;
}

export function decodeRole(token: string): { role: LiveRole; teamId: string; matchId: string } {
  try {
    const claims = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const role: LiveRole = ["instructor", "operator"].includes(claims.role)
      ? "operator" : claims.role === "observer" ? "observer" : "competitor";
    return { role, teamId: claims.team_id ?? "", matchId: claims.match_id ?? "" };
  } catch {
    return { role: "observer", teamId: "", matchId: "" };
  }
}
