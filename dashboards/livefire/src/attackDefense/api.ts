import type {
  AttackSurface, BroadcastSnapshot, CaptureRecord, KothState, LiveRole, MatchState, PatchRecord, ScoreboardResponse,
  ServiceInstance, StealthState, SubmissionResult,
  TournamentState,
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
  getBroadcastSnapshot(matchId: string): Promise<BroadcastSnapshot>;
  getState(matchId: string, role: LiveRole, token: string): Promise<MatchState>;
  getServices(matchId: string, role: LiveRole, token: string): Promise<ServiceInstance[]>;
  getScoreboard(matchId: string, role: LiveRole, token: string): Promise<ScoreboardResponse>;
  getAttackSurface(matchId: string, token: string): Promise<AttackSurface>;
  getPatches(matchId: string, role: LiveRole, token: string): Promise<PatchRecord[]>;
  getCaptures(matchId: string, role: LiveRole, token: string): Promise<CaptureRecord[]>;
  getKoth(matchId: string, role: LiveRole, token: string): Promise<KothState>;
  getStealth(matchId: string, role: LiveRole, token: string): Promise<StealthState>;
  getTournament(
    tournamentId: string, role: LiveRole, token: string,
  ): Promise<TournamentState>;
  submitStealthDetection(
    matchId: string, token: string, serviceId: string,
    indicatorHash: string, evidenceSummary: string,
  ): Promise<{ recorded: boolean; status: string; report_id: string }>;
  submitFlag(matchId: string, token: string, flag: string): Promise<SubmissionResult>;
  submitPatch(matchId: string, serviceId: string, token: string, imageReference: string): Promise<PatchRecord>;
  operatorAction(matchId: string, action: string, token: string, reason: string): Promise<unknown>;
  operatorServiceAction(
    matchId: string, teamId: string, serviceId: string,
    action: "restart" | "rollback", token: string, reason: string,
  ): Promise<unknown>;
  uploadCapture(
    matchId: string, token: string, file: File, reason: string,
  ): Promise<CaptureRecord>;
  downloadCapture(
    matchId: string, captureId: string, token: string,
  ): Promise<{ blob: Blob; filename: string }>;
}

export const httpAttackDefenseApi: AttackDefenseApi = {
  getBroadcastSnapshot(matchId) {
    return request(
      `/api/attack-defense/public/matches/${encodeURIComponent(matchId)}/broadcast`,
    );
  },
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
  async getCaptures(matchId, role, token) {
    if (role === "observer") return [];
    const path = role === "operator"
      ? `/api/attack-defense/operator/matches/${matchId}/captures`
      : `/api/attack-defense/matches/${matchId}/captures`;
    const result = await request<{ captures: CaptureRecord[] }>(path, token);
    return result.captures;
  },
  getKoth(matchId, role, token) {
    const path = role === "operator"
      ? `/api/attack-defense/operator/matches/${matchId}/koth`
      : `/api/attack-defense/matches/${matchId}/koth`;
    return request(path, token);
  },
  getStealth(matchId, role, token) {
    const path = role === "operator"
      ? `/api/attack-defense/operator/matches/${matchId}/stealth`
      : role === "observer"
        ? `/api/attack-defense/public/matches/${matchId}/stealth/summary`
        : `/api/attack-defense/matches/${matchId}/stealth`;
    return request(path, token);
  },
  getTournament(tournamentId, role, token) {
    const path = role === "operator"
      ? `/api/attack-defense/operator/tournaments/${tournamentId}`
      : role === "competitor"
        ? `/api/attack-defense/tournaments/${tournamentId}`
        : `/api/attack-defense/public/tournaments/${tournamentId}`;
    return request(path, token);
  },
  submitStealthDetection(matchId, token, serviceId, indicatorHash, evidenceSummary) {
    return request(
      `/api/attack-defense/matches/${matchId}/stealth/detections`, token,
      {
        method: "POST",
        headers: { "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          service_id: serviceId,
          indicator_hash: indicatorHash,
          evidence_summary: evidenceSummary,
        }),
      },
    );
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
  async uploadCapture(matchId, token, file, reason) {
    const response = await fetch(
      `${AD_API}/api/attack-defense/operator/matches/${matchId}/captures`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/vnd.tcpdump.pcap",
          "X-Operation-Reason": reason,
        },
        body: file,
      },
    );
    if (!response.ok) throw new Error(`${response.status} capture upload failed`);
    return response.json() as Promise<CaptureRecord>;
  },
  async downloadCapture(matchId, captureId, token) {
    const response = await fetch(
      `${AD_API}/api/attack-defense/matches/${matchId}/captures/${captureId}/download`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    if (!response.ok) throw new Error(`${response.status} capture download failed`);
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const filename = disposition.match(/filename="([^"]+)"/)?.[1]
      ?? `capture-${captureId}.pcap`;
    return { blob: await response.blob(), filename };
  },
};

export async function login(username: string, password: string) {
  const response = await fetch(`${AUTH_API}/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    credentials: "include", body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw new Error("Invalid credentials");
  return response.json() as Promise<{
    role: string; team_id: string; match_id: string; tournament_id: string;
    access_token: string;
  }>;
}

export function decodeRole(token: string): {
  role: LiveRole; teamId: string; matchId: string; tournamentId: string;
} {
  try {
    const claims = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const role: LiveRole = ["instructor", "operator"].includes(claims.role)
      ? "operator" : claims.role === "observer" ? "observer" : "competitor";
    return {
      role,
      teamId: claims.team_id ?? "",
      matchId: claims.match_id ?? "",
      tournamentId: claims.tournament_id ?? "",
    };
  } catch {
    return {
      role: "observer", teamId: "", matchId: "", tournamentId: "",
    };
  }
}
