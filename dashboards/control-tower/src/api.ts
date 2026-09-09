import {
  createClient,
  object,
  objects,
  str,
  num,
  type JsonObject,
  type RangeEvent,
  normalizeEvent,
} from "@cyber-range/command-system";
export type Role =
  "instructor" | "operator" | "competitor" | "red" | "blue" | "observer";
export interface Session {
  actor: string;
  role: Role;
  team_id: string;
  match_id: string;
  capabilities: string[];
  observer_delay_sec: number;
}
export type SourceStatus =
  "ready" | "unavailable" | "unauthorized" | "error" | "loading";
export interface Source {
  status: SourceStatus;
  data: JsonObject | null;
  observed_at: number | null;
  source: string;
  message?: string;
}
export interface Asset {
  id: string;
  name: string;
  protocol: string;
  scope: string;
  health: null;
}
export interface Snapshot {
  scenario_id: string;
  generated_at: number;
  sources: Record<string, Source>;
  assets: Asset[];
}
export interface Incident extends JsonObject {
  id: string;
  title: string;
  severity: string;
  status: string;
  team_id: string;
  host: string;
  source_alert_id: string;
  created_at: number;
  acknowledged_at: number | null;
  closed_at: number | null;
  assignee: string | null;
  timeline: JsonObject[];
  sla: JsonObject;
}
const host = location.hostname;
export const gateway = location.pathname.startsWith("/control/");
export const COMMAND_BASE =
  import.meta.env.VITE_COMMAND_API_URL ??
  (gateway
    ? "/api/instructor/command"
    : `${location.protocol}//${host}:8050/command`);
export const AUTH_BASE =
  import.meta.env.VITE_AUTH_API_URL ??
  (gateway ? "" : `${location.protocol}//${host}:8051`);
let accessToken = "";
export const setAccessToken = (token: string) => {
  accessToken = token;
};
export const getAccessToken = () => accessToken;
export const api = createClient(COMMAND_BASE, getAccessToken);
export const authApi = createClient(AUTH_BASE, getAccessToken);
export async function getSession(): Promise<Session> {
  const s = await api("/session");
  const role = str(s.role);
  if (
    ![
      "instructor",
      "operator",
      "competitor",
      "red",
      "blue",
      "observer",
    ].includes(role) ||
    !Array.isArray(s.capabilities)
  )
    throw new Error("Invalid session response");
  return {
    actor: str(s.actor),
    role: role as Role,
    team_id: str(s.team_id),
    match_id: str(s.match_id),
    capabilities: s.capabilities.filter(
      (v): v is string => typeof v === "string",
    ),
    observer_delay_sec: num(s.observer_delay_sec) ?? 30,
  };
}
export const post = (path: string, data: unknown) =>
  api(path, {
    method: "POST",
    body: JSON.stringify(data),
    timeoutMs:
      path === "/control" ? 90000 : path === "/copilot" ? 75000 : 15000,
  });
export function parseSnapshot(value: unknown): Snapshot {
  const raw = object(value);
  const sources: Record<string, Source> = {};
  for (const [key, value] of Object.entries(object(raw.sources))) {
    const s = object(value);
    const status = str(s.status);
    if (!["ready", "unavailable", "unauthorized", "error"].includes(status))
      continue;
    sources[key] = {
      status: status as SourceStatus,
      data: s.data === null ? null : object(s.data),
      observed_at: num(s.observed_at),
      source: str(s.source),
      message: str(s.message),
    };
  }
  return {
    scenario_id: str(raw.scenario_id),
    generated_at: num(raw.generated_at) ?? 0,
    sources,
    assets: objects(raw.assets)
      .filter((a) => str(a.id))
      .map((a) => ({
        id: str(a.id),
        name: str(a.name),
        protocol: str(a.protocol),
        scope: str(a.scope),
        health: null,
      })),
  };
}
export function eventsFrom(source: Source | undefined): RangeEvent[] {
  return objects(source?.data?.events)
    .map(normalizeEvent)
    .filter((e): e is RangeEvent => e !== null);
}
export function incidentFrom(value: unknown): Incident {
  const r = object(value);
  return {
    ...r,
    id: str(r.id),
    title: str(r.title),
    severity: str(r.severity),
    status: str(r.status),
    team_id: str(r.team_id),
    host: str(r.host),
    source_alert_id: str(r.source_alert_id),
    created_at: num(r.created_at) ?? 0,
    acknowledged_at: num(r.acknowledged_at),
    closed_at: num(r.closed_at),
    assignee: str(r.assignee) || null,
    timeline: objects(r.timeline),
    sla: object(r.sla),
  };
}
export const time = (epoch: unknown) =>
  typeof epoch === "number" && Number.isFinite(epoch)
    ? new Date(epoch * 1000).toLocaleTimeString("en-GB", { hour12: false })
    : "Unavailable";
export const dateTime = (epoch: unknown) =>
  typeof epoch === "number" && Number.isFinite(epoch)
    ? new Date(epoch * 1000).toLocaleString()
    : "Unavailable";
export const duration = (seconds: unknown) =>
  typeof seconds === "number" && Number.isFinite(seconds)
    ? `${Math.floor(Math.max(0, seconds) / 60)}m ${Math.floor(Math.max(0, seconds) % 60)}s`
    : "Unavailable";
export const display = (value: unknown) =>
  value === null || value === undefined || value === ""
    ? "Unavailable"
    : typeof value === "object"
      ? JSON.stringify(value)
      : String(value);
export const workspaceUrl = (name: string) => {
  const routes: Record<string, [string, number]> = {
    livefire: ["/ops/", 5178],
    red: ["/red/", 5176],
    blue: ["/blue/", 5177],
    siem: ["/blue/siem/", 5175],
    edr: ["/blue/edr/", 5173],
    beginner: ["/start/", 5179],
    competition: ["/competition/", 5181],
  };
  const item = routes[name] || routes.livefire;
  return gateway ? item[0] : `${location.protocol}//${host}:${item[1]}/`;
};
