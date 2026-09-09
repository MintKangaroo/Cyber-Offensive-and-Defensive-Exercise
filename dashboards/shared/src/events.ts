import { num, object, str, type JsonObject } from "./transport";
export interface RangeEvent {
  event_id: string;
  event_type: string;
  timestamp: number;
  actor: string;
  team_id: string;
  scenario_id: string;
  target_asset: string;
  metadata: JsonObject;
  phase?: string;
  vuln_id?: string;
  trace_id?: string;
  matched_event_id?: string;
  topic?: string;
}
export type AssetState =
  "unknown" | "under_attack" | "compromised" | "contained" | "recovered";
export function normalizeEvent(value: unknown): RangeEvent | null {
  const e = object(value);
  const timestamp = num(e.timestamp);
  if (!str(e.event_id) || !str(e.event_type) || timestamp === null) return null;
  let metadata = e.metadata;
  if (typeof metadata === "string") {
    try {
      metadata = JSON.parse(metadata);
    } catch {
      metadata = {};
    }
  }
  return {
    event_id: str(e.event_id),
    event_type: str(e.event_type),
    timestamp,
    actor: str(e.actor),
    team_id: str(e.team_id),
    scenario_id: str(e.scenario_id),
    target_asset: str(e.target_asset),
    metadata: object(metadata),
    phase: str(e.phase) || undefined,
    vuln_id: str(e.vuln_id) || undefined,
    trace_id: str(e.trace_id) || undefined,
    matched_event_id: str(e.matched_event_id) || undefined,
    topic: str(e.topic) || undefined,
  };
}
export function mergeEvents(
  current: RangeEvent[],
  incoming: RangeEvent[],
  limit = 5000,
): RangeEvent[] {
  const byId = new Map<string, RangeEvent>();
  for (const e of [...current, ...incoming]) byId.set(e.event_id, e);
  return [...byId.values()]
    .sort(
      (a, b) =>
        b.timestamp - a.timestamp || a.event_id.localeCompare(b.event_id),
    )
    .slice(0, limit);
}
export function assetStates(
  events: RangeEvent[],
  at = Infinity,
): Record<string, AssetState> {
  const states: Record<string, AssetState> = {};
  for (const e of [...events]
    .filter((e) => e.timestamp <= at)
    .sort(
      (a, b) =>
        a.timestamp - b.timestamp || a.event_id.localeCompare(b.event_id),
    )) {
    if (!e.target_asset) continue;
    if (e.event_type === "asset_compromised")
      states[e.target_asset] = "compromised";
    else if (e.event_type === "asset_recovered")
      states[e.target_asset] = "recovered";
    else if (e.event_type === "blue_block_success")
      states[e.target_asset] = "contained";
    else if (
      ["red_attack_started", "flag_exfiltrated"].includes(e.event_type) &&
      states[e.target_asset] !== "compromised"
    )
      states[e.target_asset] = "under_attack";
  }
  return states;
}
export function techniques(e: RangeEvent): string[] {
  const result: string[] = [];
  for (const field of [
    "mitre",
    "mitre_attack",
    "mitre_ics",
    "ics_technique",
    "technique",
    "technique_id",
  ]) {
    const raw = e.metadata[field];
    const vals = Array.isArray(raw) ? raw : [raw];
    for (const val of vals)
      if (typeof val === "string") {
        const matches = val.match(/\bT\d{4}(?:\.\d{3})?\b/g);
        if (matches) result.push(...matches);
      }
  }
  return [...new Set(result)];
}
