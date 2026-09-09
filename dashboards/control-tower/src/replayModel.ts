import {
  assetStates,
  object,
  objects,
  str,
  num,
  type RangeEvent,
  type JsonObject,
} from "@cyber-range/command-system";
export interface ReplayInput {
  events: RangeEvent[];
  scores: JsonObject[];
  incidents: JsonObject[];
}
/** One clock and one deterministic projection for every replay pane. */
export function reconstructReplay(input: ReplayInput, at: number) {
  const events = input.events
    .filter((e) => e.timestamp <= at)
    .sort(
      (a, b) =>
        a.timestamp - b.timestamp || a.event_id.localeCompare(b.event_id),
    );
  const scopeIds = new Set<string>();
  for (const e of input.events) {
    scopeIds.add(e.event_id);
    for (const key of ["incident_id", "alert_id", "source_alert_id"]) {
      const id = str(e.metadata[key]);
      if (id) scopeIds.add(id);
    }
  }
  const incidents = input.incidents
    .filter(
      (i) => scopeIds.has(str(i.id)) || scopeIds.has(str(i.source_alert_id)),
    )
    .filter((i) => (num(i.created_at) ?? Infinity) <= at)
    .map((i) => {
      const timeline = objects(i.timeline)
        .filter((t) => (num(t.ts) ?? Infinity) <= at)
        .sort((a, b) => (num(a.ts) ?? 0) - (num(b.ts) ?? 0));
      let status = "new";
      let assignee: string | null = null;
      for (const entry of timeline) {
        const action = str(entry.action);
        if (action.startsWith("transition:")) status = action.split(":")[1];
        if (action === "assign") assignee = str(entry.note);
      }
      // Never retain current status/assignee/closed_at from a future snapshot.
      return {
        id: str(i.id),
        title: str(i.title),
        host: str(i.host),
        severity: str(i.severity),
        status,
        assignee,
        timeline,
        created_at: i.created_at,
      };
    });
  const scores: Record<string, { red: number; blue: number }> = {};
  for (const score of input.scores) {
    if ((num(score.created_at) ?? Infinity) > at) continue;
    const actor = str(score.actor);
    if (actor !== "red" && actor !== "blue") continue;
    const key = str(score.team_id);
    scores[key] ??= { red: 0, blue: 0 };
    scores[key][actor] += num(score.points) ?? 0;
  }
  const patches: Record<
    string,
    { event_id: string; timestamp: number; vuln_id: string }
  > = {};
  for (const event of events)
    if (event.event_type === "blue_patch_verified" && event.vuln_id)
      patches[`${event.target_asset}:${event.vuln_id}`] = {
        event_id: event.event_id,
        timestamp: event.timestamp,
        vuln_id: event.vuln_id,
      };
  const phaseEvent = [...events]
    .reverse()
    .find((e) =>
      ["scenario_started", "scenario_ended", "stage_completed"].includes(
        e.event_type,
      ),
    );
  return {
    at,
    events,
    assets: assetStates(events, at),
    scores,
    incidents,
    patches,
    detections: events.filter((e) => e.event_type === "blue_detection_success"),
    phase: phaseEvent
      ? `${phaseEvent.event_type}${object(phaseEvent.metadata).stage ? " · " + str(object(phaseEvent.metadata).stage, String(object(phaseEvent.metadata).stage)) : ""}`
      : "Unavailable",
  };
}
export function keyMoments(events: RangeEvent[]) {
  const first = new Set<string>();
  return [...events]
    .sort((a, b) => a.timestamp - b.timestamp)
    .filter((e) => {
      if (
        [
          "asset_compromised",
          "blue_detection_success",
          "blue_block_success",
          "asset_recovered",
          "blue_patch_verified",
        ].includes(e.event_type)
      ) {
        const key = e.event_type + ":" + e.target_asset;
        if (first.has(key)) return false;
        first.add(key);
        return true;
      }
      return ["scenario_started", "scenario_ended", "stage_completed"].includes(
        e.event_type,
      );
    });
}
