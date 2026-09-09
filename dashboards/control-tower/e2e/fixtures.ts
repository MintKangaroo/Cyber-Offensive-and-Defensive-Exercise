// Deterministic test telemetry. This module is outside the production bundle.
import type { Page } from "@playwright/test";
export const now = 1788922800;
export const event = (
  id: string,
  offset: number,
  type = "asset_compromised",
) => ({
  event_id: id,
  event_type: type,
  timestamp: now + offset,
  team_id: "team-blue",
  scenario_id: "TRAINING-01",
  actor: type.startsWith("blue") ? "blue" : "red",
  target_asset: "power_plant",
  metadata: { mitre: ["T0836"], incident_id: "INC-1" },
});
export const incident = {
  id: "INC-1",
  title: "Unexpected SCADA setpoint change",
  severity: "critical",
  status: "new",
  team_id: "team-blue",
  host: "power_plant",
  created_at: now - 500,
  acknowledged_at: null,
  closed_at: null,
  assignee: null,
  source_alert_id: "ALERT-1",
  sla: {
    response_sla_min: 5,
    resolution_sla_min: 60,
    response_breached: true,
    resolution_breached: false,
  },
  timeline: [
    {
      ts: now - 500,
      action: "created",
      actor: "detector",
      note: "Training incident fixture",
    },
  ],
};
export const instructorCaps = [
  "overview",
  "events",
  "digital-twin",
  "incidents",
  "soc",
  "scenarios",
  "replay",
  "aar",
  "injects",
  "services",
  "audit",
  "control",
  "teams",
  "scoring",
  "copilot",
  "policy",
  "competition",
  "challenges",
  "training",
];
export const source = (data: unknown) => ({
  status: "ready",
  data,
  observed_at: now,
  source: "test-fixture",
});
export const assets = [
  ["ground_station", "Satellite ground station", "CCSDS"],
  ["power_plant", "Power grid / SCADA", "Modbus"],
  ["defense_network", "Enterprise network", "HTTP"],
  ["refinery_plant", "Refinery / petrochemical", "Modbus"],
  ["smart_factory", "Smart factory", "S7comm"],
  ["water_utility", "Water utility", "Modbus"],
  ["lng_terminal", "LNG terminal", "Modbus"],
  ["railway_signaling", "Railway signaling", "Modbus"],
  ["airport_ot", "Airport OT", "Modbus"],
  ["datacenter_bms", "Data center", "BACnet"],
  ["hospital_ot", "Hospital OT", "Modbus"],
].map(([id, name, protocol]) => ({
  id,
  name,
  protocol,
  scope: "test range",
  health: null,
}));
export async function setup(
  page: Page,
  {
    role = "instructor",
    count = 3,
    degraded = false,
    unauthenticated = false,
  }: {
    role?: string;
    count?: number;
    degraded?: boolean;
    unauthenticated?: boolean;
  } = {},
) {
  const events =
    count > 3
      ? Array.from({ length: count }, (_, i) => event(`event-${i}`, i))
      : [
          event("attack-1", 0, "red_attack_started"),
          event("compromise-1", 30),
          event("recovery-1", 90, "asset_recovered"),
        ];
  const updates: { path: string; body: Record<string, unknown> }[] = [];
  let current = { ...incident, timeline: [...incident.timeline] };
  await page.route("**/command/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.split("/command")[1];
    const body = route.request().postDataJSON() as Record<
      string,
      unknown
    > | null;
    const json = (data: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(data),
      });
    if (unauthenticated)
      return json({ detail: "Authentication required" }, 401);
    if (route.request().method() === "POST")
      updates.push({ path, body: body || {} });
    if (path === "/session")
      return json({
        actor: "Exercise controller",
        role,
        team_id: role === "instructor" ? "" : "team-blue",
        match_id: role === "instructor" ? "" : "TRAINING-01",
        capabilities:
          role === "instructor"
            ? instructorCaps
            : role === "blue"
              ? ["overview", "digital-twin", "events", "incidents", "replay"]
              : ["overview", "digital-twin", "events", "competition"],
        observer_delay_sec: 30,
      });
    if (path === "/stream")
      return route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: ": heartbeat\n\n",
      });
    if (path === "/snapshot")
      return json({
        scenario_id: "TRAINING-01",
        generated_at: now,
        assets,
        sources: {
          events: source({ events }),
          incidents: source({
            incidents: role === "observer" ? [] : [current],
          }),
          scenarios: source({
            available: ["TRAINING-01"],
            active: ["TRAINING-01"],
          }),
          scores: source({ teams: { "team-blue": { red: 25, blue: 40 } } }),
          services: degraded
            ? {
                status: "unavailable",
                source: "observability",
                data: null,
                message: "Source unavailable",
              }
            : source({
                up: 4,
                down: 1,
                total: 5,
                services: [
                  { name: "event_collector", ok: true, latency_ms: 12 },
                ],
              }),
          safety: source({ safety: { active_emergency_stop: false } }),
          alerts: source({ alerts: [] }),
        },
      });
    if (path === "/assets/power_plant")
      return json({
        vulnerabilities: [
          {
            id: "PP-TRAINING",
            name: "Training setpoint exercise",
            description: "Isolated lab scenario",
            mitre_attack: ["T0836"],
          },
        ],
      });
    if (path === "/incidents/INC-1") return json(current);
    if (path.startsWith("/incidents/INC-1/")) {
      if (path.endsWith("/transition"))
        current = {
          ...current,
          status: String(body?.value),
          timeline: [
            ...current.timeline,
            {
              ts: now,
              action: `transition:${body?.value}`,
              actor: "analyst",
              note: String(body?.note),
            },
          ],
        };
      return json(current);
    }
    if (path === "/replay")
      return json({
        sources: {
          events: source({ events }),
          incidents: source({ incidents: [current] }),
          scores: source({
            achievements: [
              {
                team_id: "team-blue",
                actor: "red",
                points: 25,
                created_at: now + 30,
              },
            ],
          }),
        },
        limits: ["Test fixture: unknown initial asset state."],
      });
    if (path === "/aar")
      return json({
        blue_performance: { mttd_sec: 12, mttr_sec: 60, detection_rate: 0.5 },
        incident_management: { avg_mtta_sec: 20 },
      });
    if (path === "/drafts") return json({ drafts: [] });
    if (path === "/scenarios/validate")
      return json({
        ok: true,
        documents: [
          {
            ok: true,
            issues: [],
            stage_count: 1,
            total_points: 100,
            time_limit_sec: 1800,
            timeline: [
              { stage: 1, name: "Initial evidence", start_sec: 0, end_sec: 60 },
            ],
          },
        ],
      });
    if (path === "/search")
      return json({
        results: [
          {
            kind: "challenge",
            id: "ICS-TRAINING",
            title: "SCADA investigation",
          },
        ],
        partial: false,
      });
    if (path === "/control")
      return json({
        audit_id: "audit-1",
        result: { emergency_stop: true },
        partial: false,
      });
    if (path === "/copilot/policy")
      return json({
        enabled: false,
        configured: false,
        trainee_mode: "conceptual",
      });
    return json({});
  });
  return updates;
}
