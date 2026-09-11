import { describe, it, expect, vi, afterEach } from "vitest";
import {
  SSEParser,
  normalizeEvent,
  assetStates,
  mergeEvents,
  techniques,
  createClient,
  ApiError,
  nextBackoff,
  type RangeEvent,
} from "@cyber-range/command-system";
import {
  editSource,
  moveStage,
  parseSource,
  NEW_SCENARIO,
} from "./scenarioModel";
import { reconstructReplay, keyMoments } from "./replayModel";
import { visibleNav } from "./navigation";
import type { Session } from "./api";
const event = (type = "asset_compromised", ts = 10, id = "e1"): RangeEvent => ({
  event_id: id,
  event_type: type,
  timestamp: ts,
  actor: "red",
  team_id: "a",
  scenario_id: "s",
  target_asset: "power_plant",
  metadata: {},
});
afterEach(() => vi.unstubAllGlobals());
describe("stream transport", () => {
  it("parses chunked CRLF frames and multiline data", () => {
    const result: unknown[] = [];
    const parser = new SSEParser((f) => result.push(f));
    parser.push(
      ': keepalive\r\nid: 41\r\nevent: detections\r\ndata: {"name":\r',
    );
    parser.push('\ndata: "signal"}\r\n\r\n');
    expect(result).toEqual([
      { id: "41", topic: "detections", data: '{"name":\n"signal"}' },
    ]);
  });
  it("ignores heartbeat and retry-only frames", () => {
    const cb = vi.fn();
    const parser = new SSEParser(cb);
    parser.push(": keepalive\n\nretry: 1000\n\n");
    expect(cb).not.toHaveBeenCalled();
  });
  it("bounds incomplete frame memory", () => {
    expect(() =>
      new SSEParser(() => {}).push("x".repeat(1024 * 1024 + 1)),
    ).toThrow("limit");
  });
  it("caps exponential reconnect delay", () => {
    expect(nextBackoff(0)).toBe(1000);
    expect(nextBackoff(100)).toBe(30000);
  });
  it("normalizes stored metadata without guessing missing event identity", () => {
    expect(
      normalizeEvent({ ...event(), metadata: '{"mitre":["T0836"]}' })?.metadata,
    ).toEqual({ mitre: ["T0836"] });
    expect(normalizeEvent({ event_type: "x" })).toBeNull();
  });
  it("dedupes, orders and bounds thousands of events", () => {
    const events = Array.from({ length: 7000 }, (_, i) =>
      event("red_attack_started", i, `id-${i}`),
    );
    const rows = mergeEvents(events, [events[6999]]);
    expect(rows).toHaveLength(5000);
    expect(rows[0].event_id).toBe("id-6999");
  });
  it("keeps compromise through unrelated telemetry and detection", () => {
    expect(
      assetStates([
        event(),
        event("blue_detection_success", 12, "e2"),
        event("score_updated", 13, "e3"),
      ]).power_plant,
    ).toBe("compromised");
    expect(assetStates([])).toEqual({});
  });
  it("requires a source observation to mark recovery", () => {
    expect(
      assetStates([event(), event("asset_recovered", 15, "e2")], 14)
        .power_plant,
    ).toBe("compromised");
    expect(
      assetStates([event(), event("asset_recovered", 15, "e2")], 15)
        .power_plant,
    ).toBe("recovered");
  });
  it("anchors bounded-window state on an authoritative checkpoint seed", () => {
    // No in-window events for power_plant → it keeps the checkpoint state, not "unknown".
    expect(assetStates([], Infinity, { power_plant: "compromised" })).toEqual({
      power_plant: "compromised",
    });
    // In-window events fold forward from the seed.
    expect(
      assetStates([event("asset_recovered", 20, "e1")], Infinity, {
        power_plant: "compromised",
      }).power_plant,
    ).toBe("recovered");
    // reconstructReplay threads the seed through as the asset baseline.
    const result = reconstructReplay(
      { events: [], scores: [], incidents: [], assetSeed: { ground_station: "contained" } },
      50,
    );
    expect(result.assets.ground_station).toBe("contained");
  });
  it("extracts only explicitly provided ATT&CK mappings", () => {
    expect(techniques(event())).toEqual([]);
    expect(
      techniques({
        ...event(),
        metadata: {
          ics_technique: "T0836 Modify Parameter",
          mitre: ["T1190", "T0836"],
        },
      }),
    ).toEqual(["T1190", "T0836"]);
  });
});
describe("typed API client", () => {
  it("carries authorization in headers, never query strings", async () => {
    const fn = vi.fn().mockResolvedValue(
      new Response('{"ok":true}', {
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fn);
    await createClient("/api", () => "authorized-token")("/events");
    expect(fn.mock.calls[0][0]).toBe("/api/events");
    expect(fn.mock.calls[0][1].headers.get("Authorization")).toBe(
      "Bearer authorized-token",
    );
  });
  it("rejects HTML masquerading as a successful API response", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html/>", { headers: { "content-type": "text/html" } }),
        ),
    );
    await expect(createClient("/api")("/snapshot")).rejects.toBeInstanceOf(
      ApiError,
    );
  });
  it("keeps 403 distinct from empty data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response('{"detail":"Forbidden"}', {
          status: 403,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(createClient("/api")("/snapshot")).rejects.toMatchObject({
      status: 403,
      message: "Forbidden",
    });
  });
  it("cannot request arbitrary remote endpoints", async () => {
    await expect(createClient("/api")("https://example.com")).rejects.toThrow(
      "relative",
    );
    await expect(createClient("/api")("//example.com")).rejects.toThrow(
      "relative",
    );
  });
});
describe("scenario fidelity", () => {
  it("preserves comments and unknown fields on an explicit edit", () => {
    const source = NEW_SCENARIO + "  vendor_extension: {nested: [one, two]}\n";
    const next = editSource(source, 0, ["scenario", "name"], "Updated mission");
    expect(next).toContain("# Instructor draft");
    expect(parseSource(next)[0].raw.vendor_extension).toEqual({
      nested: ["one", "two"],
    });
    expect(parseSource(next)[0].raw.name).toBe("Updated mission");
  });
  it("retains multiple documents through a visual edit", () => {
    const source =
      NEW_SCENARIO +
      "\n---\n" +
      NEW_SCENARIO.replace("TRAINING-DRAFT-01", "SECOND-01");
    const next = editSource(source, 1, ["scenario", "name"], "Second exercise");
    expect(parseSource(next)).toHaveLength(2);
    expect(parseSource(next)[0].raw.id).toBe("TRAINING-DRAFT-01");
    expect(parseSource(next)[1].raw.name).toBe("Second exercise");
  });
  it("rejects invalid syntax and duplicate YAML keys", () => {
    expect(() => parseSource("scenario: [")).toThrow();
    expect(() => parseSource("scenario:\n  id: a\n  id: b")).toThrow();
  });
  it("moving a stage does not rewrite dependency semantics", () => {
    const source = NEW_SCENARIO.replace(
      "  blue_objectives:",
      "    - stage: 2\n      name: second\n      objective_event: asset_compromised\n      match: {}\n      points: 20\n      requires_stage: 1\n  blue_objectives:",
    );
    const next = moveStage(source, 0, ["scenario", "stages"], 1, 0);
    const stages = parseSource(next)[0].stages;
    expect(stages[0].raw.stage).toBe(2);
    expect(stages[0].raw.requires_stage).toBe(1);
  });
});
describe("historical reconstruction", () => {
  it("never uses future incident state or assignee", () => {
    const input = {
      events: [{ ...event(), metadata: { incident_id: "INC-1" } }],
      scores: [],
      incidents: [
        {
          id: "INC-1",
          created_at: 10,
          status: "closed",
          assignee: "future",
          timeline: [
            { ts: 12, action: "transition:triage" },
            { ts: 15, action: "assign", note: "analyst" },
            { ts: 30, action: "transition:closed" },
          ],
        },
      ],
    };
    expect(reconstructReplay(input, 11).incidents[0]).toMatchObject({
      status: "new",
      assignee: null,
    });
    expect(reconstructReplay(input, 16).incidents[0]).toMatchObject({
      status: "triage",
      assignee: "analyst",
    });
  });
  it("excludes unlinked incidents from another exercise", () => {
    expect(
      reconstructReplay(
        {
          events: [event()],
          scores: [],
          incidents: [{ id: "OTHER", created_at: 1 }],
        },
        20,
      ).incidents,
    ).toEqual([]);
  });
  it("uses only ledger rows available at the playback time", () => {
    const result = reconstructReplay(
      {
        events: [event()],
        incidents: [],
        scores: [
          { team_id: "a", actor: "red", points: 20, created_at: 11 },
          { team_id: "a", actor: "red", points: -5, created_at: 30 },
        ],
      },
      20,
    );
    expect(result.scores).toEqual({ a: { red: 20, blue: 0 } });
  });
  it("reconstructs all event-derived panes from the same clock", () => {
    const events = [
      event(),
      event("blue_detection_success", 15, "d"),
      { ...event("blue_patch_verified", 20, "p"), vuln_id: "PP-001" },
      event("asset_recovered", 25, "r"),
    ];
    const state = reconstructReplay({ events, scores: [], incidents: [] }, 17);
    expect(state.events).toHaveLength(2);
    expect(state.assets.power_plant).toBe("compromised");
    expect(state.detections).toHaveLength(1);
    expect(state.patches).toEqual({});
  });
  it("highlights observed first milestones without fabricated detections", () => {
    expect(
      keyMoments([event(), event("asset_compromised", 20, "again")]),
    ).toHaveLength(1);
  });
});
describe("role-aware navigation", () => {
  it.each(["red", "blue", "observer", "competitor", "operator"] as const)(
    "does not invent privileged routes for %s",
    (role) => {
      const session = {
        actor: "a",
        role,
        team_id: "",
        match_id: "",
        capabilities: ["overview", "competition"],
        observer_delay_sec: 30,
      } as Session;
      const ids = visibleNav(session).map((n) => n.id);
      expect(ids).not.toContain("control");
      expect(ids).not.toContain("studio");
      expect(ids).not.toContain("siem");
    },
  );
});

it("reconstructs attributed incident and configuration changes without future state", () => {
  const input = {
    scenarioId: "s",
    events: [event()],
    scores: [],
    incidents: [
      {
        id: "attributed",
        scenario_id: "s",
        created_at: 5,
        timeline: [{ ts: 25, action: "transition:closed" }],
      },
      { id: "other", scenario_id: "another", created_at: 5, timeline: [] },
    ],
    configuration: [
      {
        audit_id: "patch",
        timestamp: 15,
        asset: "power_plant",
        vuln_id: "PP-001",
        after: true,
      },
      {
        audit_id: "rollback",
        timestamp: 30,
        asset: "power_plant",
        vuln_id: "PP-001",
        after: false,
      },
    ],
  };
  expect(reconstructReplay(input, 10).configuration).toEqual({});
  expect(
    reconstructReplay(input, 20).configuration["power_plant:PP-001"].after,
  ).toBe(true);
  expect(
    reconstructReplay(input, 35).configuration["power_plant:PP-001"].after,
  ).toBe(false);
  expect(
    reconstructReplay(input, 20).incidents.map((i) => [i.id, i.status]),
  ).toEqual([["attributed", "new"]]);
  expect(reconstructReplay(input, 35).incidents[0].status).toBe("closed");
});
