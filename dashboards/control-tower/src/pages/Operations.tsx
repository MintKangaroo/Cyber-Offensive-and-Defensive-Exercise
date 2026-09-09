import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  DataTable,
  EmptyState,
  Icon,
  MetricCard,
  Panel,
  SeverityBadge,
  StatusBadge,
  assetStates,
  object,
  objects,
  str,
  num,
  techniques,
  type RangeEvent,
  type AssetState,
  type Tone,
} from "@cyber-range/command-system";
import { useCommand } from "../context";
import { display, time, type Source } from "../api";
export const stateTone = (s: AssetState): Tone =>
  s === "compromised"
    ? "critical"
    : s === "under_attack"
      ? "warning"
      : s === "recovered"
        ? "healthy"
        : s === "contained"
          ? "operational"
          : "neutral";
export const stateLabel = (s: AssetState) =>
  ({
    unknown: "Unobserved",
    under_attack: "Attack observed",
    compromised: "Compromised",
    contained: "Contained",
    recovered: "Recovered",
  })[s];
export function SourceNote({
  source,
  label,
}: {
  source: Source | undefined;
  label: string;
}) {
  if (!source)
    return (
      <span className="source-note">{label}: unavailable for this role</span>
    );
  return (
    <span
      className={`source-note ${source.status !== "ready" ? "text-warning" : ""}`}
    >
      {source.status === "ready"
        ? `${label} · observed ${time(source.observed_at)}`
        : `${label} · ${source.status}${source.message ? " — " + source.message : ""}`}
    </span>
  );
}
export function Overview({ warroom = false }: { warroom?: boolean }) {
  const { data, session, navigate, inspectEvent } = useCommand();
  const sources = data.snapshot?.sources || {};
  const states = assetStates(data.events);
  const compromised = Object.values(states).filter(
    (s) => s === "compromised",
  ).length;
  const recovered = Object.values(states).filter(
    (s) => s === "recovered",
  ).length;
  const incidents = objects(sources.incidents?.data?.incidents).filter(
    (i) => i.status !== "closed",
  );
  const alerts = objects(sources.alerts?.data?.alerts).filter(
    (a) => a.status !== "closed",
  );
  const services = sources.services?.data;
  const active = Array.isArray(sources.scenarios?.data?.active)
    ? sources.scenarios.data.active
    : [];
  const teams = object(sources.scores?.data?.teams);
  const safety = object(sources.safety?.data?.safety);
  const hasEvents = sources.events?.status === "ready";
  return (
    <div className="overview-layout">
      <div className="metrics-grid">
        <MetricCard
          label="Exercise status"
          value={
            sources.scenarios?.status === "ready"
              ? active.length
                ? "Active"
                : "Standby"
              : "Unavailable"
          }
          detail={
            active.length
              ? `${active.length} active scenario${active.length > 1 ? "s" : ""}`
              : "No live phase inferred"
          }
          tone={active.length ? "operational" : "neutral"}
          icon="flag"
        />
        <MetricCard
          label="Observed compromise"
          value={hasEvents ? compromised : "—"}
          detail={`${recovered} observed recoveries · buffered evidence`}
          tone={compromised ? "critical" : "neutral"}
          icon="network"
        />
        <MetricCard
          label="Active incidents"
          value={sources.incidents?.status === "ready" ? incidents.length : "—"}
          detail={
            sources.incidents?.status === "ready"
              ? `${incidents.filter((i) => i.severity === "critical").length} critical · triage through recovery`
              : "Incident source unavailable for this role"
          }
          tone={
            incidents.some((i) => i.severity === "critical")
              ? "critical"
              : "operational"
          }
          icon="incident"
        />
        <MetricCard
          label="Service availability"
          value={
            services
              ? `${display(services.up)} / ${display(services.total)}`
              : "—"
          }
          detail={
            services
              ? `${display(services.down)} unavailable · current health scrape`
              : "Health has not been measured"
          }
          tone={num(services?.down) ? "warning" : "neutral"}
          icon="server"
        />
      </div>
      <div className="operations-grid">
        <div className="operations-primary">
          <Panel
            title="Digital twin command map"
            actions={
              <div className="panel-actions">
                <StatusBadge>
                  {data.snapshot?.assets.length ?? 0} sectors
                </StatusBadge>
                <Button onClick={() => navigate("twin")}>
                  Expand
                  <Icon name="expand" size={14} />
                </Button>
              </div>
            }
          >
            <TwinMap compact />
            <div className="map-footer">
              <div>
                <span className="legend-item">
                  <i className="legend-square text-critical" />
                  Compromised
                </span>
                <span className="legend-item">
                  <i className="legend-square text-operational" />
                  Contained
                </span>
                <span className="legend-item">
                  <i className="legend-square text-healthy" />
                  Recovered
                </span>
                <span className="legend-item">
                  <i className="legend-square" />
                  Unobserved
                </span>
              </div>
              <small>State from evidence · no assumed health</small>
            </div>
          </Panel>
          <Panel
            title="Observed attack & response path"
            actions={
              <span className="subtle">
                Inspect a stage for supporting evidence
              </span>
            }
          >
            <AttackPath events={data.events} />
          </Panel>
        </div>
        <div className="operations-rail">
          <Panel
            title="Priority incidents"
            actions={
              session.capabilities.includes("incidents") && (
                <Button onClick={() => navigate("incidents")}>
                  View queue
                  <Icon name="arrow" size={14} />
                </Button>
              )
            }
          >
            {incidents.length ? (
              incidents
                .slice()
                .sort(
                  (a, b) =>
                    (({ critical: 0, high: 1, medium: 2, low: 3 })[
                      str(a.severity)
                    ] ?? 4) -
                    ({ critical: 0, high: 1, medium: 2, low: 3 }[
                      str(b.severity)
                    ] ?? 4),
                )
                .slice(0, 4)
                .map((i) => (
                  <button
                    className="priority-incident"
                    key={str(i.id)}
                    onClick={() => navigate("incidents", str(i.id))}
                  >
                    <div>
                      <SeverityBadge severity={str(i.severity)} />
                      <span className="mono muted">{str(i.id)}</span>
                    </div>
                    <strong>{str(i.title)}</strong>
                    <div>
                      <span>{str(i.status)}</span>
                      <small>
                        {object(i.sla).resolution_breached
                          ? "! SLA breached"
                          : str(i.assignee) || "Unassigned"}
                      </small>
                    </div>
                  </button>
                ))
            ) : (
              <EmptyState
                title={
                  sources.incidents?.status === "ready"
                    ? "No open incidents"
                    : "Incident intelligence unavailable"
                }
                detail={
                  sources.incidents?.status === "ready"
                    ? "Promote an alert to begin an investigation."
                    : "This source is unavailable or outside your role."
                }
              />
            )}
          </Panel>
          <Panel title="Exercise command">
            <dl className="summary-facts">
              <dt>Phase</dt>
              <dd>
                {data.notices.find((n) => n.topic === "phase_clock")
                  ? display(
                      data.notices.find((n) => n.topic === "phase_clock")
                        ?.payload.phase,
                    )
                  : "Unavailable"}
              </dd>
              <dt>Scoring teams</dt>
              <dd>
                {sources.scores?.status === "ready"
                  ? Object.keys(teams).length
                  : "Unavailable"}
              </dd>
              <dt>Open alerts</dt>
              <dd>
                {sources.alerts?.status === "ready"
                  ? alerts.length
                  : "Unavailable"}
              </dd>
              <dt>Emergency stop</dt>
              <dd>
                {safety.active_emergency_stop === true ? (
                  <StatusBadge tone="critical">ACTIVE</StatusBadge>
                ) : safety.active_emergency_stop === false ? (
                  "Released"
                ) : (
                  "Unavailable"
                )}
              </dd>
              <dt>Ingestion backlog</dt>
              <dd>{display(sources.ingestion?.data?.dlq_pending)}</dd>
              <dt>Current match / round</dt>
              <dd>
                <button
                  className="text-button"
                  onClick={() => navigate("competition")}
                >
                  Competition command
                  <Icon name="arrow" size={12} />
                </button>
              </dd>
            </dl>
            <div className="command-scope">
              <Icon name="shield" size={16} />
              <span>
                Exercise and competition scores use separate source ledgers.
              </span>
            </div>
          </Panel>
          {!warroom && session.role === "red" && (
            <Panel title="Red mission workspace">
              <EmptyState
                title="Stay within the assigned range"
                detail="Mission targets, evidence capture and flag submission remain in the authorized attack workbench."
                action={
                  <Button onClick={() => navigate("challenges")}>
                    Open missions
                  </Button>
                }
              />
            </Panel>
          )}
        </div>
      </div>
      <Panel
        title="Live activity"
        actions={
          <div className="panel-actions">
            <span className="subtle">Latest authorized observations</span>
            <Button onClick={() => navigate("events")}>
              Open stream
              <Icon name="arrow" size={14} />
            </Button>
          </div>
        }
      >
        {data.events.length ? (
          <div className="compact-feed">
            {data.events.slice(0, warroom ? 4 : 6).map((e) => (
              <button
                key={e.event_id}
                className="compact-event"
                onClick={() => inspectEvent(e.event_id)}
              >
                <time>{time(e.timestamp)}</time>
                <span
                  className={`event-glyph ${e.actor === "red" ? "text-warning" : "text-operational"}`}
                >
                  <Icon
                    name={e.actor === "red" ? "bolt" : "shield"}
                    size={16}
                  />
                </span>
                <b>{e.event_type.replaceAll("_", " ")}</b>
                <span>{e.target_asset}</span>
                <small>{e.team_id || "Scoped public event"}</small>
                <Icon name="chevron" size={14} />
              </button>
            ))}
          </div>
        ) : (
          <EmptyState
            title="Waiting for exercise evidence"
            detail="Events appear after the collector supplies authorized telemetry. No demonstration events are inserted."
          />
        )}
      </Panel>
    </div>
  );
}
const SECTOR_ICONS: Record<string, string> = {
  ground_station: "satellite",
  power_plant: "bolt",
  defense_network: "network",
  refinery_plant: "factory",
  smart_factory: "factory",
  water_utility: "water",
  lng_terminal: "factory",
  railway_signaling: "train",
  airport_ot: "plane",
  datacenter_bms: "server",
  hospital_ot: "medical",
};
export function TwinMap({
  compact = false,
  filter = "",
  focus = "",
}: {
  compact?: boolean;
  filter?: string;
  focus?: string;
}) {
  const { data, inspectAsset } = useCommand();
  const states = useMemo(() => assetStates(data.events), [data.events]);
  const [zoom, setZoom] = useState(1);
  const assets = data.snapshot?.assets || [];
  const visible = assets.filter(
    (a) =>
      (!filter || states[a.id] === filter) &&
      (!focus ||
        `${a.id} ${a.name}`.toLowerCase().includes(focus.toLowerCase())),
  );
  return (
    <div className={`twin-map ${compact ? "compact" : ""}`}>
      <div className="map-coordinate map-coordinate-top">
        RANGE TOPOLOGY / SECTOR INVENTORY
      </div>
      {!compact && (
        <div className="map-controls">
          <Button
            aria-label="Zoom out"
            onClick={() => setZoom((z) => Math.max(0.75, z - 0.25))}
          >
            −
          </Button>
          <span className="mono">{Math.round(zoom * 100)}%</span>
          <Button
            aria-label="Zoom in"
            onClick={() => setZoom((z) => Math.min(2, z + 0.25))}
          >
            +
          </Button>
          <Button onClick={() => setZoom(1)}>Reset view</Button>
        </div>
      )}
      <div
        className="map-viewport"
        tabIndex={0}
        aria-label="Digital twin map; use Tab to inspect sectors"
      >
        <div
          className="sector-grid"
          style={{ minWidth: !compact ? `${zoom * 720}px` : undefined }}
        >
          {visible.map((a, index) => {
            const state = states[a.id] || "unknown";
            const ev = data.events.filter((e) => e.target_asset === a.id);
            const detections = ev.filter(
              (e) => e.event_type === "blue_detection_success",
            );
            return (
              <button
                className={`sector-node state-${state}`}
                key={a.id}
                onClick={() => inspectAsset(a.id)}
                aria-label={`${a.name}: ${stateLabel(state)}. Inspect sector.`}
              >
                <div className="sector-top">
                  <span className="sector-icon">
                    <Icon
                      name={SECTOR_ICONS[a.id] || "factory"}
                      size={compact ? 21 : 27}
                    />
                  </span>
                  <span className="sector-number">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span
                    className={`sector-state-marker cr-tone-${stateTone(state)}`}
                  />
                </div>
                <strong>{a.name}</strong>
                <small className="sector-protocol">{a.protocol}</small>
                <div className="sector-bottom">
                  <StatusBadge tone={stateTone(state)}>
                    {stateLabel(state)}
                  </StatusBadge>
                  <span>{detections.length} detections</span>
                </div>
              </button>
            );
          })}
        </div>
        {!visible.length && (
          <EmptyState
            title={
              assets.length
                ? "No sectors match this filter"
                : "Sector inventory unavailable"
            }
            detail="Sector status is derived only from received exercise evidence."
          />
        )}
      </div>
      <div className="map-coordinate map-coordinate-bottom">
        <Icon name="shield" size={12} /> LOGICAL SECTOR MAP · NETWORK LINKS ARE
        NOT INFERRED
      </div>
    </div>
  );
}
export function DigitalTwin() {
  const [filter, setFilter] = useState("");
  const [focus, setFocus] = useState("");
  return (
    <Panel
      title="ICS / OT sector command map"
      actions={
        <StatusBadge tone="operational">Interactive inventory</StatusBadge>
      }
    >
      <div className="toolbar">
        <label>
          Focus sector
          <input
            value={focus}
            onChange={(e) => setFocus(e.target.value)}
            placeholder="Name or asset ID"
          />
        </label>
        <label>
          Observed state
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">All states</option>
            {(
              [
                "compromised",
                "under_attack",
                "contained",
                "recovered",
              ] as AssetState[]
            ).map((s) => (
              <option key={s} value={s}>
                {stateLabel(s)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <TwinMap filter={filter} focus={focus} />
    </Panel>
  );
}
const PATH_STAGES = [
  ["Initial access", "initial_access"],
  ["Discovery", "discovery"],
  ["Exploitation", "exploitation"],
  ["Lateral movement", "lateral_movement"],
  ["ICS / OT impact", "asset_compromised"],
  ["Detection", "blue_detection_success"],
  ["Containment", "blue_block_success"],
  ["Eradication", "eradication"],
  ["Recovery", "asset_recovered"],
];
export function AttackPath({ events }: { events: RangeEvent[] }) {
  const { inspectEvent } = useCommand();
  const [selected, setSelected] = useState("");
  const buckets = PATH_STAGES.map(([label, key]) => ({
    label,
    key,
    events: events.filter((e) => e.event_type === key || e.phase === key),
  }));
  return (
    <>
      <div
        className="attack-path"
        role="list"
        aria-label="Observed attack and response stages"
      >
        {buckets.map((b, i) => (
          <div role="listitem" key={b.key}>
            <button
              disabled={!b.events.length}
              aria-pressed={selected === b.key}
              onClick={() => setSelected(b.key)}
              className={b.events.length ? "observed" : ""}
            >
              <span>{String(i + 1).padStart(2, "0")}</span>
              <strong>{b.label}</strong>
              <small>
                {b.events.length
                  ? `${b.events.length} observations`
                  : "No evidence"}
              </small>
            </button>
            {i < buckets.length - 1 && <Icon name="chevron" size={12} />}
          </div>
        ))}
      </div>
      {selected && (
        <div className="path-evidence">
          <p>
            Phase classification comes from source fields. Adjacent stages do
            not imply a proven causal relationship.
          </p>
          {buckets
            .find((b) => b.key === selected)
            ?.events.slice(0, 8)
            .map((e) => (
              <button
                key={e.event_id}
                className="notice-row"
                onClick={() => inspectEvent(e.event_id)}
              >
                <time>{time(e.timestamp)}</time>
                <span>
                  {e.target_asset} · {e.event_type}
                </span>
                <small>
                  {techniques(e).join(", ") || "No MITRE mapping supplied"}
                </small>
              </button>
            ))}
        </div>
      )}
    </>
  );
}
export function AssetList() {
  const { data, inspectAsset } = useCommand();
  const states = assetStates(data.events);
  return (
    <Panel title="Range asset inventory">
      <DataTable
        caption="Authorized sector inventory"
        columns={[
          { key: "name", label: "Asset / sector" },
          { key: "protocol", label: "Configured protocols" },
          { key: "state", label: "Observed state" },
          { key: "telemetry", label: "Last observation" },
        ]}
        rows={(data.snapshot?.assets || []).map((a) => ({
          name: (
            <button className="text-button" onClick={() => inspectAsset(a.id)}>
              {a.name}
            </button>
          ),
          protocol: a.protocol,
          state: (
            <StatusBadge tone={stateTone(states[a.id] || "unknown")}>
              {stateLabel(states[a.id] || "unknown")}
            </StatusBadge>
          ),
          telemetry: time(
            data.events.find((e) => e.target_asset === a.id)?.timestamp,
          ),
        }))}
      />
    </Panel>
  );
}
export interface EventFilters {
  search: string;
  actor: string;
  asset: string;
  type: string;
  severity: string;
  technique: string;
  team: string;
  incident: string;
}
export const filterEvents = (events: RangeEvent[], f: EventFilters) =>
  events.filter(
    (e) =>
      (!f.search ||
        JSON.stringify(e).toLowerCase().includes(f.search.toLowerCase())) &&
      (!f.actor || e.actor === f.actor) &&
      (!f.asset || e.target_asset === f.asset) &&
      (!f.type || e.event_type === f.type) &&
      (!f.severity ||
        String(e.metadata.severity || "").toLowerCase() === f.severity) &&
      (!f.technique ||
        techniques(e).some((t) => t.includes(f.technique.toUpperCase()))) &&
      (!f.team || e.team_id === f.team) &&
      (!f.incident || e.metadata.incident_id === f.incident),
  );
const EMPTY_FILTERS: EventFilters = {
  search: "",
  actor: "",
  asset: "",
  type: "",
  severity: "",
  technique: "",
  team: "",
  incident: "",
};
export function EventStream() {
  const { data, inspectEvent, session, scenarioId, notify } = useCommand();
  const [filters, setFilters] = useState<EventFilters>(EMPTY_FILTERS);
  const [frozen, setFrozen] = useState<RangeEvent[] | null>(null);
  const [scroll, setScroll] = useState(0);
  const [pinned, setPinned] = useState<Set<string>>(new Set());
  const [advanced, setAdvanced] = useState(false);
  const viewport = useRef<HTMLDivElement>(null);
  useEffect(() => {
    setScroll(0);
    if (viewport.current) viewport.current.scrollTop = 0;
  }, [filters]);
  const rows = useMemo(
    () => filterEvents(frozen || data.events, filters),
    [frozen, data.events, filters],
  );
  const rowHeight = 58;
  const viewportHeight = 522;
  const start = Math.max(
    0,
    Math.min(Math.floor(scroll / rowHeight) - 4, Math.max(0, rows.length - 1)),
  );
  const windowRows = rows.slice(start, start + 18);
  const set = (key: keyof EventFilters, value: string) => {
    setFilters((f) => ({ ...f, [key]: value }));
    setScroll(0);
  };
  const presetKey = `cr-event-filter:${session.actor}:${session.role}:${scenarioId}`;
  return (
    <Panel
      title="Event stream"
      actions={
        <div className="panel-actions">
          <StatusBadge
            tone={
              frozen
                ? "warning"
                : data.connection === "live"
                  ? "operational"
                  : "neutral"
            }
          >
            {frozen ? "View paused" : data.connection}
          </StatusBadge>
          <span className="mono subtle">
            {rows.length.toLocaleString()} /{" "}
            {data.events.length.toLocaleString()}
          </span>
        </div>
      }
    >
      <div className="event-toolbar">
        <label className="event-search">
          Search evidence
          <input
            value={filters.search}
            onChange={(e) => set("search", e.target.value)}
            placeholder="Event ID, correlation ID, payload…"
          />
        </label>
        <label>
          Source actor
          <select
            value={filters.actor}
            onChange={(e) => set("actor", e.target.value)}
          >
            <option value="">All actors</option>
            <option>red</option>
            <option>blue</option>
            <option>system</option>
          </select>
        </label>
        <label>
          Sector / asset
          <select
            value={filters.asset}
            onChange={(e) => set("asset", e.target.value)}
          >
            <option value="">All sectors</option>
            {data.snapshot?.assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <Button onClick={() => setAdvanced((v) => !v)} aria-expanded={advanced}>
          <Icon name="settings" />
          Filters
        </Button>
        <Button onClick={() => setFrozen((f) => (f ? null : [...data.events]))}>
          {frozen ? "Resume live view" : "Pause view"}
        </Button>
      </div>
      {advanced && (
        <div className="toolbar event-advanced">
          <label>
            Event type
            <select
              value={filters.type}
              onChange={(e) => set("type", e.target.value)}
            >
              <option value="">All types</option>
              {[...new Set(data.events.map((e) => e.event_type))].map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
          <label>
            Severity
            <select
              value={filters.severity}
              onChange={(e) => set("severity", e.target.value)}
            >
              <option value="">All / unspecified</option>
              {["critical", "high", "medium", "low"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <label>
            Team
            <select
              value={filters.team}
              onChange={(e) => set("team", e.target.value)}
            >
              <option value="">All visible teams</option>
              {[...new Set(data.events.map((e) => e.team_id))]
                .filter(Boolean)
                .map((t) => (
                  <option key={t}>{t}</option>
                ))}
            </select>
          </label>
          <label>
            Technique
            <input
              value={filters.technique}
              onChange={(e) => set("technique", e.target.value)}
              placeholder="T0836"
            />
          </label>
          <label>
            Incident ID
            <input
              value={filters.incident}
              onChange={(e) => set("incident", e.target.value)}
            />
          </label>
          <Button
            onClick={() => {
              localStorage.setItem(presetKey, JSON.stringify(filters));
              notify("Filter preset saved for this identity and exercise");
            }}
          >
            Save preset
          </Button>
          <Button
            onClick={() => {
              try {
                const saved = object(
                  JSON.parse(localStorage.getItem(presetKey) || "{}"),
                );
                setFilters(
                  Object.fromEntries(
                    Object.keys(EMPTY_FILTERS).map((k) => [k, str(saved[k])]),
                  ) as unknown as EventFilters,
                );
              } catch {
                notify("Saved preset could not be loaded");
              }
            }}
          >
            Load preset
          </Button>
          <Button onClick={() => setFilters(EMPTY_FILTERS)}>Clear</Button>
        </div>
      )}
      {frozen && (
        <div className="info-banner">
          The visible list is paused. Live ingestion continues in the bounded
          buffer.
        </div>
      )}
      {pinned.size > 0 && (
        <div className="pinned-events">
          <span className="eyebrow">PINNED</span>
          {data.events
            .filter((e) => pinned.has(e.event_id))
            .map((e) => (
              <Button key={e.event_id} onClick={() => inspectEvent(e.event_id)}>
                {e.event_type} · {e.target_asset}
              </Button>
            ))}
        </div>
      )}
      <div className="event-table-heading">
        <span>Timestamp</span>
        <span>Event / actor</span>
        <span>Asset / team</span>
        <span>Technique</span>
        <span>Actions</span>
      </div>
      <div
        ref={viewport}
        className="virtual-events"
        style={{ height: viewportHeight }}
        onScroll={(e) => setScroll(e.currentTarget.scrollTop)}
        tabIndex={0}
        role="region"
        aria-label="Virtualized event list"
      >
        <div
          role="list"
          aria-label={`${rows.length} matching events`}
          style={{ height: rows.length * rowHeight, position: "relative" }}
        >
          {windowRows.map((e, i) => (
            <div
              role="listitem"
              aria-posinset={start + i + 1}
              aria-setsize={rows.length}
              className="virtual-event"
              key={e.event_id}
              style={{
                position: "absolute",
                top: (start + i) * rowHeight,
                height: rowHeight,
                left: 0,
                right: 0,
              }}
            >
              <time>{time(e.timestamp)}</time>
              <button
                className="event-main"
                onClick={() => inspectEvent(e.event_id)}
              >
                <b>{e.event_type.replaceAll("_", " ")}</b>
                <small>
                  {e.actor || "Source unspecified"} · {e.event_id.slice(0, 13)}
                </small>
              </button>
              <div>
                <span>{e.target_asset || "Unavailable"}</span>
                <small>{e.team_id || "Scoped public event"}</small>
              </div>
              <span className="mono event-technique">
                {techniques(e).join(", ") || "Not supplied"}
              </span>
              <div className="event-actions">
                <Button
                  aria-label={`${pinned.has(e.event_id) ? "Unpin" : "Pin"} event ${e.event_id}`}
                  aria-pressed={pinned.has(e.event_id)}
                  onClick={() =>
                    setPinned((p) => {
                      const next = new Set(p);
                      if (next.has(e.event_id)) next.delete(e.event_id);
                      else if (next.size < 20) next.add(e.event_id);
                      return next;
                    })
                  }
                >
                  ◇
                </Button>
                <Button
                  aria-label={`Inspect event ${e.event_id}`}
                  onClick={() => inspectEvent(e.event_id)}
                >
                  <Icon name="chevron" size={14} />
                </Button>
              </div>
            </div>
          ))}
        </div>
        {!rows.length && (
          <EmptyState
            title={
              data.events.length
                ? "No events match your filters"
                : "No event evidence available"
            }
            detail="Adjust the filters, or wait for authorized exercise telemetry."
          />
        )}
      </div>
      <div className="stream-footer">
        <SourceNote source={data.snapshot?.sources.events} label="Collector" />
        <span>5,000-event buffer · fixed-height window · maximum 20 pins</span>
      </div>
    </Panel>
  );
}
