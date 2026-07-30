import {
  FormEvent, ReactNode, useEffect, useRef, useState,
} from "react";
import type {
  AsyncState, ConnectionState, LiveEvent, MatchState, PatchRecord,
  ScoreRow, ServiceInstance, SubmissionResult,
} from "./types";
import { parseFlagBatch, patchStageIndex } from "./uiLogic";

function time(value?: number | null) {
  if (!value) return "—";
  return new Date(value * 1000).toLocaleTimeString([], { hour12: false });
}

function duration(seconds: number) {
  const safe = Math.max(0, Math.floor(seconds));
  return `${String(Math.floor(safe / 60)).padStart(2, "0")}:${String(safe % 60).padStart(2, "0")}`;
}

export function LiveMatchHeader({
  state, connection, lastReceivedAt, urgentCount, modeControl, viewerLabel,
}: {
  state: MatchState | null;
  connection: ConnectionState;
  lastReceivedAt: number;
  urgentCount: number;
  modeControl?: ReactNode;
  viewerLabel?: string;
}) {
  const [localNow, setLocalNow] = useState(Date.now() / 1000);
  const clockAnchor = useRef({
    local: Date.now() / 1000,
    server: state?.server_time ?? Date.now() / 1000,
  });
  useEffect(() => {
    const timer = window.setInterval(() => setLocalNow(Date.now() / 1000), 1000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    const local = Date.now() / 1000;
    clockAnchor.current = {
      local,
      server: state?.server_time ?? local,
    };
    setLocalNow(local);
  }, [state?.server_time]);
  const serverNow = clockAnchor.current.server + (localNow - clockAnchor.current.local);
  const remaining = Math.max(
    0, (state?.round_ends_at ?? serverNow) - serverNow
  );
  const elapsed = Math.max(
    0, serverNow - (state?.starts_at ?? serverNow)
  );
  const displayStatus = state?.status === "running"
    ? "LIVE" : (state?.status ?? "CONNECTING").toUpperCase();
  return (
    <header className="live-match-header" aria-label="Live match status">
      <div className="match-identity">
        <span className={`match-state match-state--${state?.status ?? "draft"}`}>
          <span aria-hidden="true">●</span> {displayStatus}
        </span>
        <strong>{state?.name ?? "LIVE FIRE CONTROL"}</strong>
        <span className="mode-label">{state?.mode?.replace(/_/g, " ") ?? "loading"}</span>
      </div>
      <div className="match-clock">
        <span>ROUND <b>{String(state?.round ?? 0).padStart(3, "0")}</b></span>
        <RoundCountdown seconds={remaining} />
        <span className="elapsed-clock">ELAPSED <b>{duration(elapsed)}</b></span>
        <span className="server-clock">SERVER {time(serverNow)}</span>
      </div>
      <div className="match-utilities">
        <ConnectionStatus state={connection} lastReceivedAt={lastReceivedAt} />
        <span className="team-identity">{state?.team?.name ?? viewerLabel ?? "PUBLIC VIEW"}</span>
        <span className={`urgent-counter ${urgentCount ? "urgent-counter--active" : ""}`}>
          <span aria-hidden="true">!</span> {urgentCount} urgent
        </span>
        {modeControl}
      </div>
    </header>
  );
}

export function RoundCountdown({ seconds }: { seconds: number }) {
  const level = seconds <= 15 ? "critical" : seconds <= 30 ? "warning" : "normal";
  return (
    <span className={`round-countdown round-countdown--${level}`} aria-label={`${Math.ceil(seconds)} seconds remaining`}>
      {duration(seconds)} <small>REMAINING</small>
    </span>
  );
}

export function ConnectionStatus({
  state, lastReceivedAt,
}: { state: ConnectionState; lastReceivedAt: number }) {
  const age = lastReceivedAt ? Math.floor((Date.now() - lastReceivedAt) / 1000) : 0;
  const degraded = state !== "live" || age > 15;
  return (
    <span className={`connection-status connection-status--${degraded ? "degraded" : "live"}`} role="status">
      <span aria-hidden="true">{degraded ? "△" : "●"}</span>
      {degraded
        ? `LIVE FEED DEGRADED${lastReceivedAt ? ` · ${age}s AGO` : ""}`
        : `LIVE FEED${lastReceivedAt ? ` · ${age}s LAG` : ""}`}
    </span>
  );
}

export function MetricTile({
  label, value, detail, tone = "neutral", state = "normal",
}: {
  label: string; value: ReactNode; detail?: ReactNode; tone?: string; state?: AsyncState;
}) {
  return (
    <section className={`metric-tile metric-tile--${tone} state-${state}`} aria-label={label}>
      <span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}
    </section>
  );
}

export function ScoreStrip({ row }: { row?: ScoreRow }) {
  const metrics = [
    ["Rank", row ? `#${row.rank}` : "—", "operator"],
    ["Attack", row?.attack ?? 0, "attack"],
    ["Defense", row?.defense ?? 0, "defense"],
    ["Flag Defense", row?.flag_defense ?? 0, "defense"],
    ["Availability", row?.availability ?? 0, "availability"],
    ["Detection", row?.detection ?? 0, "operator"],
    ["Containment", row?.containment ?? 0, "operator"],
    ["Recovery", row?.recovery ?? 0, "operator"],
    ["Incident Response", row?.incident_response ?? 0, "operator"],
    ["Mission Inject", row?.mission_inject ?? 0, "operator"],
    ["Penalty", row?.penalty ?? 0, "critical"],
    ["Total", row?.total ?? 0, "primary"],
  ];
  return (
    <div className="score-strip" aria-label="Tactical score strip">
      {metrics.map(([label, value, tone]) => (
        <MetricTile key={label} label={String(label)} value={value} tone={String(tone)} />
      ))}
    </div>
  );
}

export function TeamRankBadge({ rank, movement = 0 }: { rank: number; movement?: number }) {
  return (
    <span className="rank-badge" aria-label={`Rank ${rank}, movement ${movement}`}>
      #{rank} <ScoreDeltaIndicator delta={movement} compact />
    </span>
  );
}

const STATUS: Record<string, { label: string; icon: string; tone: string }> = {
  healthy: { label: "HEALTHY", icon: "✓", tone: "healthy" },
  declared: { label: "INITIALIZING", icon: "◌", tone: "info" },
  degraded: { label: "DEGRADED", icon: "△", tone: "warning" },
  compromised: { label: "COMPROMISED SUSPECTED", icon: "!", tone: "critical" },
  checker_failing: { label: "CHECKER FAILING", icon: "×", tone: "critical" },
  deploying: { label: "PATCH DEPLOYING", icon: "↻", tone: "info" },
  verifying: { label: "VERIFYING", icon: "…", tone: "info" },
  rollback: { label: "ROLLBACK", icon: "↶", tone: "warning" },
  offline: { label: "OFFLINE", icon: "○", tone: "offline" },
};

export function ServiceStatusBadge({ status }: { status: string }) {
  const item = STATUS[status] ?? { label: status.replace(/_/g, " ").toUpperCase(), icon: "•", tone: "offline" };
  return (
    <span className={`status-badge status-badge--${item.tone}`}>
      <span aria-hidden="true">{item.icon}</span>{item.label}
    </span>
  );
}

export function PatchStatusBadge({ status }: { status: string }) {
  return <ServiceStatusBadge status={status === "deployed" ? "healthy" : status} />;
}

export function CheckerResultIndicator({ status }: { status: string }) {
  return (
    <span className={`checker-indicator checker-indicator--${status}`}>
      <span aria-hidden="true">{status === "ok" ? "✓" : status === "checker_system_error" ? "◇" : "×"}</span>
      checker {status.replace(/_/g, " ")}
    </span>
  );
}

export function ServiceMatrix({
  instances, onSelect,
}: { instances: ServiceInstance[]; onSelect?: (service: ServiceInstance) => void }) {
  const teams = [...new Set(instances.map((item) => item.team_slug ?? "own-team"))];
  const services = [...new Set(instances.map((item) => item.service_slug ?? item.service))];
  return (
    <div className="matrix-scroll">
      <table className="service-matrix">
        <caption className="sr-only">Team by service status matrix</caption>
        <thead><tr><th scope="col">Team</th>{services.map((service) => <th scope="col" key={service}>{service}</th>)}</tr></thead>
        <tbody>
          {teams.map((team) => (
            <tr key={team}>
              <th scope="row">{team}</th>
              {services.map((service) => {
                const instance = instances.find(
                  (item) => (item.team_slug ?? "own-team") === team
                    && (item.service_slug ?? item.service) === service,
                );
                return (
                  <td key={service}>
                    {instance ? <TeamServiceCell instance={instance} onSelect={onSelect} /> : <span>—</span>}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function TeamServiceCell({
  instance, onSelect,
}: { instance: ServiceInstance; onSelect?: (value: ServiceInstance) => void }) {
  return (
    <button
      className={`team-service-cell cell-${instance.status}`}
      aria-label={`${instance.team_slug ?? "own team"} ${instance.service_slug ?? instance.service} service details`}
      onClick={() => onSelect?.(instance)}
    >
      <ServiceStatusBadge status={instance.status} />
      <small>{instance.last_health_at ? time(instance.last_health_at) : "not checked"}</small>
    </button>
  );
}

export function FlagSubmissionPanel({
  onSubmit,
}: { onSubmit: (flag: string) => Promise<SubmissionResult> }) {
  const [value, setValue] = useState("");
  const [privacy, setPrivacy] = useState(true);
  const [queue, setQueue] = useState<Array<{ masked: string; result?: SubmissionResult }>>([]);
  const [busy, setBusy] = useState(false);
  const input = useRef<HTMLTextAreaElement>(null);

  async function submit(event?: FormEvent) {
    event?.preventDefault();
    const flags = parseFlagBatch(value);
    if (!flags.length || busy) return;
    setBusy(true);
    setValue("");
    for (const item of flags) {
      const flag = item.flag;
      const masked = `${flag.slice(0, 8)}••••${flag.slice(-4)}`;
      if (!item.valid) {
        setQueue((items) => [{ masked, result: { accepted: false, status: "rejected", reason: "invalid_or_inactive" } }, ...items]);
        continue;
      }
      const result = await onSubmit(flag).catch(() => ({
        accepted: false, status: "rejected", reason: "invalid_or_inactive",
      } as SubmissionResult));
      setQueue((items) => [{ masked, result }, ...items].slice(0, 50));
    }
    setBusy(false);
    window.setTimeout(() => input.current?.focus(), 0);
  }

  return (
    <section className="flag-panel">
      <div className="panel-heading">
        <div><span>ATTACK CONSOLE</span><h2>Flag submission</h2></div>
        <label className="privacy-toggle">
          <input type="checkbox" checked={privacy} onChange={(event) => setPrivacy(event.target.checked)} />
          Privacy mode
        </label>
      </div>
      <form onSubmit={submit}>
        <label htmlFor="flag-input">Paste up to 20 flags, separated by whitespace</label>
        <textarea
          ref={input} id="flag-input" autoFocus value={value}
          className={privacy ? "privacy-mask" : ""}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === "Enter") void submit();
          }}
          placeholder="FLAG{opaque-token}"
          spellCheck={false} autoComplete="off"
        />
        <div className="form-actions">
          <small>Ctrl/⌘ + Enter to submit · server rate limits apply</small>
          <button className="primary-action" disabled={!value.trim() || busy}>
            {busy ? "SUBMITTING…" : "SUBMIT FLAGS"}
          </button>
        </div>
      </form>
      <div className="submission-queue" aria-live="polite">
        {queue.length === 0 && <EmptyState label="No submissions in this session" />}
        {queue.map((item, index) => (
          <div key={`${item.masked}-${index}`} className={`submission-result result-${item.result?.status}`}>
            <code>{item.masked}</code>
            <strong>{item.result?.accepted ? "FLAG ACCEPTED" : "REJECTED — INVALID OR INACTIVE"}</strong>
            {item.result?.accepted && <span>+{item.result.score_delta} ATTACK</span>}
          </div>
        ))}
      </div>
    </section>
  );
}

export function SubmissionResultToast({ result }: { result?: SubmissionResult }) {
  if (!result) return null;
  return (
    <div className={`result-toast result-${result.status}`} role="status">
      {result.accepted ? `FLAG ACCEPTED · +${result.score_delta ?? 0} ATTACK` : "REJECTED — INVALID OR INACTIVE"}
    </div>
  );
}

const PATCH_STEPS = [
  "UPLOADED", "POLICY SCAN", "SANDBOX DEPLOY", "FUNCTIONAL CHECK",
  "FLAG CHECK", "RESOURCE CHECK", "APPROVED", "DEPLOYING", "LIVE",
];
export function PatchPipeline({ patch }: { patch: PatchRecord }) {
  const active = patchStageIndex(patch.status);
  const failed = ["rejected", "rollback", "failed"].includes(patch.status);
  return (
    <article className={`patch-pipeline ${failed ? "patch-pipeline--failed" : ""}`}>
      <div className="patch-summary">
        <div><PatchStatusBadge status={patch.status} /><code>{patch.image_digest?.slice(0, 22) ?? "digest pending"}</code></div>
        <time>{time(patch.submitted_at)}</time>
      </div>
      <ol>
        {PATCH_STEPS.map((step, index) => (
          <li key={step} className={index < active ? "complete" : index === active ? "active" : ""}>
            <span aria-hidden="true">{index < active ? "✓" : index === active ? (failed ? "×" : "●") : "○"}</span>
            <small>{step}</small>
          </li>
        ))}
      </ol>
      {failed && <p role="status">Validation stopped safely: {String(patch.validation_result.category ?? "policy or functionality failure")}</p>}
    </article>
  );
}

export function LiveEventFeed({ events }: { events: LiveEvent[] }) {
  const [filter, setFilter] = useState("all");
  const visible = filter === "all" ? events : events.filter((event) => event.category === filter);
  return (
    <section className="event-feed">
      <div className="panel-heading">
        <div><span>LIVE TELEMETRY</span><h2>Event feed</h2></div>
        <div className="filter-tabs" aria-label="Event filters">
          {["all", "attack", "defense", "service", "patch", "score", "system"].map((item) => (
            <button key={item} aria-pressed={filter === item} onClick={() => setFilter(item)}>{item}</button>
          ))}
        </div>
      </div>
      <ol aria-live="polite">
        {visible.length === 0 && <EmptyState label="No confirmed events" />}
        {visible.map((event) => (
          <li key={event.event_id} className={`event event-${event.category}`}>
            <time>{time(event.timestamp)}</time>
            <EventSeverityBadge event={event} />
            <div><strong>{event.type.replace(/_/g, " ")}</strong><span>{event.result}</span></div>
          </li>
        ))}
      </ol>
    </section>
  );
}

export function EventSeverityBadge({ event }: { event: LiveEvent }) {
  const severity = ["failed", "critical"].includes(event.result) ? "critical"
    : event.result === "rejected" ? "medium" : event.category === "system" ? "low" : "info";
  return <span className={`severity severity-${severity}`}>{severity}</span>;
}

export function TacticalTimeline({ events }: { events: LiveEvent[] }) {
  return (
    <ol className="tactical-timeline">
      {events.slice(0, 12).map((event) => (
        <li key={event.event_id}><time>{time(event.timestamp)}</time><span>{event.type.replace(/_/g, " ")}</span></li>
      ))}
    </ol>
  );
}

export function OperatorActionDialog({
  open, title, impact, confirmation, onClose, onConfirm,
}: {
  open: boolean; title: string; impact: string; confirmation?: string;
  onClose: () => void; onConfirm: (reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [typed, setTyped] = useState("");
  const dialog = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    setReason("");
    setTyped("");
    const first = dialog.current?.querySelector<HTMLElement>("input,button");
    first?.focus();
    const trap = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key !== "Tab" || !dialog.current) return;
      const focusable = [...dialog.current.querySelectorAll<HTMLElement>("input,button,textarea")];
      const index = focusable.indexOf(document.activeElement as HTMLElement);
      if (event.shiftKey && index <= 0) { event.preventDefault(); focusable[focusable.length - 1]?.focus(); }
      else if (!event.shiftKey && index === focusable.length - 1) { event.preventDefault(); focusable[0]?.focus(); }
    };
    document.addEventListener("keydown", trap);
    return () => document.removeEventListener("keydown", trap);
  }, [open, onClose]);
  if (!open) return null;
  const valid = reason.trim().length >= 3 && (!confirmation || typed === confirmation);
  return (
    <div className="dialog-backdrop" role="presentation">
      <div ref={dialog} className="operator-dialog" role="dialog" aria-modal="true" aria-labelledby="action-title">
        <span>OPERATOR ACTION</span><h2 id="action-title">{title}</h2>
        <p>{impact}</p>
        <label>Audit reason<textarea value={reason} onChange={(event) => setReason(event.target.value)} /></label>
        {confirmation && <label>Type <code>{confirmation}</code> to confirm<input value={typed} onChange={(event) => setTyped(event.target.value)} /></label>}
        <div className="dialog-actions">
          <button onClick={onClose}>Cancel</button>
          <button className="danger-action" disabled={!valid} onClick={() => void onConfirm(reason)}>Confirm action</button>
        </div>
      </div>
    </div>
  );
}

export function InfrastructureStatusPanel({
  items,
}: { items: Array<{ name: string; status: string; detail?: string }> }) {
  return (
    <section className="infrastructure-panel">
      <div className="panel-heading"><div><span>CONTROL PLANE</span><h2>Infrastructure health</h2></div></div>
      <ul>{items.map((item) => (
        <li key={item.name}><ServiceStatusBadge status={item.status} /><strong>{item.name}</strong><span>{item.detail}</span></li>
      ))}</ul>
    </section>
  );
}

export function TacticalNetworkView({
  instances,
}: { instances: ServiceInstance[] }) {
  const teams = [...new Set(instances.map((item) => item.team_slug ?? "team"))];
  return (
    <section className="tactical-network">
      <div className="panel-heading">
        <div><span>DECLARED TOPOLOGY</span><h2>Tactical network view</h2></div>
        <small>Traffic volume telemetry unavailable</small>
      </div>
      <div className="topology-grid" role="img" aria-label={
        `Control plane and checker connected to ${teams.length} team service groups`
      }>
        <div className="topology-control">
          <div className="topology-node topology-node--control">
            <small>CONTROL PLANE</small><strong>API / Game Engine</strong>
          </div>
          <div className="topology-node">
            <small>MANAGEMENT</small><strong>Checker / Injector</strong>
          </div>
        </div>
        <div className="topology-edge">
          <span>signed management path</span><span>game attack plane</span>
        </div>
        <div className="topology-teams">
          {teams.map((team) => {
            const teamInstances = instances.filter(
              (item) => (item.team_slug ?? "team") === team
            );
            const healthy = teamInstances.filter(
              (item) => item.status === "healthy"
            ).length;
            return (
              <article className="topology-node topology-node--team" key={team}>
                <div><small>TEAM</small><strong>{team}</strong></div>
                <span>{healthy}/{teamInstances.length} healthy</span>
                <ul>{teamInstances.map((item) => (
                  <li key={item.id}>
                    <ServiceStatusBadge status={item.status} />
                    {item.service_slug ?? item.service}
                  </li>
                ))}</ul>
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}

export function LatencySparkline({ values, label = "Latency trend" }: { values: number[]; label?: string }) {
  if (!values.length) return <div className="sparkline-empty">No latency samples</div>;
  const points = values;
  const max = Math.max(...points, 1);
  return (
    <svg className="sparkline" viewBox="0 0 100 28" role="img" aria-label={label}>
      <polyline
        points={points.map((value, index) => `${(index / Math.max(points.length - 1, 1)) * 100},${26 - (value / max) * 22}`).join(" ")}
        fill="none" vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

export function AvailabilityGauge({ value }: { value: number }) {
  const percent = Math.max(0, Math.min(100, value));
  return (
    <div className="availability-gauge" role="meter" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
      <span style={{ width: `${percent}%` }} /><b>{percent.toFixed(0)}%</b>
    </div>
  );
}

export function ScoreDeltaIndicator({ delta, compact = false }: { delta: number; compact?: boolean }) {
  const direction = delta > 0 ? "up" : delta < 0 ? "down" : "flat";
  return (
    <span className={`score-delta score-delta--${direction}`}>
      <span aria-hidden="true">{delta > 0 ? "▲" : delta < 0 ? "▼" : "—"}</span>
      {!compact && Math.abs(delta)}
    </span>
  );
}

export function IncidentQueue({ events }: { events: LiveEvent[] }) {
  const incidents = events.filter(
    (event) => event.result === "failed"
      || event.type.includes("error") || event.type.includes("violation"),
  );
  return (
    <section className="incident-queue">
      <div className="panel-heading"><div><span>TRIAGE</span><h2>Incident queue</h2></div><b>{incidents.length}</b></div>
      {incidents.length === 0 ? <EmptyState label="No active incidents" /> : (
        <ul>{incidents.map((event) => <li key={event.event_id}><EventSeverityBadge event={event} /><span>{event.type.replace(/_/g, " ")}</span><time>{time(event.timestamp)}</time></li>)}</ul>
      )}
    </section>
  );
}

export interface Command {
  id: string; label: string; group: string; run: () => void; dangerous?: boolean;
}

export function CommandPalette({ commands }: { commands: Command[] }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  useEffect(() => {
    const key = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); setOpen((value) => !value);
      }
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, []);
  const visible = commands.filter((command) => command.label.toLowerCase().includes(query.toLowerCase()));
  if (!open) return <button className="command-trigger" onClick={() => setOpen(true)}>⌘K Commands</button>;
  return (
    <div className="palette-backdrop" onMouseDown={() => setOpen(false)}>
      <div className="command-palette" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={(event) => event.stopPropagation()}>
        <input autoFocus placeholder="Type a command…" value={query} onChange={(event) => setQuery(event.target.value)} />
        <ul>{visible.map((command) => (
          <li key={command.id}><button onClick={() => { command.run(); setOpen(false); }}>
            <span>{command.label}</span><small>{command.dangerous ? "opens confirmation" : command.group}</small>
          </button></li>
        ))}</ul>
      </div>
    </div>
  );
}

export function LoadingState({ label = "Loading confirmed state…" }: { label?: string }) {
  return <div className="state-panel" role="status"><span className="activity-dot" />{label}</div>;
}

export function EmptyState({ label }: { label: string }) {
  return <div className="empty-state"><span aria-hidden="true">◇</span>{label}</div>;
}

export function ErrorState({ label, unauthorized = false }: { label: string; unauthorized?: boolean }) {
  return <div className="state-panel state-panel--error" role="alert"><span aria-hidden="true">△</span>{unauthorized ? "UNAUTHORIZED · " : ""}{label}</div>;
}
