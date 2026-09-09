import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  Button,
  Dialog,
  EmptyState,
  ErrorState,
  Icon,
  Panel,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  Timeline,
  objects,
  str,
  num,
} from "@cyber-range/command-system";
import {
  api,
  post,
  incidentFrom,
  time,
  dateTime,
  duration,
  type Incident,
} from "../api";
import { useCommand } from "../context";
export const TRANSITIONS: Record<string, string[]> = {
  new: ["triage", "closed"],
  triage: ["contained", "closed"],
  contained: ["eradicated"],
  eradicated: ["recovered"],
  recovered: ["closed"],
  closed: [],
};
export function slaRemaining(incident: Incident, now: number): number | null {
  const acknowledged = incident.acknowledged_at !== null;
  const minutes = num(
    incident.sla[acknowledged ? "resolution_sla_min" : "response_sla_min"],
  );
  if (minutes === null || incident.closed_at !== null) return null;
  return incident.created_at + minutes * 60 - now;
}
export default function Incidents() {
  const {
    data,
    entity,
    navigate,
    inspectEvent,
    inspectAsset,
    session,
    notify,
  } = useCommand();
  const [statusFilter, setStatusFilter] = useState("open");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [transition, setTransition] = useState("");
  const [reason, setReason] = useState("");
  const [now, setNow] = useState(Date.now() / 1000);
  const [note, setNote] = useState("");
  const [assignee, setAssignee] = useState("");
  const [version, setVersion] = useState(0);
  const queue = useMemo(
    () =>
      objects(data.snapshot?.sources.incidents?.data?.incidents)
        .map(incidentFrom)
        .filter(
          (i) =>
            (statusFilter === "all" ||
              (statusFilter === "open"
                ? i.status !== "closed"
                : i.status === statusFilter)) &&
            `${i.title} ${i.id} ${i.host}`
              .toLowerCase()
              .includes(search.toLowerCase()),
        ),
    [data.snapshot, statusFilter, search],
  );
  const id = entity || queue[0]?.id || "";
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (!id) {
      setSelected(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError("");
    setSelected(null);
    api(`/incidents/${encodeURIComponent(id)}`)
      .then((r) => {
        if (!cancelled) {
          const i = incidentFrom(r);
          setSelected(i);
          setAssignee(i.assignee || "");
        }
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [id, version]);
  const update = async (action: string, value: string, detail = "") => {
    if (!selected) return;
    setBusy(true);
    setError("");
    try {
      await post(`/incidents/${encodeURIComponent(selected.id)}/${action}`, {
        value,
        note: detail,
      });
      setVersion((v) => v + 1);
      void data.refresh();
      notify("Incident timeline updated");
      setTransition("");
      setNote("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Incident update failed");
    } finally {
      setBusy(false);
    }
  };
  const events = data.events.filter(
    (e) =>
      selected &&
      (e.target_asset === selected.host ||
        e.metadata.incident_id === selected.id ||
        e.event_id === selected.source_alert_id),
  );
  const remaining = selected ? slaRemaining(selected, now) : null;
  const breached =
    selected &&
    (selected.sla.response_breached === true ||
      selected.sla.resolution_breached === true ||
      (remaining !== null && remaining < 0));
  return (
    <div className="incident-workbench">
      <section className="incident-queue" aria-label="Incident queue">
        <div className="queue-heading">
          <h2>Investigation queue</h2>
          <StatusBadge tone="operational">{queue.length}</StatusBadge>
        </div>
        <label className="queue-search">
          Find incident
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Title, ID or asset"
          />
        </label>
        <label className="queue-search">
          Lifecycle
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="open">Open incidents</option>
            <option value="all">All incidents</option>
            {Object.keys(TRANSITIONS).map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <div className="queue-items">
          {queue.map((i) => (
            <button
              className={`queue-item ${id === i.id ? "selected" : ""}`}
              key={i.id}
              onClick={() => navigate("incidents", i.id)}
              aria-pressed={id === i.id}
            >
              <div>
                <SeverityBadge severity={i.severity} />
                <small className="mono">{i.id}</small>
              </div>
              <strong>{i.title}</strong>
              <div>
                <span>{i.status}</span>
                <small>{i.assignee || "Unassigned"}</small>
              </div>
              {(i.sla.response_breached === true ||
                i.sla.resolution_breached === true) && (
                <span className="sla-breach">! SLA breached</span>
              )}
            </button>
          ))}
          {!queue.length && (
            <EmptyState
              title="Queue is clear"
              detail={
                data.snapshot?.sources.incidents?.status === "ready"
                  ? "No incidents match this view."
                  : "Incident source is unavailable for your current scope."
              }
            />
          )}
        </div>
      </section>
      <section
        className="incident-investigation"
        aria-label="Incident investigation"
      >
        {error && (
          <ErrorState message={error} retry={() => setVersion((v) => v + 1)} />
        )}{" "}
        {loading ? (
          <Skeleton label="Opening investigation" />
        ) : selected ? (
          <>
            <div className="investigation-header">
              <div className="toolbar">
                <SeverityBadge severity={selected.severity} />
                <span className="mono muted">{selected.id}</span>
                <StatusBadge
                  tone={
                    selected.status === "closed" ? "healthy" : "operational"
                  }
                >
                  {selected.status}
                </StatusBadge>
              </div>
              <h2>{selected.title}</h2>
              <p className="muted">
                Opened {dateTime(selected.created_at)} ·{" "}
                {selected.host || "Asset not associated"}
              </p>
              <ol className="incident-phases" aria-label="Incident lifecycle">
                {Object.keys(TRANSITIONS).map((step, index) => (
                  <li
                    key={step}
                    className={step === selected.status ? "current" : ""}
                  >
                    <span>{index + 1}</span>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
            <div className={`sla-strip ${breached ? "breached" : ""}`}>
              <Icon name="clock" />
              <div>
                <strong>
                  {selected.closed_at !== null
                    ? "Investigation closed"
                    : remaining === null
                      ? "SLA unavailable"
                      : remaining < 0
                        ? `SLA overdue by ${duration(-remaining)}`
                        : `${duration(remaining)} to ${selected.acknowledged_at === null ? "acknowledge" : "resolve"}`}
                </strong>
                <small>
                  {breached
                    ? "Breach is recorded in the incident SLA metrics."
                    : "Deadline uses the server-provided severity SLA."}
                </small>
              </div>
            </div>
            <div className="investigation-actions">
              <form
                onSubmit={(e: FormEvent) => {
                  e.preventDefault();
                  void update("assign", assignee);
                }}
              >
                <label>
                  Assigned analyst
                  <input
                    value={assignee}
                    onChange={(e) => setAssignee(e.target.value)}
                    placeholder="Analyst identifier"
                    required
                    maxLength={200}
                  />
                </label>
                <Button type="submit" disabled={busy || !assignee.trim()}>
                  Assign
                </Button>
              </form>
              <div>
                {(TRANSITIONS[selected.status] || []).map((next) => (
                  <Button
                    key={next}
                    tone={next === "closed" ? "neutral" : "operational"}
                    disabled={busy}
                    onClick={() => {
                      setTransition(next);
                      setReason("");
                    }}
                  >
                    {next === "closed" &&
                    ["new", "triage"].includes(selected.status)
                      ? "Close / false positive"
                      : `Move to ${next}`}
                  </Button>
                ))}
              </div>
            </div>
            <Panel
              title="Investigation timeline"
              actions={
                <span className="subtle">Audited by Incident Service</span>
              }
            >
              <Timeline
                items={selected.timeline.map((t, index) => ({
                  id: `${selected.id}:${index}`,
                  time: time(t.ts),
                  title: str(t.action).replaceAll(":", " → "),
                  detail: (
                    <>
                      {str(t.actor)}
                      {str(t.note) && ` · ${str(t.note)}`}
                    </>
                  ),
                  tone: str(t.action).includes("recovered")
                    ? "healthy"
                    : str(t.action).includes("contained")
                      ? "operational"
                      : "neutral",
                }))}
              />
            </Panel>
            <form
              className="analyst-note"
              onSubmit={(e) => {
                e.preventDefault();
                void update("note", note);
              }}
            >
              <label>
                Analyst notes
                <textarea
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  required
                  maxLength={5000}
                  placeholder="Record evidence, reasoning, containment or recovery validation…"
                  rows={4}
                />
              </label>
              <div>
                <span className="muted">
                  Notes are attributed to {session.actor}.
                </span>
                <Button type="submit" disabled={busy || !note.trim()}>
                  Add note
                </Button>
              </div>
            </form>
          </>
        ) : (
          <EmptyState
            title="Select an incident"
            detail="Investigate evidence, record decisions and progress through containment and recovery."
          />
        )}
      </section>
      <aside
        className="incident-context"
        aria-label="Evidence and asset intelligence"
      >
        <Panel title="Evidence context">
          {selected ? (
            <dl className="facts">
              <dt>Source alert</dt>
              <dd className="mono">
                {selected.source_alert_id || "Unavailable"}
              </dd>
              <dt>Asset</dt>
              <dd>
                {selected.host ? (
                  <button
                    className="text-button"
                    onClick={() => inspectAsset(selected.host)}
                  >
                    {selected.host}
                    <Icon name="arrow" size={12} />
                  </button>
                ) : (
                  "Unavailable"
                )}
              </dd>
              <dt>Team</dt>
              <dd>{selected.team_id || "Not attributed"}</dd>
              <dt>Acknowledged</dt>
              <dd>{dateTime(selected.acknowledged_at)}</dd>
              <dt>Recovery state</dt>
              <dd>
                {selected.status === "recovered" || selected.status === "closed"
                  ? "See lifecycle evidence"
                  : "Pending analyst validation"}
              </dd>
            </dl>
          ) : (
            <EmptyState title="No case selected" />
          )}
        </Panel>
        <Panel title="Related asset activity">
          <p className="context-explanation">
            Asset matches provide investigation context. They do not by
            themselves establish causation.
          </p>
          {events.length ? (
            events.slice(0, 12).map((e) => (
              <button
                className="context-event"
                key={e.event_id}
                onClick={() => inspectEvent(e.event_id)}
              >
                <time>{time(e.timestamp)}</time>
                <strong>{e.event_type.replaceAll("_", " ")}</strong>
                <small className="mono">{e.event_id.slice(0, 16)}</small>
              </button>
            ))
          ) : (
            <EmptyState
              title="No correlated evidence loaded"
              detail="Only events in the current authorized buffer are shown."
            />
          )}
        </Panel>
        {session.capabilities.includes("aar") && (
          <Button onClick={() => navigate("aar", id)}>
            Open after action review
            <Icon name="arrow" size={14} />
          </Button>
        )}
      </aside>
      {transition && selected && (
        <Dialog
          title={`Move incident to ${transition}`}
          onClose={() => {
            if (!busy) setTransition("");
          }}
        >
          <p>
            {selected.id}: {selected.status} → {transition}. This decision is
            recorded in the incident timeline.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void update("transition", transition, reason);
            }}
          >
            <label>
              Evidence / reason
              <textarea
                autoFocus
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                required
                minLength={3}
                maxLength={5000}
                rows={4}
              />
            </label>
            <div className="dialog-actions">
              <Button onClick={() => setTransition("")} disabled={busy}>
                Cancel
              </Button>
              <Button
                type="submit"
                tone="operational"
                disabled={busy || reason.trim().length < 3}
              >
                {busy ? "Recording…" : "Confirm transition"}
              </Button>
            </div>
          </form>
        </Dialog>
      )}
    </div>
  );
}
