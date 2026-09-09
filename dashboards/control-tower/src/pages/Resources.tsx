import { useEffect, useState, type ReactNode } from "react";
import {
  Button,
  DataTable,
  Dialog,
  EmptyState,
  ErrorState,
  Icon,
  Panel,
  Skeleton,
  StatusBadge,
  object,
  objects,
  str,
  num,
  type JsonObject,
} from "@cyber-range/command-system";
import { api, post, display, time, dateTime, workspaceUrl } from "../api";
import { useCommand } from "../context";
import { SourceNote } from "./Operations";
const RESOURCE: Record<string, string> = {
  services: "services",
  observability: "services",
  scenarios: "scenarios",
  siem: "alerts",
  edr: "hosts",
  detections: "detections",
  teams: "teams",
  network: "network",
  challenges: "challenges",
  injects: "injects",
};
export default function Resources({ route }: { route: string }) {
  const { data, scenarioId, navigate, session, notify, inspectAsset } =
    useCommand();
  const [result, setResult] = useState<JsonObject | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [version, setVersion] = useState(0);
  const [raw, setRaw] = useState<JsonObject | null>(null);
  const [control, setControl] = useState("");
  const [reason, setReason] = useState("");
  const [target, setTarget] = useState(scenarioId);
  const [teams, setTeams] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<
    { at: number; up: number; total: number }[]
  >([]);
  useEffect(() => {
    const resource = RESOURCE[route];
    if (!resource && route !== "audit") {
      setResult(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError("");
    api(route === "audit" ? "/audit" : `/resources/${resource}`)
      .then((r) => {
        if (!cancelled) {
          setResult(r);
          if (resource === "services" && num(r.up) !== null)
            setHistory((h) =>
              [
                ...h,
                {
                  at: Date.now() / 1000,
                  up: num(r.up) ?? 0,
                  total: num(r.total) ?? 0,
                },
              ].slice(-60),
            );
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
  }, [route, version]);
  useEffect(() => {
    if (
      !["services", "observability", "siem", "edr", "injects"].includes(route)
    )
      return;
    const timer = setInterval(() => setVersion((v) => v + 1), 30000);
    return () => clearInterval(timer);
  }, [route]);
  const refresh = () => setVersion((v) => v + 1);
  const filter = (rows: JsonObject[]) =>
    rows.filter(
      (r) =>
        !query || JSON.stringify(r).toLowerCase().includes(query.toLowerCase()),
    );
  async function execute() {
    setBusy(true);
    setError("");
    try {
      const r = await post("/control", {
        action: control,
        target,
        reason,
        confirm: true,
        team_ids: teams
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      });
      setControl("");
      setRaw(r);
      notify(
        r.partial
          ? "Control action partially failed. Inspect service results and audit before retrying."
          : "Control action completed; inspect the source result and audit record.",
      );
      void data.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Control action failed");
      setControl("");
    } finally {
      setBusy(false);
    }
  }
  function controls(safetyOnly = false) {
    const safety = object(data.snapshot?.sources.safety?.data?.safety);
    return (
      <div className="control-workspace">
        <Panel title="Range safety">
          <div className="control-safety">
            <Icon name="shield" size={36} />
            <div>
              <h2>
                {safety.active_emergency_stop === true
                  ? "Emergency stop is active"
                  : safety.active_emergency_stop === false
                    ? "Emergency stop is released"
                    : "Emergency-stop state unavailable"}
              </h2>
              <p>
                Safety status comes from Range Control and Config Service.
                Network isolation requires the existing runtime isolation
                checks.
              </p>
            </div>
          </div>
          <dl className="facts">
            <dt>Internet egress</dt>
            <dd>{display(safety.internet_egress)}</dd>
            <dt>Cross-team traffic</dt>
            <dd>{display(safety.cross_team_traffic)}</dd>
            <dt>Containment verification</dt>
            <dd>{display(safety.range_containment_score)}</dd>
          </dl>
          <div className="toolbar">
            <Button
              tone="critical"
              onClick={() => {
                setReason("");
                setControl("emergency-stop");
              }}
            >
              Emergency stop
            </Button>
            <Button
              tone="warning"
              onClick={() => {
                setReason("");
                setControl("release");
              }}
            >
              Release stop
            </Button>
          </div>
        </Panel>
        {!safetyOnly && (
          <Panel title="Exercise controller">
            <div className="panel-padding">
              <div className="scenario-fields">
                <label>
                  Scenario / range identifier
                  <input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    pattern="[\w.-]+"
                  />
                </label>
                <label>
                  Teams (comma separated)
                  <input
                    value={teams}
                    onChange={(e) => setTeams(e.target.value)}
                    placeholder="Assigned team identifiers"
                  />
                </label>
              </div>
              <div className="toolbar">
                <Button
                  tone="operational"
                  onClick={() => {
                    setReason("");
                    setControl("scenario-start");
                  }}
                >
                  Start scenario
                </Button>
                <Button
                  tone="warning"
                  onClick={() => {
                    setReason("");
                    setControl("scenario-end");
                  }}
                >
                  End scenario
                </Button>
                <Button
                  tone="critical"
                  onClick={() => {
                    setReason("");
                    setControl("reset");
                  }}
                >
                  Reset exercise state
                </Button>
              </div>
              <p className="muted">
                Reset uses the existing eight-service range reset. It clears
                exercise events, scores, patches, solves and SOC state.
                Competition state is managed in the competition workbench.
              </p>
            </div>
          </Panel>
        )}
      </div>
    );
  }
  function content(): ReactNode {
    if (route === "control" || route === "safety")
      return controls(route === "safety");
    if (route === "scoring") {
      const scores = object(data.snapshot?.sources.scores?.data?.teams);
      return (
        <Panel title="Exercise score ledger">
          <DataTable
            caption="Source exercise scores"
            columns={[
              { key: "team", label: "Team" },
              { key: "red", label: "Red" },
              { key: "blue", label: "Blue" },
            ]}
            rows={Object.entries(scores).map(([team, s]) => ({
              team,
              red: display(object(s).red),
              blue: display(object(s).blue),
            }))}
          />
          <div className="panel-padding">
            <SourceNote
              source={data.snapshot?.sources.scores}
              label="Scoring Engine"
            />
            <p className="muted">
              Competition scores use their own ledger and visibility rules.
            </p>
            <a className="cr-button" href={workspaceUrl("livefire")}>
              Open existing score administration
              <Icon name="arrow" size={14} />
            </a>
          </div>
        </Panel>
      );
    }
    if (loading && !result) return <Skeleton />;
    if (!result)
      return (
        <EmptyState
          title="Source unavailable"
          detail="Reconnect to load this workspace."
        />
      );
    if (["services", "observability"].includes(route))
      return (
        <>
          <Panel
            title="Platform service health"
            actions={
              <StatusBadge tone={num(result.down) ? "warning" : "operational"}>
                {display(result.up)} / {display(result.total)} available
              </StatusBadge>
            }
          >
            <DataTable
              caption="Measured platform service health"
              columns={[
                { key: "name", label: "Service" },
                { key: "state", label: "Health scrape" },
                { key: "latency", label: "Latency (ms)" },
                { key: "source", label: "Measurement" },
              ]}
              rows={filter(objects(result.services)).map((s) => ({
                name: (
                  <button className="text-button" onClick={() => setRaw(s)}>
                    {str(s.name)}
                  </button>
                ),
                state: (
                  <StatusBadge
                    tone={
                      s.up === true
                        ? "healthy"
                        : s.up === false
                          ? "critical"
                          : "neutral"
                    }
                  >
                    {s.up === true
                      ? "Up"
                      : s.up === false
                        ? "Unavailable"
                        : "Unknown"}
                  </StatusBadge>
                ),
                latency: display(s.latency_ms),
                source: "Observability health scrape",
              }))}
            />
          </Panel>
          <Panel title="Collection reliability">
            <dl className="summary-facts">
              <dt>Stream connection</dt>
              <dd>{data.connection}</dd>
              <dt>Last received event</dt>
              <dd>
                {data.lastReceived
                  ? time(data.lastReceived / 1000)
                  : "No events received"}
              </dd>
              <dt>Forwarding backlog</dt>
              <dd>
                {display(data.snapshot?.sources.ingestion?.data?.dlq_pending)}
              </dd>
              <dt>Forward retries</dt>
              <dd>
                {display(
                  data.snapshot?.sources.ingestion?.data?.forward_retries,
                )}
              </dd>
              <dt>Platform-wide EPS</dt>
              <dd>
                Unavailable; session arrivals are not ingestion throughput
              </dd>
            </dl>
          </Panel>
          <Panel title="Health history observed in this session">
            <DataTable
              caption="Actual session health observations"
              columns={[
                { key: "time", label: "Observed at" },
                { key: "up", label: "Services up" },
                { key: "total", label: "Monitored" },
              ]}
              rows={history.map((h) => ({
                time: time(h.at),
                up: h.up,
                total: h.total,
              }))}
            />
          </Panel>
        </>
      );
    if (route === "scenarios")
      return (
        <Panel
          title="Available scenarios"
          actions={
            <Button tone="operational" onClick={() => navigate("studio")}>
              Create draft
            </Button>
          }
        >
          <DataTable
            caption="Loaded scenario library"
            columns={[
              { key: "id", label: "Scenario" },
              { key: "status", label: "Engine status" },
              { key: "action", label: "Authoring" },
            ]}
            rows={(Array.isArray(result.available) ? result.available : [])
              .filter((id) =>
                String(id).toLowerCase().includes(query.toLowerCase()),
              )
              .map((id) => ({
                id: String(id),
                status: (
                  <StatusBadge
                    tone={
                      Array.isArray(result.active) && result.active.includes(id)
                        ? "operational"
                        : "neutral"
                    }
                  >
                    {Array.isArray(result.active) && result.active.includes(id)
                      ? "Active"
                      : "Ready"}
                  </StatusBadge>
                ),
                action: (
                  <Button onClick={() => navigate("studio", String(id))}>
                    Open in Scenario Studio
                  </Button>
                ),
              }))}
          />
        </Panel>
      );
    if (route === "siem")
      return (
        <>
          <div className="toolbar">
            <Button
              onClick={() => {
                setBusy(true);
                api("/resources/siem?text=" + encodeURIComponent(query))
                  .then(setRaw)
                  .catch((e) => setError(e.message))
                  .finally(() => setBusy(false));
              }}
              disabled={busy}
            >
              Search raw SIEM telemetry
            </Button>
            <a className="cr-button" href={workspaceUrl("siem")}>
              Open full SIEM console
              <Icon name="arrow" size={14} />
            </a>
          </div>
          <Panel title="SIEM alert queue">
            <DataTable
              caption="SIEM alerts and incident promotion"
              columns={[
                { key: "title", label: "Detection" },
                { key: "severity", label: "Severity" },
                { key: "status", label: "Status" },
                { key: "time", label: "Timestamp" },
                { key: "action", label: "Investigation" },
              ]}
              rows={filter(objects(result.alerts)).map((a) => ({
                title: (
                  <button className="text-button" onClick={() => setRaw(a)}>
                    {display(a.title || a.rule_id)}
                  </button>
                ),
                severity: (
                  <StatusBadge
                    tone={
                      Number(a.severity) >= 4
                        ? "critical"
                        : Number(a.severity) >= 3
                          ? "warning"
                          : "neutral"
                    }
                  >
                    {display(a.severity)}
                  </StatusBadge>
                ),
                status: display(a.status),
                time: dateTime(a.timestamp),
                action: (
                  <Button
                    disabled={busy}
                    onClick={() => {
                      setBusy(true);
                      post("/promote", { alert_id: String(a.id) })
                        .then((r) => {
                          notify("Alert promoted to incident");
                          navigate("incidents", str(r.id));
                        })
                        .catch((e) => setError(e.message))
                        .finally(() => setBusy(false));
                    }}
                  >
                    Create incident
                  </Button>
                ),
              }))}
            />
          </Panel>
        </>
      );
    if (route === "edr")
      return (
        <Panel
          title="Endpoint fleet"
          actions={
            <a className="cr-button" href={workspaceUrl("edr")}>
              Open full EDR console
              <Icon name="arrow" size={14} />
            </a>
          }
        >
          <DataTable
            caption="Observed endpoint fleet"
            columns={[
              { key: "host", label: "Endpoint" },
              { key: "status", label: "Status" },
              { key: "last", label: "Last seen" },
              { key: "details", label: "Evidence" },
            ]}
            rows={filter(objects(result.hosts)).map((h) => ({
              host: display(h.asset || h.hostname),
              status: display(h.status || h.online),
              last: time(h.last_seen),
              details: (
                <Button onClick={() => setRaw(h)}>Inspect host record</Button>
              ),
            }))}
          />
        </Panel>
      );
    if (route === "network") {
      const assets = object(result.assets);
      return (
        <Panel title="Network operations measurements">
          <DataTable
            caption="Measured range NOC health"
            columns={[
              { key: "asset", label: "Asset" },
              { key: "health", label: "Measured health" },
              { key: "latency", label: "Latency" },
              { key: "availability", label: "1 hour availability" },
              { key: "errors", label: "5 minute error rate" },
            ]}
            rows={Object.entries(assets).map(([asset, raw]) => {
              const v = object(raw);
              return {
                asset: (
                  <button
                    className="text-button"
                    onClick={() => inspectAsset(asset)}
                  >
                    {asset}
                  </button>
                ),
                health: display(v.healthy ?? v.status),
                latency: display(v.latency_ms),
                availability: display(v.uptime_pct_1h),
                errors: display(v.error_rate_5m),
              };
            })}
          />
        </Panel>
      );
    }
    if (route === "challenges")
      return (
        <Panel
          title="Authorized training challenges"
          actions={
            <a
              className="cr-button cr-button-operational"
              href={workspaceUrl(session.role === "blue" ? "blue" : "red")}
            >
              Open mission workbench
              <Icon name="arrow" size={14} />
            </a>
          }
        >
          <div className="challenge-grid">
            {filter(objects(result.challenges)).map((c) => (
              <article className="challenge-card" key={str(c.id)}>
                <div>
                  <span className="mono text-operational">{str(c.id)}</span>
                  <StatusBadge tone={c.solved ? "healthy" : "neutral"}>
                    {c.solved ? "Completed" : str(c.difficulty)}
                  </StatusBadge>
                </div>
                <h3>{str(c.title)}</h3>
                <p>{str(c.goal)}</p>
                <footer>
                  <span>{str(c.category)}</span>
                  <b>{display(c.dynamic_points ?? c.points_red)} points</b>
                  <a
                    className="text-button"
                    href={workspaceUrl(
                      session.role === "blue" ? "blue" : "red",
                    )}
                  >
                    Open mission
                    <Icon name="arrow" size={12} />
                  </a>
                </footer>
              </article>
            ))}
          </div>
        </Panel>
      );
    if (route === "teams")
      return (
        <Panel title="Exercise teams">
          <DataTable
            caption="Configured exercise teams"
            columns={[
              { key: "id", label: "Team ID" },
              { key: "name", label: "Display name" },
              { key: "side", label: "Team identity" },
            ]}
            rows={filter(objects(result.teams)).map((t) => ({
              id: str(t.team_id),
              name: str(t.name),
              side: (
                <StatusBadge
                  tone={t.side === "red" ? "warning" : "operational"}
                >
                  {str(t.side)}
                </StatusBadge>
              ),
            }))}
          />
        </Panel>
      );
    if (route === "audit")
      return (
        <Panel title="Instructor audit trail">
          <DataTable
            caption="Audited instructor actions"
            columns={[
              { key: "time", label: "Timestamp" },
              { key: "actor", label: "Actor" },
              { key: "action", label: "Action" },
              { key: "target", label: "Target" },
              { key: "reason", label: "Reason" },
            ]}
            rows={filter(objects(result.entries)).map((e) => ({
              time: dateTime(e.timestamp),
              actor: str(e.actor),
              action: str(e.action),
              target: str(e.target),
              reason: str(e.reason),
            }))}
          />
        </Panel>
      );
    if (route === "injects")
      return <Injects result={result} refresh={refresh} />;
    return (
      <Panel title="Detection coverage source">
        <p className="panel-padding muted">
          MITRE mappings and coverage below are supplied by the detection
          service.
        </p>
        <pre className="raw-payload">{JSON.stringify(result, null, 2)}</pre>
      </Panel>
    );
  }
  return (
    <div className="resource-workspace">
      {error && <ErrorState message={error} retry={refresh} />}{" "}
      {!["control", "safety", "scoring"].includes(route) && (
        <div className="toolbar">
          <label className="resource-search">
            Search this workspace
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Find authorized records…"
            />
          </label>
          <span className="spacer" />
          <Button onClick={refresh} disabled={loading}>
            Refresh source
          </Button>
        </div>
      )}
      {content()}
      {raw && (
        <Dialog
          title="Advanced source evidence"
          wide
          onClose={() => setRaw(null)}
        >
          <pre className="raw-payload">{JSON.stringify(raw, null, 2)}</pre>
        </Dialog>
      )}
      {control && (
        <Dialog
          title={
            control === "reset"
              ? "Confirm exercise reset"
              : `Confirm ${control.replaceAll("-", " ")}`
          }
          onClose={() => {
            if (!busy) setControl("");
          }}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void execute();
            }}
          >
            <div className="confirmation-warning">
              <Icon name="incident" />
              <p>
                {control === "reset"
                  ? "This clears exercise events, scores, patches, solves, SIEM, EDR, incidents and injects. The action cannot be undone from this screen."
                  : `Apply ${control.replaceAll("-", " ")} to the authorized training range.`}
              </p>
            </div>
            <p>
              Actor: {session.actor} · Target: {target}
            </p>
            <label>
              Required audit reason
              <textarea
                autoFocus
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={4}
                required
                minLength={3}
                maxLength={2000}
              />
            </label>
            <div className="dialog-actions">
              <Button onClick={() => setControl("")} disabled={busy}>
                Cancel
              </Button>
              <Button
                tone="critical"
                type="submit"
                disabled={busy || reason.trim().length < 3}
              >
                {busy ? "Applying…" : "Confirm action"}
              </Button>
            </div>
          </form>
        </Dialog>
      )}
    </div>
  );
}
function Injects({
  result,
  refresh,
}: {
  result: JsonObject;
  refresh: () => void;
}) {
  const { session, notify } = useCommand();
  const [selected, setSelected] = useState<JsonObject | null>(null);
  const [response, setResponse] = useState("");
  const [error, setError] = useState("");
  const [library, setLibrary] = useState<JsonObject[]>([]);
  const [template, setTemplate] = useState("");
  const [teams, setTeams] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (session.role === "instructor")
      api("/resources/inject-library")
        .then((r) => setLibrary(objects(r.library)))
        .catch((e) => setError(e.message));
  }, [session.role]);
  return (
    <>
      <Panel title="Exercise injects">
        {error && <ErrorState message={error} />}
        <DataTable
          caption="Exercise inject queue"
          columns={[
            { key: "subject", label: "Subject" },
            { key: "team", label: "Team" },
            { key: "deadline", label: "Deadline" },
            { key: "status", label: "Status" },
            { key: "action", label: "Response" },
          ]}
          rows={objects(result.injects || result.inbox).map((i) => ({
            subject: str(i.subject),
            team: display(i.team_id || session.team_id),
            deadline: dateTime(i.deadline_at),
            status: (
              <StatusBadge
                tone={i.deadline_state === "expired" ? "warning" : "neutral"}
              >
                {display(i.deadline_state || i.status)}
              </StatusBadge>
            ),
            action: (
              <Button
                onClick={() => {
                  setSelected(i);
                  setResponse("");
                }}
              >
                Inspect inject
              </Button>
            ),
          }))}
        />
      </Panel>
      {session.role === "instructor" && (
        <Panel title="Dispatch training inject">
          <form
            className="panel-padding"
            onSubmit={(e) => {
              e.preventDefault();
              setBusy(true);
              post("/injects/dispatch", {
                template_id: template,
                team_ids: teams
                  .split(",")
                  .map((t) => t.trim())
                  .filter(Boolean),
                deadline_min: 30,
                reason,
              })
                .then(() => {
                  notify("Training inject dispatched");
                  refresh();
                })
                .catch((e) => setError(e.message))
                .finally(() => setBusy(false));
            }}
          >
            <div className="scenario-fields">
              <label>
                Approved template
                <select
                  value={template}
                  onChange={(e) => setTemplate(e.target.value)}
                  required
                >
                  <option value="">Select template</option>
                  {library.map((t) => (
                    <option key={str(t.id)} value={str(t.id)}>
                      {str(t.subject) || str(t.id)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Assigned teams
                <input
                  value={teams}
                  onChange={(e) => setTeams(e.target.value)}
                  required
                  placeholder="Comma-separated team IDs"
                />
              </label>
              <label className="field-wide">
                Audit reason
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  required
                  minLength={3}
                />
              </label>
            </div>
            <Button
              type="submit"
              disabled={busy || !template || reason.trim().length < 3}
            >
              Dispatch inject · 30 minute deadline
            </Button>
          </form>
        </Panel>
      )}
      {selected && (
        <Dialog title={str(selected.subject)} onClose={() => setSelected(null)}>
          <p className="inject-body">{str(selected.body)}</p>
          {session.team_id ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                setBusy(true);
                post(
                  `/injects/${encodeURIComponent(str(selected.id))}/respond`,
                  { response_text: response },
                )
                  .then(() => {
                    notify("Inject response recorded");
                    setSelected(null);
                    refresh();
                  })
                  .catch((e) => setError(e.message))
                  .finally(() => setBusy(false));
              }}
            >
              <label>
                Team response
                <textarea
                  value={response}
                  onChange={(e) => setResponse(e.target.value)}
                  required
                  rows={6}
                  maxLength={10000}
                />
              </label>
              <Button type="submit" disabled={busy || !response.trim()}>
                Submit response
              </Button>
            </form>
          ) : (
            <pre className="raw-payload">
              {JSON.stringify(selected, null, 2)}
            </pre>
          )}
        </Dialog>
      )}
    </>
  );
}
