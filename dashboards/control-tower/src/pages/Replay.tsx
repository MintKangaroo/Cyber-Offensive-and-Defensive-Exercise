import { useEffect, useMemo, useState } from "react";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorState,
  Icon,
  MetricCard,
  Panel,
  Skeleton,
  StatusBadge,
  Timeline,
  normalizeEvent,
  object,
  objects,
  str,
  num,
  type RangeEvent,
  type JsonObject,
} from "@cyber-range/command-system";
import { api, post, display, time, duration, incidentFrom } from "../api";
import { useCommand } from "../context";
import {
  reconstructReplay,
  keyMoments,
  type ReplayInput,
} from "../replayModel";
import { AttackPath, stateLabel, stateTone } from "./Operations";
export default function Replay({ mode }: { mode: string }) {
  const { scenarioId, entity, data, notify, session } = useCommand();
  const [input, setInput] = useState<ReplayInput | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [at, setAt] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [report, setReport] = useState<JsonObject | null>(null);
  const [annotation, setAnnotation] = useState("");
  const [annotations, setAnnotations] = useState<JsonObject[]>([]);
  const [limitations, setLimitations] = useState<string[]>([]);
  const [inspect, setInspect] = useState<RangeEvent | null>(null);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setPlaying(false);
    setError("");
    api(`/replay?scenario_id=${encodeURIComponent(scenarioId)}`)
      .then((result) => {
        if (cancelled) return;
        const sources = object(result.sources);
        const eventsSource = object(sources.events);
        if (eventsSource.status !== "ready")
          throw new Error("Replay event source is unavailable");
        const e = objects(object(eventsSource.data).events)
          .map(normalizeEvent)
          .filter((e): e is RangeEvent => e !== null)
          .sort((a, b) => a.timestamp - b.timestamp);
        const scores = objects(
          object(object(sources.scores).data).achievements,
        );
        const incidents = objects(
          object(object(sources.incidents).data).incidents,
        ).map(incidentFrom);
        setInput({ events: e, scores, incidents });
        setAt(
          e.find((ev) => ev.event_id === entity)?.timestamp ??
            e[0]?.timestamp ??
            0,
        );
        const limits = Array.isArray(result.limits)
          ? result.limits.filter((s): s is string => typeof s === "string")
          : [];
        if (object(eventsSource.data).truncated)
          limits.push(
            "History exceeds the 50,000-event retained window. This replay is partial.",
          );
        if (object(sources.scores).status !== "ready")
          limits.push("Historical score ledger is unavailable for this view.");
        setLimitations(limits);
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    if (session.capabilities.includes("aar")) {
      api(`/aar?scenario_id=${encodeURIComponent(scenarioId)}`)
        .then((r) => {
          if (!cancelled) setReport(r);
        })
        .catch(() => {
          if (!cancelled) setReport(null);
        });
      api(`/annotations?scenario_id=${encodeURIComponent(scenarioId)}`)
        .then((r) => {
          if (!cancelled) setAnnotations(objects(r.annotations));
        })
        .catch(() => {
          if (!cancelled) setAnnotations([]);
        });
    }
    return () => {
      cancelled = true;
    };
  }, [scenarioId, entity, session.capabilities]);
  const start = input?.events[0]?.timestamp ?? 0;
  const end = input?.events.at(-1)?.timestamp ?? 0;
  useEffect(() => {
    if (!playing) return;
    let previous = performance.now();
    const timer = setInterval(() => {
      const current = performance.now();
      const delta = ((current - previous) / 1000) * speed;
      previous = current;
      setAt((t) => Math.min(end, t + delta));
    }, 100);
    return () => clearInterval(timer);
  }, [playing, speed, end]);
  useEffect(() => {
    if (at >= end) setPlaying(false);
  }, [at, end]);
  const projection = useMemo(
    () => (input ? reconstructReplay(input, at) : null),
    [input, at],
  );
  const moments = useMemo(() => keyMoments(input?.events || []), [input]);
  if (loading) return <Skeleton label="Loading recorded exercise" />;
  if (error) return <ErrorState message={error} />;
  if (!input?.events.length || !projection)
    return (
      <EmptyState
        illustration={`${import.meta.env.BASE_URL}brand/empty-no-replay.webp`}
        title="No replay data"
        detail="Select an exercise with retained events. Replay never substitutes current state for missing history."
      />
    );
  const metrics = object(report?.blue_performance);
  const incidentsMetrics =
    object(report?.source_status).incidents === "unavailable"
      ? {}
      : object(report?.incident_management);
  const jump = (type: string) => {
    const ev = input.events.find(
      (e) => e.event_type === type && e.timestamp > at,
    );
    if (ev) {
      setAt(ev.timestamp);
      setPlaying(false);
    } else notify("No later matching event in this replay.");
  };
  return (
    <div className="replay-workspace">
      <div className="replay-control-bar">
        <StatusBadge tone="intelligence">
          {mode === "replay" ? "REPLAY" : "AFTER ACTION REVIEW"}
        </StatusBadge>
        <span className="mono">{time(at)}</span>
        <span className="muted">
          {duration(at - start)} / {duration(end - start)}
        </span>
        <span className="spacer" />
        <Button
          onClick={() => {
            setAt(start);
            setPlaying(false);
          }}
        >
          ↤ Start
        </Button>
        <Button
          tone="operational"
          onClick={() => {
            if (at >= end) setAt(start);
            setPlaying((p) => !p);
          }}
        >
          {playing ? "Pause" : "Play"}
        </Button>
        <label>
          Playback speed
          <select
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
          >
            {[0.25, 0.5, 1, 2, 4, 8].map((v) => (
              <option value={v} key={v}>
                {v}×
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="replay-scrubber">
        <label htmlFor="replay-time">Exercise timeline · {time(at)}</label>
        <input
          id="replay-time"
          aria-label="Scrub exercise timeline"
          type="range"
          min={start}
          max={Math.max(start + 1, end)}
          step={0.1}
          value={at}
          onChange={(e) => {
            setPlaying(false);
            setAt(Number(e.target.value));
          }}
        />
        <div className="scrubber-marks">
          <span>{time(start)}</span>
          <span>One playback clock drives every historical pane</span>
          <span>{time(end)}</span>
        </div>
        <div className="toolbar">
          <Button onClick={() => jump("red_attack_started")}>
            Next attack
          </Button>
          <Button onClick={() => jump("blue_detection_success")}>
            Next detection
          </Button>
          <Button onClick={() => jump("blue_block_success")}>
            Next containment
          </Button>
          <Button onClick={() => jump("asset_recovered")}>Next recovery</Button>
        </div>
      </div>
      <details className="replay-limits">
        <summary>
          Historical coverage & limitations ({limitations.length})
        </summary>
        <ul>
          {limitations.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
      </details>
      {mode !== "replay" && (
        <div className="metrics-grid">
          <MetricCard
            label="Mean time to detect"
            value={duration(metrics.mttd_sec)}
            detail="Reported AAR correlation metric"
            icon="clock"
            tone="operational"
          />
          <MetricCard
            label="Mean time to recover"
            value={duration(metrics.mttr_sec)}
            detail="Reported asset recovery metric"
            icon="shield"
            tone="healthy"
          />
          <MetricCard
            label="Detection rate"
            value={
              num(metrics.detection_rate) !== null
                ? `${((num(metrics.detection_rate) || 0) * 100).toFixed(1)}%`
                : "Unavailable"
            }
            detail="Exact source denominator applies"
          />
          <MetricCard
            label="Platform incident response"
            value={duration(incidentsMetrics.avg_mtta_sec)}
            detail="MTTA across available platform incidents; not scenario-scoped"
            icon="incident"
          />
        </div>
      )}
      <div className="replay-grid">
        <div>
          <Panel
            title="Historical asset state"
            actions={<StatusBadge>{projection.phase}</StatusBadge>}
          >
            <div className="replay-assets">
              {data.snapshot?.assets.map((a) => (
                <div className="replay-asset" key={a.id}>
                  <span>{a.name}</span>
                  <StatusBadge
                    tone={stateTone(projection.assets[a.id] || "unknown")}
                  >
                    {stateLabel(projection.assets[a.id] || "unknown")}
                  </StatusBadge>
                </div>
              ))}
            </div>
          </Panel>
          <Panel title="Attack & response evidence at playback time">
            <AttackPath events={projection.events} />
          </Panel>
          <Panel
            title="Score history"
            actions={
              <span className="subtle">
                Sum of source ledger entries at this time
              </span>
            }
          >
            <ScoreChart scores={input.scores} at={at} />
            <DataTable
              caption="Historical score ledger totals"
              columns={[
                { key: "team", label: "Team" },
                { key: "red", label: "Red score" },
                { key: "blue", label: "Blue score" },
              ]}
              rows={Object.entries(projection.scores).map(([team, scores]) => ({
                team,
                ...scores,
              }))}
            />
          </Panel>
          <Panel title="Historical incident lifecycle">
            <DataTable
              caption="Incidents attributed to this exercise"
              columns={[
                { key: "id", label: "Incident" },
                { key: "status", label: "Status at playback time" },
                { key: "assignee", label: "Assignee" },
              ]}
              rows={projection.incidents.map((i) => ({
                id: i.id,
                status: i.status,
                assignee: i.assignee || "Unassigned",
              }))}
            />
            <p className="panel-padding muted">
              Cases without an exact exercise evidence link are excluded.
            </p>
          </Panel>
        </div>
        <aside>
          <Panel
            title="Key moments"
            actions={<span className="subtle">Observed milestones</span>}
          >
            <div className="key-moments">
              {moments.map((e) => (
                <button
                  key={e.event_id}
                  className={e.timestamp === at ? "selected" : ""}
                  onClick={() => {
                    setAt(e.timestamp);
                    setPlaying(false);
                  }}
                >
                  <time>{time(e.timestamp)}</time>
                  <strong>{e.event_type.replaceAll("_", " ")}</strong>
                  <small>{e.target_asset}</small>
                </button>
              ))}
            </div>
          </Panel>
          <Panel title="Historical event feed">
            <div className="replay-events">
              {projection.events
                .slice(-25)
                .reverse()
                .map((e) => (
                  <button
                    className="context-event"
                    key={e.event_id}
                    onClick={() => setInspect(e)}
                  >
                    <time>{time(e.timestamp)}</time>
                    <strong>{e.event_type}</strong>
                    <small>{e.target_asset}</small>
                  </button>
                ))}
            </div>
          </Panel>
          <Panel title="Detection & patch evidence">
            <dl className="summary-facts">
              <dt>Detection observations</dt>
              <dd>{projection.detections.length}</dd>
              <dt>Patch verifications</dt>
              <dd>{Object.keys(projection.patches).length}</dd>
              <dt>Current patch state</dt>
              <dd>Not inferred from historical verification</dd>
            </dl>
          </Panel>
        </aside>
      </div>
      {mode !== "replay" && (
        <Panel title="Instructor review notes">
          <div className="panel-padding">
            <Timeline
              items={annotations.map((a) => ({
                id: str(a.id),
                time: time(a.timestamp),
                title: str(a.note),
                detail: str(a.actor),
                tone: "intelligence",
              }))}
            />
            <form
              onSubmit={(e) => {
                e.preventDefault();
                post("/annotations", {
                  scenario_id: scenarioId,
                  timestamp: at,
                  note: annotation,
                })
                  .then(() => {
                    setAnnotation("");
                    notify("Review annotation saved");
                    return api(
                      `/annotations?scenario_id=${encodeURIComponent(scenarioId)}`,
                    );
                  })
                  .then((r) => setAnnotations(objects(r.annotations)))
                  .catch((e) => setError(e.message));
              }}
            >
              <label>
                Add annotation at {time(at)}
                <textarea
                  value={annotation}
                  onChange={(e) => setAnnotation(e.target.value)}
                  rows={3}
                  required
                  maxLength={5000}
                />
              </label>
              <Button type="submit" disabled={!annotation.trim()}>
                Save instructor annotation
              </Button>
            </form>
          </div>
        </Panel>
      )}
      {mode !== "replay" && (
        <Panel title="Source AAR & defensive recommendations">
          <div className="panel-padding">
            {report ? (
              <>
                <p className="muted">
                  Source metrics are distinct from the playback reconstruction
                  above. Review source availability before using the report for
                  assessment.
                </p>
                <pre className="raw-payload">
                  {JSON.stringify(report, null, 2)}
                </pre>
                <Button
                  onClick={() => {
                    const blob = new Blob(
                      [
                        JSON.stringify(
                          {
                            scenario_id: scenarioId,
                            report,
                            annotations,
                            limitations,
                          },
                          null,
                          2,
                        ),
                      ],
                      { type: "application/json" },
                    );
                    const url = URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = `aar-${scenarioId}.json`;
                    link.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  Export AAR JSON
                </Button>
                <Button onClick={() => window.print()}>Print report</Button>
              </>
            ) : (
              <EmptyState
                title="AAR service unavailable"
                detail="The retained event replay remains available independently."
              />
            )}
          </div>
        </Panel>
      )}
      {inspect && (
        <div className="replay-evidence">
          <Panel
            title={`Recorded evidence · ${inspect.event_id}`}
            actions={
              <Button
                onClick={() => setInspect(null)}
                aria-label="Close recorded evidence"
              >
                <Icon name="close" />
              </Button>
            }
          >
            <pre className="raw-payload">
              {JSON.stringify(inspect, null, 2)}
            </pre>
          </Panel>
        </div>
      )}
    </div>
  );
}
function ScoreChart({ scores, at }: { scores: JsonObject[]; at: number }) {
  const rows = scores
    .filter((s) => (num(s.created_at) ?? Infinity) <= at)
    .sort((a, b) => (num(a.created_at) ?? 0) - (num(b.created_at) ?? 0));
  if (!rows.length)
    return (
      <EmptyState
        title="No score entries at this time"
        detail="Authoritative score changes are read from the scoring ledger."
      />
    );
  const min = num(rows[0].created_at) ?? 0;
  const max = Math.max(min + 1, at);
  let red = 0,
    blue = 0;
  const points = rows.map((r) => {
    if (r.actor === "red") red += num(r.points) ?? 0;
    if (r.actor === "blue") blue += num(r.points) ?? 0;
    return { t: num(r.created_at) ?? min, red, blue };
  });
  const high = Math.max(1, ...points.flatMap((p) => [p.red, p.blue]));
  const low = Math.min(0, ...points.flatMap((p) => [p.red, p.blue]));
  const x = (t: number) => 35 + ((t - min) / (max - min)) * 650;
  const y = (v: number) => 145 - ((v - low) / (high - low)) * 115;
  return (
    <figure className="score-chart">
      <svg
        viewBox="0 0 720 170"
        role="img"
        aria-label="Cumulative red and blue ledger score history. Exact totals appear in the table below."
      >
        <line x1="35" y1={y(0)} x2="695" y2={y(0)} className="chart-axis" />
        {(["red", "blue"] as const).map((actor) => (
          <polyline
            key={actor}
            points={points.map((p) => `${x(p.t)},${y(p[actor])}`).join(" ")}
            fill="none"
            className={`score-line ${actor}`}
          />
        ))}
        {points.map((p, i) => (
          <circle
            key={i}
            cx={x(p.t)}
            cy={y(p.red)}
            r="3"
            className="score-point"
          >
            <title>
              {time(p.t)} · Red {p.red} · Blue {p.blue}
            </title>
          </circle>
        ))}
      </svg>
      <figcaption>
        <span className="text-warning">— Red</span>
        <span className="text-operational">— Blue</span>
        <span>
          {display(low)} to {display(high)} points
        </span>
      </figcaption>
    </figure>
  );
}
