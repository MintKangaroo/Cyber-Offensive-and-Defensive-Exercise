import { useEffect, useState } from "react";
import {
  DataTable,
  EmptyState,
  ErrorState,
  Icon,
  MetricCard,
  Panel,
  Skeleton,
  StatusBadge,
  object,
  objects,
  str,
  type JsonObject,
} from "@cyber-range/command-system";
import { api, display, time, workspaceUrl } from "../api";
import { useCommand } from "../context";
export default function Competition() {
  const { session } = useCommand();
  const [match, setMatch] = useState(session.match_id || "ad-demo");
  const [result, setResult] = useState<JsonObject | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    const load = () =>
      api("/competition?match_id=" + encodeURIComponent(match))
        .then((r) => {
          if (!cancelled) {
            setResult(r);
            setError("");
          }
        })
        .catch((e) => {
          if (!cancelled) setError(e.message);
        });
    void load();
    const timer = setInterval(load, 30000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [match]);
  if (error) return <ErrorState message={error} />;
  if (!result) return <Skeleton label="Opening competition command" />;
  const sources = object(result.sources);
  const state = object(object(sources.state).data);
  const board = object(object(sources.scores).data);
  const scores = objects(board.scoreboard);
  const services = objects(object(object(sources.services).data).services);
  const patches = objects(object(object(sources.patches).data).patches);
  const own = scores.find((r) => r.team_id === session.team_id);
  return (
    <div className="competition-workspace">
      <div className="toolbar">
        <label>
          Match
          <input
            value={match}
            onChange={(e) => setMatch(e.target.value)}
            readOnly={!["instructor", "operator"].includes(session.role)}
          />
        </label>
        <StatusBadge tone="intelligence">{str(result.view)} view</StatusBadge>
        <span className="spacer" />
        <a
          className="cr-button cr-button-operational"
          href={workspaceUrl("livefire") + "?mode=attack_defense"}
        >
          Open full competition workbench
          <Icon name="arrow" />
        </a>
      </div>
      <div className="info-banner">
        <Icon name="shield" /> {str(result.disclosure)}{" "}
        {board.delay_rounds !== undefined &&
          `Disclosure delay: ${display(board.delay_rounds)} rounds.`}
      </div>
      <div className="metrics-grid">
        <MetricCard
          label={str(state.name) || "Match status"}
          value={display(state.status)}
          detail={
            state.mode ? display(state.mode) : "Competition state unavailable"
          }
          icon="flag"
        />
        <MetricCard
          label="Current round"
          value={display(state.round)}
          detail={`Round ends ${time(state.round_ends_at)}`}
          tone="operational"
          icon="clock"
        />
        <MetricCard
          label="Your visible rank"
          value={own ? display(own.rank) : "—"}
          detail={
            own
              ? `${display(own.total)} total points`
              : "No team rank in this projection"
          }
          icon="users"
        />
        <MetricCard
          label="Visible services"
          value={
            object(sources.services).status === "ready" ? services.length : "—"
          }
          detail="Scope is enforced by the game engine"
          icon="server"
        />
      </div>
      <Panel
        title="Competition scoreboard"
        actions={
          <StatusBadge>
            {board.view ? display(board.view) : "Source projection"}
          </StatusBadge>
        }
      >
        <DataTable
          caption="Attack defense competition scoreboard"
          columns={[
            { key: "rank", label: "Rank" },
            { key: "team", label: "Team" },
            { key: "attack", label: "Attack" },
            { key: "defense", label: "Defense" },
            { key: "availability", label: "Availability" },
            { key: "total", label: "Total" },
            { key: "round", label: "Updated round" },
          ]}
          rows={scores.map((s) => ({
            rank: display(s.rank),
            team: <strong>{display(s.team)}</strong>,
            attack: <span className="text-warning">{display(s.attack)}</span>,
            defense: (
              <span className="text-operational">{display(s.defense)}</span>
            ),
            availability: display(s.availability),
            total: <strong>{display(s.total)}</strong>,
            round: display(s.last_updated_round),
          }))}
        />
      </Panel>
      <Panel title="Service command">
        <DataTable
          caption="Role-scoped competition service state"
          columns={[
            { key: "service", label: "Service" },
            { key: "team", label: "Team / aggregate" },
            { key: "status", label: "Operational state" },
            { key: "health", label: "Health observation" },
          ]}
          rows={services.map((s) => ({
            service: display(s.name || s.service),
            team: display(s.team_slug || s.team_id || s.total),
            status: (
              <StatusBadge
                tone={s.status === "running" ? "operational" : "neutral"}
              >
                {display(s.status)}
              </StatusBadge>
            ),
            health:
              s.healthy !== undefined
                ? `${display(s.healthy)} healthy / ${display(s.total)}`
                : time(s.last_health_at),
          }))}
        />
      </Panel>
      <Panel title="Patch pipeline">
        {patches.length ? (
          <DataTable
            caption="Authorized competition patches"
            columns={[
              { key: "id", label: "Patch" },
              { key: "service", label: "Service" },
              { key: "status", label: "Status" },
              { key: "time", label: "Submitted" },
            ]}
            rows={patches.map((p) => ({
              id: display(p.id),
              service: display(p.service_id),
              status: <StatusBadge>{display(p.status)}</StatusBadge>,
              time: time(p.created_at),
            }))}
          />
        ) : (
          <EmptyState
            title={
              result.view === "observer"
                ? "Patch details are private"
                : "No patch records available"
            }
            detail="The full competition workbench retains flag submission, digest-pinned patches, rollback, score history, stealth reports, tournament and broadcast controls."
          />
        )}
      </Panel>
    </div>
  );
}
