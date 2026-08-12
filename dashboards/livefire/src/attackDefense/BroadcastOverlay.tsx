import { CSSProperties, useEffect, useMemo, useRef, useState } from "react";
import { httpAttackDefenseApi } from "./api";
import {
  formatBroadcastCountdown, parseBroadcastOptions,
} from "./broadcastLogic";
import type {
  BroadcastSnapshot, ScoreRow, TournamentFixture, TournamentState,
} from "./types";

type OverlayStyle = CSSProperties & { "--broadcast-accent": string };

export function BroadcastOverlay() {
  const options = useMemo(
    () => parseBroadcastOptions(new URLSearchParams(window.location.search)),
    [],
  );
  const [snapshot, setSnapshot] = useState<BroadcastSnapshot | null>(null);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(Date.now());
  const receivedAt = useRef(Date.now());

  useEffect(() => {
    document.documentElement.dataset.broadcastBackground = options.background;
    return () => { delete document.documentElement.dataset.broadcastBackground; };
  }, [options.background]);

  useEffect(() => {
    const timer = window.setInterval(() => setTick(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    async function refresh() {
      let nextRefresh = 5;
      try {
        const next = await httpAttackDefenseApi.getBroadcastSnapshot(options.matchId);
        if (cancelled) return;
        receivedAt.current = Date.now();
        setSnapshot(next);
        setError("");
        nextRefresh = Math.min(30, Math.max(2, next.refresh_after_seconds));
      } catch (reason) {
        if (cancelled) return;
        setError(String(reason));
      }
      timer = window.setTimeout(refresh, nextRefresh * 1_000);
    }
    void refresh();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [options.matchId]);

  const style = { "--broadcast-accent": options.accent } as OverlayStyle;
  if (!snapshot) {
    return (
      <main className={`broadcast-root broadcast-bg-${options.background}`} style={style}>
        <div className="broadcast-loading" role="status">
          <span>LIVE FIRE BROADCAST</span>
          <strong>{error ? "PUBLIC FEED UNAVAILABLE" : "CONNECTING TO PUBLIC FEED"}</strong>
          <small>{options.matchId}</small>
        </div>
      </main>
    );
  }

  const elapsed = tick - receivedAt.current;
  const countdown = formatBroadcastCountdown(
    snapshot.match.round_ends_at, snapshot.match.server_time, elapsed,
  );
  return (
    <main
      className={`broadcast-root broadcast-bg-${options.background} broadcast-layout-${options.layout}`}
      data-disclosure={snapshot.disclosure.audience}
      style={style}
    >
      <h1 className="sr-only">{snapshot.match.name} public broadcast overlay</h1>
      {options.layout === "scorebar" && (
        <Scorebar snapshot={snapshot} countdown={countdown} maximum={options.maxTeams} stale={Boolean(error)} />
      )}
      {options.layout === "standings" && (
        <Standings snapshot={snapshot} countdown={countdown} maximum={options.maxTeams} stale={Boolean(error)} />
      )}
      {options.layout === "bracket" && (
        <BracketOverlay snapshot={snapshot} countdown={countdown} stale={Boolean(error)} />
      )}
    </main>
  );
}

function BroadcastBrand({ stale }: { stale: boolean }) {
  return (
    <div className="broadcast-brand">
      <span className="broadcast-mark" aria-hidden="true">◆</span>
      <div><strong>LIVE FIRE</strong><small>PUBLIC BROADCAST</small></div>
      <span className={`broadcast-signal ${stale ? "is-stale" : ""}`}>
        {stale ? "FEED STALE" : "PUBLIC LIVE"}
      </span>
    </div>
  );
}

function MatchBug({
  snapshot, countdown,
}: {
  snapshot: BroadcastSnapshot; countdown: string;
}) {
  return (
    <div className="broadcast-match-bug">
      <div>
        <span>{snapshot.match.mode.replace(/_/g, " ")}</span>
        <strong>{snapshot.match.name}</strong>
      </div>
      <div className="broadcast-round">
        <span>ROUND {snapshot.match.round}</span>
        <b>{countdown}</b>
      </div>
    </div>
  );
}

function DisclosureBadge({ snapshot }: { snapshot: BroadcastSnapshot }) {
  const delay = snapshot.disclosure.scoreboard_delay_rounds;
  return (
    <div className="broadcast-disclosure">
      <span>PUBLIC PROJECTION</span>
      <strong>{delay > 0 ? `DELAYED ${delay} ROUND${delay === 1 ? "" : "S"}` : "NO SCORE DELAY"}</strong>
      <small>THROUGH R{snapshot.disclosure.last_public_round}</small>
    </div>
  );
}

function Scorebar({
  snapshot, countdown, maximum, stale,
}: {
  snapshot: BroadcastSnapshot; countdown: string; maximum: number; stale: boolean;
}) {
  const rows = snapshot.scoreboard.scoreboard.slice(0, maximum);
  return (
    <section className="broadcast-scorebar" aria-label="Public match scorebar">
      <div className="broadcast-topline">
        <BroadcastBrand stale={stale} />
        <MatchBug snapshot={snapshot} countdown={countdown} />
      </div>
      <ol className="broadcast-score-cards">
        {rows.map((row) => <ScoreCard key={row.team_id} row={row} />)}
      </ol>
      <DisclosureBadge snapshot={snapshot} />
    </section>
  );
}

function ScoreCard({ row }: { row: ScoreRow }) {
  return (
    <li className={row.rank === 1 ? "is-leader" : ""}>
      <span className="broadcast-rank">{row.rank.toString().padStart(2, "0")}</span>
      <strong>{row.team}</strong>
      <b>{row.total.toLocaleString()}</b>
      <small>A {row.attack} · D {row.defense} · U {row.availability}</small>
    </li>
  );
}

function Standings({
  snapshot, countdown, maximum, stale,
}: {
  snapshot: BroadcastSnapshot; countdown: string; maximum: number; stale: boolean;
}) {
  const rows = snapshot.scoreboard.scoreboard.slice(0, maximum);
  const healthy = snapshot.services.reduce((total, service) => total + Number(service.healthy ?? 0), 0);
  const total = snapshot.services.reduce((sum, service) => sum + Number(service.total ?? 0), 0);
  return (
    <section className="broadcast-standings" aria-label="Public match standings">
      <header>
        <BroadcastBrand stale={stale} />
        <MatchBug snapshot={snapshot} countdown={countdown} />
      </header>
      <div className="broadcast-standings-grid">
        <section className="broadcast-board">
          <div className="broadcast-section-title">
            <div><span>AUTHORITATIVE PUBLIC SCORE</span><h2>Current standings</h2></div>
            {snapshot.scoreboard.provisional && <b>PROVISIONAL</b>}
          </div>
          <ol>
            {rows.map((row) => (
              <li key={row.team_id} className={row.rank === 1 ? "is-leader" : ""}>
                <span>{row.rank.toString().padStart(2, "0")}</span>
                <strong>{row.team}</strong>
                <dl>
                  <div><dt>ATK</dt><dd>{row.attack}</dd></div>
                  <div><dt>DEF</dt><dd>{row.defense}</dd></div>
                  <div><dt>UP</dt><dd>{row.availability}</dd></div>
                </dl>
                <b>{row.total.toLocaleString()}</b>
              </li>
            ))}
          </ol>
        </section>
        <aside className="broadcast-posture">
          <div className="broadcast-section-title"><div><span>AGGREGATE ONLY</span><h2>Service posture</h2></div></div>
          <div className="broadcast-health-total">
            <strong>{healthy}<small> / {total}</small></strong><span>HEALTHY INSTANCES</span>
          </div>
          <ul>{snapshot.services.map((service) => (
            <li key={service.service_id}>
              <div><strong>{service.name ?? service.service}</strong><span>{service.status.toUpperCase()}</span></div>
              <div className="broadcast-health-track"><i style={{ width: `${Number(service.total) > 0 ? Number(service.healthy) / Number(service.total) * 100 : 0}%` }} /></div>
              <small>{service.healthy ?? 0} OF {service.total ?? 0} HEALTHY</small>
            </li>
          ))}</ul>
          <DisclosureBadge snapshot={snapshot} />
        </aside>
      </div>
    </section>
  );
}

function BracketOverlay({
  snapshot, countdown, stale,
}: {
  snapshot: BroadcastSnapshot; countdown: string; stale: boolean;
}) {
  const tournament = snapshot.tournament;
  return (
    <section className="broadcast-bracket" aria-label="Public tournament bracket">
      <header>
        <BroadcastBrand stale={stale} />
        <MatchBug snapshot={snapshot} countdown={countdown} />
      </header>
      {!tournament ? (
        <div className="broadcast-unavailable" role="status">
          <span>TOURNAMENT GRAPHIC</span><strong>No public bracket is attached to this Match</strong>
        </div>
      ) : <PublicBracket tournament={tournament} />}
      <DisclosureBadge snapshot={snapshot} />
    </section>
  );
}

function PublicBracket({ tournament }: { tournament: TournamentState }) {
  const entries = new Map(tournament.entries.map((entry) => [entry.id, entry]));
  return (
    <div className="broadcast-bracket-frame">
      <div className="broadcast-bracket-heading">
        <div><span>LIVECTF · SINGLE ELIMINATION</span><h2>{tournament.name}</h2></div>
        <strong>{tournament.status.toUpperCase()} · {tournament.bracket_size} TEAMS</strong>
      </div>
      <div className="broadcast-bracket-stages">
        {tournament.stages.map((stage) => (
          <section key={stage.id}>
            <header><span>STAGE {stage.sequence}</span><strong>{stage.name}</strong></header>
            <div>{tournament.fixtures.filter((fixture) => fixture.stage_sequence === stage.sequence).map(
              (fixture) => <PublicFixture key={fixture.id} fixture={fixture} tournament={tournament} entries={entries} />,
            )}</div>
          </section>
        ))}
      </div>
      {tournament.winner_entry_id && (
        <div className="broadcast-champion">
          <span>TOURNAMENT CHAMPION</span>
          <strong>{entries.get(tournament.winner_entry_id)?.name ?? "Confirmed winner"}</strong>
        </div>
      )}
    </div>
  );
}

function PublicFixture({
  fixture, entries,
}: {
  fixture: TournamentFixture;
  tournament: TournamentState;
  entries: Map<string, TournamentState["entries"][number]>;
}) {
  const teamIds = [fixture.team_a_entry_id, fixture.team_b_entry_id];
  return (
    <article className={`broadcast-fixture is-${fixture.status}`}>
      <div><span>MATCH {fixture.bracket_position.toString().padStart(2, "0")}</span><b>{fixture.status.toUpperCase()}</b></div>
      {teamIds.map((entryId, index) => {
        const entry = entryId ? entries.get(entryId) : undefined;
        const winner = entry?.id === fixture.winner_entry_id;
        const total = entry ? fixture.result?.scores?.[entry.id]?.total : undefined;
        return (
          <p key={entryId ?? `tbd-${index}`} className={winner ? "is-winner" : ""}>
            <span>{entry?.seed ? `#${entry.seed}` : "—"}</span>
            <strong>{entry?.name ?? "TBD"}</strong>
            {winner && <small>ADV</small>}
            {typeof total === "number" && <b>{total}</b>}
          </p>
        );
      })}
    </article>
  );
}
