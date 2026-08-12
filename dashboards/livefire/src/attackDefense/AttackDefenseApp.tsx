import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import {
  Command, CommandPalette, EmptyState, ErrorState,
  FlagSubmissionPanel, IncidentQueue, InfrastructureStatusPanel, LatencySparkline,
  KothControlBoard, LiveEventFeed, LiveMatchHeader, LoadingState, MetricTile, OperatorActionDialog,
  PatchPipeline, ScoreStrip, ServiceMatrix, ServiceStatusBadge,
  StealthOperationsBoard, TacticalNetworkView, TeamRankBadge,
} from "./components";
import { decodeRole, httpAttackDefenseApi, login } from "./api";
import { useLiveEvents } from "./useLiveEvents";
import type {
  AttackSurface, CaptureRecord, KothState, LiveRole, MatchState, PatchRecord, RuntimeSnapshot,
  ScoreRow, ScoreboardResponse, ServiceInstance, StealthState, TournamentState,
} from "./types";
import { NAVIGATION } from "./types";


export function visibleNavigation(role: LiveRole, tournamentAvailable = false) {
  return tournamentAvailable
    ? [...NAVIGATION[role], "Tournament Bracket"]
    : NAVIGATION[role];
}

function initialIdentity() {
  const token = localStorage.getItem("cr_access_token") ?? "";
  const claims = decodeRole(token);
  const presentation = window.location.pathname.startsWith("/observer/");
  return { token, ...claims, role: presentation ? "observer" as const : claims.role };
}

export function AttackDefenseApp({ modeControl }: { modeControl: ReactNode }) {
  const [identity, setIdentity] = useState(initialIdentity);
  const [matchId, setMatchId] = useState(
    identity.matchId || localStorage.getItem("cr_match_id") || "ad-demo",
  );
  const [active, setActive] = useState(visibleNavigation(identity.role)[0]);
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot>({
    state: null, services: [], scoreboard: null, attackSurface: null,
    patches: [], captures: [], koth: null, stealth: null,
    tournament: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [action, setAction] = useState<"pause" | "resume" | "finalize" | "end" | null>(null);
  const { events, connection, lastReceivedAt } = useLiveEvents(matchId, identity.token);

  const refresh = useCallback(async () => {
    try {
      const [state, scoreboard] = await Promise.all([
        httpAttackDefenseApi.getState(matchId, identity.role, identity.token),
        httpAttackDefenseApi.getScoreboard(matchId, identity.role, identity.token),
      ]);
      const [services, attackSurface, patches, captures, koth, stealth] = await Promise.all([
        httpAttackDefenseApi.getServices(matchId, identity.role, identity.token).catch(() => []),
        identity.role === "competitor"
          ? httpAttackDefenseApi.getAttackSurface(matchId, identity.token).catch(() => null)
          : Promise.resolve(null),
        identity.role === "observer"
          ? Promise.resolve([]) : httpAttackDefenseApi.getPatches(matchId, identity.role, identity.token).catch(() => []),
        httpAttackDefenseApi.getCaptures(matchId, identity.role, identity.token).catch(() => []),
        httpAttackDefenseApi.getKoth(matchId, identity.role, identity.token).catch(() => null),
        httpAttackDefenseApi.getStealth(matchId, identity.role, identity.token).catch(() => null),
      ]);
      const configuredTournament = state.tournament_id
        ?? identity.tournamentId
        ?? new URLSearchParams(window.location.search).get("tournament_id");
      const tournament = configuredTournament
        ? await httpAttackDefenseApi.getTournament(
          configuredTournament, identity.role, identity.token,
        ).catch(() => null)
        : null;
      // The API is authoritative for Match mode and state. The shell selector
      // chooses a client experience; it must never rewrite server-confirmed mode.
      setSnapshot({
        state, scoreboard, services, attackSurface, patches, captures, koth,
        stealth, tournament,
      });
      setError("");
    } catch (reason) {
      setError(String(reason));
    } finally {
      setLoading(false);
    }
  }, [identity.role, identity.token, matchId]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), document.visibilityState === "hidden" ? 15_000 : 5_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => setActive(visibleNavigation(identity.role)[0]), [identity.role]);

  const navigation = visibleNavigation(identity.role, Boolean(snapshot.tournament));
  const navigationKey = navigation.join("|");

  const ownScore = snapshot.scoreboard?.scoreboard.find(
    (row) => row.team_id === snapshot.state?.team?.id,
  );
  const urgent = events.filter(
    (event) => event.result === "failed" || event.type.includes("error"),
  ).length;

  const navigate = (label: string) => setActive(label);
  const commands = useMemo<Command[]>(() => {
    const base: Command[] = navigation.map((label) => ({
      id: `go-${label}`, label: `Go to ${label}`, group: "Navigation",
      run: () => navigate(label),
    }));
    if (identity.role === "competitor") {
      base.push({ id: "submit-flag", label: "Submit Flag", group: "Attack", run: () => navigate("Attack Console") });
    }
    if (identity.role === "operator") {
      base.push(
        { id: "pause-match", label: "Pause Match", group: "Match control", dangerous: true, run: () => setAction("pause") },
        { id: "finalize-round", label: "Finalize Round", group: "Round control", dangerous: true, run: () => setAction("finalize") },
      );
    }
    return base;
  }, [identity.role, navigationKey]);

  if (loading && !snapshot.state) return <div className="ad-root"><LoadingState /></div>;

  return (
    <div className={`ad-root role-${identity.role}`}>
      <a className="skip-link" href="#main-content">Skip to live match content</a>
      <LiveMatchHeader
        state={snapshot.state} connection={connection} lastReceivedAt={lastReceivedAt}
        urgentCount={urgent} modeControl={modeControl}
        viewerLabel={identity.role === "operator" ? "OPERATOR VIEW" : "PUBLIC VIEW"}
      />
      <div className="operations-shell">
        <aside className="role-navigation" aria-label={`${identity.role} navigation`}>
          <div className="role-block">
            <span>ACTIVE ROLE</span><strong>{identity.role.toUpperCase()}</strong>
            <small>{snapshot.state?.team?.name ?? (
              identity.role === "operator"
                ? "full operational view"
                : "sanitized public feed"
            )}</small>
          </div>
          <nav>{navigation.map((label) => (
            <button key={label} className={active === label ? "active" : ""} onClick={() => navigate(label)}>
              <span aria-hidden="true">{navIcon(label)}</span>{label}
            </button>
          ))}</nav>
          <div className="nav-footer">
            <label>Match ID<input value={matchId} onChange={(event) => {
              setMatchId(event.target.value); localStorage.setItem("cr_match_id", event.target.value);
            }} /></label>
            {!identity.token && <LoginPanel onLogin={(next) => {
              localStorage.setItem("cr_access_token", next.access_token);
              localStorage.setItem("cr_match_id", next.match_id);
              const claims = decodeRole(next.access_token);
              setIdentity({ token: next.access_token, ...claims });
              setMatchId(next.match_id);
            }} />}
          </div>
        </aside>
        <main id="main-content" className="operations-main" tabIndex={-1}>
          {error && <ErrorState label="Confirmed state could not be refreshed. Showing last known data." unauthorized={error.includes("401") || error.includes("403")} />}
          <Page
            active={active} role={identity.role} matchId={matchId} token={identity.token}
            state={snapshot.state} services={snapshot.services}
            scoreboard={snapshot.scoreboard} ownScore={ownScore}
            attackSurface={snapshot.attackSurface} patches={snapshot.patches}
            captures={snapshot.captures}
            koth={snapshot.koth}
            stealth={snapshot.stealth}
            tournament={snapshot.tournament}
            events={events} refresh={refresh} setAction={setAction}
          />
        </main>
      </div>
      <CommandPalette commands={commands} />
      <OperatorActionDialog
        open={action !== null}
        title={actionTitle(action)}
        impact={actionImpact(action)}
        confirmation={action === "end" ? snapshot.state?.name : undefined}
        onClose={() => setAction(null)}
        onConfirm={async (reason) => {
          if (!action) return;
          await httpAttackDefenseApi.operatorAction(matchId, action, identity.token, reason);
          setAction(null); await refresh();
        }}
      />
    </div>
  );
}

function Page(props: {
  active: string; role: LiveRole; matchId: string; token: string;
  state: MatchState | null; services: ServiceInstance[];
  scoreboard: ScoreboardResponse | null; ownScore?: ScoreRow;
  attackSurface: AttackSurface | null; patches: PatchRecord[]; captures: CaptureRecord[];
  koth: KothState | null;
  stealth: StealthState | null;
  tournament: TournamentState | null;
  events: ReturnType<typeof useLiveEvents>["events"]; refresh: () => Promise<void>;
  setAction: (action: "pause" | "resume" | "finalize" | "end") => void;
}) {
  if (props.active === "Tournament Bracket") {
    return <TournamentBracket tournament={props.tournament} role={props.role} />;
  }
  if (props.role === "operator" && [
    "Command Center", "Match Control", "Team Matrix", "Service Matrix", "Round Control",
    "Infrastructure", "Observability", "Checker Operations", "Flag Operations",
  ].includes(props.active)) {
    return <OperatorCommandCenter {...props} />;
  }
  if (props.role === "observer") {
    return <ObserverView {...props} />;
  }
  switch (props.active) {
    case "Attack Console":
      return <FlagSubmissionPanel onSubmit={(flag) => httpAttackDefenseApi.submitFlag(props.matchId, props.token, flag)} />;
    case "Defense Console":
    case "Services":
      return <DefenseConsole services={props.services} patches={props.patches} />;
    case "Patches":
      return <PatchOperations {...props} />;
    case "Captures":
      return <CaptureEvidence {...props} />;
    case "Scoreboard":
    case "Scoring":
      return <ScoreboardView scoreboard={props.scoreboard} />;
    case "Event Feed":
    case "Patch Review":
      return props.active === "Patch Review"
        ? <PatchList patches={props.patches} />
        : <LiveEventFeed events={props.events} />;
    case "Evidence":
      return <div className="page-grid"><CaptureEvidence {...props} /><LiveEventFeed events={props.events} /></div>;
    default:
      return <BattleOverview {...props} />;
  }
}

function BattleOverview(props: {
  matchId: string; token: string; refresh: () => Promise<void>;
  state: MatchState | null; services: ServiceInstance[]; ownScore?: ScoreRow;
  attackSurface: AttackSurface | null; koth: KothState | null;
  stealth: StealthState | null;
  events: ReturnType<typeof useLiveEvents>["events"];
}) {
  return (
    <div className="page-grid battle-overview">
      <section className="span-all"><div className="section-kicker">TACTICAL SCORE</div><ScoreStrip row={props.ownScore} /></section>
      <section className="panel own-services">
        <div className="panel-heading"><div><span>DEFENSE POSTURE</span><h1>Own service status</h1></div><b>{props.services.length} services</b></div>
        <div className="service-card-grid">
          {props.services.length === 0 ? <EmptyState label="No service state available for this role" /> : props.services.map((service) => (
            <article className="service-card" key={service.id}>
              <div><strong>{service.service_slug ?? service.service}</strong><ServiceStatusBadge status={service.status} /></div>
              <dl>
                <div><dt>Last confirmed</dt><dd>{service.last_health_at ? new Date(service.last_health_at * 1000).toLocaleTimeString() : "not checked"}</dd></div>
                <div><dt>Image</dt><dd><code>{service.image_digest?.slice(0, 18) ?? "pending"}</code></dd></div>
              </dl>
              <small className="confirmed-signal">
                {service.last_health_at ? "✓ CHECKER CONFIRMED" : "◇ CHECK PENDING"}
              </small>
            </article>
          ))}
        </div>
      </section>
      <section className="panel attack-surface">
        <div className="panel-heading"><div><span>PUBLIC ATTACK PLANE</span><h2>Attack surface</h2></div></div>
        {!props.attackSurface ? <EmptyState label="Attack surface is hidden in this role" /> : (
          <div className="matrix-scroll"><table><thead><tr><th>Team</th>{props.attackSurface.services.map((service) => <th key={service.id}>{service.name}</th>)}</tr></thead>
            <tbody>{props.attackSurface.teams.map((team) => <tr key={team.id}><th>{team.name}</th>{props.attackSurface!.services.map((service) => (
              <td key={service.id}><span className="reachable-cell"><span aria-hidden="true">↗</span> target</span></td>
            ))}</tr>)}</tbody>
          </table></div>
        )}
      </section>
      {props.koth?.enabled && <KothControlBoard state={props.koth} />}
      {props.stealth?.enabled && <StealthOperationsBoard
        state={props.stealth}
        services={props.services}
        onReport={async (serviceId, indicatorHash, summary) => {
          await httpAttackDefenseApi.submitStealthDetection(
            props.matchId, props.token, serviceId, indicatorHash, summary,
          );
          await props.refresh();
        }}
      />}
      <LiveEventFeed events={props.events} />
    </div>
  );
}

function DefenseConsole({ services, patches }: { services: ServiceInstance[]; patches: PatchRecord[] }) {
  const [selected, setSelected] = useState<ServiceInstance | null>(services[0] ?? null);
  return (
    <div className="defense-layout">
      <section className="panel">
        <div className="panel-heading"><div><span>SERVICE DEFENSE</span><h1>Defense console</h1></div></div>
        <div className="service-list">
          {services.map((service) => (
            <button key={service.id} className={selected?.id === service.id ? "selected" : ""} onClick={() => setSelected(service)}>
              <ServiceStatusBadge status={service.status} /><strong>{service.service_slug ?? service.service}</strong>
              <code>{service.image_digest?.slice(0, 16) ?? "pending"}</code>
            </button>
          ))}
        </div>
      </section>
      <aside className="detail-panel">
        {!selected ? <EmptyState label="Select a service" /> : <>
          <div className="panel-heading"><div><span>SERVICE DETAIL</span><h2>{selected.service_slug ?? selected.service}</h2></div><ServiceStatusBadge status={selected.status} /></div>
          <div className="detail-metrics">
            <MetricTile label="Last healthy" value={selected.last_health_at ? new Date(selected.last_health_at * 1000).toLocaleTimeString() : "—"} />
            <MetricTile label="Current image" value={<code>{selected.image_digest?.slice(0, 18) ?? "—"}</code>} />
          </div>
          <h3>Latency</h3><LatencySparkline values={[]} />
          <h3>Patch history</h3>
          {patches.filter((patch) => patch.service_id === selected.service_id).map((patch) => <PatchPipeline key={patch.id} patch={patch} />)}
        </>}
      </aside>
    </div>
  );
}

function PatchOperations(props: {
  matchId: string; token: string; services: ServiceInstance[];
  patches: PatchRecord[]; refresh: () => Promise<void>;
}) {
  const [serviceId, setServiceId] = useState(props.services[0]?.service_id ?? "");
  const [reference, setReference] = useState("");
  const [message, setMessage] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      await httpAttackDefenseApi.submitPatch(props.matchId, serviceId, props.token, reference);
      setMessage("Patch uploaded. Validation waits for the trusted runtime runner.");
      setReference(""); await props.refresh();
    } catch {
      setMessage("Patch submission rejected. Verify registry namespace, tag, and policy.");
    }
  }
  return (
    <div className="page-grid">
      <section className="panel patch-submit">
        <div className="panel-heading"><div><span>PATCH OPERATIONS</span><h1>Submit candidate image</h1></div></div>
        <p>Service remains on the previous image until validation completes.</p>
        <form onSubmit={submit}>
          <label>Service<select value={serviceId} onChange={(event) => setServiceId(event.target.value)}>
            {props.services.map((service) => <option key={service.id} value={service.service_id}>{service.service_slug ?? service.service}</option>)}
          </select></label>
          <label>Image reference<input value={reference} onChange={(event) => setReference(event.target.value)} placeholder="registry.local:5000/team-01/vulnerable-notes:patch-001" /></label>
          <button className="primary-action" disabled={!serviceId || !reference}>UPLOAD PATCH</button>
          {message && <p role="status">{message}</p>}
        </form>
      </section>
      <PatchList patches={props.patches} />
    </div>
  );
}

function PatchList({ patches }: { patches: PatchRecord[] }) {
  return (
    <section className="panel span-all">
      <div className="panel-heading"><div><span>DEPLOYMENT HISTORY</span><h2>Patch pipelines</h2></div><b>{patches.length}</b></div>
      {patches.length === 0 ? <EmptyState label="No patch submissions" /> : patches.map((patch) => <PatchPipeline key={patch.id} patch={patch} />)}
    </section>
  );
}

function CaptureEvidence(props: {
  role: LiveRole; matchId: string; token: string; captures: CaptureRecord[];
  refresh: () => Promise<void>;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState("");

  async function upload(event: FormEvent) {
    event.preventDefault();
    if (!file || reason.trim().length < 3) return;
    try {
      await httpAttackDefenseApi.uploadCapture(props.matchId, props.token, file, reason);
      setMessage("Capture sanitized. Release remains server-gated until its configured time.");
      setFile(null); setReason(""); await props.refresh();
    } catch {
      setMessage("Capture rejected. Verify classic PCAP format, size, timestamp, and policy.");
    }
  }

  async function download(capture: CaptureRecord) {
    try {
      const result = await httpAttackDefenseApi.downloadCapture(
        props.matchId, capture.id, props.token,
      );
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = result.filename; anchor.click();
      URL.revokeObjectURL(url);
      setMessage("Sanitized team-watermarked capture downloaded.");
    } catch {
      setMessage("Capture is still withheld or temporarily unavailable.");
    }
  }

  return (
    <section className="panel capture-evidence span-all">
      <div className="panel-heading">
        <div><span>PRIVACY-GATED EVIDENCE</span><h1>Sanitized packet captures</h1></div>
        <b>{props.captures.filter((item) => item.available).length} available</b>
      </div>
      {props.role === "operator" && (
        <form className="capture-upload" onSubmit={upload}>
          <label>Classic PCAP file<input type="file" accept=".pcap,application/vnd.tcpdump.pcap" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>
          <label>Audit reason<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="post-round evidence release" /></label>
          <button className="primary-action" disabled={!file || reason.trim().length < 3}>SANITIZE CAPTURE</button>
        </form>
      )}
      <p className="sanitized-note">RAW CAPTURE IS NOT STORED · IP/MAC PSEUDONYMIZED · FLAGS AND CREDENTIALS REDACTED · DOWNLOADS WATERMARKED</p>
      {props.captures.length === 0 ? <EmptyState label="No sanitized captures registered" /> : (
        <div className="matrix-scroll"><table>
          <thead><tr><th>Captured</th><th>Round</th><th>Service</th><th>Packets</th><th>Size</th><th>Release</th><th>Action</th></tr></thead>
          <tbody>{props.captures.map((capture) => <tr key={capture.id}>
            <td><time>{new Date(capture.captured_until * 1000).toLocaleString()}</time></td>
            <td>{capture.round ?? "—"}</td><td>{capture.service ?? "match-wide"}</td>
            <td>{capture.packet_count.toLocaleString()}</td>
            <td>{Math.ceil(capture.size_bytes / 1024).toLocaleString()} KiB</td>
            <td><ServiceStatusBadge status={capture.available ? "healthy" : "withheld"} /> <time>{new Date(capture.release_at * 1000).toLocaleString()}</time></td>
            <td>{props.role === "competitor"
              ? <button disabled={!capture.available} onClick={() => void download(capture)}>{capture.available ? "Download" : "Withheld"}</button>
              : <code>{capture.sanitizer_version ?? "pcap-v1"}</code>}</td>
          </tr>)}</tbody>
        </table></div>
      )}
      {message && <p className="capture-message" role="status">{message}</p>}
    </section>
  );
}

function OperatorCommandCenter(props: {
  matchId: string; token: string; refresh: () => Promise<void>;
  state: MatchState | null; services: ServiceInstance[]; scoreboard: ScoreboardResponse | null;
  patches: PatchRecord[]; events: ReturnType<typeof useLiveEvents>["events"];
  koth: KothState | null;
  stealth: StealthState | null;
  setAction: (action: "pause" | "resume" | "finalize" | "end") => void;
}) {
  const [selected, setSelected] = useState<ServiceInstance | null>(null);
  const [serviceAction, setServiceAction] = useState<"restart" | "rollback" | null>(null);
  const healthy = props.services.filter((service) => service.status === "healthy").length;
  const degraded = props.services.filter((service) => service.status !== "healthy").length;
  return (
    <div className="page-grid command-center">
      <section className="global-ribbon span-all">
        <MetricTile label="Teams" value={props.scoreboard?.scoreboard.length ?? 0} />
        <MetricTile label="Healthy services" value={healthy} tone="defense" />
        <MetricTile label="Degraded services" value={degraded} tone={degraded ? "critical" : "neutral"} />
        <MetricTile label="Pending patches" value={props.patches.filter((patch) => !["deployed", "rejected", "failed"].includes(patch.status)).length} tone="operator" />
        <MetricTile label="Critical incidents" value={props.events.filter((event) => event.result === "failed").length} tone="critical" />
      </section>
      <section className="panel span-all">
        <div className="panel-heading"><div><span>TEAM × SERVICE</span><h1>Service matrix</h1></div></div>
        <ServiceMatrix instances={props.services} onSelect={setSelected} />
        {selected && (
          <aside className="operator-service-detail" aria-live="polite">
            <div>
              <span>SELECTED SERVICE</span>
              <strong>{selected.team_slug} / {selected.service_slug ?? selected.service}</strong>
              <ServiceStatusBadge status={selected.status} />
            </div>
            <dl>
              <div><dt>Last check</dt><dd>{selected.last_health_at ? new Date(selected.last_health_at * 1000).toLocaleTimeString() : "not checked"}</dd></div>
              <div><dt>Image</dt><dd><code>{selected.image_digest?.slice(0, 22) ?? "pending"}</code></dd></div>
            </dl>
            <div className="operator-actions">
              <button onClick={() => setServiceAction("restart")}>Restart service</button>
              <button className="danger-action" disabled={!selected.previous_image_digest} onClick={() => setServiceAction("rollback")}>Rollback image</button>
            </div>
          </aside>
        )}
      </section>
      {props.koth?.enabled && <KothControlBoard state={props.koth} />}
      {props.stealth?.enabled && <StealthOperationsBoard state={props.stealth} />}
      <TacticalNetworkView instances={props.services} />
      <section className="panel round-control">
        <div className="panel-heading"><div><span>AUTHORITY REQUIRED</span><h2>Round control</h2></div></div>
        <p>Every action requires an audit reason and server authorization.</p>
        <div className="operator-actions">
          {props.state?.status === "paused"
            ? <button onClick={() => props.setAction("resume")}>Resume match</button>
            : <button onClick={() => props.setAction("pause")}>Pause match</button>}
          <button onClick={() => props.setAction("finalize")}>Finalize round</button>
          <button className="danger-action" onClick={() => props.setAction("end")}>Stop match</button>
        </div>
      </section>
      <InfrastructureStatusPanel items={[
        { name: "Attack/Defense API", status: props.state ? "healthy" : "offline", detail: props.state ? "confirmed" : "unreachable" },
        { name: "Game engine", status: props.state?.status === "running" ? "healthy" : "degraded", detail: props.state?.round_status ?? "not active" },
        { name: "Checker workers", status: "declared", detail: "worker telemetry unavailable" },
        { name: "Registry / runtime", status: props.patches.some((patch) => patch.status === "failed") ? "degraded" : "declared", detail: "job-backed status only" },
      ]} />
      <IncidentQueue events={props.events} />
      <OperatorActionDialog
        open={serviceAction !== null}
        title={`${serviceAction === "rollback" ? "Rollback" : "Restart"} service`}
        impact="This operation can interrupt the service and reduce Availability. A durable runtime job and audit event will be created."
        confirmation={selected?.service_slug ?? selected?.service}
        onClose={() => setServiceAction(null)}
        onConfirm={async (reason) => {
          if (!selected?.team_id || !serviceAction) return;
          await httpAttackDefenseApi.operatorServiceAction(
            props.matchId, selected.team_id, selected.service_id,
            serviceAction, props.token, reason,
          );
          setServiceAction(null);
          await props.refresh();
        }}
      />
    </div>
  );
}

function ObserverView(props: {
  active: string; scoreboard: ScoreboardResponse | null; services: ServiceInstance[];
  koth: KothState | null;
  stealth: StealthState | null;
  events: ReturnType<typeof useLiveEvents>["events"];
}) {
  if (props.active === "Scoreboard") return <ScoreboardView scoreboard={props.scoreboard} />;
  if (["Match Timeline", "Major Events"].includes(props.active)) return <LiveEventFeed events={props.events} />;
  return (
    <div className="page-grid observer-view">
      <ScoreboardView scoreboard={props.scoreboard} />
      {props.koth?.enabled && <KothControlBoard state={props.koth} />}
      {props.stealth?.enabled && <StealthOperationsBoard state={props.stealth} />}
      <section className="panel">
        <div className="panel-heading"><div><span>BROADCAST SAFE</span><h2>Service availability</h2></div></div>
        <div className="service-card-grid">
          {props.services.length === 0
            ? <EmptyState label="No public service summary available" />
            : props.services.map((service) => (
              <article className="service-card" key={service.service_id}>
                <div>
                  <strong>{service.service}</strong>
                  <ServiceStatusBadge status={service.status} />
                </div>
                <MetricTile
                  label="Healthy instances"
                  value={`${service.healthy ?? 0}/${service.total ?? 0}`}
                  detail={`${service.degraded ?? 0} degraded · aggregate only`}
                />
              </article>
            ))}
        </div>
        <p className="sanitized-note">SANITIZED · No endpoints, checker logs, team mapping, or image references</p>
      </section>
      <LiveEventFeed events={props.events} />
    </div>
  );
}

function ScoreboardView({ scoreboard }: { scoreboard: ScoreboardResponse | null }) {
  if (!scoreboard) return <LoadingState label="Loading authoritative scores…" />;
  return (
    <section className="panel scoreboard-view span-all">
      <div className="panel-heading">
        <div><span>{scoreboard.view === "operator" ? "REAL-TIME INTERNAL" : "PUBLIC SCORE"}</span><h1>Scoreboard</h1></div>
        <div>{(scoreboard.delay_rounds ?? 0) > 0 && <strong>DELAYED BY {scoreboard.delay_rounds} ROUNDS</strong>} {scoreboard.provisional && <span className="provisional">PROVISIONAL</span>}</div>
      </div>
      <div className="matrix-scroll"><table>
        <thead><tr><th>Rank</th><th>Team</th><th>Attack</th><th>Defense</th><th>Flag Defense</th><th>Availability</th><th>Detection</th><th>Containment</th><th>Recovery</th><th>Incident Response</th><th>Mission Inject</th><th>KOTH</th><th>Stealth Attack</th><th>Stealth Detection</th><th>Penalty</th><th>Adjustment</th><th>Total</th><th>Round</th></tr></thead>
        <tbody>{scoreboard.scoreboard.map((row) => <tr key={row.team_id}>
          <td><TeamRankBadge rank={row.rank} /></td><th>{row.team}</th>
          <td className="score-attack">{row.attack}</td>
          <td className="score-defense">{row.defense}</td>
          <td className="score-defense">{row.flag_defense}</td>
          <td className="score-availability">{row.availability}</td>
          <td>{row.detection}</td><td>{row.containment}</td><td>{row.recovery}</td>
          <td>{row.incident_response}</td><td>{row.mission_inject}</td>
          <td className="score-koth">{row.koth}</td>
          <td className="score-stealth-attack">{row.stealth_attack}</td>
          <td className="score-stealth-detection">{row.stealth_detection}</td>
          <td>{row.penalty}</td><td>{row.adjustment}</td>
          <td className="score-total">{row.total}</td>
          <td>{row.last_updated_round}</td>
        </tr>)}</tbody>
      </table></div>
    </section>
  );
}

function TournamentBracket({
  tournament, role,
}: {
  tournament: TournamentState | null; role: LiveRole;
}) {
  if (!tournament) {
    return <EmptyState label="No tournament is attached to this Match" />;
  }
  const entryById = new Map(tournament.entries.map((entry) => [entry.id, entry]));
  const ownEntryId = tournament.identity?.entry_id;
  return (
    <section className="panel tournament-bracket span-all">
      <div className="panel-heading tournament-heading">
        <div>
          <span>LIVECTF · SERVER-CONFIRMED BRACKET</span>
          <h1>{tournament.name}</h1>
        </div>
        <div className="tournament-summary">
          <ServiceStatusBadge status={tournament.status} />
          <strong>{tournament.bracket_size} TEAMS · {tournament.match_mode.replace(/_/g, " ")}</strong>
        </div>
      </div>
      <p className="sanitized-note">
        {role === "operator"
          ? "OPERATOR VIEW · Fixture Match IDs and real-time results are visible"
          : "BROADCAST SAFE · No credentials, endpoints, checker detail, or runtime mapping"}
      </p>
      <div className="bracket-scroll" role="region" aria-label={`${tournament.name} elimination bracket`} tabIndex={0}>
        <div className="bracket-grid">
          {tournament.stages.map((stage) => {
            const fixtures = tournament.fixtures.filter(
              (fixture) => fixture.stage_sequence === stage.sequence,
            );
            return (
              <section className="bracket-stage" key={stage.id} aria-labelledby={`stage-${stage.id}`}>
                <header>
                  <div><span>STAGE {stage.sequence}</span><h2 id={`stage-${stage.id}`}>{stage.name}</h2></div>
                  <ServiceStatusBadge status={stage.status} />
                </header>
                <div className="bracket-fixtures">
                  {fixtures.map((fixture) => {
                    const teamA = fixture.team_a_entry_id
                      ? entryById.get(fixture.team_a_entry_id) : undefined;
                    const teamB = fixture.team_b_entry_id
                      ? entryById.get(fixture.team_b_entry_id) : undefined;
                    return (
                      <article className={`bracket-fixture fixture-${fixture.status}`} key={fixture.id}>
                        <div className="fixture-meta">
                          <span>MATCH {fixture.bracket_position.toString().padStart(2, "0")}</span>
                          <ServiceStatusBadge status={fixture.status} />
                        </div>
                        <BracketTeam
                          entry={teamA}
                          own={teamA?.id === ownEntryId}
                          winner={teamA?.id === fixture.winner_entry_id}
                          total={teamA ? fixture.result?.scores?.[teamA.id]?.total : undefined}
                        />
                        <BracketTeam
                          entry={teamB}
                          own={teamB?.id === ownEntryId}
                          winner={teamB?.id === fixture.winner_entry_id}
                          total={teamB ? fixture.result?.scores?.[teamB.id]?.total : undefined}
                        />
                        {role === "operator" && fixture.match_id && (
                          <code className="fixture-match-id">{fixture.match_id}</code>
                        )}
                      </article>
                    );
                  })}
                </div>
              </section>
            );
          })}
        </div>
      </div>
      {tournament.winner_entry_id && (
        <div className="champion-ribbon" role="status">
          <span aria-hidden="true">◆</span>
          <div><small>TOURNAMENT CHAMPION</small><strong>{entryById.get(tournament.winner_entry_id)?.name ?? "Confirmed winner"}</strong></div>
        </div>
      )}
    </section>
  );
}

function BracketTeam({
  entry, own, winner, total,
}: {
  entry?: TournamentState["entries"][number];
  own: boolean;
  winner: boolean;
  total?: number;
}) {
  return (
    <div className={`bracket-team ${winner ? "winner" : ""} ${own ? "own" : ""}`}>
      <span className="seed">{entry?.seed ? `#${entry.seed}` : "—"}</span>
      <strong>{entry?.name ?? "TBD"}</strong>
      {own && <small>YOU</small>}
      {winner && <span aria-label="winner">ADV</span>}
      {typeof total === "number" && <b>{total}</b>}
    </div>
  );
}

function LoginPanel({ onLogin }: { onLogin: (value: { access_token: string; match_id: string }) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  return (
    <form className="login-panel" onSubmit={async (event) => {
      event.preventDefault();
      try { onLogin(await login(username, password)); }
      catch { setError("Login failed"); }
    }}>
      <strong>Competitor / operator login</strong>
      <input aria-label="Username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="username" />
      <input aria-label="Password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="password" type="password" />
      <button>Sign in</button>{error && <small role="alert">{error}</small>}
    </form>
  );
}

function navIcon(label: string) {
  if (label.includes("Tournament")) return "◆";
  if (label.includes("Attack")) return "↗";
  if (label.includes("Defense") || label.includes("Service")) return "⬡";
  if (label.includes("Patch")) return "⇪";
  if (label.includes("Capture") || label.includes("Evidence")) return "◫";
  if (label.includes("Score")) return "▥";
  if (label.includes("Event") || label.includes("Timeline")) return "≋";
  if (label.includes("Control") || label.includes("Command")) return "⌘";
  return "·";
}

function actionTitle(action: string | null) {
  return action ? `${action[0].toUpperCase()}${action.slice(1)} match` : "Operator action";
}

function actionImpact(action: string | null) {
  if (action === "pause") return "Round clocks and active flag wall-clock expiry are suspended for every team.";
  if (action === "resume") return "Round processing and checker schedules resume for every team.";
  if (action === "finalize") return "The current round will stop accepting flags and calculate final defense and availability.";
  if (action === "end") return "The match will end. This action affects every team and requires the match name.";
  return "";
}
