import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Button, EmptyState, StatusBadge } from "@cyber-range/command-system";
import {
  getAttackSurface, getScoreboard, getState, login, sendTargetRequest,
  submitCapturedFlag, targetBaseUrl,
  type AttackSurface, type AttackTarget, type MatchState, type ScoreRow, type Session,
} from "./api";
import { GuidedMode } from "./GuidedMode";

const SESSION_KEY = "redportal_ad_session";
const MODE_KEY = "redportal_mode";
type PortalMode = "beginner" | "advanced";

function storedMode(): PortalMode {
  // URL ?mode=advanced|beginner 가 있으면 그것을 우선 적용하고 저장한다(저장된 값 덮어씀).
  try {
    const fromUrl = new URLSearchParams(window.location.search).get("mode");
    if (fromUrl === "advanced" || fromUrl === "beginner") {
      localStorage.setItem(MODE_KEY, fromUrl);
      return fromUrl;
    }
  } catch {
    /* window/localStorage 미가용 시 무시 */
  }
  try {
    return localStorage.getItem(MODE_KEY) === "advanced" ? "advanced" : "beginner";
  } catch {
    return "beginner";
  }
}

function storedSession(): Session | null {
  try {
    const value = localStorage.getItem(SESSION_KEY);
    return value ? JSON.parse(value) as Session : null;
  } catch {
    return null;
  }
}

export default function App() {
  const [session, setSession] = useState<Session | null>(storedSession);
  const [state, setState] = useState<MatchState | null>(null);
  const [surface, setSurface] = useState<AttackSurface | null>(null);
  const [scoreboard, setScoreboard] = useState<ScoreRow[]>([]);
  const [selected, setSelected] = useState<AttackTarget | null>(null);
  const [mode, setMode] = useState<PortalMode>(storedMode);
  const [error, setError] = useState("");

  const changeMode = useCallback((next: PortalMode) => {
    try { localStorage.setItem(MODE_KEY, next); } catch { /* private mode */ }
    setMode(next);
  }, []);

  const refresh = useCallback(async () => {
    if (!session) return;
    try {
      const [nextState, nextSurface, scores] = await Promise.all([
        getState(session.match_id, session.access_token),
        getAttackSurface(session.match_id, session.access_token),
        getScoreboard(session.match_id),
      ]);
      setState(nextState);
      setSurface(nextSurface);
      setScoreboard(scores.scoreboard);
      setSelected((current) => current
        ? nextSurface.targets.find(
          (target) => target.team_id === current.team_id
            && target.service_id === current.service_id,
        ) ?? nextSurface.targets[0] ?? null
        : nextSurface.targets[0] ?? null);
      setError("");
    } catch (reason) {
      setError(String(reason));
    }
  }, [session]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  if (!session) {
    return <LoginScreen onLogin={(next) => {
      try { localStorage.setItem(SESSION_KEY, JSON.stringify(next)); } catch { /* */ }
      setSession(next);
    }} />;
  }

  const ownScore = scoreboard.find((row) => row.team_id === session.team_id);
  return (
    <div className="rp-shell">
      <header className="rp-header">
        <div style={{ minWidth: 0 }}>
          <div className="rp-brand">RED OPERATIONS</div>
          <div className="rp-brand-sub">live service intrusion · no challenge cards</div>
        </div>
        <StatusBadge tone={state?.status === "running" ? "healthy" : "warning"}>
          {state?.status?.toUpperCase() ?? "CONNECTING"}
        </StatusBadge>
        <div className="rp-spacer" />
        <div className="rp-mode-toggle" role="group" aria-label="Portal mode">
          <button type="button" className="rp-mode-btn" aria-pressed={mode === "beginner"}
            onClick={() => changeMode("beginner")}>초보자 가이드</button>
          <button type="button" className="rp-mode-btn" aria-pressed={mode === "advanced"}
            onClick={() => changeMode("advanced")}>고급(워크벤치)</button>
        </div>
        <div className="rp-meta">{state?.name ?? session.match_id} · R{state?.round ?? "—"}</div>
        <div className="rp-score">ATK {ownScore?.attack ?? 0} · TOTAL {ownScore?.total ?? 0}</div>
        <Button onClick={() => {
          try { localStorage.removeItem(SESSION_KEY); } catch { /* */ }
          setSession(null);
        }}>LOGOUT</Button>
      </header>

      {error && <div role="alert" className="rp-error">PUBLIC GAME PLANE DEGRADED · {error}</div>}

      <main className="rp-main">
        <TargetList targets={surface?.targets ?? []} selected={selected} onSelect={setSelected} />
        {mode === "beginner"
          ? <GuidedMode target={selected} session={session} onFlagAccepted={refresh} />
          : <RequestWorkbench target={selected} />}
        <aside className="rp-aside" aria-label="Scoreboard and engagement rules">
          {mode === "advanced" && <FlagSubmission session={session} onAccepted={refresh} />}
          <Scoreboard rows={scoreboard} ownTeamId={session.team_id} />
          <section className="rp-card">
            <div className="rp-section-label">Rules of engagement</div>
            <ul className="rp-rules">
              <li>화면에 표시된 상대 팀 게임 포트만 공격합니다.</li>
              <li>관리 포트, Docker API와 호스트 OS는 공격 범위가 아닙니다.</li>
              <li>서비스를 파괴하지 말고 취약점으로 라운드 플래그를 획득합니다.</li>
              <li>자동 exploit은 실행되지 않습니다. 요청과 판단은 공격팀이 수행합니다.</li>
            </ul>
          </section>
        </aside>
      </main>
    </div>
  );
}

function LoginScreen({ onLogin }: { onLogin: (session: Session) => void }) {
  const [username, setUsername] = useState("team01");
  const [password, setPassword] = useState("demo-team-01-change-me");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { onLogin(await login(username, password)); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }
  return (
    <main className="rp-login">
      <form onSubmit={submit} className="rp-login-card">
        <span className="rp-eyebrow">LIVE FIRE · ATTACK PLANE</span>
        <h1 style={{ fontSize: "1.5rem", margin: "8px 0 4px" }}>Red Operations Login</h1>
        <p className="rp-muted" style={{ fontSize: 14, marginBottom: 20 }}>
          문제 목록이 아니라 실제 상대 서비스에 접속하는 공격 워크벤치입니다.
        </p>
        <label className="rp-field">Username
          <input className="rp-input" aria-label="Username" value={username}
            onChange={(event) => setUsername(event.target.value)} />
        </label>
        <label className="rp-field">Password
          <input className="rp-input" aria-label="Password" type="password" value={password}
            onChange={(event) => setPassword(event.target.value)} />
        </label>
        <Button type="submit" tone="critical" disabled={busy} className="rp-block">
          {busy ? "CONNECTING…" : "ENTER ATTACK PLANE"}
        </Button>
        {error && <p role="alert" className="rp-accent" style={{ fontSize: 12, marginTop: 12 }}>{error}</p>}
      </form>
    </main>
  );
}

function TargetList({ targets, selected, onSelect }: {
  targets: AttackTarget[]; selected: AttackTarget | null;
  onSelect: (target: AttackTarget) => void;
}) {
  return (
    <aside className="rp-targets rp-col" aria-label="Authorized targets">
      <div style={{ padding: "8px 8px 12px" }}>
        <span className="rp-section-label">AUTHORIZED TARGETS</span>
        <h2 style={{ fontSize: "1.1rem", margin: "4px 0 0" }}>Opponent attack surface</h2>
      </div>
      {targets.map((target) => {
        const active = selected?.team_id === target.team_id && selected.service_id === target.service_id;
        return (
          <button key={`${target.team_id}:${target.service_id}`} type="button" className="rp-target"
            aria-pressed={active} onClick={() => onSelect(target)}>
            <div className="rp-target-head"><strong>{target.team}</strong>
              <span className="rp-target-port">:{target.public_port}</span></div>
            <div className="rp-muted" style={{ fontSize: 12, marginTop: 4 }}>{target.service}</div>
            <div className="rp-target-url">{targetBaseUrl(target)}</div>
          </button>
        );
      })}
      {targets.length === 0 && (
        <EmptyState title="공격 표면 대기 중" detail="공개 공격 표면을 기다리는 중입니다." />
      )}
    </aside>
  );
}

function RequestWorkbench({ target }: { target: AttackTarget | null }) {
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/api/version");
  const [bearer, setBearer] = useState("");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<{ status: number; elapsed_ms: number; headers: string; body: string } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const recipes = useMemo(() => target?.service_slug === "file-vault" ? [
    ["RECON", "GET", "/api/version", ""],
    ["REGISTER", "POST", "/api/register", '{"username":"redops","password":"redops-pass-2026"}'],
    ["LOGIN", "POST", "/api/login", '{"username":"redops","password":"redops-pass-2026"}'],
    ["DISCOVER", "GET", "/api/files?path=../../system", ""],
    ["EXFIL", "GET", "/api/files?path=../../system/<discovered-file>.txt", ""],
  ] : [
    ["RECON", "GET", "/api/version", ""],
    ["REGISTER", "POST", "/api/register", '{"username":"redops","password":"redops-pass-2026"}'],
    ["LOGIN", "POST", "/api/login", '{"username":"redops","password":"redops-pass-2026"}'],
    ["ENUMERATE", "GET", "/api/notes/1", ""],
  ], [target?.service_slug]);

  if (!target) return <section className="rp-stack rp-col">상대 서비스 인스턴스를 선택하세요.</section>;
  async function execute(event: FormEvent) {
    event.preventDefault(); if (!target) return;
    setBusy(true); setError(""); setResult(null);
    try { setResult(await sendTargetRequest(target, method, path, bearer, body)); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }
  return (
    <section className="rp-work rp-col">
      <div className="rp-work-head">
        <div>
          <span className="rp-eyebrow">SELECTED LIVE TARGET</span>
          <h1 style={{ fontSize: "1.5rem", margin: "4px 0" }}>{target.team} · {target.service}</h1>
          <code className="rp-subtle" style={{ fontSize: 12 }}>{targetBaseUrl(target)}</code>
        </div>
        <a href={`${targetBaseUrl(target)}/docs`} target="_blank" rel="noreferrer"
          className="rp-dataset" style={{ padding: "8px 12px", border: "1px solid color-mix(in srgb, var(--cr-red) 50%, transparent)", borderRadius: "var(--cr-radius-sm)", color: "var(--cr-red)", textDecoration: "none", fontSize: 12 }}>
          OPEN API SURFACE ↗
        </a>
      </div>

      <div className="rp-recipes">
        {recipes.map(([label, recipeMethod, recipePath, recipeBody]) => (
          <button key={label} type="button" className="rp-recipe"
            onClick={() => { setMethod(recipeMethod); setPath(recipePath); setBody(recipeBody); setResult(null); }}>
            <span className="rp-recipe-label">{label}</span>
            <strong>{recipeMethod} {recipePath}</strong>
          </button>
        ))}
      </div>

      <form onSubmit={execute} className="rp-request">
        <div className="rp-request-line">
          <select className="rp-select" aria-label="HTTP method" value={method}
            onChange={(event) => setMethod(event.target.value)}>
            <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option>
          </select>
          <input className="rp-input" aria-label="Request path" value={path}
            onChange={(event) => setPath(event.target.value)} />
        </div>
        <div className="rp-request-grid">
          <label>BEARER TOKEN
            <input className="rp-input" aria-label="Target bearer token" value={bearer}
              onChange={(event) => setBearer(event.target.value)} placeholder="login 응답의 access_token" />
          </label>
          <label>JSON BODY
            <textarea className="rp-textarea" aria-label="JSON request body" value={body}
              onChange={(event) => setBody(event.target.value)} rows={4} />
          </label>
        </div>
        <button type="submit" className="rp-send" disabled={busy}>
          {busy ? "REQUEST IN FLIGHT…" : "SEND TO LIVE SERVICE"}
        </button>
      </form>

      <section className="rp-response">
        <div className="rp-response-head">
          <span>RAW RESPONSE</span>
          {result && <span className={result.status < 400 ? "rp-log-label rp-ok" : "rp-log-label rp-bad"}>HTTP {result.status} · {result.elapsed_ms}ms</span>}
        </div>
        {error ? <pre className="rp-accent">{error}</pre>
          : result ? <pre>{result.headers}{"\n\n"}{prettyBody(result.body)}</pre>
          : <div className="rp-placeholder">실제 대상에 요청을 보내면 서버 응답이 여기에 표시됩니다. 로그인 응답 토큰은 위 Bearer Token 필드에 복사하세요.</div>}
      </section>
    </section>
  );
}

function FlagSubmission({ session, onAccepted }: { session: Session; onAccepted: () => void }) {
  const [flag, setFlag] = useState("");
  const [message, setMessage] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      const result = await submitCapturedFlag(session.match_id, session.access_token, flag);
      setMessage(result.accepted ? `FLAG ACCEPTED · +${result.score_delta ?? 0} ATTACK` : "FLAG REJECTED · inactive, duplicate, self, or invalid");
      if (result.accepted) { setFlag(""); await onAccepted(); }
    } catch (reason) { setMessage(String(reason)); }
  }
  return (
    <section className="rp-card rp-danger">
      <span className="rp-eyebrow">EXFILTRATED FLAG</span>
      <h2 style={{ fontSize: "1.1rem", margin: "4px 0 0" }}>Submit captured token</h2>
      <form onSubmit={submit} style={{ display: "grid", gap: 8, marginTop: 12 }}>
        <textarea className="rp-textarea" aria-label="Captured flag" value={flag}
          onChange={(event) => setFlag(event.target.value.trim())} placeholder="FLAG{...}" rows={3} />
        <Button type="submit" tone="critical" disabled={!flag} className="rp-block">SUBMIT TO GAME ENGINE</Button>
      </form>
      {message && <p role="status" className="rp-muted" style={{ fontSize: 11, marginTop: 8 }}>{message}</p>}
    </section>
  );
}

function Scoreboard({ rows, ownTeamId }: { rows: ScoreRow[]; ownTeamId: string }) {
  return (
    <section className="rp-card rp-scoreboard">
      <div className="rp-section-label" style={{ marginBottom: 8 }}>LIVE SCOREBOARD</div>
      <ol>
        {rows.map((row) => (
          <li key={row.team_id} className={`rp-score-row${row.team_id === ownTeamId ? " rp-me" : ""}`}>
            <span className="rp-subtle">{row.rank}</span>
            <strong>{row.team}</strong>
            <span className="rp-score-total">{row.total}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function prettyBody(body: string): string {
  try { return JSON.stringify(JSON.parse(body), null, 2); }
  catch { return body; }
}
