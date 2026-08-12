import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  getAttackSurface, getScoreboard, getState, login, sendTargetRequest,
  submitCapturedFlag, targetBaseUrl,
  type AttackSurface, type AttackTarget, type MatchState, type ScoreRow, type Session,
} from "./api";

const SESSION_KEY = "redportal_ad_session";

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
  const [error, setError] = useState("");

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
      localStorage.setItem(SESSION_KEY, JSON.stringify(next));
      setSession(next);
    }} />;
  }

  const ownScore = scoreboard.find((row) => row.team_id === session.team_id);
  return (
    <div className="min-h-screen bg-[#08090d] text-[#f3e9eb]">
      <header className="min-h-16 border-b border-[#382127] bg-[#0d090b]/95 px-4 py-3 flex flex-wrap items-center gap-3 sticky top-0 z-20">
        <div className="min-w-0">
          <div className="font-mono text-sm tracking-[0.22em] text-[#FB7185]">RED OPERATIONS</div>
          <div className="text-[10px] uppercase tracking-[0.16em] text-[#9b737b] mt-1">live service intrusion · no challenge cards</div>
        </div>
        <span className={`font-mono text-[10px] px-2 py-1 rounded border ${state?.status === "running" ? "text-[#34D399] border-[#34D399]/50" : "text-[#F5A623] border-[#F5A623]/50"}`}>
          {state?.status?.toUpperCase() ?? "CONNECTING"}
        </span>
        <div className="flex-1" />
        <div className="font-mono text-[10px] text-[#9b737b]">{state?.name ?? session.match_id} · R{state?.round ?? "—"}</div>
        <div className="font-mono text-xs text-[#FB7185]">ATK {ownScore?.attack ?? 0} · TOTAL {ownScore?.total ?? 0}</div>
        <button className="border border-[#382127] rounded px-2 py-1 text-[10px] text-[#9b737b]" onClick={() => {
          localStorage.removeItem(SESSION_KEY);
          setSession(null);
        }}>LOGOUT</button>
      </header>

      {error && <div role="alert" className="px-4 py-2 bg-[#FB7185]/10 text-[#FB7185] font-mono text-xs">PUBLIC GAME PLANE DEGRADED · {error}</div>}

      <main className="grid grid-cols-1 xl:grid-cols-[310px_minmax(0,1fr)_350px] min-h-[calc(100vh-4rem)]">
        <TargetList targets={surface?.targets ?? []} selected={selected} onSelect={setSelected} />
        <RequestWorkbench target={selected} />
        <aside className="border-l border-[#2a1a1c] bg-[#0c090a] p-4 flex flex-col gap-4">
          <FlagSubmission session={session} onAccepted={refresh} />
          <Scoreboard rows={scoreboard} ownTeamId={session.team_id} />
          <section className="border border-[#2a1a1c] rounded-lg p-3 bg-[#120c0e]">
            <div className="text-[10px] text-[#9b737b] tracking-widest uppercase">Rules of engagement</div>
            <ul className="mt-2 pl-4 list-disc text-xs leading-6 text-[#bea7ac]">
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
    <main className="min-h-screen bg-[#08090d] text-[#f3e9eb] grid place-items-center p-4">
      <form onSubmit={submit} className="w-full max-w-md border border-[#4a252d] bg-[#100a0c] rounded-xl p-6 shadow-2xl">
        <span className="font-mono text-[10px] tracking-[0.2em] text-[#FB7185]">LIVE FIRE · ATTACK PLANE</span>
        <h1 className="text-2xl mt-2 mb-1">Red Operations Login</h1>
        <p className="text-sm text-[#9b737b] mb-5">문제 목록이 아니라 실제 상대 서비스에 접속하는 공격 워크벤치입니다.</p>
        <label className="grid gap-1 text-xs text-[#bea7ac] mb-3">Username<input aria-label="Username" value={username} onChange={(event) => setUsername(event.target.value)} className="bg-[#08090d] border border-[#4a252d] rounded px-3 py-2 text-[#f3e9eb]" /></label>
        <label className="grid gap-1 text-xs text-[#bea7ac] mb-4">Password<input aria-label="Password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} className="bg-[#08090d] border border-[#4a252d] rounded px-3 py-2 text-[#f3e9eb]" /></label>
        <button disabled={busy} className="w-full py-2 rounded border border-[#FB7185] bg-[#FB7185]/15 text-[#FB7185] font-mono text-xs tracking-wider">{busy ? "CONNECTING…" : "ENTER ATTACK PLANE"}</button>
        {error && <p role="alert" className="text-xs text-[#FB7185] mt-3">{error}</p>}
      </form>
    </main>
  );
}

function TargetList({ targets, selected, onSelect }: {
  targets: AttackTarget[]; selected: AttackTarget | null;
  onSelect: (target: AttackTarget) => void;
}) {
  return (
    <aside className="border-r border-[#2a1a1c] bg-[#0c090a] p-3">
      <div className="px-2 py-2 mb-2"><span className="font-mono text-[10px] tracking-widest text-[#9b737b]">AUTHORIZED TARGETS</span><h2 className="text-lg mt-1">Opponent attack surface</h2></div>
      <div className="grid gap-2">
        {targets.map((target) => {
          const active = selected?.team_id === target.team_id && selected.service_id === target.service_id;
          return (
            <button key={`${target.team_id}:${target.service_id}`} onClick={() => onSelect(target)} className={`text-left rounded-lg border p-3 ${active ? "border-[#FB7185] bg-[#FB7185]/10" : "border-[#2a1a1c] bg-[#120c0e] hover:border-[#6d3944]"}`}>
              <div className="flex justify-between gap-2"><strong>{target.team}</strong><span className="font-mono text-[10px] text-[#FB7185]">:{target.public_port}</span></div>
              <div className="text-xs text-[#9b737b] mt-1">{target.service}</div>
              <div className="font-mono text-[10px] text-[#6f555a] mt-2 truncate">{targetBaseUrl(target)}</div>
            </button>
          );
        })}
        {targets.length === 0 && <div className="text-xs text-[#9b737b] p-3">공개 공격 표면을 기다리는 중입니다.</div>}
      </div>
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

  if (!target) return <section className="p-6 text-[#9b737b]">상대 서비스 인스턴스를 선택하세요.</section>;
  async function execute(event: FormEvent) {
    event.preventDefault(); if (!target) return;
    setBusy(true); setError(""); setResult(null);
    try { setResult(await sendTargetRequest(target, method, path, bearer, body)); }
    catch (reason) { setError(String(reason)); }
    finally { setBusy(false); }
  }
  return (
    <section className="p-4 md:p-6 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-5">
        <div><span className="font-mono text-[10px] tracking-widest text-[#FB7185]">SELECTED LIVE TARGET</span><h1 className="text-2xl mt-1">{target.team} · {target.service}</h1><code className="text-xs text-[#9b737b]">{targetBaseUrl(target)}</code></div>
        <a href={`${targetBaseUrl(target)}/docs`} target="_blank" rel="noreferrer" className="px-3 py-2 border border-[#FB7185]/50 rounded text-xs text-[#FB7185]">OPEN API SURFACE ↗</a>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-4">
        {recipes.map(([label, recipeMethod, recipePath, recipeBody]) => (
          <button key={label} onClick={() => { setMethod(recipeMethod); setPath(recipePath); setBody(recipeBody); setResult(null); }} className="text-left border border-[#2a1a1c] bg-[#120c0e] rounded p-3 hover:border-[#FB7185]/60">
            <span className="font-mono text-[9px] text-[#FB7185]">{label}</span><strong className="block text-xs mt-1">{recipeMethod} {recipePath}</strong>
          </button>
        ))}
      </div>

      <form onSubmit={execute} className="border border-[#382127] rounded-lg bg-[#100b0d] overflow-hidden">
        <div className="grid grid-cols-[110px_minmax(0,1fr)] border-b border-[#382127]">
          <select aria-label="HTTP method" value={method} onChange={(event) => setMethod(event.target.value)} className="bg-[#180e11] px-3 py-3 border-r border-[#382127] text-[#FB7185] font-mono text-xs"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option></select>
          <input aria-label="Request path" value={path} onChange={(event) => setPath(event.target.value)} className="bg-[#090709] px-3 py-3 font-mono text-xs text-[#f3e9eb]" />
        </div>
        <div className="grid md:grid-cols-2">
          <label className="grid gap-1 p-3 text-[10px] text-[#9b737b] border-b md:border-b-0 md:border-r border-[#382127]">BEARER TOKEN<input aria-label="Target bearer token" value={bearer} onChange={(event) => setBearer(event.target.value)} placeholder="login 응답의 access_token" className="bg-[#090709] border border-[#382127] rounded px-2 py-2 font-mono text-xs text-[#f3e9eb]" /></label>
          <label className="grid gap-1 p-3 text-[10px] text-[#9b737b]">JSON BODY<textarea aria-label="JSON request body" value={body} onChange={(event) => setBody(event.target.value)} rows={4} className="bg-[#090709] border border-[#382127] rounded px-2 py-2 font-mono text-xs text-[#f3e9eb] resize-y" /></label>
        </div>
        <button disabled={busy} className="w-full border-t border-[#FB7185]/40 bg-[#FB7185]/15 py-3 text-[#FB7185] font-mono text-xs tracking-wider">{busy ? "REQUEST IN FLIGHT…" : "SEND TO LIVE SERVICE"}</button>
      </form>

      <section className="mt-4 border border-[#2a1a1c] rounded-lg bg-[#070608] min-h-64 overflow-hidden">
        <div className="flex justify-between px-3 py-2 border-b border-[#2a1a1c] font-mono text-[10px] text-[#9b737b]"><span>RAW RESPONSE</span>{result && <span className={result.status < 400 ? "text-[#34D399]" : "text-[#FB7185]"}>HTTP {result.status} · {result.elapsed_ms}ms</span>}</div>
        {error ? <pre className="p-3 text-xs text-[#FB7185] whitespace-pre-wrap">{error}</pre> : result ? <pre className="p-3 text-xs text-[#cdbcc0] whitespace-pre-wrap break-all">{result.headers}{"\n\n"}{prettyBody(result.body)}</pre> : <div className="p-5 text-xs text-[#6f555a]">실제 대상에 요청을 보내면 서버 응답이 여기에 표시됩니다. 로그인 응답 토큰은 위 Bearer Token 필드에 복사하세요.</div>}
      </section>
    </section>
  );
}

function FlagSubmission({ session, onAccepted }: { session: Session; onAccepted: () => Promise<void> }) {
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
    <section className="border border-[#5a2933] rounded-lg bg-[#140c0f] p-3">
      <span className="font-mono text-[10px] tracking-widest text-[#FB7185]">EXFILTRATED FLAG</span>
      <h2 className="text-lg mt-1">Submit captured token</h2>
      <form onSubmit={submit} className="grid gap-2 mt-3"><textarea aria-label="Captured flag" value={flag} onChange={(event) => setFlag(event.target.value.trim())} placeholder="FLAG{...}" rows={3} className="bg-[#080608] border border-[#5a2933] rounded p-2 font-mono text-xs resize-none" /><button disabled={!flag} className="border border-[#FB7185] bg-[#FB7185]/15 rounded py-2 text-[#FB7185] font-mono text-xs">SUBMIT TO GAME ENGINE</button></form>
      {message && <p role="status" className="text-[10px] text-[#bea7ac] mt-2">{message}</p>}
    </section>
  );
}

function Scoreboard({ rows, ownTeamId }: { rows: ScoreRow[]; ownTeamId: string }) {
  return <section className="border border-[#2a1a1c] rounded-lg bg-[#120c0e] overflow-hidden"><div className="px-3 py-2 border-b border-[#2a1a1c] text-[10px] text-[#9b737b] tracking-widest">LIVE SCOREBOARD</div><ol className="m-0 p-0 list-none">{rows.map((row) => <li key={row.team_id} className={`grid grid-cols-[28px_1fr_auto] gap-2 px-3 py-2 border-b border-[#21171a] text-xs ${row.team_id === ownTeamId ? "bg-[#FB7185]/10" : ""}`}><span className="font-mono text-[#9b737b]">{row.rank}</span><strong>{row.team}</strong><span className="font-mono text-[#FB7185]">{row.total}</span></li>)}</ol></section>;
}

function prettyBody(body: string): string {
  try { return JSON.stringify(JSON.parse(body), null, 2); }
  catch { return body; }
}
