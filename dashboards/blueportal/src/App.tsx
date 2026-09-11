import { useEffect, useState, useCallback } from "react";
import { Button, EmptyState, StatusBadge } from "@cyber-range/command-system";
import {
  fetchBlueChallenges, submitRule, fetchBlueScoreboard, datasetUrl,
  fetchEvents, fetchPatches, togglePatch, fetchTeams,
  type BlueChallenge, type BlueSubmitResult, type ScoreRow, type RangeEvent, type Patches, type Team,
} from "./api";
import { difficultyTone, eventLabel, eventTone, isActiveIncident } from "./helpers";

const CYAN = "var(--cr-cyan)";
const GREEN = "var(--cr-green)";
const RED = "var(--cr-red)";

function useLocalState(key: string, initial: string): [string, (v: string) => void] {
  const [v, setV] = useState(() => {
    try { return localStorage.getItem(key) ?? initial; } catch { return initial; }
  });
  return [v, useCallback((nv: string) => {
    setV(nv);
    try { localStorage.setItem(key, nv); } catch { /* private mode */ }
  }, [key])];
}

function Badge({ d }: { d: string }) {
  return <StatusBadge tone={difficultyTone(d)}>{d}</StatusBadge>;
}

// ── CTF 시각화 ────────────────────────────────────────────────
function Donut({ frac, big, sub, color }: { frac: number; big: string; sub: string; color: string }) {
  const R = 30, C = 2 * Math.PI * R;
  return (
    <svg viewBox="0 0 80 80" width={76} height={76} style={{ flexShrink: 0 }}>
      <circle cx="40" cy="40" r={R} fill="none" strokeWidth="7" style={{ stroke: "var(--cr-raised)" }} />
      <circle cx="40" cy="40" r={R} fill="none" strokeWidth="7" strokeLinecap="round"
        strokeDasharray={C} strokeDashoffset={C * (1 - frac)} transform="rotate(-90 40 40)"
        className="bp-donut-arc" style={{ stroke: color }} />
      <text x="40" y="38" textAnchor="middle" fontSize="15" fontWeight="700" style={{ fill: color }}>{big}</text>
      <text x="40" y="52" textAnchor="middle" fontSize="8" style={{ fill: "var(--cr-subtle)" }}>{sub}</text>
    </svg>
  );
}

function StatItem({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="bp-stat-item">
      <div className="bp-stat-value" style={{ color }}>{value}</div>
      <div className="bp-stat-label">{label}</div>
    </div>
  );
}

function BlueStats({ challenges, patches, incidents, points, rank }: {
  challenges: BlueChallenge[]; patches: Patches; incidents: number; points: number; rank: number | null;
}) {
  const detTotal = challenges.length || 1;
  const detSolved = challenges.filter((c) => c.solved).length;
  let vulnTotal = 0, vulnPatched = 0;
  for (const a of Object.values(patches)) for (const p of Object.values(a)) { vulnTotal++; if (p) vulnPatched++; }
  const patchFrac = vulnTotal ? vulnPatched / vulnTotal : 0;
  return (
    <div className="bp-stats">
      <div className="bp-stat-group">
        <Donut frac={detSolved / detTotal} big={`${detSolved}/${detTotal}`} sub="탐지" color={CYAN} />
        <div>
          <div className="bp-headline">{points}<small>pt</small></div>
          <div className="bp-muted" style={{ marginTop: 4 }}>{rank ? `🏆 순위 ${rank}위` : "미제출"}</div>
        </div>
      </div>
      <div className="bp-stat-group">
        <Donut frac={patchFrac} big={`${Math.round(patchFrac * 100)}%`} sub={`${vulnPatched}/${vulnTotal}`} color={GREEN} />
        <div className="bp-muted">패치<br />커버리지</div>
      </div>
      <div className="bp-stat-group bp-stat-divider">
        <StatItem label="활성 공격" value={String(incidents)} color={incidents ? RED : GREEN} />
        <StatItem label="탐지 해결" value={String(detSolved)} color={CYAN} />
        <StatItem label="패치 완료" value={String(vulnPatched)} color={GREEN} />
      </div>
    </div>
  );
}

function ScoreboardBars({ rows, me }: { rows: ScoreRow[]; me: string }) {
  const max = Math.max(1, ...rows.map((r) => r.points));
  return (
    <div>
      {rows.slice(0, 6).map((r, i) => (
        <div key={r.team_id} className="bp-score-row">
          <span className={`bp-score-name${r.team_id === me ? " bp-me" : ""}`}>{i + 1}. {r.team_id}</span>
          <div className="bp-score-track">
            <div className={`bp-bar-fill${r.team_id === me ? " bp-me" : ""}`} style={{ width: `${(r.points / max) * 100}%` }} />
          </div>
          <span className="bp-score-pts">{r.points}pt·{r.solved}</span>
        </div>
      ))}
    </div>
  );
}

// ── 인시던트 피드 ──────────────────────────────────────────────
function IncidentFeed({ events }: { events: RangeEvent[] }) {
  return (
    <div>
      <div className="bp-hint">🔵 아래 공격 이벤트에 <b>EDR 격리·SIEM 규칙·패치</b>로 대응하세요. (실시간)</div>
      {events.length === 0 ? (
        <EmptyState title="이벤트 없음" detail="레드팀 공격을 대기 중입니다." />
      ) : (
        <div className="bp-feed">
          {events.map((e) => (
            <div key={e.event_id} className={`bp-event cr-tone-${eventTone(e.event_type)}`}>
              <span className="bp-event-type">{eventLabel(e.event_type)}</span>
              <span className="bp-event-asset">{e.target_asset}</span>
              {e.vuln_id && <span className="bp-event-meta">{e.vuln_id}</span>}
              {e.phase && <span className="bp-event-meta">{e.phase}</span>}
              <span style={{ flex: 1 }} />
              <span className="bp-event-meta">team:{e.team_id}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── 패치 보드 ──────────────────────────────────────────────────
function PatchBoard({ patches, reload }: { patches: Patches; reload: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const assets = Object.keys(patches).sort();
  const doToggle = async (asset: string, vid: string, next: boolean) => {
    setBusy(`${asset}:${vid}`);
    setErr(null);
    try { await togglePatch(asset, vid, next, "blue portal patch"); await reload(); }
    catch (e) { setErr("패치 토글 실패: " + e); }
    finally { setBusy(null); }
  };
  return (
    <div>
      <div className="bp-hint">🔧 취약 서비스를 <b>패치</b>하면 해당 공격이 막힙니다. 침해된 자산부터 우선 조치하세요.</div>
      {err && <div className="bp-error" role="alert">{err}</div>}
      <div className="bp-patch-grid">
        {assets.map((asset) => {
          const vulns = patches[asset] || {};
          const total = Object.keys(vulns).length;
          const patched = Object.values(vulns).filter(Boolean).length;
          return (
            <div key={asset} className="bp-patch-card">
              <div className="bp-patch-head">
                <span className="bp-event-asset">{asset}</span>
                <span className="bp-muted">패치 {patched}/{total}</span>
              </div>
              <div>
                {Object.entries(vulns).map(([vid, isP]) => (
                  <div key={vid} className="bp-vuln-row">
                    <span className={`bp-vuln ${isP ? "bp-patched" : "bp-open"}`}>
                      {isP ? "✓" : "✗"} {vid}
                    </span>
                    <Button
                      tone={isP ? "neutral" : "operational"}
                      disabled={busy === `${asset}:${vid}`}
                      onClick={() => doToggle(asset, vid, !isP)}
                    >
                      {busy === `${asset}:${vid}` ? "…" : isP ? "unpatch" : "patch"}
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── 탐지 챌린지 ────────────────────────────────────────────────
const RULE_TEMPLATE = `- id: MY-RULE
  title: "내 탐지 규칙"
  severity: 4
  source_type: twin
  kind: match
  match:
    raw.필드경로: 값        # 예: raw.bacnet_service: 15
`;

function DetectionPanel({ c, team, onSolved }: { c: BlueChallenge; team: string; onSolved: () => void }) {
  const [rule, setRule] = useState(RULE_TEMPLATE);
  const [res, setRes] = useState<BlueSubmitResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { setRes(null); setErr(null); setRule(RULE_TEMPLATE); }, [c.id]);
  const submit = async () => {
    setBusy(true); setErr(null); setRes(null);
    try { const r = await submitRule(c.id, team, rule); setRes(r); if (r.passed && !r.already_solved) onSolved(); }
    catch (e) { setErr(String(e)); } finally { setBusy(false); }
  };
  return (
    <div className="bp-stack">
      <div>
        <div className="bp-field-label">목표</div>
        <div className="bp-event-asset">{c.goal}</div>
      </div>
      {c.description && <div className="bp-hint" style={{ whiteSpace: "pre-wrap", margin: 0 }}>{c.description}</div>}
      {c.success_criteria && (
        <div className="bp-criteria">
          <div className="bp-field-label">성공 기준</div>
          <div className="bp-muted" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>{c.success_criteria}</div>
        </div>
      )}
      <div style={{ display: "flex", gap: 8 }}>
        <a href={datasetUrl(c.id, "attack")} download className="bp-dataset cr-tone-critical">⬇ 공격 로그</a>
        <a href={datasetUrl(c.id, "normal")} download className="bp-dataset cr-tone-healthy">⬇ 정상 로그</a>
      </div>
      <div>
        <div className="bp-field-label">탐지 규칙 (YAML)</div>
        <textarea className="bp-textarea" value={rule} onChange={(e) => setRule(e.target.value)}
          spellCheck={false} rows={12} aria-label="탐지 규칙 YAML" />
      </div>
      <Button tone="operational" onClick={submit} disabled={busy || !team}>
        {busy ? "채점 중(SIEM 엔진)…" : "규칙 제출"}
      </Button>
      {err && <div className="bp-result cr-tone-critical">⚠ {err}</div>}
      {res && (
        <div className={`bp-result cr-tone-${res.passed ? "healthy" : "critical"}`} role="status">
          {res.passed ? (res.already_solved ? "✓ 이미 해결됨" : `✓ 정답! +${res.points_awarded}pt 🎉`) : "✗ 오답 — attack 미탐지 또는 normal 오탐"}
          <small>{res.detail}</small>
        </div>
      )}
    </div>
  );
}

// ── 앱 ─────────────────────────────────────────────────────────
type Tab = "incident" | "patch" | "detection";

export default function App() {
  const [team, setTeam] = useLocalState("blueportal_team", "blue_alpha");
  const [teams, setTeams] = useState<Team[]>([]);
  const [tab, setTab] = useState<Tab>("incident");
  const [events, setEvents] = useState<RangeEvent[]>([]);
  const [patches, setPatches] = useState<Patches>({});
  const [challenges, setChallenges] = useState<BlueChallenge[]>([]);
  const [selected, setSelected] = useState<BlueChallenge | null>(null);
  const [scoreboard, setScoreboard] = useState<ScoreRow[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const loadChallenges = useCallback(async () => {
    try {
      const [d, s] = await Promise.all([fetchBlueChallenges(team), fetchBlueScoreboard()]);
      setChallenges(d.challenges); setScoreboard(s.scoreboard); setErr(null);
    } catch (e) { setErr(String(e)); }
  }, [team]);
  const loadPatches = useCallback(async () => { try { setPatches(await fetchPatches()); } catch { /* */ } }, []);
  const loadEvents = useCallback(async () => { try { setEvents((await fetchEvents(40)).events); } catch { /* */ } }, []);

  useEffect(() => { loadChallenges(); }, [loadChallenges]);
  useEffect(() => {
    fetchTeams("blue").then((r) => {
      setTeams(r.teams);
      if (r.teams.length && !r.teams.some((t) => t.team_id === team)) setTeam(r.teams[0].team_id);
    }).catch(() => { /* 백엔드 미기동 시 자유입력 유지 */ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    loadEvents(); loadPatches();
    const t = setInterval(() => { loadEvents(); loadPatches(); }, 4000);
    return () => clearInterval(t);
  }, [loadEvents, loadPatches]);

  const myScore = scoreboard.find((r) => r.team_id === team);
  const solvedCount = challenges.filter((c) => c.solved).length;
  const activeIncidents = events.filter((e) => isActiveIncident(e.event_type)).length;
  const rankIdx = scoreboard.findIndex((r) => r.team_id === team);
  const rank = rankIdx >= 0 ? rankIdx + 1 : null;

  const TABS: [Tab, string, string][] = [
    ["incident", "인시던트 피드", activeIncidents ? `🔴 ${activeIncidents}` : ""],
    ["patch", "패치 보드", ""],
    ["detection", "탐지 챌린지", `${solvedCount}/${challenges.length}`],
  ];

  return (
    <div className="bp-shell">
      <header className="bp-header">
        <span className="bp-title">🛡️ BLUE PORTAL</span>
        <span className="bp-pill">방어팀 전용</span>
        <div className="bp-spacer" />
        <label className="bp-label" htmlFor="bp-team">TEAM</label>
        {teams.length > 0 ? (
          <select id="bp-team" className="bp-select" value={team} onChange={(e) => setTeam(e.target.value)}>
            {teams.map((t) => <option key={t.team_id} value={t.team_id}>{t.name}</option>)}
          </select>
        ) : (
          <input id="bp-team" className="bp-input" value={team}
            onChange={(e) => setTeam(e.target.value.trim())} style={{ width: 128 }} />
        )}
        <div className="bp-points">{myScore?.points ?? 0}<small>pt</small></div>
      </header>

      {err && <div className="bp-error" role="alert">⚠ 포털 백엔드(8060) 연결 실패: {err}</div>}

      <nav className="bp-tabs" aria-label="Blue portal views">
        {TABS.map(([id, label, badge]) => (
          <button key={id} type="button" className="bp-tab" aria-current={tab === id ? "page" : undefined}
            onClick={() => setTab(id)}>
            {label} {badge && <span style={{ fontSize: 10, marginLeft: 4 }}>{badge}</span>}
          </button>
        ))}
      </nav>

      <div className="bp-body">
        <main className="bp-main">
          <BlueStats challenges={challenges} patches={patches} incidents={activeIncidents} points={myScore?.points ?? 0} rank={rank} />
          {tab === "incident" && <IncidentFeed events={events} />}
          {tab === "patch" && <PatchBoard patches={patches} reload={loadPatches} />}
          {tab === "detection" && (
            <div className="bp-chal-grid">
              {challenges.map((c) => (
                <button key={c.id} type="button" className={`bp-chal-card${c.solved ? " bp-solved" : ""}`}
                  onClick={() => setSelected(c)}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span className="bp-muted">{c.id}</span>
                    <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      {c.solved && <span style={{ color: "var(--cr-green)" }}>✓</span>}<Badge d={c.difficulty} />
                    </span>
                  </div>
                  <div className="bp-chal-title">{c.title}</div>
                  <div className="bp-chal-points">{c.points_blue}pt</div>
                </button>
              ))}
            </div>
          )}
        </main>

        {tab === "detection" && selected && (
          <aside className="bp-panel">
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
              <div>
                <div className="bp-muted">{selected.id}</div>
                <div style={{ fontSize: 15, fontWeight: 600, marginTop: 2 }}>{selected.title}</div>
              </div>
              <button type="button" className="bp-close" aria-label="닫기" onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
              <Badge d={selected.difficulty} />
              <span className="bp-chal-points">{selected.points_blue}pt</span>
              {selected.solved && <span style={{ color: "var(--cr-green)", fontSize: 11 }}>✓ solved</span>}
            </div>
            <DetectionPanel c={selected} team={team} onSolved={loadChallenges} />
          </aside>
        )}
      </div>

      {scoreboard.length > 0 && (
        <div className="bp-scoreboard">
          <div className="bp-field-label" style={{ marginBottom: 8 }}>🏆 Blue Scoreboard</div>
          <ScoreboardBars rows={scoreboard} me={team} />
        </div>
      )}
    </div>
  );
}
