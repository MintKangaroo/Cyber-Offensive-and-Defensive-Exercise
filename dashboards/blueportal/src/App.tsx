import { useEffect, useState, useCallback } from "react";
import {
  fetchBlueChallenges, submitRule, fetchBlueScoreboard, datasetUrl,
  fetchEvents, fetchPatches, togglePatch, fetchTeams,
  type BlueChallenge, type BlueSubmitResult, type ScoreRow, type RangeEvent, type Patches, type Team,
} from "./api";

const DIFF: Record<string, string> = {
  easy: "border-[#34D399]/40 text-[#34D399]", medium: "border-[#F5A623]/40 text-[#F5A623]",
  hard: "border-[#FB7185]/50 text-[#FB7185]", insane: "border-[#C084FC]/50 text-[#C084FC]",
};
// 공격/위험 이벤트 vs 방어/정상 이벤트 색
const EV_STYLE = (t: string) =>
  /compromis|attack|exfil|objective_success/.test(t) ? "text-[#FB7185]"
    : /blue_|recover|patch|detection|block/.test(t) ? "text-[#34D399]"
    : "text-[#8aa0b8]";
const EV_LABEL: Record<string, string> = {
  red_attack_started: "공격 개시", asset_compromised: "자산 침해", red_objective_success: "목표 달성",
  flag_exfiltrated: "플래그 유출", blue_detection_success: "탐지 성공", blue_patch_verified: "패치 검증",
  blue_block_success: "차단 성공", asset_recovered: "복구 완료", stage_completed: "단계 완료",
};

function useLocalState(key: string, initial: string): [string, (v: string) => void] {
  const [v, setV] = useState(() => localStorage.getItem(key) ?? initial);
  return [v, useCallback((nv: string) => { setV(nv); localStorage.setItem(key, nv); }, [key])];
}

function Badge({ d }: { d: string }) {
  return <span className={`font-mono text-[9px] uppercase px-1.5 py-0.5 rounded border ${DIFF[d] ?? "border-[#6B7A99]/40 text-[#6B7A99]"}`}>{d}</span>;
}

// ── 인시던트 피드 ──────────────────────────────────────────────
function IncidentFeed({ events }: { events: RangeEvent[] }) {
  return (
    <div>
      <div className="text-[12px] text-[#8aa0b8] mb-3">🔵 아래 공격 이벤트에 <b className="text-[#22D3EE]">EDR 격리·SIEM 규칙·패치</b>로 대응하세요. (실시간)</div>
      <div className="flex flex-col gap-1.5">
        {events.length === 0 && <div className="text-[#5a7088] font-mono text-sm">이벤트 없음 — 레드팀 공격을 대기 중…</div>}
        {events.map((e) => (
          <div key={e.event_id} className="flex items-center gap-3 border border-[#16263a] rounded px-3 py-2 bg-[#0d1a2a]">
            <span className={`font-mono text-[11px] w-20 ${EV_STYLE(e.event_type)}`}>{EV_LABEL[e.event_type] ?? e.event_type}</span>
            <span className="font-mono text-[12px] text-[#cfe0f0]">{e.target_asset}</span>
            {e.vuln_id && <span className="font-mono text-[10px] text-[#8aa0b8]">{e.vuln_id}</span>}
            {e.phase && <span className="font-mono text-[10px] text-[#5a7088]">{e.phase}</span>}
            <span className="flex-1" />
            <span className="font-mono text-[10px] text-[#5a7088]">team:{e.team_id}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── 패치 보드 ──────────────────────────────────────────────────
function PatchBoard({ patches, reload }: { patches: Patches; reload: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const assets = Object.keys(patches).sort();
  const doToggle = async (asset: string, vid: string, next: boolean) => {
    setBusy(`${asset}:${vid}`);
    try { await togglePatch(asset, vid, next, "blue portal patch"); await reload(); }
    catch (e) { alert("패치 토글 실패: " + e); }
    finally { setBusy(null); }
  };
  return (
    <div>
      <div className="text-[12px] text-[#8aa0b8] mb-3">🔧 취약 서비스를 <b className="text-[#22D3EE]">패치</b>하면 해당 공격이 막힙니다. 침해된 자산부터 우선 조치하세요.</div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {assets.map((asset) => {
          const vulns = patches[asset] || {};
          const total = Object.keys(vulns).length;
          const patched = Object.values(vulns).filter(Boolean).length;
          return (
            <div key={asset} className="border border-[#16263a] rounded-lg bg-[#0d1a2a] p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-[12px] text-[#cfe0f0]">{asset}</span>
                <span className="font-mono text-[10px] text-[#8aa0b8]">패치 {patched}/{total}</span>
              </div>
              <div className="flex flex-col gap-1">
                {Object.entries(vulns).map(([vid, isP]) => (
                  <div key={vid} className="flex items-center justify-between gap-2">
                    <span className={`font-mono text-[11px] ${isP ? "text-[#34D399]" : "text-[#FB7185]"}`}>
                      {isP ? "✓" : "✗"} {vid}
                    </span>
                    <button disabled={busy === `${asset}:${vid}`} onClick={() => doToggle(asset, vid, !isP)}
                      className={`font-mono text-[9px] uppercase px-1.5 py-0.5 rounded border ${
                        isP ? "border-[#6B7A99]/40 text-[#8aa0b8]" : "border-[#22D3EE]/50 text-[#22D3EE] hover:bg-[#22D3EE]/10"}`}>
                      {busy === `${asset}:${vid}` ? "…" : isP ? "unpatch" : "patch"}
                    </button>
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
    <div className="flex flex-col gap-3">
      <div>
        <div className="text-[10px] uppercase tracking-widest text-[#5a7088] mb-1">목표</div>
        <div className="text-[13px] text-[#cfe0f0]">{c.goal}</div>
      </div>
      {c.description && <div className="text-[12px] text-[#8aa0b8] whitespace-pre-wrap leading-relaxed">{c.description}</div>}
      {c.success_criteria && (
        <div className="border border-[#16263a] rounded px-3 py-2 bg-[#0a1420]">
          <div className="text-[10px] uppercase tracking-widest text-[#5a7088] mb-1">성공 기준</div>
          <div className="text-[12px] text-[#8aa0b8] whitespace-pre-wrap">{c.success_criteria}</div>
        </div>
      )}
      <div className="flex gap-2">
        <a href={datasetUrl(c.id, "attack")} download className="font-mono text-[11px] px-2.5 py-1 rounded border border-[#FB7185]/50 text-[#FB7185] hover:bg-[#FB7185]/10">⬇ 공격 로그</a>
        <a href={datasetUrl(c.id, "normal")} download className="font-mono text-[11px] px-2.5 py-1 rounded border border-[#34D399]/50 text-[#34D399] hover:bg-[#34D399]/10">⬇ 정상 로그</a>
      </div>
      <div>
        <div className="text-[10px] uppercase tracking-widest text-[#5a7088] mb-1">탐지 규칙 (YAML)</div>
        <textarea value={rule} onChange={(e) => setRule(e.target.value)} spellCheck={false} rows={12}
          className="w-full bg-[#0a1420] border border-[#16263a] rounded px-2.5 py-2 font-mono text-[11px] text-[#cfe0f0] focus:border-[#22D3EE]/60 outline-none resize-y" />
      </div>
      <button onClick={submit} disabled={busy || !team}
        className="font-mono text-[12px] uppercase tracking-wider px-3 py-2 rounded bg-[#22D3EE]/15 border border-[#22D3EE]/50 text-[#22D3EE] hover:bg-[#22D3EE]/25 disabled:opacity-40">
        {busy ? "채점 중(SIEM 엔진)…" : "규칙 제출"}
      </button>
      {err && <div className="text-[12px] text-[#FB7185] font-mono">⚠ {err}</div>}
      {res && (
        <div className={`rounded px-3 py-2 text-[13px] font-mono border ${res.passed ? "border-[#34D399]/50 bg-[#34D399]/10 text-[#34D399]" : "border-[#FB7185]/50 bg-[#FB7185]/10 text-[#FB7185]"}`}>
          {res.passed ? (res.already_solved ? "✓ 이미 해결됨" : `✓ 정답! +${res.points_awarded}pt 🎉`) : "✗ 오답 — attack 미탐지 또는 normal 오탐"}
          <div className="text-[10px] text-[#5a7088] mt-1">{res.detail}</div>
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
  const activeIncidents = events.filter((e) => /compromis|attack|exfil/.test(e.event_type)).length;

  const TABS: [Tab, string, string][] = [
    ["incident", "인시던트 피드", activeIncidents ? `🔴 ${activeIncidents}` : ""],
    ["patch", "패치 보드", ""],
    ["detection", "탐지 챌린지", `${solvedCount}/${challenges.length}`],
  ];

  return (
    <div className="min-h-screen bg-[#081018] text-[#cfe0f0] font-sans">
      <header className="h-14 border-b border-[#16263a] flex items-center px-4 gap-3 sticky top-0 bg-[#081018] z-10">
        <span className="font-mono text-sm tracking-[0.25em] text-[#22D3EE]">🛡️ BLUE PORTAL</span>
        <span className="text-[10px] uppercase tracking-widest text-[#5a7088] px-2 py-0.5 rounded border border-[#16263a]">방어팀 전용</span>
        <div className="flex-1" />
        <label className="text-[10px] uppercase tracking-widest text-[#5a7088]">TEAM</label>
        {teams.length > 0 ? (
          <select value={team} onChange={(e) => setTeam(e.target.value)}
            className="bg-[#0d1a2a] border border-[#16263a] rounded px-2 py-1 font-mono text-[12px] text-[#cfe0f0] focus:border-[#22D3EE]/60 outline-none">
            {teams.map((t) => <option key={t.team_id} value={t.team_id}>{t.name}</option>)}
          </select>
        ) : (
          <input value={team} onChange={(e) => setTeam(e.target.value.trim())}
            className="bg-[#0d1a2a] border border-[#16263a] rounded px-2 py-1 font-mono text-[12px] text-[#cfe0f0] w-32 focus:border-[#22D3EE]/60 outline-none" />
        )}
        <div className="font-mono text-[13px] text-[#22D3EE] font-bold">{myScore?.points ?? 0}<span className="text-[10px] text-[#5a7088] ml-1">pt</span></div>
      </header>

      {err && <div className="px-4 py-2 text-[12px] text-[#FB7185] font-mono bg-[#FB7185]/10">⚠ 포털 백엔드(8060) 연결 실패: {err}</div>}

      <div className="flex border-b border-[#16263a] px-4">
        {TABS.map(([id, label, badge]) => (
          <button key={id} onClick={() => setTab(id)}
            className={`px-3 py-2.5 text-[12px] font-mono border-b-2 -mb-px ${tab === id ? "border-[#22D3EE] text-[#22D3EE]" : "border-transparent text-[#5a7088]"}`}>
            {label} {badge && <span className="ml-1 text-[10px]">{badge}</span>}
          </button>
        ))}
      </div>

      <div className="flex">
        <main className="flex-1 p-4 min-w-0">
          {tab === "incident" && <IncidentFeed events={events} />}
          {tab === "patch" && <PatchBoard patches={patches} reload={loadPatches} />}
          {tab === "detection" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {challenges.map((c) => (
                <button key={c.id} onClick={() => setSelected(c)}
                  className={`text-left border rounded-lg px-3 py-2.5 bg-[#0d1a2a] hover:bg-[#11202f] ${c.solved ? "border-[#34D399]/50" : "border-[#16263a]"}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[10px] text-[#5a7088]">{c.id}</span>
                    <div className="flex items-center gap-1.5">{c.solved && <span className="text-[#34D399] text-[11px]">✓</span>}<Badge d={c.difficulty} /></div>
                  </div>
                  <div className="text-[13px] text-[#cfe0f0] leading-snug mb-1">{c.title}</div>
                  <div className="text-right font-mono text-[12px] font-bold text-[#22D3EE]">{c.points_blue}pt</div>
                </button>
              ))}
            </div>
          )}
        </main>

        {tab === "detection" && selected && (
          <aside className="w-[26rem] border-l border-[#16263a] p-4 shrink-0 h-[calc(100vh-6.5rem)] overflow-y-auto sticky top-[6.5rem]">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="font-mono text-[11px] text-[#5a7088]">{selected.id}</div>
                <div className="text-[15px] font-semibold leading-snug mt-0.5">{selected.title}</div>
              </div>
              <button onClick={() => setSelected(null)} className="text-[#5a7088] hover:text-[#cfe0f0]">✕</button>
            </div>
            <div className="flex items-center gap-2 mb-3"><Badge d={selected.difficulty} /><span className="font-mono text-[12px] font-bold text-[#22D3EE]">{selected.points_blue}pt</span>{selected.solved && <span className="text-[#34D399] text-[11px]">✓ solved</span>}</div>
            <DetectionPanel c={selected} team={team} onSolved={loadChallenges} />
          </aside>
        )}
      </div>

      {scoreboard.length > 0 && (
        <div className="fixed bottom-3 left-3 bg-[#0d1a2a] border border-[#16263a] rounded-lg px-3 py-2">
          <div className="text-[10px] uppercase tracking-widest text-[#5a7088] mb-1">Blue Scoreboard</div>
          {scoreboard.slice(0, 5).map((r, i) => (
            <div key={r.team_id} className={`flex items-center justify-between gap-4 font-mono text-[11px] ${r.team_id === team ? "text-[#22D3EE]" : "text-[#8aa0b8]"}`}>
              <span>{i + 1}. {r.team_id}</span><span>{r.points}pt · {r.solved}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
