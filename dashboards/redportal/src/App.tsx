import { useEffect, useMemo, useState, useCallback } from "react";
import {
  fetchChallenges, submitFlag, fetchScoreboard, artifactUrl, fetchTeams,
  type Challenge, type SubmitResult, type ScoreRow, type Team,
} from "./api";

const DIFF_STYLE: Record<string, string> = {
  easy: "border-[#34D399]/40 text-[#34D399]",
  medium: "border-[#F5A623]/40 text-[#F5A623]",
  hard: "border-[#FB7185]/50 text-[#FB7185]",
  insane: "border-[#C084FC]/50 text-[#C084FC]",
};
const CAT_LABEL: Record<string, string> = {
  web: "Web", ics: "ICS/OT", network: "Network", forensics: "Forensics",
  reversing: "Reversing", ai: "AI Security",
};

function useLocalState(key: string, initial: string): [string, (v: string) => void] {
  const [v, setV] = useState(() => localStorage.getItem(key) ?? initial);
  const set = useCallback((nv: string) => { setV(nv); localStorage.setItem(key, nv); }, [key]);
  return [v, set];
}

function DifficultyBadge({ d }: { d: string }) {
  return (
    <span className={`font-mono text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded border ${DIFF_STYLE[d] ?? "border-[#6B7A99]/40 text-[#6B7A99]"}`}>
      {d}
    </span>
  );
}

// ── CTF 시각화 ────────────────────────────────────────────────
function Donut({ frac, big, sub, color }: { frac: number; big: string; sub: string; color: string }) {
  const R = 30, C = 2 * Math.PI * R;
  return (
    <svg viewBox="0 0 80 80" className="w-[76px] h-[76px] shrink-0">
      <circle cx="40" cy="40" r={R} fill="none" stroke="#2a1a1c" strokeWidth="7" />
      <circle cx="40" cy="40" r={R} fill="none" stroke={color} strokeWidth="7" strokeLinecap="round"
        strokeDasharray={C} strokeDashoffset={C * (1 - frac)} transform="rotate(-90 40 40)"
        style={{ transition: "stroke-dashoffset 0.8s ease" }} />
      <text x="40" y="38" textAnchor="middle" fontSize="16" fontWeight="700" fill={color}>{big}</text>
      <text x="40" y="52" textAnchor="middle" fontSize="8" fill="#8a6a6e">{sub}</text>
    </svg>
  );
}

const DIFF_COLOR: Record<string, string> = { easy: "#34D399", medium: "#F5A623", hard: "#FB7185", insane: "#C084FC" };

function StatsPanel({ challenges, points, rank }: { challenges: Challenge[]; points: number; rank: number | null }) {
  const total = challenges.length || 1;
  const solved = challenges.filter((c) => c.solved).length;
  const frac = solved / total;

  const byCat = useMemo(() => {
    const m: Record<string, { total: number; solved: number }> = {};
    for (const c of challenges) {
      const b = (m[c.category] ??= { total: 0, solved: 0 });
      b.total++; if (c.solved) b.solved++;
    }
    return Object.entries(m).sort((a, b) => a[0].localeCompare(b[0]));
  }, [challenges]);

  const byDiff = useMemo(() => {
    const m: Record<string, { total: number; solved: number }> = {};
    for (const c of challenges) {
      const b = (m[c.difficulty] ??= { total: 0, solved: 0 });
      b.total++; if (c.solved) b.solved++;
    }
    return (["easy", "medium", "hard", "insane"] as const).map((d) => [d, m[d] ?? { total: 0, solved: 0 }] as const);
  }, [challenges]);

  return (
    <div className="border border-[#2a1a1c] rounded-xl bg-gradient-to-br from-[#150d0f] to-[#0f0809] p-4 mb-4">
      <div className="flex flex-wrap items-center gap-6">
        {/* 완료율 도넛 */}
        <div className="flex items-center gap-3">
          <Donut frac={frac} big={`${Math.round(frac * 100)}%`} sub={`${solved}/${total}`} color="#FB7185" />
          <div>
            <div className="font-mono text-3xl font-bold text-[#FB7185] tabular-nums leading-none">{points}<span className="text-sm text-[#8a6a6e] ml-1">pt</span></div>
            <div className="font-mono text-[11px] text-[#8a6a6e] mt-1">{rank ? `🏆 순위 ${rank}위` : "미제출"} · {solved} solved</div>
          </div>
        </div>

        {/* 난이도 분포 */}
        <div className="flex items-center gap-3">
          {byDiff.map(([d, b]) => (
            <div key={d} className="text-center">
              <div className="font-mono text-lg font-bold tabular-nums" style={{ color: DIFF_COLOR[d] }}>{b.solved}<span className="text-[10px] text-[#5a4548]">/{b.total}</span></div>
              <div className="font-mono text-[9px] uppercase" style={{ color: DIFF_COLOR[d] }}>{d}</div>
            </div>
          ))}
        </div>

        {/* 카테고리 진행 바 */}
        <div className="flex-1 min-w-[260px] grid grid-cols-2 gap-x-5 gap-y-1.5">
          {byCat.map(([cat, b]) => (
            <div key={cat} className="flex items-center gap-2">
              <span className="font-mono text-[10px] text-[#8a6a6e] w-16 shrink-0">{CAT_LABEL[cat] ?? cat}</span>
              <div className="flex-1 h-1.5 rounded-full bg-[#2a1a1c] overflow-hidden">
                <div className="h-full rounded-full bg-[#FB7185] transition-all duration-700" style={{ width: `${(b.solved / b.total) * 100}%` }} />
              </div>
              <span className="font-mono text-[10px] text-[#8a6a6e] w-8 text-right tabular-nums">{b.solved}/{b.total}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ScoreboardBars({ rows, me }: { rows: ScoreRow[]; me: string }) {
  const max = Math.max(1, ...rows.map((r) => r.points));
  return (
    <div className="flex flex-col gap-1.5">
      {rows.slice(0, 6).map((r, i) => (
        <div key={r.team_id} className="flex items-center gap-2">
          <span className={`font-mono text-[10px] w-24 shrink-0 truncate ${r.team_id === me ? "text-[#FB7185]" : "text-[#c9b8ba]"}`}>{i + 1}. {r.team_id}</span>
          <div className="flex-1 h-3 rounded bg-[#2a1a1c] overflow-hidden min-w-[60px]">
            <div className={`h-full rounded transition-all duration-700 ${r.team_id === me ? "bg-[#FB7185]" : "bg-[#8a5a60]"}`} style={{ width: `${(r.points / max) * 100}%` }} />
          </div>
          <span className="font-mono text-[10px] text-[#8a6a6e] w-14 text-right tabular-nums">{r.points}pt·{r.solved}</span>
        </div>
      ))}
    </div>
  );
}

function ChallengeCard({ c, onClick }: { c: Challenge; onClick: () => void }) {
  return (
    <button onClick={onClick}
      className={`text-left border rounded-lg px-3 py-2.5 bg-[#151011] hover:bg-[#1c1315] transition-colors ${
        c.solved ? "border-[#34D399]/50" : "border-[#2a1a1c]"}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono text-[10px] text-[#8a6a6e]">{c.id}</span>
        <div className="flex items-center gap-1.5">
          {c.solved && <span className="text-[#34D399] text-[11px]">✓ solved</span>}
          <DifficultyBadge d={c.difficulty} />
        </div>
      </div>
      <div className="text-[13px] text-[#F0E6E6] leading-snug mb-1.5">{c.title}</div>
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] text-[#8a6a6e]">{c.gate === "artifact" ? "📦 분석형" : "🎯 서비스형"}</span>
        <span className="font-mono text-[12px] font-bold text-[#FB7185]">{c.points_red}pt</span>
      </div>
    </button>
  );
}

function SubmitPanel({ c, teamId, onSolved }: { c: Challenge; teamId: string; onSolved: () => void }) {
  const [fields, setFields] = useState<Record<string, string>>({});
  const [result, setResult] = useState<SubmitResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { setFields({}); setResult(null); setErr(null); }, [c.id]);

  const submit = async () => {
    setBusy(true); setErr(null); setResult(null);
    try {
      const r = await submitFlag(c.id, teamId, fields);
      setResult(r);
      if (r.passed && !r.already_solved) onSolved();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  };

  return (
    <div className="flex flex-col gap-3">
      {/* 무엇을 해야 하는가 */}
      <div>
        <div className="text-[10px] uppercase tracking-widest text-[#8a6a6e] mb-1">목표 (Goal)</div>
        <div className="text-[13px] text-[#F0E6E6] leading-relaxed">{c.goal || "플래그를 획득하라."}</div>
      </div>
      {c.description && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-[#8a6a6e] mb-1">설명</div>
          <div className="text-[12px] text-[#c9b8ba] leading-relaxed whitespace-pre-wrap">{c.description}</div>
        </div>
      )}
      {c.mitre?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {c.mitre.map((m) => (
            <span key={m} className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-[#2a1a1c] text-[#c98a8f]">{m}</span>
          ))}
        </div>
      )}

      {/* 공격 방법 안내 */}
      <div className="border border-[#2a1a1c] rounded-md px-3 py-2 bg-[#120c0d]">
        <div className="text-[10px] uppercase tracking-widest text-[#8a6a6e] mb-1">공격 방법</div>
        {c.gate === "artifact" ? (
          <div className="text-[12px] text-[#c9b8ba] leading-relaxed">
            아래 <b className="text-[#FB7185]">아티팩트</b>를 내려받아 분석 → 정답 필드를 도출해 제출하세요. (팀별 고유 데이터)
            <a href={artifactUrl(c.id, teamId)} download
               className="mt-2 inline-block font-mono text-[12px] px-3 py-1.5 rounded border border-[#FB7185]/50 text-[#FB7185] hover:bg-[#FB7185]/10">
              ⬇ 아티팩트 다운로드
            </a>
          </div>
        ) : (
          <div className="text-[12px] text-[#c9b8ba] leading-relaxed">
            <b className="text-[#FB7185]">서비스형</b> — 실제 취약 서비스를 직접 익스플로잇해 플래그를 획득하세요.
            트윈 포트(위성 8001 · 발전소 8002 · 사내망 8003 · 섹터 8201~8208) 또는 챌린지 배포 서비스가 대상입니다.
            <div className="mt-1 font-mono text-[11px] text-[#8a6a6e]">예: curl 로 취약 엔드포인트에 페이로드 전송 → 응답에서 flag 추출</div>
          </div>
        )}
      </div>

      {/* 제출 폼(필드는 챌린지별 submit_fields) */}
      <div>
        <div className="text-[10px] uppercase tracking-widest text-[#8a6a6e] mb-1.5">제출 (Submit)</div>
        <div className="flex flex-col gap-2">
          {c.submit_fields.map((f) => (
            <input key={f} value={fields[f] ?? ""} placeholder={f}
              onChange={(e) => setFields((s) => ({ ...s, [f]: e.target.value }))}
              className="bg-[#0c0809] border border-[#2a1a1c] rounded px-2.5 py-1.5 font-mono text-[12px] text-[#F0E6E6] placeholder:text-[#5a4548] focus:border-[#FB7185]/60 outline-none" />
          ))}
          <button onClick={submit} disabled={busy || !teamId}
            className="font-mono text-[12px] uppercase tracking-wider px-3 py-2 rounded bg-[#FB7185]/15 border border-[#FB7185]/50 text-[#FB7185] hover:bg-[#FB7185]/25 disabled:opacity-40">
            {busy ? "채점 중…" : "제출"}
          </button>
        </div>
      </div>

      {err && <div className="text-[12px] text-[#FB7185] font-mono">⚠ {err}</div>}
      {result && (
        <div className={`rounded-md px-3 py-2 text-[13px] font-mono border ${
          result.passed ? "border-[#34D399]/50 bg-[#34D399]/10 text-[#34D399]" : "border-[#FB7185]/50 bg-[#FB7185]/10 text-[#FB7185]"}`}>
          {result.passed
            ? (result.already_solved ? "✓ 이미 해결한 챌린지입니다." : `✓ 정답! +${result.points_awarded}pt 획득 🎉`)
            : "✗ 오답입니다. 다시 시도하세요."}
          <div className="text-[10px] text-[#8a6a6e] mt-1">{result.detail}</div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [teamId, setTeamId] = useLocalState("redportal_team", "red_alpha");
  const [teams, setTeams] = useState<Team[]>([]);
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [cat, setCat] = useState<string>("all");
  const [selected, setSelected] = useState<Challenge | null>(null);
  const [scoreboard, setScoreboard] = useState<ScoreRow[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [d, s] = await Promise.all([fetchChallenges(teamId), fetchScoreboard()]);
      setChallenges(d.challenges); setScoreboard(s.scoreboard); setErr(null);
    } catch (e) { setErr(String(e)); }
  }, [teamId]);

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);
  useEffect(() => {
    fetchTeams("red").then((r) => {
      setTeams(r.teams);
      // 저장된 팀이 목록에 없으면 첫 팀으로.
      if (r.teams.length && !r.teams.some((t) => t.team_id === teamId)) setTeamId(r.teams[0].team_id);
    }).catch(() => { /* 백엔드 미기동 시 자유입력 유지 */ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const cats = useMemo(() => ["all", ...Array.from(new Set(challenges.map((c) => c.category)))], [challenges]);
  const shown = useMemo(() => challenges.filter((c) => cat === "all" || c.category === cat), [challenges, cat]);
  const myScore = scoreboard.find((r) => r.team_id === teamId);
  const solvedCount = challenges.filter((c) => c.solved).length;
  const rankIdx = scoreboard.findIndex((r) => r.team_id === teamId);
  const rank = rankIdx >= 0 ? rankIdx + 1 : null;

  return (
    <div className="min-h-screen bg-[#0c0809] text-[#F0E6E6] font-sans">
      <header className="h-14 border-b border-[#2a1a1c] flex items-center px-4 gap-3 sticky top-0 bg-[#0c0809] z-10">
        <span className="font-mono text-sm tracking-[0.25em] text-[#FB7185]">🚩 RED PORTAL</span>
        <span className="text-[10px] uppercase tracking-widest text-[#8a6a6e] px-2 py-0.5 rounded border border-[#2a1a1c]">
          공격팀 전용
        </span>
        <div className="flex-1" />
        <label className="text-[10px] uppercase tracking-widest text-[#8a6a6e]">TEAM</label>
        {teams.length > 0 ? (
          <select value={teamId} onChange={(e) => setTeamId(e.target.value)}
            className="bg-[#151011] border border-[#2a1a1c] rounded px-2 py-1 font-mono text-[12px] text-[#F0E6E6] focus:border-[#FB7185]/60 outline-none">
            {teams.map((t) => <option key={t.team_id} value={t.team_id}>{t.name}</option>)}
          </select>
        ) : (
          <input value={teamId} onChange={(e) => setTeamId(e.target.value.trim())}
            className="bg-[#151011] border border-[#2a1a1c] rounded px-2 py-1 font-mono text-[12px] text-[#F0E6E6] w-32 focus:border-[#FB7185]/60 outline-none" />
        )}
        <div className="font-mono text-[13px] text-[#FB7185] font-bold">
          {myScore?.points ?? 0}<span className="text-[10px] text-[#8a6a6e] ml-1">pt</span>
        </div>
        <div className="font-mono text-[11px] text-[#8a6a6e]">{solvedCount}/{challenges.length} solved</div>
      </header>

      {err && <div className="px-4 py-2 text-[12px] text-[#FB7185] font-mono bg-[#FB7185]/10">⚠ 포털 백엔드(8060) 연결 실패: {err}</div>}

      <div className="flex">
        {/* 챌린지 목록 */}
        <main className="flex-1 p-4 min-w-0">
          <StatsPanel challenges={challenges} points={myScore?.points ?? 0} rank={rank} />
          <div className="flex flex-wrap gap-1.5 mb-4">
            {cats.map((c) => (
              <button key={c} onClick={() => setCat(c)}
                className={`font-mono text-[11px] px-2.5 py-1 rounded border ${
                  cat === c ? "border-[#FB7185] text-[#FB7185] bg-[#FB7185]/10" : "border-[#2a1a1c] text-[#8a6a6e]"}`}>
                {c === "all" ? "전체" : CAT_LABEL[c] ?? c}
              </button>
            ))}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2.5">
            {shown.map((c) => (
              <ChallengeCard key={c.id} c={c} onClick={() => setSelected(c)} />
            ))}
          </div>
          {shown.length === 0 && !err && <div className="text-[#8a6a6e] font-mono text-sm">불러오는 중…</div>}
        </main>

        {/* 상세/제출 사이드 */}
        {selected && (
          <aside className="w-96 border-l border-[#2a1a1c] p-4 shrink-0 h-[calc(100vh-3.5rem)] overflow-y-auto sticky top-14">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="font-mono text-[11px] text-[#8a6a6e]">{selected.id} · {CAT_LABEL[selected.category] ?? selected.category}</div>
                <div className="text-[15px] text-[#F0E6E6] font-semibold leading-snug mt-0.5">{selected.title}</div>
              </div>
              <button onClick={() => setSelected(null)} className="text-[#8a6a6e] hover:text-[#F0E6E6] text-sm">✕</button>
            </div>
            <div className="flex items-center gap-2 mb-3">
              <DifficultyBadge d={selected.difficulty} />
              <span className="font-mono text-[12px] font-bold text-[#FB7185]">{selected.points_red}pt</span>
              {selected.solved && <span className="text-[#34D399] text-[11px]">✓ solved</span>}
            </div>
            <SubmitPanel c={selected} teamId={teamId} onSolved={load} />
          </aside>
        )}
      </div>

      {/* 스코어보드(막대) */}
      {scoreboard.length > 0 && (
        <div className="fixed bottom-3 left-3 bg-[#151011] border border-[#2a1a1c] rounded-lg px-3 py-2.5 w-72 shadow-lg">
          <div className="text-[10px] uppercase tracking-widest text-[#8a6a6e] mb-2">🏆 Scoreboard</div>
          <ScoreboardBars rows={scoreboard} me={teamId} />
        </div>
      )}
    </div>
  );
}
