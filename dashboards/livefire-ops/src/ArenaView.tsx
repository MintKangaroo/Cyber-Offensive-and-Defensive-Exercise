import { Dome } from "./components/Dome";
import type { ConnStatus } from "./api";
import { ARENA_NODES, SCOREBOARD, SOLVE_LOG } from "./data";
import type { ArenaNode, ScoreRow, SolveEntry } from "./types";

export interface ArenaData {
  timeRemaining: string;
  nextAttack: string;
  patchCount: number;
  atkCount: number;
  defCount: number;
  nodes: ArenaNode[];
  scoreboard: ScoreRow[];
  solveLog: SolveEntry[];
  activeLine: string;
}

export const DEFAULT_ARENA: ArenaData = {
  timeRemaining: "00:51:32",
  nextAttack: "00:01:27",
  patchCount: 7,
  atkCount: 12,
  defCount: 7,
  nodes: ARENA_NODES,
  scoreboard: SCOREBOARD,
  solveLog: SOLVE_LOG,
  activeLine: "RED·TEAM-01 → 발전소 안전계통 · coil0 latch OFF · 터빈 과속 5,240 RPM",
};

export function ArenaView({ data, status, onSelectFacility }: { data: ArenaData; status: ConnStatus; onSelectFacility: (sector: ArenaNode["sector"]) => void }) {
  const live = status === "live";
  return (
    <div className="lf-arena">
      <div className="stars" />

      <header className="topbar">
        <div className="brand">
          <div className="cce">CC</div>
          <div>
            <div className="t2 lf-op">
              국가 기반시설 공방 현황 <span className="sub">· LIVE FIRE STATUS</span>
            </div>
            <div className="t1">CYBER LIVE-FIRE EXERCISE · 2026</div>
          </div>
        </div>
        <div className="topright">
          <span>ROUND 03 / 06</span>
          <span>SECTORS 11 · TARGETS {data.nodes.length}</span>
          <span className="live" style={live ? undefined : { color: "var(--lf-amber)" }} title="백엔드 연결 상태">
            <span className="d" style={live ? undefined : { background: "var(--lf-amber)" }} /> {live ? "LIVE" : status === "connecting" ? "연결중" : "DEMO"}
          </span>
        </div>
      </header>

      <div className="arena">
        <div className="arena-stage">
        <Dome />

        {data.nodes.map((n) => (
          <button
            key={n.id}
            className={`node ${n.status}`}
            style={{ left: `${n.xPct}%`, top: `${n.yPct}%` }}
            onClick={() => onSelectFacility(n.sector)}
            aria-label={`${n.label} ${n.code} — ${n.sector} 콘솔 열기`}
          >
            {n.status === "active" && <><span className="ring" /><span className="ring2" /></>}
            <span className="sq" />
            <span className="lb">{n.label}<br /><span className="id">{n.code}</span></span>
          </button>
        ))}
        </div>

        <section className="ov timers" aria-label="라이브파이어 클럭">
          <div className="ovh">⟡ LIVE FIRE CLOCK</div>
          <div className="tmr"><div className="k">Time Remaining</div><div className="v rem lf-mono">{data.timeRemaining}</div></div>
          <div className="tmr"><div className="k">Next Attack</div><div className="v nxt lf-mono">{data.nextAttack}</div></div>
          <div className="tmr pc">
            <div><div className="k">Patch Count</div><div className="pcnum lf-mono">{String(data.patchCount).padStart(2, "0")}</div></div>
            <div className="leg">
              <span><span className="d" style={{ background: "var(--lf-red)" }} />공격 {data.atkCount}</span>
              <span><span className="d" style={{ background: "var(--lf-cyan)" }} />방어 {data.defCount}</span>
            </div>
          </div>
        </section>

        <section className="ov lb2" aria-label="스코어보드">
          <div className="ovh">⟡ SCOREBOARD · TOP 5</div>
          {data.scoreboard.map((r) => (
            <div key={r.rank} className={`lbr ${r.me ? "me" : ""}`}>
              <span className="rk">{String(r.rank).padStart(2, "0")}</span>
              <span className="nm">{r.team}</span>
              <span className="sc">{r.score.toLocaleString()}</span>
            </div>
          ))}
        </section>

        <section className="ov log" aria-label="Solve Log">
          <div className="ovh">⟡ SOLVE LOG · 실시간</div>
          <div className="logbody">
            {data.solveLog.map((e) => (
              <div key={e.id} className="lge">
                <span className={`tg ${e.side === "attack" ? "atk" : "def"}`}>{e.side === "attack" ? "공격" : "방어"}</span>
                <span className="tx"><b>{e.team}</b> {e.text}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <div className="foot">
        <div className="seg"><span className="d" /><span className="sub">ACTIVE</span> <b className="r">{data.activeLine}</b></div>
        <div className="seg" style={{ marginLeft: "auto", color: "var(--lf-sub)" }}>event_collector :8010 · SSE /stream · topics events,scores,safety,phase_clock</div>
      </div>
    </div>
  );
}
