import { SectorIcon } from "./components/icons";
import { Schematic, SCHEMATIC_TITLE } from "./components/schematics";
import type { ConnStatus } from "./api";
import { FACILITIES, FACILITY_ORDER, PHASE_LABEL } from "./data";
import type { AttackStep, FacilityConfig, PhaseStep, RegisterRow, ScoreRow, StrikeLogEntry } from "./types";

const STATUS_LABEL: Record<ConnStatus, string> = { live: "LIVE", connecting: "연결중", mock: "DEMO" };

const SECTOR_STATUS: Record<string, string> = {
  power: "ENGAGED", nuclear: "PATCHED", water: "PROBED", lng: "PROBED",
  railway: "DEFENDED", airport: "PROBED", hospital: "PROBED", finance: "—",
  telecom: "—", satellite: "—", factory: "—",
};

export interface ConsoleData {
  phases: PhaseStep[];
  scoreboard: ScoreRow[];
  strikeLog: StrikeLogEntry[];
  registers?: RegisterRow[]; // 라이브 override (발전소)
  footLine: string;
  atkScore: number;
  defScore: number;
}

export function FacilityConsole({
  facility, data, status, done, nextStepId, executingStep, onBack, onSelectFacility, onExecuteStep,
}: {
  facility: FacilityConfig;
  data: ConsoleData;
  status: ConnStatus;
  done: Set<string>;
  nextStepId: string | null;
  executingStep: string | null;
  onBack: () => void;
  onSelectFacility: (id: FacilityConfig["id"]) => void;
  onExecuteStep: (step: AttackStep) => void;
}) {
  const registers = data.registers ?? facility.registers;
  const nextStep = facility.attackChain.find((s) => s.id === nextStepId) ?? null;
  return (
    <div className="lf-console">
      {/* TOP */}
      <div className="top">
        <button className="back" onClick={onBack} aria-label="현황 아레나로 돌아가기">◂ 현황</button>
        <div className="title">
          <div className="l2 lf-op">OPERATION <span className="r">BLACKOUT</span></div>
          <div className="l1">[ 사이버 공방 훈련 · LIVE-FIRE ]</div>
        </div>
        <div className="statrow">
          <div className="stat"><span className="k">Round</span><span className="v">03 / 06</span></div>
          <div className="stat"><span className="k">T+ Engage</span><span className="v">00:41:17</span></div>
          <div className="stat"><span className="k">Attack</span><span className="v red">{data.atkScore}</span></div>
          <div className="stat"><span className="k">Defense</span><span className="v blue">{data.defScore}</span></div>
          <div className="stat"><span className="k">Kill-chain</span><span className="v amber">{data.phases.filter((p) => p.state === "done").length} / {data.phases.length}</span></div>
        </div>
        <div className="livebox" style={status === "live" ? undefined : { color: "var(--lf-amber)" }} title="백엔드 연결 상태">
          <span className="d" style={status === "live" ? undefined : { background: "var(--lf-amber)" }} /> {STATUS_LABEL[status]}
        </div>
      </div>

      {/* phases */}
      <div className="phases">
        {data.phases.map((p, i) => (
          <div key={p.phase} className={`ph ${p.state}`}>
            <span className="n">{String(i + 1).padStart(2, "0")}</span>
            {PHASE_LABEL[p.phase]}
            {p.points ? <span className="pts">+{p.points}</span> : null}
          </div>
        ))}
      </div>

      {/* MAIN */}
      <div className="main">
        {/* LEFT: leaderboard + sector selector */}
        <div className="col">
          <div className="panel" style={{ flex: "none" }}>
            <div className="phead"><div className="bk"><span className="br">[</span>LEADERBOARD<span className="br">]</span></div></div>
            <div className="lbh"><span>#</span><span>TEAM</span><span>ATK</span><span>DEF</span></div>
            {data.scoreboard.map((r) => (
              <div key={r.rank} className={`lbrow ${r.me ? "me" : ""}`}>
                <span className="rk">{String(r.rank).padStart(2, "0")}</span>
                <span className="tm">{r.team}</span>
                <span className="atk">{Math.round(r.score / 10)}</span>
                <span className="def">{Math.round(r.score / 25)}</span>
              </div>
            ))}
          </div>
          <div className="panel sect">
            <div className="phead">
              <div className="bk"><span className="br">[</span>국가핵심기반 11<span className="br">]</span></div>
              <span className="lf-mono" style={{ fontSize: 8, color: "var(--lf-sub)" }}>SELECT</span>
            </div>
            <div className="sectlist">
              {FACILITY_ORDER.map((id) => {
                const f = FACILITIES[id];
                const on = id === facility.id;
                const breach = SECTOR_STATUS[id] === "PATCHED";
                return (
                  <button
                    key={id}
                    className={`srow ${on ? "on" : ""} ${breach ? "breach" : ""}`}
                    onClick={() => onSelectFacility(id)}
                    aria-current={on ? "true" : undefined}
                  >
                    <SectorIcon kind={f.icon} className="ic" />
                    <span className="nm">{f.name}</span>
                    <span className="st">{SECTOR_STATUS[id] ?? "—"}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* CENTER: strike map + log */}
        <div className="col">
          <div className="panel map">
            <div className="mapcanvas" />
            <svg className="edges" viewBox="0 0 1000 620" preserveAspectRatio="none" aria-hidden="true">
              <defs>
                <marker id="ah" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                  <path d="M0 0 L6 3 L0 6 Z" fill="#ff5b60" />
                </marker>
              </defs>
              {facility.otEdges.map((e, i) => {
                const a = facility.otNodes.find((n) => n.id === e.from);
                const b = facility.otNodes.find((n) => n.id === e.to);
                if (!a || !b) return null;
                const x1 = (a.xPct / 100) * 1000, y1 = (a.yPct / 100) * 620;
                const x2 = (b.xPct / 100) * 1000, y2 = (b.yPct / 100) * 620;
                return (
                  <line
                    key={i} x1={x1} y1={y1} x2={x2} y2={y2}
                    stroke={e.active ? "#ff5b60" : "#35506e"}
                    strokeWidth={e.active ? 2.4 : 1.3}
                    markerEnd={e.active ? "url(#ah)" : undefined}
                  />
                );
              })}
            </svg>
            <div className="maplbl bk"><span className="br">[</span>OT STRIKE MAP · 침투 작전도<span className="br">]</span></div>
            <div className="mapr">ZONE OT/CONTROL · L2 PURDUE<br />HOSTS {facility.otNodes.length} · OWNED {facility.otNodes.filter((n) => n.status === "owned").length} · 1 ACTIVE</div>
            {facility.otNodes.map((n) => (
              <div key={n.id} className={`node ${n.status}`} style={{ left: `${n.xPct}%`, top: `${n.yPct}%` }}>
                <div className="nb">
                  {n.status === "owned" && <span className="ntag">OWNED</span>}
                  {n.status === "target" && <span className="ntag">TARGET</span>}
                  <div className="nt"><span className="dotm" />{n.name}</div>
                  <div className="ns">{n.sub}</div>
                  {(n.protocols || n.vulns) && (
                    <div className="nchips">
                      {n.protocols?.map((p) => <span key={p} className="cp p">{p}</span>)}
                      {n.vulns?.map((v) => <span key={v} className="cp v">{v}</span>)}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="panel slog">
            <div className="phead">
              <div className="bk"><span className="br">[</span>STRIKE LOG<span className="br">]</span></div>
              <span className="lf-mono" style={{ fontSize: 8, color: "var(--lf-sub)" }}>SSE /stream · :8010</span>
            </div>
            {data.strikeLog.map((s) => (
              <div key={s.id} className={`slr ${s.current ? "sel" : ""}`}>
                <span className="tm">{s.time}</span>
                <span className="pill">
                  <span className={`tag ${tagClass(s.phase)}`}>{PHASE_LABEL[s.phase]}</span> {s.text}
                </span>
                <span className="sc">{s.tag}</span>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT: facility panel */}
        <div className="col">
          <div className="panel" style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
            <div className="fachead">
              <div>
                <div className="facname">{facility.name} · {facility.nameEn}</div>
                <div className="facmeta">{facility.meta}</div>
              </div>
              <SectorIcon kind={facility.icon} className="facicon" />
            </div>
            <div className="objbar">
              <div><div className="ol">OBJECTIVE</div><div className="ot">{facility.objective}</div></div>
              <div className="op">+{facility.objectivePoints}</div>
            </div>
            <div className="facbody">
              <div>
                <div className="sub">{SCHEMATIC_TITLE[facility.schematic]}</div>
                <div className="oneline"><Schematic kind={facility.schematic} /></div>
              </div>
              <div>
                <div className="sub">{facility.registersTitle}</div>
                <div className="regtab">
                  <div className="reg hd"><div>REGISTER</div><div>ADDR</div><div>VALUE</div><div>STATE</div></div>
                  {registers.map((r, i) => (
                    <div className="reg" key={r.name} style={i === registers.length - 1 ? { borderBottom: "none" } : undefined}>
                      <div className="rn">{r.name}</div>
                      <div className="ra">{r.addr}</div>
                      <div className={`rv ${r.tone}`}>{r.value}</div>
                      <div className={`rs ${r.tone === "neutral" ? "neutral" : "al"}`}>{r.state}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div className="sub">노출 서비스 · SERVICE STATUS</div>
                <div className="svc">
                  {facility.services.map((s) => (
                    <div className="svrow" key={s.name}><span className="sn">{s.name}</span><span className={`en ${s.state}`}>{s.state.toUpperCase()}</span></div>
                  ))}
                </div>
              </div>
              <div>
                <div className="sub">킬체인 공격 · ATTACK CHAIN {status === "live" ? "· LIVE 트윈" : ""}</div>
                <div className="chain">
                  {facility.attackChain.map((s) => {
                    const st = done.has(s.id) ? "done" : s.id === nextStepId ? "next" : "locked";
                    return (
                      <div className={`cstep ${st}`} key={s.id}>
                        <span className="cph">{PHASE_LABEL[s.phase]}</span>
                        <span className="cl">{s.label}</span>
                        <span className="cv">{s.vuln}</span>
                        <span className="cpts">+{s.points}</span>
                        {st === "next" ? (
                          <button className="cx" onClick={() => onExecuteStep(s)} disabled={!!executingStep}>
                            {executingStep === s.id ? "실행중" : "EXEC"}
                          </button>
                        ) : (
                          <span className="cstate">{st === "done" ? "완료" : "대기"}</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
            <div className="exbar">
              {nextStep ? (
                <>
                  <div className="exinfo">▸ 다음 <b>{nextStep.label}</b> · {nextStep.vuln} · {PHASE_LABEL[nextStep.phase]} +{nextStep.points}</div>
                  <button className="exbtn" onClick={() => onExecuteStep(nextStep)} disabled={!!executingStep}>
                    {executingStep === nextStep.id ? "EXECUTING…" : "EXECUTE STRIKE"}
                  </button>
                </>
              ) : (
                <div className="exinfo" style={{ color: "var(--lf-red)" }}>▸ 작전 완료 · OPERATION COMPLETE · 전 단계 실행됨</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* FOOT */}
      <div className="foot">
        <div className="fl"><span className="k">ACTIVE STRIKE</span> <b>{facility.exploit.label}</b> · {facility.exploit.detail}</div>
        <div className="fr"><span className="d" /><span className="lf-mono">{data.footLine}</span></div>
      </div>
    </div>
  );
}

function tagClass(phase: StrikeLogEntry["phase"]): string {
  if (phase === "objective" || phase === "impact") return "red";
  if (phase === "lateral_movement" || phase === "privilege_escalation") return "amber";
  return "blue";
}
