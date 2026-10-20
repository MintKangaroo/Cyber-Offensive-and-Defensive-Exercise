import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArenaView, DEFAULT_ARENA } from "./ArenaView";
import { FacilityConsole, type ConsoleData } from "./FacilityConsole";
import {
  type ConnStatus,
  executeStep,
  fetchPowerTelemetry,
  fetchSectorTelemetry,
  fmtClock,
  powerRegistersFromTelemetry,
  registersFromSectorTelemetry,
  sectorFootLine,
  subscribeStream,
  type StreamEvent,
} from "./api";
import { FACILITIES, PHASE_LABEL, SCOREBOARD } from "./data";
import type { AttackStep, FacilityConfig, PhaseStep, RedPhase, RegisterRow, ScoreRow, SolveEntry, StrikeLogEntry } from "./types";

type View = "arena" | "facility";
type TeamTally = Record<string, { attack: number; defense: number }>;
const OUR_TEAM = "default"; // 트윈 TEAM_ID 기본값 = 우리 팀(RED·TEAM-01)
const TEAM_DISPLAY: Record<string, string> = { default: "RED · TEAM-01" };

/** 라이브 점수 누적(team→{attack,defense})에서 스코어보드를 만든다. 비면 정적 폴백. */
function buildScoreboard(tally: TeamTally): ScoreRow[] {
  const ids = Object.keys(tally);
  if (ids.length === 0) return SCOREBOARD;
  return ids
    .map((id) => ({ id, score: tally[id].attack + tally[id].defense }))
    .sort((a, b) => b.score - a.score)
    .map((r, i) => ({ rank: i + 1, team: TEAM_DISPLAY[r.id] ?? r.id, score: r.score, me: r.id === OUR_TEAM }));
}

/** 실행된 단계(done)로부터 킬체인 phase 상태를 계산 — recon 는 항상 완료, impact 는 전단계 완료 시 활성. */
function computePhases(chain: AttackStep[], done: Set<string>): PhaseStep[] {
  const order: RedPhase[] = [];
  for (const s of chain) if (!order.includes(s.phase)) order.push(s.phase);
  let activeAssigned = false;
  const mid: PhaseStep[] = order.map((ph) => {
    const steps = chain.filter((s) => s.phase === ph);
    const allDone = steps.every((s) => done.has(s.id));
    const pts = steps.reduce((a, s) => a + s.points, 0);
    let state: PhaseStep["state"];
    if (allDone) state = "done";
    else if (!activeAssigned) { state = "active"; activeAssigned = true; }
    else state = "todo";
    return { phase: ph, label: PHASE_LABEL[ph], points: pts, state };
  });
  const allChainDone = chain.length > 0 && chain.every((s) => done.has(s.id));
  return [
    { phase: "recon", label: "RECON", state: "done" },
    ...mid,
    { phase: "impact", label: "IMPACT", state: allChainDone ? "active" : "todo" },
  ];
}

function initialFromUrl(): { view: View; sector: FacilityConfig["id"] } {
  try {
    const q = new URLSearchParams(window.location.search);
    const s = q.get("sector") as FacilityConfig["id"] | null;
    const sector = s && FACILITIES[s] ? s : "power";
    const view: View = q.get("v") === "facility" ? "facility" : "arena";
    return { view, sector };
  } catch {
    return { view: "arena", sector: "power" };
  }
}

export default function App() {
  const init = initialFromUrl();
  const [view, setView] = useState<View>(init.view);
  const [sector, setSector] = useState<FacilityConfig["id"]>(init.sector);
  const [status, setStatus] = useState<ConnStatus>("connecting");
  const [liveRegisters, setLiveRegisters] = useState<RegisterRow[] | null>(null);
  const [liveFootLine, setLiveFootLine] = useState<string | null>(null);
  const [extraStrikes, setExtraStrikes] = useState<StrikeLogEntry[]>([]);
  const [done, setDone] = useState<Set<string>>(new Set());
  const [executingStep, setExecutingStep] = useState<string | null>(null);
  const [liveScores, setLiveScores] = useState<TeamTally>({}); // event_collector scores 토픽 누적
  const [liveSolve, setLiveSolve] = useState<SolveEntry[]>([]); // 라이브 Solve Log
  const [liveClock, setLiveClock] = useState<{ remaining: number; elapsed: number; stageRemaining: number; overtime: boolean } | null>(null); // phase_clock 토픽
  const everLive = useRef(false);

  // 시설 전환 시 작전 진행(실행 단계·라이브 로그·라이브 게이지) 초기화 — 각 시설은 독립 작전.
  useEffect(() => { setDone(new Set()); setExtraStrikes([]); setLiveRegisters(null); setLiveFootLine(null); }, [sector]);

  // 선택 섹터의 라이브 텔레메트리 폴링 — 게이지/레지스터가 실제로 움직임.
  //  · 발전소: 전용 스키마(냉각수/온도 포함) · 그 외: twin_modbus 통일 스키마.
  //  URL 미해석 섹터(VITE_TWIN_* 미설정)는 폴백(정적) — 정직하게 라이브로 표시하지 않음.
  useEffect(() => {
    let timer: number | undefined;
    let cancelled = false;
    const tick = async () => {
      if (sector === "power") {
        const t = await fetchPowerTelemetry();
        if (cancelled) return;
        if (t) {
          everLive.current = true;
          setLiveRegisters(powerRegistersFromTelemetry(t));
          setLiveFootLine(
            `ACTUAL_RPM ${t.actual_rpm.toLocaleString()} · COOLANT ${t.coolant_flow}/${t.coolant_temp}°C · SIS ${t.interlock ? "ARMED" : "BYPASS"} · DAMAGE ${t.damage}%${t.failed ? " · CATASTROPHIC_FAILURE" : ""}`,
          );
          setStatus("live");
        } else if (!everLive.current) {
          setStatus((s) => (s === "live" ? s : "mock"));
        }
      } else {
        const t = await fetchSectorTelemetry(sector);
        if (cancelled) return;
        if (t) {
          everLive.current = true;
          setLiveRegisters(registersFromSectorTelemetry(t));
          setLiveFootLine(sectorFootLine(t));
          setStatus("live");
        }
      }
      timer = window.setTimeout(tick, 1500);
    };
    tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [sector]);

  // event_collector SSE — 스트라이크/이벤트 피드.
  useEffect(() => {
    const onEvent = (e: StreamEvent) => {
      // scores 토픽: 어워드 델타를 팀별로 누적 → 라이브 스코어보드/점수.
      if (e.topic === "scores" && typeof e.points === "number" && e.points) {
        const team = e.team_id || OUR_TEAM;
        const isRed = e.actor === "red";
        const pts = e.points;
        setLiveScores((prev) => {
          const cur = prev[team] ?? { attack: 0, defense: 0 };
          return { ...prev, [team]: { attack: cur.attack + (isRed ? pts : 0), defense: cur.defense + (isRed ? 0 : pts) } };
        });
        const side: SolveEntry["side"] = isRed ? "attack" : "defense";
        setLiveSolve((prev) => [
          { id: `sc-${Date.now()}-${prev.length}`, side, team: TEAM_DISPLAY[team] ?? team, text: `${e.category ?? "award"} · +${pts}`, points: pts },
          ...prev,
        ].slice(0, 8));
      }
      // phase_clock 토픽: scenario_engine 투영 타임라인 → 타이머 3종 라이브.
      if (e.topic === "phase_clock" && typeof e.remaining_sec === "number") {
        everLive.current = true;
        setLiveClock({
          remaining: e.remaining_sec,
          elapsed: e.elapsed_sec ?? 0,
          stageRemaining: e.stage_remaining_sec ?? 0,
          overtime: Boolean(e.overtime),
        });
      }
      if (e.topic === "events" && e.event_type) {
        setExtraStrikes((prev) => [
          {
            id: `live-${Date.now()}-${prev.length}`,
            time: new Date().toLocaleTimeString("en-GB").slice(3),
            phase: (e.phase as RedPhase) ?? "lateral_movement",
            text: `${e.event_type}${e.vuln_id ? ` · ${e.vuln_id}` : ""}${e.target_asset ? ` · ${e.target_asset}` : ""}`,
            tag: "LIVE",
            current: true,
          },
          ...prev.slice(0, 5).map((s) => ({ ...s, current: false })),
        ]);
      }
    };
    return subscribeStream(onEvent, (s) => { if (!everLive.current) setStatus(s); });
  }, []);

  const facility = FACILITIES[sector];

  // 다음 실행 가능한 단계(순차 게이팅) — done 에 없는 첫 단계.
  const nextStepId = facility.attackChain.find((s) => !done.has(s.id))?.id ?? null;
  // 실행된 단계의 로컬 점수(백엔드 미연결 시 폴백). 라이브 연결 시 event_collector 집계로 대체.
  const chainScore = facility.attackChain.filter((s) => done.has(s.id)).reduce((a, s) => a + s.points, 0);
  const ourLive = liveScores[OUR_TEAM];
  const liveScoreboard = buildScoreboard(liveScores);

  const consoleData: ConsoleData = useMemo(() => {
    const strikeLog = extraStrikes.length
      ? [...extraStrikes, ...facility.strikeLog].slice(0, 6)
      : facility.strikeLog;
    return {
      phases: computePhases(facility.attackChain, done),
      scoreboard: liveScoreboard,
      strikeLog,
      registers: liveRegisters ?? undefined,
      footLine: liveFootLine ?? facility.footLine,
      atkScore: ourLive ? ourLive.attack : chainScore,
      defScore: ourLive ? ourLive.defense : 40,
      elapsed: liveClock ? fmtClock(liveClock.elapsed) : undefined,
    };
  }, [facility, liveRegisters, liveFootLine, extraStrikes, done, chainScore, ourLive, liveScoreboard, liveClock]);

  const arenaData = useMemo(
    () => ({
      ...DEFAULT_ARENA,
      scoreboard: liveScoreboard,
      solveLog: liveSolve.length ? liveSolve : DEFAULT_ARENA.solveLog,
      timeRemaining: liveClock ? fmtClock(liveClock.remaining) : DEFAULT_ARENA.timeRemaining,
      nextAttack: liveClock ? fmtClock(liveClock.stageRemaining) : DEFAULT_ARENA.nextAttack,
      activeLine: liveFootLine ? `RED·TEAM-01 → 발전소 안전계통 · ${liveFootLine}` : DEFAULT_ARENA.activeLine,
    }),
    [liveFootLine, liveScoreboard, liveSolve, liveClock],
  );

  const onSelectFacility = useCallback((s: FacilityConfig["id"]) => { setSector(s); setView("facility"); }, []);

  const onExecuteStep = useCallback(async (step: AttackStep) => {
    if (done.has(step.id) || executingStep) return;
    setExecutingStep(step.id);
    const res = await executeStep(sector, step);
    if (res.ok) {
      setDone((prev) => new Set(prev).add(step.id));
      setExtraStrikes((prev) => [
        {
          id: `step-${step.id}`,
          time: new Date().toLocaleTimeString("en-GB").slice(3),
          phase: step.phase,
          text: `${step.label} · ${step.vuln}${res.live ? "" : " (narrative)"}`,
          tag: `+${step.points}`,
          current: true,
        },
        ...prev.map((s) => ({ ...s, current: false })),
      ]);
    }
    setExecutingStep(null);
  }, [sector, done, executingStep]);

  return (
    <div className="lf-root">
      {view === "arena" ? (
        <ArenaView data={arenaData} status={status} onSelectFacility={onSelectFacility} />
      ) : (
        <FacilityConsole
          facility={facility}
          data={consoleData}
          status={status}
          done={done}
          nextStepId={nextStepId}
          executingStep={executingStep}
          onBack={() => setView("arena")}
          onSelectFacility={setSector}
          onExecuteStep={onExecuteStep}
        />
      )}
    </div>
  );
}
