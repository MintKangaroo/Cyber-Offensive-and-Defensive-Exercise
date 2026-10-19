import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArenaView, DEFAULT_ARENA } from "./ArenaView";
import { FacilityConsole, type ConsoleData } from "./FacilityConsole";
import {
  type ConnStatus,
  executeStep,
  fetchPowerTelemetry,
  powerRegistersFromTelemetry,
  subscribeStream,
  type StreamEvent,
} from "./api";
import { FACILITIES, PHASE_LABEL, SCOREBOARD } from "./data";
import type { AttackStep, FacilityConfig, PhaseStep, RedPhase, RegisterRow, StrikeLogEntry } from "./types";

type View = "arena" | "facility";

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
  const everLive = useRef(false);

  // 시설 전환 시 작전 진행(실행 단계·라이브 로그) 초기화 — 각 시설은 독립 작전.
  useEffect(() => { setDone(new Set()); setExtraStrikes([]); }, [sector]);

  // 발전소 라이브 텔레메트리 폴링 — 게이지/레지스터가 실제로 움직임.
  useEffect(() => {
    let timer: number | undefined;
    let cancelled = false;
    const tick = async () => {
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
      timer = window.setTimeout(tick, 1500);
    };
    tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, []);

  // event_collector SSE — 스트라이크/이벤트 피드.
  useEffect(() => {
    const onEvent = (e: StreamEvent) => {
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
  const isPower = sector === "power";

  // 다음 실행 가능한 단계(순차 게이팅) — done 에 없는 첫 단계.
  const nextStepId = facility.attackChain.find((s) => !done.has(s.id))?.id ?? null;
  // 실행으로 누적되는 공격 점수(라이브). ②에서 event_collector 집계로 대체 예정.
  const atkScore = facility.attackChain.filter((s) => done.has(s.id)).reduce((a, s) => a + s.points, 0);

  const consoleData: ConsoleData = useMemo(() => {
    const strikeLog = extraStrikes.length
      ? [...extraStrikes, ...facility.strikeLog].slice(0, 6)
      : facility.strikeLog;
    return {
      phases: computePhases(facility.attackChain, done),
      scoreboard: SCOREBOARD,
      strikeLog,
      registers: isPower && liveRegisters ? liveRegisters : undefined,
      footLine: isPower && liveFootLine ? liveFootLine : facility.footLine,
      atkScore,
      defScore: 40,
    };
  }, [facility, isPower, liveRegisters, liveFootLine, extraStrikes, done, atkScore]);

  const arenaData = useMemo(
    () => ({ ...DEFAULT_ARENA, activeLine: liveFootLine ? `RED·TEAM-01 → 발전소 안전계통 · ${liveFootLine}` : DEFAULT_ARENA.activeLine }),
    [liveFootLine],
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
