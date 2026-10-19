import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArenaView, DEFAULT_ARENA } from "./ArenaView";
import { FacilityConsole, type ConsoleData } from "./FacilityConsole";
import {
  type ConnStatus,
  executeStrike,
  fetchPowerTelemetry,
  powerRegistersFromTelemetry,
  subscribeStream,
  type StreamEvent,
} from "./api";
import { FACILITIES, powerKillChain, SCOREBOARD, STRIKE_LOG } from "./data";
import type { FacilityConfig, PhaseStep, RegisterRow, StrikeLogEntry } from "./types";

type View = "arena" | "facility";

function genericKillChain(): PhaseStep[] {
  return [
    { phase: "recon", label: "RECON", state: "done" },
    { phase: "initial_access", label: "INITIAL ACCESS", points: 20, state: "done" },
    { phase: "lateral_movement", label: "LATERAL MOVEMENT", points: 30, state: "active" },
    { phase: "objective", label: "OBJECTIVE", points: 100, state: "todo" },
    { phase: "impact", label: "IMPACT", state: "todo" },
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
  const [footLine, setFootLine] = useState<string>(
    "00:41:12 · asset_compromised · power_plant · sustained_overspeed_sis_disabled · CRITICAL · phase=objective",
  );
  const [extraStrikes, setExtraStrikes] = useState<StrikeLogEntry[]>([]);
  const [executing, setExecuting] = useState(false);
  const everLive = useRef(false);

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
        setFootLine(
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
            phase: (e.phase as StrikeLogEntry["phase"]) ?? "lateral_movement",
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

  const consoleData: ConsoleData = useMemo(() => {
    const isPower = sector === "power";
    const liveStrikes = extraStrikes.length ? [...extraStrikes, ...STRIKE_LOG].slice(0, 6) : STRIKE_LOG;
    return {
      phases: isPower ? powerKillChain() : genericKillChain(),
      scoreboard: SCOREBOARD,
      strikeLog: liveStrikes,
      registers: isPower && liveRegisters ? liveRegisters : undefined,
      footLine,
      atkScore: 150,
      defScore: 40,
    };
  }, [sector, liveRegisters, footLine, extraStrikes]);

  const arenaData = useMemo(() => ({ ...DEFAULT_ARENA, activeLine: footLine.startsWith("ACTUAL_RPM") ? `RED·TEAM-01 → 발전소 안전계통 · ${footLine}` : DEFAULT_ARENA.activeLine }), [footLine]);

  const onSelectFacility = useCallback((s: FacilityConfig["id"]) => { setSector(s); setView("facility"); }, []);
  const onExecute = useCallback(async () => {
    setExecuting(true);
    await executeStrike(sector);
    setExtraStrikes((prev) => [
      { id: `strike-${Date.now()}`, time: new Date().toLocaleTimeString("en-GB").slice(3), phase: "objective", text: `${facility.exploit.label} · ${facility.exploit.detail}`, tag: "FIRED", current: true },
      ...prev.map((s) => ({ ...s, current: false })),
    ]);
    setTimeout(() => setExecuting(false), 1200);
  }, [sector, facility]);

  return (
    <div className="lf-root">
      {view === "arena" ? (
        <ArenaView data={arenaData} status={status} onSelectFacility={onSelectFacility} />
      ) : (
        <FacilityConsole
          facility={facility}
          data={consoleData}
          status={status}
          onBack={() => setView("arena")}
          onSelectFacility={setSector}
          onExecute={onExecute}
          executing={executing}
        />
      )}
    </div>
  );
}
