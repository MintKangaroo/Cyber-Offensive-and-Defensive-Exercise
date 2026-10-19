// 라이브 데이터 계층.
//  - 발전소 트윈(services/power_plant) /api/telemetry 폴링 → 게이지가 실제로 움직임
//  - 발전소 트윈 공격 엔드포인트 호출(EXECUTE STRIKE) → 물리 파국 유발
//  - event_collector :8010 /stream SSE → 스트라이크/이벤트 피드
// 백엔드 미도달 시 정적 목업으로 폴백(오프라인에서도 UI 동작).
import type { PowerTelemetry, RegisterRow } from "./types";

const COLLECTOR_URL = import.meta.env.VITE_COLLECTOR_URL || "http://localhost:8010";
const POWER_TWIN_URL = import.meta.env.VITE_POWER_TWIN_URL || "http://localhost:8002";

export type ConnStatus = "connecting" | "live" | "mock";

function withTimeout(ms: number): AbortSignal {
  const c = new AbortController();
  setTimeout(() => c.abort(), ms);
  return c.signal;
}

/** 발전소 트윈 라이브 물리 텔레메트리(실 Modbus 뱅크 HR0~4 / coil0). */
export async function fetchPowerTelemetry(): Promise<PowerTelemetry | null> {
  try {
    const r = await fetch(`${POWER_TWIN_URL}/api/telemetry`, { signal: withTimeout(2000) });
    if (!r.ok) return null;
    const d = await r.json();
    return {
      actual_rpm: Number(d.actual_rpm ?? 0),
      cmd_rpm: Number(d.cmd_rpm ?? 0),
      coolant_flow: Number(d.coolant_flow ?? 0),
      coolant_temp: Number(d.coolant_temp ?? 0),
      damage: Number(d.damage ?? 0),
      interlock: Boolean(d.interlock),
      failed: Boolean(d.failed),
    };
  } catch {
    return null;
  }
}

/** 발전소 트윈에 라이브 텔레메트리를 반영한 레지스터 테이블 행. */
export function powerRegistersFromTelemetry(t: PowerTelemetry): RegisterRow[] {
  const overspeed = t.actual_rpm > 4500;
  const lowFlow = t.coolant_flow < 50;
  const hotTemp = t.coolant_temp > 110;
  return [
    { name: "TURBINE_RPM (cmd)", addr: "HR0", value: t.cmd_rpm.toLocaleString(), state: "SET", tone: t.cmd_rpm > 4500 ? "red" : "neutral" },
    { name: "ACTUAL_RPM", addr: "HR2", value: `${t.actual_rpm.toLocaleString()}${overspeed ? " ▲" : ""}`, state: overspeed ? "O-SPD" : "OK", tone: overspeed ? "red" : "blue" },
    { name: "COOLANT_FLOW", addr: "HR1", value: `${t.coolant_flow}${lowFlow ? " ▼" : ""}`, state: lowFlow ? "LOW" : "OK", tone: lowFlow ? "red" : "blue" },
    { name: "COOLANT_TEMP", addr: "HR3", value: `${t.coolant_temp}°C`, state: hotTemp ? "HIGH" : "OK", tone: hotTemp ? "amber" : "blue" },
    { name: "DAMAGE", addr: "HR4", value: `${t.damage}%`, state: t.damage > 0 ? "▲" : "—", tone: t.damage > 0 ? "red" : "neutral" },
    { name: "SAFETY_INTERLOCK", addr: "coil0", value: t.interlock ? "ON" : "OFF", state: t.interlock ? "ARMED" : "BYPASS", tone: t.interlock ? "blue" : "red" },
  ];
}

/** EXECUTE STRIKE — 실 트윈 훈련 엔드포인트 구동(발전소: 안전 오버라이드 → SIS OFF, PP-005 objective). */
export async function executeStrike(sector: string): Promise<boolean> {
  if (sector !== "power") return false; // 수직 슬라이스: 발전소만 라이브 구동
  try {
    const r = await fetch(`${POWER_TWIN_URL}/api/safety/override`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ override: true }),
      signal: withTimeout(2500),
    });
    return r.ok;
  } catch {
    return false;
  }
}

export interface StreamEvent {
  topic: string;
  event_type?: string;
  target_asset?: string;
  phase?: string;
  vuln_id?: string;
  actor?: string;
  metadata?: Record<string, unknown>;
}

/** event_collector /stream SSE 구독. 실패 시 onStatus('mock'). cleanup 반환. */
export function subscribeStream(onEvent: (e: StreamEvent) => void, onStatus: (s: ConnStatus) => void): () => void {
  if (typeof EventSource === "undefined") {
    onStatus("mock");
    return () => {};
  }
  let es: EventSource | null = null;
  let closed = false;
  const topics = "events,scores,safety,phase_clock";
  try {
    es = new EventSource(`${COLLECTOR_URL}/stream?topics=${topics}`);
    const handle = (topic: string) => (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data);
        onEvent({ topic, ...data });
      } catch {
        /* keepalive/control frame */
      }
    };
    es.onopen = () => !closed && onStatus("live");
    es.onerror = () => {
      if (closed) return;
      onStatus("mock");
      es?.close();
    };
    for (const t of ["events", "scores", "safety", "phase_clock"]) es.addEventListener(t, handle(t));
    es.onmessage = handle("events");
  } catch {
    onStatus("mock");
  }
  return () => {
    closed = true;
    es?.close();
  };
}
