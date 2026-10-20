// 라이브 데이터 계층.
//  - 발전소 트윈(services/power_plant) /api/telemetry 폴링 → 게이지가 실제로 움직임
//  - 발전소 트윈 공격 엔드포인트 호출(EXECUTE STRIKE) → 물리 파국 유발
//  - event_collector :8010 /stream SSE → 스트라이크/이벤트 피드
// 백엔드 미도달 시 정적 목업으로 폴백(오프라인에서도 UI 동작).
import type { AttackStep, PowerTelemetry, RegisterRow } from "./types";

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

/** 섹터별 트윈 베이스 URL. 환경변수 VITE_TWIN_<SECTOR>(예: VITE_TWIN_HOSPITAL) 로 주입.
 *  미설정이면 발전소만 기본값(POWER_TWIN_URL) — 다른 섹터는 그 트윈을 띄우고 URL 을 주면 라이브. */
function resolveTwinUrl(sector: string): string | null {
  const env = import.meta.env as unknown as Record<string, string | undefined>;
  const fromEnv = env[`VITE_TWIN_${sector.toUpperCase()}`];
  if (fromEnv) return fromEnv;
  if (sector === "power") return POWER_TWIN_URL;
  return null;
}

function toQuery(body: Record<string, unknown>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) q.set(k, String(v));
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** 킬체인 단계 실행 — step.action 과 섹터 트윈 URL 이 있으면 실제 트윈 엔드포인트를 호출(라이브).
 *  트윈 미도달 시설은 서사 진행({live:false})만 한다(정직). GET/POST 모두 지원. */
export async function executeStep(sector: string, step: AttackStep): Promise<{ ok: boolean; live: boolean }> {
  const base = resolveTwinUrl(sector);
  if (base && step.action) {
    const { method, path, body } = step.action;
    try {
      const url = method === "GET" ? `${base}${path}${toQuery(body)}` : `${base}${path}`;
      const init: RequestInit = { method, signal: withTimeout(2500) };
      if (method === "POST") {
        init.headers = { "content-type": "application/json" };
        init.body = JSON.stringify(body);
      }
      await fetch(url, init); // 응답코드와 무관하게 트윈에 도달하면 공격 시도는 라이브
      return { ok: true, live: true };
    } catch {
      return { ok: true, live: false }; // 트윈 미도달 → 서사 진행
    }
  }
  return { ok: true, live: false };
}

export interface StreamEvent {
  topic: string;
  // events 토픽
  event_type?: string;
  target_asset?: string;
  phase?: string;
  vuln_id?: string;
  metadata?: Record<string, unknown>;
  // scores 토픽(어워드 델타): {team_id, actor, category, points, timestamp}
  actor?: string;
  team_id?: string;
  category?: string;
  points?: number;
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
