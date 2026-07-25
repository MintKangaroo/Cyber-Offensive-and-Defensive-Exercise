import { useEffect, useRef, useState, useCallback } from "react";
import type {
  RangeEvent, ScoresResponse, Achievement, AllPatches, AuditEntry,
} from "./types";

// 백엔드 호스트는 "페이지를 로드한 호스트"를 따른다. WSL2/원격에서 대시보드를 WSL IP로 열면
// 브라우저의 localhost는 클라이언트 PC(Windows)를 가리켜 백엔드에 못 붙는다("reconnecting…").
// window.location.hostname을 쓰면 localhost 접속이든 WSL IP 접속이든 같은 호스트의 백엔드로 붙는다.
// (VITE_*_URL 환경변수로 명시 지정하면 그게 우선.)
const H = typeof window !== "undefined" ? window.location.hostname : "localhost";
const EVENT_COLLECTOR = import.meta.env.VITE_EVENT_COLLECTOR_URL ?? `http://${H}:8010`;
const SCORING_ENGINE = import.meta.env.VITE_SCORING_ENGINE_URL ?? `http://${H}:8020`;
const CONFIG_SERVICE = import.meta.env.VITE_CONFIG_SERVICE_URL ?? `http://${H}:8030`;
const INSTRUCTOR_API = import.meta.env.VITE_INSTRUCTOR_API_URL ?? `http://${H}:8050`;
// same-origin 상대경로(/api/…, 프로덕션 gateway)면 window.location에서 ws(s) 절대 URL 구성.
const WS_URL = EVENT_COLLECTOR.startsWith("/")
  ? `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${EVENT_COLLECTOR}/ws`
  : EVENT_COLLECTOR.replace(/^http/, "ws") + "/ws";

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text().catch(() => "")}`);
  return r.json();
}

export async function fetchScores(scenarioId = "default"): Promise<ScoresResponse> {
  return j(`${SCORING_ENGINE}/scores?scenario_id=${encodeURIComponent(scenarioId)}`);
}

export async function fetchScoreHistory(scenarioId = "default"): Promise<{ achievements: Achievement[] }> {
  return j(`${SCORING_ENGINE}/scores/history?scenario_id=${encodeURIComponent(scenarioId)}`);
}

export async function fetchPatches(): Promise<AllPatches> {
  return j(`${CONFIG_SERVICE}/config/patches`);
}

export async function fetchReplayEvents(scenarioId: string): Promise<{ events: RangeEvent[] }> {
  return j(`${EVENT_COLLECTOR}/replay/events?scenario_id=${encodeURIComponent(scenarioId)}`);
}

export async function fetchRecentEvents(limit = 200): Promise<{ events: RangeEvent[] }> {
  return j(`${EVENT_COLLECTOR}/events?limit=${limit}`);
}

/** 관전자용 지연 이벤트(P3) — delaySec 만큼 지난 이벤트만. 실시간 정보 누출 방지. */
export async function fetchDelayedEvents(delaySec = 30, limit = 200): Promise<{ events: RangeEvent[] }> {
  return j(`${EVENT_COLLECTOR}/events/delayed?delay_sec=${delaySec}&limit=${limit}`);
}

// ---- Instructor 액션(전부 사유 필수, 백엔드가 400으로 강제) ----
export async function scenarioStart(scenarioId: string, teamIds: string[], reason: string, token: string) {
  return j(`${INSTRUCTOR_API}/instructor/scenario/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ scenario_id: scenarioId, team_ids: teamIds, reason }),
  });
}

export async function scenarioEnd(scenarioId: string, reason: string, token: string) {
  return j(`${INSTRUCTOR_API}/instructor/scenario/end`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ scenario_id: scenarioId, reason }),
  });
}

export async function scoreAdjust(
  teamId: string, actor: "red" | "blue", delta: number, reason: string, token: string
) {
  return j(`${INSTRUCTOR_API}/instructor/score/adjust`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ team_id: teamId, actor, delta, reason }),
  });
}

export async function eventInject(
  eventType: string, targetAsset: string, teamId: string, reason: string, token: string
) {
  return j(`${INSTRUCTOR_API}/instructor/event/inject`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ event_type: eventType, target_asset: targetAsset, team_id: teamId, reason }),
  });
}

export async function fetchAudit(): Promise<{ entries: AuditEntry[] }> {
  return j(`${INSTRUCTOR_API}/instructor/audit`);
}

/** 실시간 이벤트 스트림. 지수 백오프 재연결. */
export function useEventStream(onEvent: (e: RangeEvent) => void) {
  const cbRef = useRef(onEvent);
  cbRef.current = onEvent;
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let cancelled = false;
    let delay = 1000;
    let timer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (cancelled) return;
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        setConnected(true);
        delay = 1000;
      };
      ws.onmessage = (evt) => {
        try {
          cbRef.current(JSON.parse(evt.data) as RangeEvent);
        } catch {
          /* 파싱 실패 무시 */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!cancelled) {
          timer = setTimeout(connect, delay);
          delay = Math.min(delay * 2, 15000);
        }
      };
      ws.onerror = () => ws?.close();
    }
    connect();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, []);

  return { connected };
}

export function usePolling<T>(fn: () => Promise<T>, intervalMs: number, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const reload = useCallback(() => {
    fnRef.current().then(setData).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    reload();
    const id = setInterval(reload, intervalMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps]);

  return { data, error, reload };
}
