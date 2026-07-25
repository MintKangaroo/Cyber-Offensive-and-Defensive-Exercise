import { useEffect, useRef, useState, useCallback } from "react";
import type { NormalizedEvent, Alert, SourceHealthEntry, Stats, AttackCoverage } from "./types";

// 백엔드 호스트는 페이지를 로드한 호스트를 따른다(WSL IP·Tailscale·localhost 모두 대응).
const H = typeof window !== "undefined" ? window.location.hostname : "localhost";
const SIEM_API = import.meta.env.VITE_SIEM_API_URL ?? `http://${H}:8040`;
// same-origin 상대경로(/api/…, 프로덕션 gateway) 대응 ws(s) URL 빌더.
const _ws = (path: string) => SIEM_API.startsWith("/")
  ? `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${SIEM_API}${path}`
  : SIEM_API.replace(/^http/, "ws") + path;
const WS_ALERTS_URL = _ws("/ws/alerts");
const WS_LOGS_URL = _ws("/ws/logs");

async function j<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

export interface SearchParams {
  text?: string;
  source_type?: string;
  asset?: string;
  severity_min?: number;
  mitre?: string;
  limit?: number;
  offset?: number;
}

export async function search(params: SearchParams): Promise<{ total: number; returned: number; events: NormalizedEvent[] }> {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  });
  return j(`${SIEM_API}/search?${qs.toString()}`);
}

export async function fetchAlerts(status?: string, severityMin?: number): Promise<{ alerts: Alert[] }> {
  const qs = new URLSearchParams();
  if (status) qs.set("status", status);
  if (severityMin !== undefined) qs.set("severity_min", String(severityMin));
  return j(`${SIEM_API}/alerts?${qs.toString()}`);
}

export async function updateAlertStatus(alertId: string, status: string): Promise<void> {
  await fetch(`${SIEM_API}/alerts/${alertId}?status=${status}`, { method: "POST" });
}

export async function fetchStats(): Promise<Stats> {
  return j(`${SIEM_API}/stats`);
}

export async function fetchSourceHealth(): Promise<{ sources: Record<string, SourceHealthEntry> }> {
  return j(`${SIEM_API}/sources/health`);
}

export async function fetchAttackCoverage(): Promise<AttackCoverage> {
  return j(`${SIEM_API}/detection/attack-coverage`);
}

function useWs<T>(url: string, onMessage: (msg: T) => void) {
  const cbRef = useRef(onMessage);
  cbRef.current = onMessage;
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let cancelled = false;
    let delay = 1000;
    let timer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (cancelled) return;
      ws = new WebSocket(url);
      ws.onopen = () => {
        setConnected(true);
        delay = 1000;
      };
      ws.onmessage = (evt) => {
        try {
          cbRef.current(JSON.parse(evt.data) as T);
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
  }, [url]);

  return { connected };
}

export function useLogStream(onLog: (payload: { type: string; event: NormalizedEvent }) => void) {
  return useWs(WS_LOGS_URL, onLog);
}

export function useAlertStream(onAlert: (payload: { type: string } & Partial<Alert>) => void) {
  return useWs(WS_ALERTS_URL, onAlert);
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
