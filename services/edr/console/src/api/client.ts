import { useEffect, useRef, useState, useCallback } from "react";
import type { Host, ProcessNode, Alert, KillCommand, AuditEntry, WsAlertMessage } from "./types";

// 백엔드 호스트는 페이지를 로드한 호스트를 따른다(WSL IP·Tailscale·localhost 모두 대응).
// EDR 백엔드 포트는 override로 리맵될 수 있어 포트만 VITE_EDR_BACKEND_PORT로 조정 가능(기본 8080).
const H = typeof window !== "undefined" ? window.location.hostname : "localhost";
const EDR_PORT = import.meta.env.VITE_EDR_BACKEND_PORT ?? "8080";
const EDR_BASE = import.meta.env.VITE_EDR_BACKEND_URL ?? `http://${H}:${EDR_PORT}`;
const CONFIG_BASE = import.meta.env.VITE_CONFIG_SERVICE_URL ?? `http://${H}:8030`;
const WS_URL = EDR_BASE.replace(/^http/, "ws") + "/edr/ws";

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`${r.status} ${r.statusText}: ${body}`);
  }
  return r.json();
}

export async function fetchHosts(): Promise<Host[]> {
  const [{ hosts }, quarantine] = await Promise.all([
    j<{ hosts: Host[] }>(`${EDR_BASE}/edr/hosts`),
    j<Record<string, boolean>>(`${CONFIG_BASE}/config/quarantine`),
  ]);
  return hosts.map((h) => ({ ...h, isolated: !!quarantine[h.asset] }));
}

export async function fetchProcessTree(asset: string): Promise<ProcessNode[]> {
  const { process_tree } = await j<{ process_tree: ProcessNode[] }>(
    `${EDR_BASE}/edr/hosts/${asset}/processes`
  );
  return process_tree;
}

export async function fetchAlerts(asset?: string): Promise<Alert[]> {
  const qs = asset ? `?asset=${encodeURIComponent(asset)}` : "";
  const { alerts } = await j<{ alerts: Alert[] }>(`${EDR_BASE}/edr/alerts${qs}`);
  return alerts;
}

export async function fetchAudit(): Promise<AuditEntry[]> {
  const { entries } = await j<{ entries: AuditEntry[] }>(`${EDR_BASE}/edr/audit`);
  return entries;
}

export async function isolateHost(asset: string, reason: string): Promise<void> {
  await j(`${EDR_BASE}/edr/hosts/${asset}/isolate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
}

export async function unisolateHost(asset: string, reason: string): Promise<void> {
  await j(`${EDR_BASE}/edr/hosts/${asset}/unisolate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
}

export async function killProcess(
  asset: string,
  pid: number,
  reason: string
): Promise<{ command_id: string; warning: string | null }> {
  return j(`${EDR_BASE}/edr/hosts/${asset}/process/${pid}/kill`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
}

export async function fetchKillCommands(asset: string): Promise<KillCommand[]> {
  const { commands } = await j<{ commands: KillCommand[] }>(
    `${EDR_BASE}/edr/hosts/${asset}/kill-commands`
  );
  return commands;
}

/** 실시간 알림 스트림. 연결이 끊기면 지수 백오프로 재연결한다. */
export function useEdrAlertStream(onAlert: (msg: WsAlertMessage) => void) {
  const onAlertRef = useRef(onAlert);
  onAlertRef.current = onAlert;
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retryDelay = 1000;
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    function connect() {
      if (cancelled) return;
      ws = new WebSocket(WS_URL);
      ws.onopen = () => {
        setConnected(true);
        retryDelay = 1000;
      };
      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg?.type === "alert") onAlertRef.current(msg as WsAlertMessage);
        } catch {
          /* 파싱 실패 메시지는 무시 */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!cancelled) {
          retryTimer = setTimeout(connect, retryDelay);
          retryDelay = Math.min(retryDelay * 2, 15000);
        }
      };
      ws.onerror = () => ws?.close();
    }

    connect();
    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
      ws?.close();
    };
  }, []);

  return { connected };
}

/** N초마다 폴링하는 범용 훅(호스트 목록/프로세스 트리 등). */
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
