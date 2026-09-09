import { useCallback, useEffect, useRef, useState } from "react";
import {
  mergeEvents,
  normalizeEvent,
  object,
  SSEParser,
  nextBackoff,
  type RangeEvent,
  type JsonObject,
} from "@cyber-range/command-system";
import {
  api,
  COMMAND_BASE,
  getAccessToken,
  parseSnapshot,
  eventsFrom,
  type Session,
  type Snapshot,
} from "./api";
export type Connection =
  | "connecting"
  | "live"
  | "reconnecting"
  | "disconnected"
  | "unauthorized"
  | "delayed";
export interface Notice {
  id: string;
  topic: string;
  payload: JsonObject;
  received: number;
}
export function useCommandData(session: Session, scenarioId: string) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<RangeEvent[]>([]);
  const [notices, setNotices] = useState<Notice[]>([]);
  const [connection, setConnection] = useState<Connection>("connecting");
  const [error, setError] = useState("");
  const [lastReceived, setLastReceived] = useState<number | null>(null);
  const [received, setReceived] = useState(0);
  const active = useRef(false);
  const generation = useRef(0);
  const loading = useRef(false);
  const refresh = useCallback(async () => {
    if (loading.current) return;
    loading.current = true;
    const requestGeneration = generation.current;
    try {
      const data = parseSnapshot(
        await api(`/snapshot?scenario_id=${encodeURIComponent(scenarioId)}`),
      );
      if (!active.current || requestGeneration !== generation.current) return;
      setSnapshot(data);
      setEvents((cur) => mergeEvents(cur, eventsFrom(data.sources.events)));
      setError("");
    } catch (e) {
      if (active.current && requestGeneration === generation.current)
        setError(e instanceof Error ? e.message : "Command source unavailable");
    } finally {
      if (requestGeneration === generation.current) loading.current = false;
    }
  }, [scenarioId]);
  useEffect(() => {
    generation.current++;
    active.current = true;
    loading.current = false;
    setSnapshot(null);
    setEvents([]);
    setNotices([]);
    setLastReceived(null);
    setReceived(0);
    void refresh();
    // Non-streamed sources and durable reconciliation. Live score/safety updates
    // invalidate only their own source, below, rather than polling every service.
    const timer = setInterval(() => void refresh(), 30000);
    return () => {
      active.current = false;
      generation.current++;
      clearInterval(timer);
    };
  }, [refresh]);
  useEffect(() => {
    if (!session.capabilities.includes("events")) {
      setConnection("disconnected");
      return;
    }
    if (session.role === "observer") {
      setConnection("delayed");
      return;
    }
    let stopped = false,
      attempt = 0,
      cursor = "",
      connectedAt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined,
      flushTimer: ReturnType<typeof setTimeout> | undefined,
      sourceTimer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | null = null;
    let batch: RangeEvent[] = [];
    let pendingNotices: Notice[] = [];
    let lastSeen = 0;
    const invalidated = new Set<string>();
    const flush = () => {
      if (stopped) return;
      if (batch.length) {
        const incoming = batch;
        batch = [];
        setEvents((cur) => mergeEvents(cur, incoming));
        setReceived((n) => n + incoming.length);
      }
      if (pendingNotices.length) {
        const incoming = pendingNotices;
        pendingNotices = [];
        setNotices((cur) =>
          [...new Map([...incoming, ...cur].map((n) => [n.id, n])).values()]
            .sort((a, b) => b.received - a.received)
            .slice(0, 200),
        );
      }
      setLastReceived(lastSeen);
      flushTimer = undefined;
    };
    const invalidate = (section: string) => {
      invalidated.add(section);
      if (sourceTimer) return;
      sourceTimer = setTimeout(async () => {
        const sections = [...invalidated].join(",");
        invalidated.clear();
        try {
          const patch = parseSnapshot(
            await api(
              `/snapshot?scenario_id=${encodeURIComponent(scenarioId)}&sections=${sections}`,
            ),
          );
          if (!stopped)
            setSnapshot((current) =>
              current
                ? {
                    ...current,
                    sources: { ...current.sources, ...patch.sources },
                    generated_at: patch.generated_at,
                  }
                : patch,
            );
        } catch {
          /* reconciliation reports source failure at its next bounded interval */
        } finally {
          sourceTimer = undefined;
        }
      }, 1000);
    };
    const connect = async () => {
      if (stopped) return;
      controller = new AbortController();
      setConnection(attempt ? "reconnecting" : "connecting");
      const token = getAccessToken();
      try {
        const response = await fetch(
          `${COMMAND_BASE}/stream?scenario_id=${encodeURIComponent(scenarioId)}`,
          {
            headers: {
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
              "Last-Event-ID": cursor,
            },
            credentials: "include",
            signal: controller.signal,
            redirect: "error",
          },
        );
        if (response.status === 401 || response.status === 403) {
          setConnection("unauthorized");
          return;
        }
        if (!response.ok || !response.body)
          throw new Error("Stream unavailable");
        setConnection("live");
        connectedAt = Date.now();
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        const parser = new SSEParser((frame) => {
          if (frame.topic === "degraded")
            throw new Error("Upstream disconnected");
          const value: unknown = JSON.parse(frame.data);
          lastSeen = Date.now();
          if (frame.id) cursor = frame.id;
          const ev = normalizeEvent(value);
          if (ev) {
            batch.push(ev);
            if (batch.length > 5000) batch.splice(0, batch.length - 5000);
          }
          if (["safety", "phase_clock", "scores"].includes(frame.topic)) {
            pendingNotices.push({
              id: `${frame.topic}:${frame.id}:${String(object(value).timestamp)}`,
              topic: frame.topic,
              payload: object(value),
              received: lastSeen,
            });
            if (pendingNotices.length > 200) pendingNotices.shift();
            invalidate(
              frame.topic === "scores"
                ? "scores"
                : frame.topic === "safety"
                  ? "safety"
                  : "scenarios",
            );
          }
          if (!flushTimer) flushTimer = setTimeout(flush, 150);
        });
        while (!stopped) {
          const { done, value } = await reader.read();
          if (done) throw new Error("Stream ended");
          try {
            parser.push(decoder.decode(value, { stream: true }));
          } catch (e) {
            if (e instanceof SyntaxError) continue;
            throw e;
          }
        }
      } catch {
        if (stopped) return;
        if (connectedAt && Date.now() - connectedAt > 10000) attempt = 0;
        flush();
        setConnection("reconnecting");
        timer = setTimeout(connect, nextBackoff(attempt++));
      }
    };
    void connect();
    return () => {
      stopped = true;
      controller?.abort();
      clearTimeout(timer);
      clearTimeout(flushTimer);
      clearTimeout(sourceTimer);
    };
  }, [scenarioId, session.role, session.capabilities]);
  return {
    snapshot,
    events,
    notices,
    connection,
    error,
    lastReceived,
    received,
    refresh,
  };
}
export type CommandData = ReturnType<typeof useCommandData>;
