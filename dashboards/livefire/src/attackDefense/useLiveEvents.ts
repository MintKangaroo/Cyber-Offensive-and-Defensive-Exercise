import { useEffect, useRef, useState } from "react";
import type { ConnectionState, LiveEvent } from "./types";
import { nextBackoff } from "./uiLogic";

const host = typeof window !== "undefined" ? window.location.hostname : "localhost";
const AD_API = import.meta.env.VITE_ATTACK_DEFENSE_API_URL ?? `http://${host}:8100`;

export function orderAndDedupe(events: LiveEvent[]): LiveEvent[] {
  const seen = new Set<string>();
  return [...events]
    .sort((a, b) => b.timestamp - a.timestamp)
    .filter((event) => {
      if (seen.has(event.event_id)) return false;
      seen.add(event.event_id);
      return true;
    });
}

export function useLiveEvents(matchId: string, token: string) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [lastReceivedAt, setLastReceivedAt] = useState(0);
  const cursor = useRef(sessionStorage.getItem(`ad-event-cursor:${matchId}`) ?? "0");

  useEffect(() => {
    let cancelled = false;
    let controller: AbortController | null = null;
    let backoff = 1000;

    async function connect() {
      if (cancelled || document.visibilityState === "hidden") return;
      controller = new AbortController();
      setConnection(backoff > 1000 ? "degraded" : "connecting");
      try {
        const response = await fetch(
          `${AD_API}/api/attack-defense/matches/${matchId}/events/stream`,
          {
            headers: {
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
              "Last-Event-ID": cursor.current,
            },
            signal: controller.signal,
          },
        );
        if (!response.ok || !response.body) throw new Error(`stream ${response.status}`);
        setConnection("live");
        backoff = 1000;
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let batch: LiveEvent[] = [];
        let flushTimer: ReturnType<typeof setTimeout> | null = null;
        const flush = () => {
          if (batch.length) {
            const incoming = batch;
            batch = [];
            setEvents((current) => orderAndDedupe([...incoming, ...current]).slice(0, 500));
          }
          flushTimer = null;
        };
        while (!cancelled) {
          const { value, done } = await reader.read();
          if (done) throw new Error("stream ended");
          buffer += decoder.decode(value, { stream: true });
          const frames = buffer.split("\n\n");
          buffer = frames.pop() ?? "";
          for (const frame of frames) {
            const id = frame.match(/^id:\s*(.+)$/m)?.[1];
            const data = frame.match(/^data:\s*(.+)$/m)?.[1];
            if (!data) continue;
            try {
              batch.push(JSON.parse(data) as LiveEvent);
              setLastReceivedAt(Date.now());
              if (id) {
                cursor.current = id;
                sessionStorage.setItem(`ad-event-cursor:${matchId}`, id);
              }
            } catch { /* malformed event is isolated */ }
          }
          if (!flushTimer) flushTimer = setTimeout(flush, 100);
        }
      } catch {
        if (cancelled) return;
        setConnection("degraded");
        window.setTimeout(connect, backoff);
        backoff = nextBackoff(backoff);
      }
    }
    const visibility = () => {
      if (document.visibilityState === "hidden") {
        controller?.abort();
      } else if (!cancelled) {
        connect();
      }
    };
    document.addEventListener("visibilitychange", visibility);
    connect();
    return () => {
      cancelled = true;
      controller?.abort();
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [matchId, token]);

  return { events, connection, lastReceivedAt };
}
