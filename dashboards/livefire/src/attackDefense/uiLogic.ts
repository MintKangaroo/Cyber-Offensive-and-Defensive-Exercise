import type { ConnectionState, PatchRecord, ScoreboardResponse } from "./types";

export const FLAG_FORMAT = /^FLAG\{[A-Za-z0-9_-]{32}\}$/;
export const INDICATOR_HASH_FORMAT = /^[0-9a-f]{64}$/;

export function isIndicatorHash(value: string) {
  return INDICATOR_HASH_FORMAT.test(value);
}

export function parseFlagBatch(value: string, maximum = 20) {
  return value.split(/\s+/).map((item) => item.trim()).filter(Boolean).slice(0, maximum)
    .map((flag) => ({ flag, valid: FLAG_FORMAT.test(flag) }));
}

export function nextBackoff(current: number) {
  return Math.min(Math.max(1000, current) * 2, 30_000);
}

export function isConnectionDegraded(
  state: ConnectionState, lastReceivedAt: number, now = Date.now(),
) {
  return state !== "live" || (lastReceivedAt > 0 && now - lastReceivedAt > 15_000);
}

export function patchStageIndex(status: PatchRecord["status"]) {
  return ({
    uploaded: 0, validating: 3, approved: 6, deploying: 7, deployed: 8,
    rejected: 3, rollback: 7, failed: 7,
  } as Record<string, number>)[status] ?? 0;
}

export function scoreboardDisclosure(scoreboard: ScoreboardResponse) {
  const delay = scoreboard.delay_rounds ?? 0;
  return delay > 0 ? `PUBLIC SCORE — DELAYED BY ${delay} ROUNDS`
    : scoreboard.provisional ? "PROVISIONAL SCORE" : "FINALIZED SCORE";
}
