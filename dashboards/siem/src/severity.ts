/**
 * Detection semantics preserved from the original SIEM console.
 * Numeric severity 0–4 keeps its labels and thresholds exactly; only the colors
 * move onto the shared design-system tones so the workspace matches the command
 * palette. Pure functions so the mapping is unit-tested.
 */
import type { Tone } from "@cyber-range/command-system";
import { SEVERITY_LABEL } from "./api/types";

export { SEVERITY_LABEL };

/** 0 INFO → neutral · 1 LOW → operational · 2 MEDIUM → intelligence · 3 HIGH → warning · 4 CRITICAL → critical. */
export function severityTone(severity: number): Tone {
  switch (severity) {
    case 4:
      return "critical";
    case 3:
      return "warning";
    case 2:
      return "intelligence";
    case 1:
      return "operational";
    default:
      return "neutral";
  }
}

export function severityLabel(severity: number): string {
  return SEVERITY_LABEL[severity] ?? String(severity);
}

/** Korean relative time used by both detections and source health. */
export function relativeTime(secondsAgo: number): string {
  const s = Math.max(0, secondsAgo);
  if (s < 60) return `${Math.floor(s)}초 전`;
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  return `${Math.floor(s / 3600)}시간 전`;
}

/** Alert.mitre arrives as a JSON string; parse defensively to a string array. */
export function parseMitre(raw: string): string[] {
  try {
    const value: unknown = JSON.parse(raw);
    return Array.isArray(value) ? (value as string[]) : [];
  } catch {
    return [];
  }
}
