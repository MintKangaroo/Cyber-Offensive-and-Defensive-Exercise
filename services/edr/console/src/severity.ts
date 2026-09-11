/**
 * EDR detection severity, mapped onto shared design-system tones.
 * The five string levels are preserved exactly; only the color moves onto the
 * command palette so five levels stay distinguishable. Pure + unit-tested.
 */
import type { Tone } from "@cyber-range/command-system";
import type { Severity } from "./api/types";

/** critical→critical · high→warning · medium→intelligence · low→operational · info→neutral. */
export function severityTone(severity: Severity): Tone {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "warning";
    case "medium":
      return "intelligence";
    case "low":
      return "operational";
    default:
      return "neutral";
  }
}

/** Korean relative time shared across detection cards. */
export function relativeTime(secondsAgo: number): string {
  const s = Math.max(0, secondsAgo);
  if (s < 60) return `${Math.floor(s)}초 전`;
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  return `${Math.floor(s / 3600)}시간 전`;
}
