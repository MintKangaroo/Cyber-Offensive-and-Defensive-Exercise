/**
 * Blue portal presentation helpers, mapped onto shared design-system tones.
 * Pure + unit-tested; labels and classification are preserved from the original.
 */
import type { Tone } from "@cyber-range/command-system";

/** easy→healthy · medium→warning · hard→critical · insane→intelligence. */
export function difficultyTone(difficulty: string): Tone {
  switch (difficulty) {
    case "easy":
      return "healthy";
    case "medium":
      return "warning";
    case "hard":
      return "critical";
    case "insane":
      return "intelligence";
    default:
      return "neutral";
  }
}

/** Red/attack events → critical, blue/defensive events → healthy, otherwise neutral. */
export function eventTone(eventType: string): Tone {
  if (/compromis|attack|exfil|objective_success/.test(eventType)) return "critical";
  if (/blue_|recover|patch|detection|block/.test(eventType)) return "healthy";
  return "neutral";
}

/** Whether an event counts as an active incident (attack in progress). */
export function isActiveIncident(eventType: string): boolean {
  return /compromis|attack|exfil/.test(eventType);
}

export const EV_LABEL: Record<string, string> = {
  red_attack_started: "공격 개시",
  asset_compromised: "자산 침해",
  red_objective_success: "목표 달성",
  flag_exfiltrated: "플래그 유출",
  blue_detection_success: "탐지 성공",
  blue_patch_verified: "패치 검증",
  blue_block_success: "차단 성공",
  asset_recovered: "복구 완료",
  stage_completed: "단계 완료",
};

export function eventLabel(eventType: string): string {
  return EV_LABEL[eventType] ?? eventType;
}
