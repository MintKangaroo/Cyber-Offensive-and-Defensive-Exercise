export type BroadcastLayout = "scorebar" | "standings" | "bracket";
export type BroadcastBackground = "transparent" | "solid" | "chroma";

export interface BroadcastOptions {
  matchId: string;
  layout: BroadcastLayout;
  background: BroadcastBackground;
  maxTeams: number;
  accent: string;
}

const LAYOUTS = new Set<BroadcastLayout>(["scorebar", "standings", "bracket"]);
const BACKGROUNDS = new Set<BroadcastBackground>(["transparent", "solid", "chroma"]);
const HEX_COLOR = /^#[0-9a-f]{6}$/i;

export function parseBroadcastOptions(params: URLSearchParams): BroadcastOptions {
  const requestedLayout = params.get("layout") as BroadcastLayout | null;
  const requestedBackground = params.get("background") as BroadcastBackground | null;
  const requestedMaximum = Number.parseInt(params.get("max_teams") ?? "6", 10);
  const requestedAccent = params.get("accent") ?? "#69afff";
  return {
    matchId: (params.get("match_id") ?? "ad-demo").trim() || "ad-demo",
    layout: requestedLayout && LAYOUTS.has(requestedLayout) ? requestedLayout : "scorebar",
    background: requestedBackground && BACKGROUNDS.has(requestedBackground)
      ? requestedBackground : "transparent",
    maxTeams: Number.isFinite(requestedMaximum)
      ? Math.min(16, Math.max(2, requestedMaximum)) : 6,
    accent: HEX_COLOR.test(requestedAccent) ? requestedAccent : "#69afff",
  };
}

export function formatBroadcastCountdown(
  roundEndsAt: number | null | undefined,
  serverTime: number,
  elapsedMilliseconds: number,
): string {
  if (!roundEndsAt) return "--:--";
  const remaining = Math.max(
    0, Math.ceil(roundEndsAt - serverTime - elapsedMilliseconds / 1000),
  );
  const minutes = Math.floor(remaining / 60).toString().padStart(2, "0");
  const seconds = (remaining % 60).toString().padStart(2, "0");
  return `${minutes}:${seconds}`;
}
