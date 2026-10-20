import type { IconKind } from "../types";

// 드로운 SVG 아이콘(이모지 금지). 단일 stroke/weight.
const PATHS: Record<IconKind, string> = {
  power: "M13 2 4 14h7l-1 8 9-12h-7z",
  nuclear: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6ZM12 2v4M12 18v4M2 12h4M18 12h4M5 5l3 3M16 16l3 3M19 5l-3 3M8 16l-3 3",
  water: "M12 3c4 5 6 8 6 11a6 6 0 0 1-12 0c0-3 2-6 6-11z",
  lng: "M5 3h14v18H5zM9 21v-4h6v4",
  railway: "M4 5h16v11H4zM4 16l-1 4M20 16l1 4M9 20h6",
  airport: "M2 12l20-7-7 20-4-9z",
  hospital: "M12 5v14M5 12h14",
  finance: "M4 20V8l8-4 8 4v12M9 20v-6h6v6",
  telecom: "M12 18v3M8 14a5.6 5.6 0 0 1 8 0M5 11a10 10 0 0 1 14 0M12 18a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z",
  satellite: "M3 11l5-5 4 4-5 5zM12 7l5-5 4 4-5 5zM9 15l-4 4M14 10a4 4 0 0 1 0 8",
  factory: "M3 21V10l5 3V10l5 3V7l6 3v11zM7 21v-4M12 21v-4M17 21v-4",
};

export function SectorIcon({ kind, className }: { kind: IconKind; className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} aria-hidden="true">
      <path d={PATHS[kind]} />
    </svg>
  );
}
