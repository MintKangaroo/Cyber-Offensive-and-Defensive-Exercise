import type { Session } from "./api";
export interface NavItem {
  id: string;
  label: string;
  group: string;
  icon: string;
  capability?: string;
}
export const NAV: NavItem[] = [
  { id: "overview", label: "Overview", group: "Command", icon: "overview" },
  {
    id: "live",
    label: "Live operations",
    group: "Command",
    icon: "activity",
    capability: "events",
  },
  {
    id: "twin",
    label: "Digital twin",
    group: "Command",
    icon: "network",
    capability: "digital-twin",
  },
  {
    id: "events",
    label: "Event stream",
    group: "Command",
    icon: "activity",
    capability: "events",
  },
  {
    id: "incidents",
    label: "Incidents",
    group: "Operations",
    icon: "incident",
    capability: "incidents",
  },
  {
    id: "soc",
    label: "Blue workspace",
    group: "Operations",
    icon: "shield",
    capability: "incidents",
  },
  {
    id: "siem",
    label: "SIEM",
    group: "Operations",
    icon: "search",
    capability: "soc",
  },
  {
    id: "edr",
    label: "EDR",
    group: "Operations",
    icon: "shield",
    capability: "soc",
  },
  {
    id: "detections",
    label: "Detection coverage",
    group: "Operations",
    icon: "activity",
    capability: "soc",
  },
  {
    id: "assets",
    label: "Assets",
    group: "Operations",
    icon: "server",
    capability: "digital-twin",
  },
  {
    id: "network",
    label: "Network",
    group: "Operations",
    icon: "network",
    capability: "soc",
  },
  {
    id: "scenarios",
    label: "Scenarios",
    group: "Exercise",
    icon: "flag",
    capability: "scenarios",
  },
  {
    id: "challenges",
    label: "Challenges",
    group: "Exercise",
    icon: "flag",
    capability: "challenges",
  },
  {
    id: "competition",
    label: "Attack / Defense",
    group: "Exercise",
    icon: "bolt",
    capability: "competition",
  },
  {
    id: "injects",
    label: "Injects",
    group: "Exercise",
    icon: "report",
    capability: "injects",
  },
  {
    id: "training",
    label: "Guided missions",
    group: "Exercise",
    icon: "shield",
    capability: "training",
  },
  {
    id: "replay",
    label: "Replay",
    group: "Analysis",
    icon: "replay",
    capability: "replay",
  },
  {
    id: "aar",
    label: "After action review",
    group: "Analysis",
    icon: "report",
    capability: "aar",
  },
  {
    id: "analytics",
    label: "Analytics",
    group: "Analysis",
    icon: "activity",
    capability: "aar",
  },
  {
    id: "services",
    label: "Services",
    group: "Platform",
    icon: "server",
    capability: "services",
  },
  {
    id: "observability",
    label: "Observability",
    group: "Platform",
    icon: "activity",
    capability: "services",
  },
  {
    id: "audit",
    label: "Audit log",
    group: "Platform",
    icon: "report",
    capability: "audit",
  },
  {
    id: "settings",
    label: "Configuration",
    group: "Platform",
    icon: "settings",
  },
  {
    id: "control",
    label: "Exercise control",
    group: "Instructor",
    icon: "settings",
    capability: "control",
  },
  {
    id: "studio",
    label: "Scenario Studio",
    group: "Instructor",
    icon: "flag",
    capability: "scenarios",
  },
  {
    id: "safety",
    label: "Safety controls",
    group: "Instructor",
    icon: "shield",
    capability: "control",
  },
  {
    id: "teams",
    label: "Teams",
    group: "Instructor",
    icon: "users",
    capability: "teams",
  },
  {
    id: "scoring",
    label: "Scoring",
    group: "Instructor",
    icon: "activity",
    capability: "scoring",
  },
];
export const visibleNav = (session: Session) =>
  NAV.filter(
    (item) =>
      !item.capability || session.capabilities.includes(item.capability),
  );
