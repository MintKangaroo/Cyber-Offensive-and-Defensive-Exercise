import { useState } from "react";
import { StatusBadge } from "@cyber-range/command-system";
import { useAlertStream } from "./api/client";
import { Discover } from "./components/Discover/Discover";
import { AlertsView } from "./components/Alerts/AlertsView";
import { SourceHealth } from "./components/SourceHealth/SourceHealth";
import { AttackCoverageView } from "./components/AttackCoverage/AttackCoverageView";

type Tab = "discover" | "alerts" | "coverage";
const TABS: { id: Tab; label: string }[] = [
  { id: "discover", label: "Discover" },
  { id: "alerts", label: "Alerts" },
  { id: "coverage", label: "Coverage" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("discover");
  const [alertBanner, setAlertBanner] = useState<string | null>(null);

  const { connected } = useAlertStream((msg) => {
    if (msg.type === "alert") {
      setAlertBanner(`${msg.title ?? ""} (${msg.rule_id ?? ""})`);
      setTimeout(() => setAlertBanner(null), 4000);
    }
  });

  return (
    <div className="siem-shell">
      <header className="siem-header">
        <span className="siem-title">SIEM</span>
        <span className="siem-pill">training environment</span>
        <nav className="siem-tabs" aria-label="SIEM views">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              className="siem-tab"
              aria-current={tab === t.id ? "page" : undefined}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
        <div className="siem-live">
          <StatusBadge tone={connected ? "healthy" : "neutral"}>
            {connected ? "live" : "reconnecting…"}
          </StatusBadge>
        </div>
      </header>

      {alertBanner && (
        <div className="siem-banner" role="status">
          <span aria-hidden="true">🔺</span>
          신규 탐지: {alertBanner}
        </div>
      )}

      <div className="siem-body">
        <main className="siem-main">
          {tab === "discover" && <Discover />}
          {tab === "alerts" && <AlertsView />}
          {tab === "coverage" && <AttackCoverageView />}
        </main>
        <aside className="siem-aside">
          <SourceHealth />
        </aside>
      </div>
    </div>
  );
}
