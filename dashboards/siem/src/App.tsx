import { useState } from "react";
import { useAlertStream } from "./api/client";
import { Discover } from "./components/Discover/Discover";
import { AlertsView } from "./components/Alerts/AlertsView";
import { SourceHealth } from "./components/SourceHealth/SourceHealth";
import { AttackCoverageView } from "./components/AttackCoverage/AttackCoverageView";

type Tab = "discover" | "alerts" | "coverage";

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
    <div className="h-screen w-screen bg-[#0A1119] text-[#C7D0DA] flex flex-col font-sans">
      <header className="h-11 border-b border-[#22303F] flex items-center px-4 gap-3 shrink-0">
        <span className="font-mono text-sm tracking-wider text-[#C7D0DA]">SIEM</span>
        <span className="text-[10px] uppercase tracking-widest text-[#5C6B7A] px-2 py-0.5 rounded border border-[#22303F]">
          training environment
        </span>
        <nav className="flex gap-1 ml-4">
          {(["discover", "alerts", "coverage"] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`text-[11px] font-mono uppercase tracking-wider px-2.5 py-1 rounded ${
                tab === t ? "bg-[#5FA8D3]/15 text-[#5FA8D3]" : "text-[#5C6B7A] hover:text-[#8A99AB]"
              }`}
            >
              {t}
            </button>
          ))}
        </nav>
        <div className="flex-1" />
        <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#5C6B7A]">
          <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-[#3FBF7F]" : "bg-[#5C6B7A]"}`} />
          {connected ? "live" : "reconnecting…"}
        </div>
      </header>

      {alertBanner && (
        <div className="bg-[#D64545]/15 border-b border-[#D64545]/40 text-[#D64545] font-mono text-xs px-4 py-1.5">
          🔺 신규 탐지: {alertBanner}
        </div>
      )}

      <div className="flex-1 flex min-h-0">
        <main className="flex-1 min-w-0 border-r border-[#22303F]">
          {tab === "discover" && <Discover />}
          {tab === "alerts" && <AlertsView />}
          {tab === "coverage" && <AttackCoverageView />}
        </main>

        <aside className="w-72 overflow-y-auto shrink-0">
          <SourceHealth />
        </aside>
      </div>
    </div>
  );
}
