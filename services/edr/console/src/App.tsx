import { useMemo, useState } from "react";
import { HostList } from "./components/HostList";
import { ProcessTree } from "./components/ProcessTree";
import { AlertsPanel } from "./components/AlertsPanel";
import { fetchHosts, fetchProcessTree, fetchAlerts, usePolling, useEdrAlertStream } from "./api/client";
import type { Alert } from "./api/types";

export default function App() {
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([]);

  const { data: hosts, reload: reloadHosts } = usePolling(fetchHosts, 5000);
  const { data: tree, reload: reloadTree } = usePolling(
    () => (selectedAsset ? fetchProcessTree(selectedAsset) : Promise.resolve([])),
    5000,
    [selectedAsset]
  );
  const { data: alerts, reload: reloadAlerts } = usePolling(
    () => fetchAlerts(selectedAsset ?? undefined),
    5000,
    [selectedAsset]
  );

  const { connected } = useEdrAlertStream((msg) => {
    setLiveAlerts((prev) => [
      {
        id: msg.id,
        asset: msg.asset,
        rule_id: msg.rule_id,
        rule_name: msg.rule_name,
        severity: msg.severity,
        pid: msg.pid,
        cmdline: "",
        timestamp: Date.now() / 1000,
        detail: msg.detail,
      },
      ...prev,
    ].slice(0, 50));
  });

  const mergedAlerts = useMemo(() => {
    const base = alerts ?? [];
    const seen = new Set(base.map((a) => a.id));
    const extra = liveAlerts.filter((a) => !seen.has(a.id) && (!selectedAsset || a.asset === selectedAsset));
    return [...extra, ...base];
  }, [alerts, liveAlerts, selectedAsset]);

  const flaggedPids = useMemo(
    () => new Set((mergedAlerts ?? []).filter((a) => a.asset === selectedAsset).map((a) => a.pid)),
    [mergedAlerts, selectedAsset]
  );
  const alertsByPid = useMemo(() => {
    const m = new Map<number, Alert[]>();
    for (const a of mergedAlerts ?? []) {
      if (a.asset !== selectedAsset) continue;
      m.set(a.pid, [...(m.get(a.pid) ?? []), a]);
    }
    return m;
  }, [mergedAlerts, selectedAsset]);

  function handleActionDone() {
    reloadHosts();
    reloadTree();
    reloadAlerts();
  }

  return (
    <div className="h-screen w-screen bg-[#0B0F14] text-[#D9E1E8] flex flex-col font-sans">
      <header className="h-12 border-b border-[#1F2933] flex items-center px-4 gap-3 shrink-0">
        <span className="font-mono text-sm tracking-widest text-[#D9E1E8]">EDR CONSOLE</span>
        <span className="text-[10px] uppercase tracking-widest text-[#5B6570] px-2 py-0.5 rounded border border-[#242E38]">
          training environment
        </span>
        <div className="flex-1" />
        <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#5B6570]">
          <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-[#3DDC84]" : "bg-[#5B6570]"}`} />
          {connected ? "live" : "reconnecting…"}
        </div>
      </header>

      <div className="flex-1 flex min-h-0">
        <aside className="w-64 border-r border-[#1F2933] overflow-y-auto shrink-0">
          <HostList
            hosts={hosts ?? []}
            selectedAsset={selectedAsset}
            onSelectAsset={(a) => {
              setSelectedAsset(a);
              setSelectedPid(null);
            }}
            onActionDone={handleActionDone}
          />
        </aside>

        <main className="flex-1 flex flex-col min-w-0">
          <div className="h-10 border-b border-[#1F2933] flex items-center px-4 text-[11px] uppercase tracking-widest text-[#5B6570] shrink-0">
            Process Explorer{selectedAsset ? ` — ${selectedAsset}` : ""}
          </div>
          <div className="flex-1 overflow-auto">
            {selectedAsset ? (
              <ProcessTree
                tree={tree ?? []}
                flaggedPids={flaggedPids}
                alertsByPid={alertsByPid}
                onSelectPid={setSelectedPid}
                selectedPid={selectedPid}
              />
            ) : (
              <div className="p-6 font-mono text-sm text-[#5B6570]">
                왼쪽에서 호스트를 선택하면 프로세스 트리가 표시됩니다.
              </div>
            )}
          </div>
        </main>

        <aside className="w-96 border-l border-[#1F2933] overflow-y-auto shrink-0">
          <div className="h-10 border-b border-[#1F2933] flex items-center px-4 text-[11px] uppercase tracking-widest text-[#5B6570]">
            Detections
          </div>
          <AlertsPanel alerts={mergedAlerts ?? []} onKillDone={handleActionDone} />
        </aside>
      </div>
    </div>
  );
}
