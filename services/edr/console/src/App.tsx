import { useMemo, useState } from "react";
import { EmptyState, StatusBadge } from "@cyber-range/command-system";
import { HostList } from "./components/HostList";
import { ProcessTree } from "./components/ProcessTree";
import { AlertsPanel } from "./components/AlertsPanel";
import {
  fetchHosts,
  fetchProcessTree,
  fetchAlerts,
  usePolling,
  useEdrAlertStream,
} from "./api/client";
import type { Alert } from "./api/types";

export default function App() {
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([]);

  const { data: hosts, reload: reloadHosts } = usePolling(fetchHosts, 5000);
  const { data: tree, reload: reloadTree } = usePolling(
    () => (selectedAsset ? fetchProcessTree(selectedAsset) : Promise.resolve([])),
    5000,
    [selectedAsset],
  );
  const { data: alerts, reload: reloadAlerts } = usePolling(
    () => fetchAlerts(selectedAsset ?? undefined),
    5000,
    [selectedAsset],
  );

  const { connected } = useEdrAlertStream((msg) => {
    setLiveAlerts((prev) =>
      [
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
      ].slice(0, 50),
    );
  });

  const mergedAlerts = useMemo(() => {
    const base = alerts ?? [];
    const seen = new Set(base.map((a) => a.id));
    const extra = liveAlerts.filter(
      (a) => !seen.has(a.id) && (!selectedAsset || a.asset === selectedAsset),
    );
    return [...extra, ...base];
  }, [alerts, liveAlerts, selectedAsset]);

  const flaggedPids = useMemo(
    () =>
      new Set(
        mergedAlerts.filter((a) => a.asset === selectedAsset).map((a) => a.pid),
      ),
    [mergedAlerts, selectedAsset],
  );
  const alertsByPid = useMemo(() => {
    const m = new Map<number, Alert[]>();
    for (const a of mergedAlerts) {
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
    <div className="edr-shell">
      <header className="edr-header">
        <span className="edr-title">EDR CONSOLE</span>
        <span className="edr-pill">training environment</span>
        <div className="edr-live">
          <StatusBadge tone={connected ? "healthy" : "neutral"}>
            {connected ? "live" : "reconnecting…"}
          </StatusBadge>
        </div>
      </header>

      <div className="edr-body">
        <aside className="edr-pane-hosts">
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

        <main className="edr-pane-main">
          <div className="edr-pane-heading">
            Process Explorer{selectedAsset ? ` — ${selectedAsset}` : ""}
          </div>
          <div className="edr-scroll">
            {selectedAsset ? (
              <ProcessTree
                tree={tree ?? []}
                flaggedPids={flaggedPids}
                alertsByPid={alertsByPid}
                onSelectPid={setSelectedPid}
                selectedPid={selectedPid}
              />
            ) : (
              <EmptyState
                title="호스트를 선택하세요"
                detail="왼쪽에서 호스트를 선택하면 프로세스 트리가 표시됩니다."
              />
            )}
          </div>
        </main>

        <aside className="edr-pane-alerts">
          <div className="edr-pane-heading">Detections</div>
          <AlertsPanel alerts={mergedAlerts} onKillDone={handleActionDone} />
        </aside>
      </div>
    </div>
  );
}
