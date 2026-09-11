import { useState } from "react";
import { Button, StatusBadge } from "@cyber-range/command-system";
import type { Host } from "../api/types";
import { isolateHost, unisolateHost } from "../api/client";

interface Props {
  hosts: Host[];
  selectedAsset: string | null;
  onSelectAsset: (asset: string) => void;
  onActionDone: () => void;
}

const ASSET_LABEL: Record<string, string> = {
  ground_station: "위성 지상국",
  power_plant: "발전소 / SCADA",
  defense_network: "사내망",
  refinery_plant: "정유·석유화학",
  smart_factory: "스마트팩토리",
  water_utility: "수도 시설",
  lng_terminal: "LNG 터미널",
  railway_signaling: "철도 신호",
  airport_ot: "공항 OT",
  datacenter_bms: "데이터센터",
  hospital_ot: "병원 OT",
};

/** isolated → critical, online → healthy, offline → neutral. */
function hostTone(host: Host): "critical" | "healthy" | "neutral" {
  if (host.isolated) return "critical";
  return host.status === "online" ? "healthy" : "neutral";
}

export function HostList({
  hosts,
  selectedAsset,
  onSelectAsset,
  onActionDone,
}: Props) {
  const [pendingAsset, setPendingAsset] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function confirmIsolate(asset: string, target: boolean) {
    setBusy(true);
    setError(null);
    try {
      if (target)
        await isolateHost(asset, reason || "manual isolation from EDR console");
      else await unisolateHost(asset, reason || "manual release from EDR console");
      onActionDone();
      setPendingAsset(null);
      setReason("");
    } catch (e) {
      setError(`요청 실패: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="edr-pane-heading">Hosts</div>
      {hosts.map((h) => {
        const tone = hostTone(h);
        const pulse = h.isolated || h.status === "online" ? " edr-live-dot" : "";
        return (
          <div key={h.asset}>
            <button
              type="button"
              className="edr-host"
              aria-current={selectedAsset === h.asset}
              onClick={() => onSelectAsset(h.asset)}
            >
              <span
                className={`edr-dot cr-tone-${tone}${pulse}`}
                role="img"
                aria-label={h.isolated ? "격리됨" : h.status}
              />
              <span style={{ flex: 1, minWidth: 0 }}>
                <span className="edr-host-name" style={{ display: "block" }}>
                  {ASSET_LABEL[h.asset] ?? h.asset}
                </span>
                <span className="edr-host-meta">
                  {h.asset} · {h.process_count}procs
                </span>
              </span>
              {h.isolated && <StatusBadge tone="critical">isolated</StatusBadge>}
            </button>

            {selectedAsset === h.asset && (
              <>
                {error && <div className="edr-inline-error">{error}</div>}
                {pendingAsset === h.asset ? (
                  <div className="edr-confirm">
                    <input
                      className="edr-input"
                      autoFocus
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      placeholder="사유 입력 (감사 로그에 기록됨)"
                      aria-label="격리 사유"
                    />
                    <div className="edr-row">
                      <Button
                        tone="critical"
                        style={{ flex: 1 }}
                        disabled={busy || !reason.trim()}
                        onClick={() => confirmIsolate(h.asset, !h.isolated)}
                      >
                        {h.isolated ? "격리 해제 확인" : "격리 확인"}
                      </Button>
                      <Button onClick={() => setPendingAsset(null)}>취소</Button>
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: "0 12px 8px" }}>
                    <Button
                      tone={h.isolated ? "healthy" : "warning"}
                      style={{ width: "100%" }}
                      onClick={() => {
                        setError(null);
                        setPendingAsset(h.asset);
                      }}
                    >
                      {h.isolated ? "격리 해제 (Unisolate)" : "호스트 격리 (Isolate)"}
                    </Button>
                  </div>
                )}
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
