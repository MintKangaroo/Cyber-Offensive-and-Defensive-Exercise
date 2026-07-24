import { useState } from "react";
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
  defense_network: "국방망",
};

function StatusDot({ status, isolated }: { status: Host["status"]; isolated?: boolean }) {
  const color = isolated ? "bg-[#FF3B3B]" : status === "online" ? "bg-[#3DDC84]" : "bg-[#5B6570]";
  const pulse = isolated || status === "online" ? "animate-pulse" : "";
  return <span className={`inline-block w-2 h-2 rounded-full ${color} ${pulse}`} />;
}

export function HostList({ hosts, selectedAsset, onSelectAsset, onActionDone }: Props) {
  const [pendingAsset, setPendingAsset] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  async function confirmIsolate(asset: string, target: boolean) {
    setBusy(true);
    try {
      if (target) await isolateHost(asset, reason || "manual isolation from EDR console");
      else await unisolateHost(asset, reason || "manual release from EDR console");
      onActionDone();
    } catch (e) {
      alert(`요청 실패: ${e}`);
    } finally {
      setBusy(false);
      setPendingAsset(null);
      setReason("");
    }
  }

  return (
    <div className="flex flex-col gap-1">
      <div className="text-[11px] uppercase tracking-widest text-[#5B6570] px-3 pt-2 pb-1">
        Hosts
      </div>
      {hosts.map((h) => (
        <div key={h.asset}>
          <button
            onClick={() => onSelectAsset(h.asset)}
            className={`w-full text-left px-3 py-2 flex items-center gap-2 border-l-2 transition-colors
              ${
                selectedAsset === h.asset
                  ? "bg-[#141B22] border-[#3DA9FC]"
                  : "border-transparent hover:bg-[#10151A]"
              }`}
          >
            <StatusDot status={h.status} isolated={h.isolated} />
            <div className="flex-1 min-w-0">
              <div className="font-mono text-sm text-[#D9E1E8] truncate">
                {ASSET_LABEL[h.asset] ?? h.asset}
              </div>
              <div className="font-mono text-[10px] text-[#5B6570]">
                {h.asset} · {h.process_count}procs
              </div>
            </div>
            {h.isolated && (
              <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-[#3A1414] text-[#FF3B3B] border border-[#5A2323]">
                isolated
              </span>
            )}
          </button>

          {selectedAsset === h.asset && (
            <div className="px-3 pb-2">
              {pendingAsset === h.asset ? (
                <div className="flex flex-col gap-1.5 bg-[#0F1419] border border-[#242E38] rounded p-2">
                  <input
                    autoFocus
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="사유 입력 (감사 로그에 기록됨)"
                    className="bg-[#131920] border border-[#242E38] rounded px-2 py-1 text-xs text-[#D9E1E8] font-mono focus:outline-none focus:border-[#3DA9FC]"
                  />
                  <div className="flex gap-1.5">
                    <button
                      disabled={busy || !reason.trim()}
                      onClick={() => confirmIsolate(h.asset, !h.isolated)}
                      className="flex-1 text-xs py-1 rounded bg-[#FF3B3B] text-white disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[#E02F2F]"
                    >
                      {h.isolated ? "격리 해제 확인" : "격리 확인"}
                    </button>
                    <button
                      onClick={() => setPendingAsset(null)}
                      className="text-xs py-1 px-2 rounded border border-[#242E38] text-[#9FB0C0] hover:bg-[#141B22]"
                    >
                      취소
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setPendingAsset(h.asset)}
                  className={`w-full text-xs py-1 rounded border transition-colors ${
                    h.isolated
                      ? "border-[#2A3D2E] text-[#3DDC84] hover:bg-[#12201A]"
                      : "border-[#3A2323] text-[#FF8A3D] hover:bg-[#201414]"
                  }`}
                >
                  {h.isolated ? "격리 해제 (Unisolate)" : "호스트 격리 (Isolate)"}
                </button>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
