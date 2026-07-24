import { fetchPatches, usePolling } from "../../api/client";

const ASSET_LABEL: Record<string, string> = {
  ground_station: "위성 지상국",
  power_plant: "발전소",
  defense_network: "국방망",
};

export function PatchMatrix() {
  const { data: patches } = usePolling(fetchPatches, 5000);

  if (!patches) {
    return <div className="p-4 font-mono text-sm text-[#6B7A99]">패치 상태 로딩 중...</div>;
  }

  const assets = Object.keys(patches);
  if (assets.length === 0) {
    return (
      <div className="p-4 font-mono text-sm text-[#6B7A99]">
        아직 패치 데이터 없음 — Config Service에 취약점 상태가 등록되면 표시됩니다.
      </div>
    );
  }

  return (
    <div className="p-3">
      <div className="text-[11px] uppercase tracking-widest text-[#6B7A99] mb-2">Patch Status</div>
      <div className="flex flex-col gap-3">
        {assets.map((asset) => (
          <div key={asset}>
            <div className="font-mono text-[11px] text-[#E8EDF5] mb-1">{ASSET_LABEL[asset] ?? asset}</div>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(patches[asset]).map(([vulnId, isPatched]) => (
                <div
                  key={vulnId}
                  className={`px-2 py-1 rounded text-[10px] font-mono border ${
                    isPatched
                      ? "border-[#34D399]/50 text-[#34D399] bg-[#34D399]/10"
                      : "border-[#FF4D4D]/50 text-[#FF4D4D] bg-[#FF4D4D]/10"
                  }`}
                  title={isPatched ? "patched" : "vulnerable"}
                >
                  {vulnId}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
