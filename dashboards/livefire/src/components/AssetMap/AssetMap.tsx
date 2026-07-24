import { useRangeStore } from "../../store/rangeStore";
import type { AssetState } from "../../api/types";
import { ASSETS } from "../../api/types";

const ASSET_LABEL: Record<string, string> = {
  ground_station: "위성 지상국",
  power_plant: "발전소 · SCADA",
  defense_network: "국방망",
};

const ASSET_POS: Record<string, { x: number; y: number }> = {
  ground_station: { x: 120, y: 80 },
  power_plant: { x: 340, y: 80 },
  defense_network: { x: 230, y: 220 },
};
const DMZ_POS = { x: 230, y: 20 };

const STATE_COLOR: Record<AssetState, string> = {
  secure: "#22D3EE",
  under_attack: "#F5A623",
  compromised: "#FF4D4D",
  recovered: "#34D399",
};

function StateIcon({ state }: { state: AssetState }) {
  // 색만으로 구분하지 않도록 상태별 아이콘 병행(접근성)
  switch (state) {
    case "secure":
      return <path d="M0,-10 L8,-6 L8,4 Q8,10 0,12 Q-8,10 -8,4 L-8,-6 Z" fill="none" stroke="#22D3EE" strokeWidth="1.5" />;
    case "under_attack":
      return <path d="M0,-10 L3,2 L9,2 L0,12 L-3,2 L-9,2 Z" fill="#F5A623" opacity="0.9" />;
    case "compromised":
      return (
        <g stroke="#FF4D4D" strokeWidth="2.5" strokeLinecap="round">
          <line x1="-7" y1="-7" x2="7" y2="7" />
          <line x1="7" y1="-7" x2="-7" y2="7" />
        </g>
      );
    case "recovered":
      return <path d="M-7,0 L-2,6 L8,-8" fill="none" stroke="#34D399" strokeWidth="2.5" strokeLinecap="round" />;
  }
}

function AssetNode({ asset, state, onClick }: { asset: string; state: AssetState; onClick: () => void }) {
  const pos = ASSET_POS[asset];
  const color = STATE_COLOR[state];
  const pulsing = state === "under_attack" || state === "compromised";

  return (
    <g transform={`translate(${pos.x}, ${pos.y})`} onClick={onClick} className="cursor-pointer">
      {pulsing && (
        <circle r="28" fill={color} opacity="0.15">
          <animate attributeName="r" values="24;34;24" dur="1.6s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.25;0.05;0.25" dur="1.6s" repeatCount="indefinite" />
        </circle>
      )}
      <circle r="24" fill="#111725" stroke={color} strokeWidth="2" />
      <StateIcon state={state} />
      <text y="42" textAnchor="middle" className="fill-[#E8EDF5] text-[11px] font-mono">
        {ASSET_LABEL[asset] ?? asset}
      </text>
      <text y="55" textAnchor="middle" className="fill-[#6B7A99] text-[9px] font-mono uppercase tracking-wider">
        {state}
      </text>
    </g>
  );
}

export function AssetMap({ onSelectAsset }: { onSelectAsset: (asset: string) => void }) {
  const assetStates = useRangeStore((s) => s.assetStates);

  return (
    <svg viewBox="0 0 460 280" className="w-full h-full">
      {/* DMZ -> 각 자산 연결선 */}
      {ASSETS.map((asset) => {
        const pos = ASSET_POS[asset];
        const state = assetStates[asset] ?? "secure";
        const active = state === "under_attack" || state === "compromised";
        return (
          <line
            key={`link-${asset}`}
            x1={DMZ_POS.x} y1={DMZ_POS.y} x2={pos.x} y2={pos.y}
            stroke={active ? STATE_COLOR[state] : "#1E2A3F"}
            strokeWidth={active ? 2 : 1}
            strokeDasharray={active ? "4 3" : undefined}
          >
            {active && (
              <animate attributeName="stroke-dashoffset" values="14;0" dur="0.6s" repeatCount="indefinite" />
            )}
          </line>
        );
      })}

      {/* DMZ 노드 */}
      <g transform={`translate(${DMZ_POS.x}, ${DMZ_POS.y})`}>
        <rect x="-30" y="-10" width="60" height="20" rx="3" fill="#111725" stroke="#1E2A3F" strokeWidth="1.5" />
        <text y="4" textAnchor="middle" className="fill-[#6B7A99] text-[10px] font-mono tracking-widest">DMZ</text>
      </g>

      {ASSETS.map((asset) => (
        <AssetNode
          key={asset}
          asset={asset}
          state={assetStates[asset] ?? "secure"}
          onClick={() => onSelectAsset(asset)}
        />
      ))}
    </svg>
  );
}
