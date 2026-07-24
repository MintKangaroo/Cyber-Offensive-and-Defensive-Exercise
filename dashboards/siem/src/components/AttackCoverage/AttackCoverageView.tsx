import { usePolling, fetchAttackCoverage } from "../../api/client";

export function AttackCoverageView() {
  const { data } = usePolling(fetchAttackCoverage, 15000);
  const entries = Object.entries(data?.technique_coverage ?? {});

  return (
    <div className="p-3">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[11px] uppercase tracking-widest text-[#5C6B7A]">ATT&CK Coverage</span>
        <span className="text-[10px] font-mono text-[#5C6B7A]">({data?.total_rules ?? 0} rules loaded)</span>
      </div>
      {entries.length === 0 ? (
        <div className="font-mono text-sm text-[#5C6B7A]">규칙에 MITRE 태그가 없음</div>
      ) : (
        <div className="grid grid-cols-2 gap-1.5">
          {entries.map(([technique, ruleIds]) => (
            <div
              key={technique}
              className="px-2 py-1.5 rounded border border-[#3FBF7F]/40 bg-[#3FBF7F]/10"
              title={`탐지 규칙: ${ruleIds.join(", ")}`}
            >
              <div className="font-mono text-[12px] text-[#3FBF7F]">{technique}</div>
              <div className="font-mono text-[9px] text-[#5C6B7A] truncate">{ruleIds.length}개 규칙</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
