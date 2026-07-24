import { useMemo } from "react";
import { useRangeStore } from "../../store/rangeStore";

export function FlagList() {
  const events = useRangeStore((s) => s.events);

  const flags = useMemo(() => {
    const byVuln = new Map<string, { asset: string; vuln_id: string; timestamp: number }>();
    for (const e of events) {
      if (e.event_type === "flag_exfiltrated" && e.vuln_id) {
        const key = `${e.target_asset}:${e.vuln_id}`;
        if (!byVuln.has(key)) {
          byVuln.set(key, { asset: e.target_asset, vuln_id: e.vuln_id, timestamp: e.timestamp });
        }
      }
    }
    return Array.from(byVuln.values()).sort((a, b) => b.timestamp - a.timestamp);
  }, [events]);

  return (
    <div className="p-3">
      <div className="text-[11px] uppercase tracking-widest text-[#6B7A99] mb-2">Flag Tracker</div>
      {flags.length === 0 ? (
        <div className="font-mono text-sm text-[#6B7A99]">유출된 플래그 없음</div>
      ) : (
        <div className="flex flex-col gap-1.5">
          {flags.map((f) => (
            <div
              key={`${f.asset}:${f.vuln_id}`}
              className="flex items-center gap-2 px-2 py-1.5 rounded border border-[#E84BC9]/40 bg-[#E84BC9]/10"
            >
              <span className="w-2 h-2 rounded-full bg-[#E84BC9] shrink-0 animate-pulse" />
              <span className="font-mono text-[12px] text-[#E8EDF5]">
                {f.asset} · {f.vuln_id}
              </span>
              <span className="ml-auto text-[10px] font-mono uppercase tracking-wider text-[#E84BC9]">
                exfiltrated
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
