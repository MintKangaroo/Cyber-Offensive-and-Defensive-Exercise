import { useState, useCallback } from "react";
import { search } from "../../api/client";
import type { NormalizedEvent } from "../../api/types";
import { SEVERITY_LABEL } from "../../api/types";

const SEVERITY_COLOR: Record<number, string> = {
  0: "#7A8699", 1: "#5FA8D3", 2: "#D9A441", 3: "#E0703A", 4: "#D64545",
};

function SeverityBadge({ severity }: { severity: number }) {
  const color = SEVERITY_COLOR[severity] ?? "#7A8699";
  return (
    <span
      className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded"
      style={{ color, backgroundColor: `${color}1A`, border: `1px solid ${color}55` }}
    >
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  );
}

function EventDetailRow({ event }: { event: NormalizedEvent }) {
  return (
    <tr className="border-b border-[#22303F] hover:bg-[#0E1620]">
      <td className="px-2 py-1.5 font-mono text-[11px] text-[#8A99AB] whitespace-nowrap">
        {new Date(event.timestamp).toLocaleTimeString("ko-KR")}
      </td>
      <td className="px-2 py-1.5"><SeverityBadge severity={event.severity} /></td>
      <td className="px-2 py-1.5 font-mono text-[11px] text-[#5FA8D3]">{event.source_type}</td>
      <td className="px-2 py-1.5 font-mono text-[11px] text-[#C7D0DA]">{event.asset ?? "-"}</td>
      <td className="px-2 py-1.5 font-mono text-[11px] text-[#C7D0DA] max-w-md truncate">{event.message}</td>
      <td className="px-2 py-1.5 font-mono text-[10px] text-[#5C6B7A]">
        {event.mitre.length > 0 ? event.mitre.join(", ") : "-"}
      </td>
    </tr>
  );
}

export function Discover() {
  const [text, setText] = useState("");
  const [sourceType, setSourceType] = useState("");
  const [severityMin, setSeverityMin] = useState<number | undefined>(undefined);
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const runSearch = useCallback(async () => {
    setLoading(true);
    try {
      const res = await search({ text: text || undefined, source_type: sourceType || undefined, severity_min: severityMin, limit: 200 });
      setEvents(res.events);
      setTotal(res.total);
    } finally {
      setLoading(false);
    }
  }, [text, sourceType, severityMin]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[#22303F] shrink-0">
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runSearch()}
          placeholder="전문검색어 (예: SQLi, UNION)"
          className="flex-1 bg-[#0E1620] border border-[#22303F] rounded px-2 py-1 text-xs font-mono text-[#C7D0DA] focus:outline-none focus:border-[#5FA8D3]"
        />
        <select
          value={sourceType}
          onChange={(e) => setSourceType(e.target.value)}
          className="bg-[#0E1620] border border-[#22303F] rounded text-[11px] font-mono text-[#C7D0DA] px-1.5 py-1"
        >
          <option value="">전체 소스</option>
          <option value="twin">twin</option>
          <option value="suricata">suricata</option>
          <option value="zeek">zeek</option>
          <option value="pfsense">pfsense</option>
        </select>
        <select
          value={severityMin ?? ""}
          onChange={(e) => setSeverityMin(e.target.value ? Number(e.target.value) : undefined)}
          className="bg-[#0E1620] border border-[#22303F] rounded text-[11px] font-mono text-[#C7D0DA] px-1.5 py-1"
        >
          <option value="">전체 심각도</option>
          <option value="2">MEDIUM 이상</option>
          <option value="3">HIGH 이상</option>
          <option value="4">CRITICAL만</option>
        </select>
        <button
          onClick={runSearch}
          disabled={loading}
          className="text-xs font-mono px-3 py-1 rounded bg-[#5FA8D3]/20 border border-[#5FA8D3]/50 text-[#5FA8D3] disabled:opacity-40"
        >
          {loading ? "검색중..." : "검색"}
        </button>
        <div className="text-[11px] font-mono text-[#5C6B7A] ml-auto">total: {total}</div>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 bg-[#0A1119]">
            <tr className="border-b border-[#22303F] text-left">
              <th className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-[#5C6B7A]">시각</th>
              <th className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-[#5C6B7A]">심각도</th>
              <th className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-[#5C6B7A]">소스</th>
              <th className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-[#5C6B7A]">자산</th>
              <th className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-[#5C6B7A]">메시지</th>
              <th className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-[#5C6B7A]">ATT&CK</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center font-mono text-sm text-[#5C6B7A]">
                  검색 결과 없음 — 검색어를 입력하거나 필터를 조정하세요.
                </td>
              </tr>
            ) : (
              events.map((e) => <EventDetailRow key={e.event_id} event={e} />)
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
