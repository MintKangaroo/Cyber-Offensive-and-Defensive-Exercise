import { useState, useCallback } from "react";
import { Button, EmptyState, ErrorState, Panel } from "@cyber-range/command-system";
import { search } from "../../api/client";
import type { NormalizedEvent } from "../../api/types";
import { SeverityChip } from "../SeverityChip";

const COLUMNS = ["시각", "심각도", "소스", "자산", "메시지", "ATT&CK"];

function EventRow({ event }: { event: NormalizedEvent }) {
  return (
    <tr>
      <td className="siem-cell-mono">
        {new Date(event.timestamp).toLocaleTimeString("ko-KR")}
      </td>
      <td>
        <SeverityChip severity={event.severity} />
      </td>
      <td className="siem-cell-mono">{event.source_type}</td>
      <td>{event.asset ?? "-"}</td>
      <td className="siem-cell-msg" title={event.message}>
        {event.message}
      </td>
      <td className="siem-cell-mono">
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
  const [error, setError] = useState<string | null>(null);

  const runSearch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await search({
        text: text || undefined,
        source_type: sourceType || undefined,
        severity_min: severityMin,
        limit: 200,
      });
      setEvents(res.events);
      setTotal(res.total);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [text, sourceType, severityMin]);

  return (
    <Panel
      title="Log discovery"
      actions={<span className="siem-total">total: {total}</span>}
    >
      <div className="siem-toolbar">
        <input
          className="siem-input"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runSearch()}
          placeholder="전문검색어 (예: SQLi, UNION)"
          aria-label="전문 검색어"
        />
        <select
          className="siem-select"
          value={sourceType}
          onChange={(e) => setSourceType(e.target.value)}
          aria-label="소스 필터"
        >
          <option value="">전체 소스</option>
          <option value="twin">twin</option>
          <option value="suricata">suricata</option>
          <option value="zeek">zeek</option>
          <option value="pfsense">pfsense</option>
        </select>
        <select
          className="siem-select"
          value={severityMin ?? ""}
          onChange={(e) =>
            setSeverityMin(e.target.value ? Number(e.target.value) : undefined)
          }
          aria-label="심각도 필터"
        >
          <option value="">전체 심각도</option>
          <option value="2">MEDIUM 이상</option>
          <option value="3">HIGH 이상</option>
          <option value="4">CRITICAL만</option>
        </select>
        <Button tone="operational" onClick={runSearch} disabled={loading}>
          {loading ? "검색중..." : "검색"}
        </Button>
      </div>

      {error ? (
        <ErrorState message={error} retry={runSearch} />
      ) : events.length === 0 ? (
        <EmptyState
          title="검색 결과 없음"
          detail="검색어를 입력하거나 필터를 조정하세요."
        />
      ) : (
        <div className="cr-table-scroll" tabIndex={0} role="region" aria-label="검색 결과">
          <table className="cr-table">
            <thead>
              <tr>
                {COLUMNS.map((c) => (
                  <th key={c} scope="col">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <EventRow key={e.event_id} event={e} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
