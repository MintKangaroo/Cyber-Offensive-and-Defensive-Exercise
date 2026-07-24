import { useMemo } from "react";
import { updateAlertStatus, usePolling, fetchAlerts } from "../../api/client";
import type { Alert } from "../../api/types";
import { SEVERITY_LABEL } from "../../api/types";

const SEVERITY_COLOR: Record<number, string> = {
  0: "#7A8699", 1: "#5FA8D3", 2: "#D9A441", 3: "#E0703A", 4: "#D64545",
};

function timeAgo(ts: number): string {
  const sec = Math.max(0, Date.now() / 1000 - ts);
  if (sec < 60) return `${Math.floor(sec)}초 전`;
  if (sec < 3600) return `${Math.floor(sec / 60)}분 전`;
  return `${Math.floor(sec / 3600)}시간 전`;
}

function AlertRow({ alert, onStatusChange }: { alert: Alert; onStatusChange: () => void }) {
  const color = SEVERITY_COLOR[alert.severity] ?? "#7A8699";
  let mitre: string[] = [];
  try {
    mitre = JSON.parse(alert.mitre);
  } catch {
    /* 파싱 실패 시 빈 배열 */
  }

  async function setStatus(status: string) {
    await updateAlertStatus(alert.id, status);
    onStatusChange();
  }

  return (
    <div
      className="px-3 py-2 border-b border-[#22303F] flex items-start gap-3"
      style={{ opacity: alert.status === "closed" ? 0.5 : 1 }}
    >
      <span
        className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded shrink-0 mt-0.5"
        style={{ color, backgroundColor: `${color}1A`, border: `1px solid ${color}55` }}
      >
        {SEVERITY_LABEL[alert.severity] ?? alert.severity}
      </span>
      <div className="flex-1 min-w-0">
        <div className="font-mono text-[13px] text-[#C7D0DA]">
          {alert.title} <span className="text-[#5C6B7A]">· {alert.rule_id}</span>
        </div>
        <div className="font-mono text-[11px] text-[#8A99AB] mt-0.5">{alert.detail}</div>
        <div className="font-mono text-[10px] text-[#5C6B7A] mt-1">
          {timeAgo(alert.timestamp)} {mitre.length > 0 && `· ${mitre.join(", ")}`}
        </div>
      </div>
      <div className="flex gap-1 shrink-0">
        {alert.status !== "ack" && (
          <button
            onClick={() => setStatus("ack")}
            className="text-[10px] font-mono px-2 py-1 rounded border border-[#D9A441]/50 text-[#D9A441]"
          >
            확인
          </button>
        )}
        {alert.status !== "closed" && (
          <button
            onClick={() => setStatus("closed")}
            className="text-[10px] font-mono px-2 py-1 rounded border border-[#22303F] text-[#5C6B7A]"
          >
            종결
          </button>
        )}
      </div>
    </div>
  );
}

export function AlertsView() {
  const { data, reload } = usePolling(() => fetchAlerts(), 5000);
  const alerts = useMemo(() => data?.alerts ?? [], [data]);

  const openCount = alerts.filter((a) => a.status === "open").length;

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-[#22303F] flex items-center gap-2">
        <span className="text-[11px] uppercase tracking-widest text-[#5C6B7A]">Detections</span>
        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#D64545]/15 border border-[#D64545]/40 text-[#D64545]">
          {openCount} open
        </span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {alerts.length === 0 ? (
          <div className="p-4 font-mono text-sm text-[#5C6B7A]">탐지된 알림 없음</div>
        ) : (
          alerts.map((a) => <AlertRow key={a.id} alert={a} onStatusChange={reload} />)
        )}
      </div>
    </div>
  );
}
