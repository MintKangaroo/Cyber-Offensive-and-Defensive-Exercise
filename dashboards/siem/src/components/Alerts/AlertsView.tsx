import { useMemo } from "react";
import {
  Button,
  EmptyState,
  ErrorState,
  Panel,
  StatusBadge,
} from "@cyber-range/command-system";
import { updateAlertStatus, usePolling, fetchAlerts } from "../../api/client";
import type { Alert } from "../../api/types";
import { parseMitre, relativeTime } from "../../severity";
import { SeverityChip } from "../SeverityChip";

function AlertRow({
  alert,
  onStatusChange,
}: {
  alert: Alert;
  onStatusChange: () => void;
}) {
  const mitre = parseMitre(alert.mitre);
  const secondsAgo = Date.now() / 1000 - alert.timestamp;

  async function setStatus(status: string) {
    await updateAlertStatus(alert.id, status);
    onStatusChange();
  }

  return (
    <div
      className="siem-alert"
      style={{ opacity: alert.status === "closed" ? 0.5 : 1 }}
    >
      <SeverityChip severity={alert.severity} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="siem-alert-title">
          {alert.title} <span>· {alert.rule_id}</span>
        </div>
        <p className="siem-alert-detail">{alert.detail}</p>
        <div className="siem-alert-meta">
          {relativeTime(secondsAgo)}
          {mitre.length > 0 && ` · ${mitre.join(", ")}`}
        </div>
      </div>
      <div className="siem-alert-actions">
        {alert.status !== "ack" && (
          <Button tone="warning" onClick={() => setStatus("ack")}>
            확인
          </Button>
        )}
        {alert.status !== "closed" && (
          <Button onClick={() => setStatus("closed")}>종결</Button>
        )}
      </div>
    </div>
  );
}

export function AlertsView() {
  const { data, error, reload } = usePolling(() => fetchAlerts(), 5000);
  const alerts = useMemo(() => data?.alerts ?? [], [data]);
  const openCount = alerts.filter((a) => a.status === "open").length;

  return (
    <Panel
      title="Detections"
      actions={
        <StatusBadge tone={openCount ? "critical" : "healthy"}>
          {openCount} open
        </StatusBadge>
      }
    >
      {error ? (
        <ErrorState message={error} retry={reload} />
      ) : alerts.length === 0 ? (
        <EmptyState
          title="탐지된 알림 없음"
          detail="탐지 규칙이 매칭되면 여기에 나타납니다."
        />
      ) : (
        alerts.map((a) => (
          <AlertRow key={a.id} alert={a} onStatusChange={reload} />
        ))
      )}
    </Panel>
  );
}
