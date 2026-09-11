import { useState } from "react";
import { Button, EmptyState } from "@cyber-range/command-system";
import type { Alert } from "../api/types";
import { killProcess } from "../api/client";
import { relativeTime, severityTone } from "../severity";

interface Props {
  alerts: Alert[];
  onKillDone: () => void;
}

export function AlertsPanel({ alerts, onKillDone }: Props) {
  const [killTarget, setKillTarget] = useState<{ asset: string; pid: number } | null>(
    null,
  );
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [lastResult, setLastResult] = useState<string | null>(null);

  async function confirmKill() {
    if (!killTarget) return;
    setBusy(true);
    try {
      const res = await killProcess(killTarget.asset, killTarget.pid, reason);
      setLastResult(
        res.warning
          ? `요청됨(command ${res.command_id.slice(0, 8)}) — ${res.warning}`
          : `요청됨(command ${res.command_id.slice(0, 8)}). 에이전트가 다음 폴링 주기에 실행합니다.`,
      );
      onKillDone();
    } catch (e) {
      setLastResult(`실패: ${e}`);
    } finally {
      setBusy(false);
      setKillTarget(null);
      setReason("");
    }
  }

  if (alerts.length === 0) {
    return (
      <EmptyState title="탐지된 알림 없음" detail="정상 상태입니다." />
    );
  }

  return (
    <div className="edr-alerts">
      {lastResult && (
        <div className="edr-result" role="status">
          {lastResult}
        </div>
      )}
      {alerts.map((a) => {
        const isKillTarget =
          killTarget?.asset === a.asset && killTarget?.pid === a.pid;
        return (
          <div key={a.id} className={`edr-alert cr-tone-${severityTone(a.severity)}`}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="edr-alert-sev">{a.severity}</span>
              <span className="edr-proc-pid">{a.rule_id}</span>
            </div>
            <div className="edr-alert-rule">{a.rule_name}</div>
            <div className="edr-alert-detail" title={a.detail}>
              {a.detail}
            </div>
            <div className="edr-alert-meta">
              {a.asset} · pid {a.pid} · {relativeTime(Date.now() / 1000 - a.timestamp)}
            </div>

            {isKillTarget ? (
              <div className="edr-confirm" style={{ margin: "8px 0 0", padding: 0 }}>
                <input
                  className="edr-input"
                  autoFocus
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="종료 사유 입력(감사 로그 필수)"
                  aria-label="프로세스 종료 사유"
                />
                <div className="edr-row">
                  <Button
                    tone="critical"
                    style={{ flex: 1 }}
                    disabled={busy || !reason.trim()}
                    onClick={confirmKill}
                  >
                    Kill Process 확인
                  </Button>
                  <Button onClick={() => setKillTarget(null)}>취소</Button>
                </div>
              </div>
            ) : (
              <div style={{ marginTop: 8 }}>
                <Button
                  tone="warning"
                  onClick={() => setKillTarget({ asset: a.asset, pid: a.pid })}
                >
                  Kill Process (pid {a.pid})
                </Button>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
