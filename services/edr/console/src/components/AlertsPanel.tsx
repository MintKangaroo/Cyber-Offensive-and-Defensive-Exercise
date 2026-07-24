import { useState } from "react";
import type { Alert, Severity } from "../api/types";
import { killProcess } from "../api/client";

const SEVERITY_STYLE: Record<Severity, { text: string; bg: string; border: string }> = {
  critical: { text: "text-[#FF3B3B]", bg: "bg-[#2A1414]", border: "border-[#5A2323]" },
  high: { text: "text-[#FF8A3D]", bg: "bg-[#2A1F14]", border: "border-[#5A4223]" },
  medium: { text: "text-[#FFD23D]", bg: "bg-[#2A2614]", border: "border-[#5A5223]" },
  low: { text: "text-[#3DA9FC]", bg: "bg-[#141F2A]", border: "border-[#23425A]" },
  info: { text: "text-[#7C8A99]", bg: "bg-[#131920]", border: "border-[#242E38]" },
};

function timeAgo(ts: number): string {
  const sec = Math.max(0, Date.now() / 1000 - ts);
  if (sec < 60) return `${Math.floor(sec)}초 전`;
  if (sec < 3600) return `${Math.floor(sec / 60)}분 전`;
  return `${Math.floor(sec / 3600)}시간 전`;
}

interface Props {
  alerts: Alert[];
  onKillDone: () => void;
}

export function AlertsPanel({ alerts, onKillDone }: Props) {
  const [killTarget, setKillTarget] = useState<{ asset: string; pid: number } | null>(null);
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
          : `요청됨(command ${res.command_id.slice(0, 8)}). 에이전트가 다음 폴링 주기에 실행합니다.`
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
      <div className="font-mono text-sm text-[#5B6570] p-4 text-center">
        탐지된 알림 없음 — 정상 상태
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1.5 p-2">
      {lastResult && (
        <div className="text-xs font-mono text-[#9FB0C0] bg-[#0F1419] border border-[#242E38] rounded px-2 py-1.5">
          {lastResult}
        </div>
      )}
      {alerts.map((a) => {
        const style = SEVERITY_STYLE[a.severity];
        const isKillTarget = killTarget?.asset === a.asset && killTarget?.pid === a.pid;
        return (
          <div key={a.id} className={`rounded border ${style.border} ${style.bg} px-3 py-2`}>
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] uppercase tracking-widest font-semibold ${style.text}`}>
                    {a.severity}
                  </span>
                  <span className="font-mono text-[11px] text-[#5B6570]">{a.rule_id}</span>
                </div>
                <div className="font-mono text-sm text-[#D9E1E8] mt-0.5">{a.rule_name}</div>
                <div className="font-mono text-[11px] text-[#7C8A99] mt-1 truncate">{a.detail}</div>
                <div className="font-mono text-[10px] text-[#5B6570] mt-1">
                  {a.asset} · pid {a.pid} · {timeAgo(a.timestamp)}
                </div>
              </div>
            </div>

            {isKillTarget ? (
              <div className="mt-2 flex flex-col gap-1.5">
                <input
                  autoFocus
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="종료 사유 입력(감사 로그 필수)"
                  className="bg-[#0F1419] border border-[#242E38] rounded px-2 py-1 text-xs text-[#D9E1E8] font-mono focus:outline-none focus:border-[#FF3B3B]"
                />
                <div className="flex gap-1.5">
                  <button
                    disabled={busy || !reason.trim()}
                    onClick={confirmKill}
                    className="flex-1 text-xs py-1 rounded bg-[#FF3B3B] text-white disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[#E02F2F]"
                  >
                    Kill Process 확인
                  </button>
                  <button
                    onClick={() => setKillTarget(null)}
                    className="text-xs py-1 px-2 rounded border border-[#242E38] text-[#9FB0C0] hover:bg-[#141B22]"
                  >
                    취소
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setKillTarget({ asset: a.asset, pid: a.pid })}
                className="mt-2 text-xs py-1 px-3 rounded border border-[#5A2323] text-[#FF8A3D] hover:bg-[#201414]"
              >
                Kill Process (pid {a.pid})
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}
