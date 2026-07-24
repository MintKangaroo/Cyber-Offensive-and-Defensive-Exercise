import { useState } from "react";
import { scenarioStart, scenarioEnd, scoreAdjust, fetchAudit, usePolling } from "../../api/client";
import { useRangeStore } from "../../store/rangeStore";

function timeAgo(ts: number): string {
  const sec = Math.max(0, Date.now() / 1000 - ts);
  if (sec < 60) return `${Math.floor(sec)}초 전`;
  if (sec < 3600) return `${Math.floor(sec / 60)}분 전`;
  return `${Math.floor(sec / 3600)}시간 전`;
}

export function AuditLogView() {
  const { data } = usePolling(fetchAudit, 5000);
  const entries = data?.entries ?? [];

  return (
    <div className="flex-1 overflow-y-auto">
      {entries.length === 0 ? (
        <div className="p-3 font-mono text-sm text-[#6B7A99]">교관 조작 이력 없음</div>
      ) : (
        entries.map((e, i) => (
          <div key={e.audit_id ?? i} className="px-3 py-2 border-b border-[#1E2A3F]/60">
            <div className="font-mono text-[11px] text-[#E8EDF5]">
              <span className="text-[#F5A623]">{e.action}</span> · {e.target}
            </div>
            <div className="font-mono text-[10px] text-[#6B7A99]">
              {e.actor} · {timeAgo(e.timestamp)} · {e.reason}
            </div>
          </div>
        ))
      )}
    </div>
  );
}

export function InstructorConsole() {
  const scenarioId = useRangeStore((s) => s.scenarioId);
  const setScenarioId = useRangeStore((s) => s.setScenarioId);
  const token = useRangeStore((s) => s.instructorToken);
  const setToken = useRangeStore((s) => s.setInstructorToken);

  const [reason, setReason] = useState("");
  const [teamIds, setTeamIds] = useState("team_alpha");
  const [adjustTeam, setAdjustTeam] = useState("team_alpha");
  const [adjustActor, setAdjustActor] = useState<"red" | "blue">("blue");
  const [adjustDelta, setAdjustDelta] = useState(0);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<unknown>) {
    if (!reason.trim()) {
      setStatus("사유를 입력해야 합니다(감사 로그 필수).");
      return;
    }
    setBusy(true);
    try {
      await fn();
      setStatus("완료");
    } catch (e) {
      setStatus(`실패: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b border-[#1E2A3F] flex flex-col gap-2">
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="교관 토큰(INSTRUCTOR_TOKEN)"
          type="password"
          className="bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]"
        />
        <input
          value={scenarioId}
          onChange={(e) => setScenarioId(e.target.value)}
          placeholder="scenario_id"
          className="bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]"
        />
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="사유 (모든 조작에 필수)"
          className="bg-[#111725] border border-[#F5A623]/40 rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]"
        />
      </div>

      <div className="p-3 border-b border-[#1E2A3F] flex flex-col gap-2">
        <div className="text-[10px] uppercase tracking-widest text-[#6B7A99]">시나리오 제어</div>
        <input
          value={teamIds}
          onChange={(e) => setTeamIds(e.target.value)}
          placeholder="team_ids (콤마 구분)"
          className="bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]"
        />
        <div className="flex gap-2">
          <button
            disabled={busy}
            onClick={() => run(() => scenarioStart(scenarioId, teamIds.split(",").map((s) => s.trim()), reason, token))}
            className="flex-1 text-xs py-1 rounded bg-[#22D3EE]/20 border border-[#22D3EE]/50 text-[#22D3EE] disabled:opacity-40"
          >
            시나리오 시작
          </button>
          <button
            disabled={busy}
            onClick={() => run(() => scenarioEnd(scenarioId, reason, token))}
            className="flex-1 text-xs py-1 rounded bg-[#FF4D4D]/20 border border-[#FF4D4D]/50 text-[#FF4D4D] disabled:opacity-40"
          >
            시나리오 종료
          </button>
        </div>
      </div>

      <div className="p-3 border-b border-[#1E2A3F] flex flex-col gap-2">
        <div className="text-[10px] uppercase tracking-widest text-[#6B7A99]">점수 수동조정</div>
        <div className="flex gap-2">
          <input
            value={adjustTeam}
            onChange={(e) => setAdjustTeam(e.target.value)}
            placeholder="team_id"
            className="flex-1 bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]"
          />
          <select
            value={adjustActor}
            onChange={(e) => setAdjustActor(e.target.value as "red" | "blue")}
            className="bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]"
          >
            <option value="red">red</option>
            <option value="blue">blue</option>
          </select>
          <input
            type="number"
            value={adjustDelta}
            onChange={(e) => setAdjustDelta(Number(e.target.value))}
            className="w-20 bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]"
          />
        </div>
        <button
          disabled={busy}
          onClick={() => run(() => scoreAdjust(adjustTeam, adjustActor, adjustDelta, reason, token))}
          className="text-xs py-1 rounded bg-[#F5A623]/20 border border-[#F5A623]/50 text-[#F5A623] disabled:opacity-40"
        >
          점수 조정 적용
        </button>
      </div>

      {status && (
        <div className="px-3 py-2 font-mono text-[11px] text-[#6B7A99] border-b border-[#1E2A3F]">{status}</div>
      )}

      <div className="px-3 py-2 text-[10px] uppercase tracking-widest text-[#6B7A99]">Audit Log</div>
      <AuditLogView />
    </div>
  );
}
