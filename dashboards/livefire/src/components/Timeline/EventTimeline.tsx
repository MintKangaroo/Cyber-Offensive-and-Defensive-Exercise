import { useMemo, useState } from "react";
import { useRangeStore } from "../../store/rangeStore";
import type { RangeEvent } from "../../api/types";

const EVENT_STYLE: Record<string, { color: string; label: string }> = {
  red_attack_started: { color: "#F5A623", label: "공격" },
  red_objective_success: { color: "#FF4D4D", label: "목표달성" },
  blue_patch_verified: { color: "#34D399", label: "패치" },
  blue_detection_success: { color: "#22D3EE", label: "탐지" },
  blue_block_success: { color: "#22D3EE", label: "차단" },
  asset_compromised: { color: "#FF4D4D", label: "침해" },
  asset_recovered: { color: "#34D399", label: "복구" },
  flag_exfiltrated: { color: "#E84BC9", label: "유출" },
  stage_completed: { color: "#A78BFA", label: "단계완료" },
  scenario_started: { color: "#6B7A99", label: "시나리오 시작" },
  scenario_ended: { color: "#6B7A99", label: "시나리오 종료" },
};

function timeAgo(ts: number): string {
  const sec = Math.max(0, Date.now() / 1000 - ts);
  if (sec < 60) return `${Math.floor(sec)}초 전`;
  if (sec < 3600) return `${Math.floor(sec / 60)}분 전`;
  return `${Math.floor(sec / 3600)}시간 전`;
}

function EventRow({ event }: { event: RangeEvent }) {
  const style = EVENT_STYLE[event.event_type] ?? { color: "#6B7A99", label: event.event_type };
  return (
    <div className="flex items-start gap-2 px-3 py-1.5 border-b border-[#1E2A3F]/60 hover:bg-[#111725]">
      <span
        className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded shrink-0 font-mono"
        style={{ color: style.color, backgroundColor: `${style.color}22`, border: `1px solid ${style.color}55` }}
      >
        {style.label}
      </span>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[12px] text-[#E8EDF5] truncate">
          {event.target_asset} {event.vuln_id ? `· ${event.vuln_id}` : ""} · team:{event.team_id}
        </div>
        <div className="font-mono text-[10px] text-[#6B7A99]">{timeAgo(event.timestamp)}</div>
      </div>
    </div>
  );
}

export function EventTimeline() {
  const events = useRangeStore((s) => s.events);
  const paused = useRangeStore((s) => s.paused);
  const togglePause = useRangeStore((s) => s.togglePause);
  const [assetFilter, setAssetFilter] = useState<string>("all");
  const [teamFilter, setTeamFilter] = useState<string>("all");

  const teams = useMemo(() => Array.from(new Set(events.map((e) => e.team_id))), [events]);

  const filtered = useMemo(
    () =>
      events.filter(
        (e) =>
          (assetFilter === "all" || e.target_asset === assetFilter) &&
          (teamFilter === "all" || e.team_id === teamFilter)
      ),
    [events, assetFilter, teamFilter]
  );

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-[#1E2A3F] shrink-0">
        <select
          value={assetFilter}
          onChange={(e) => setAssetFilter(e.target.value)}
          className="bg-[#111725] border border-[#1E2A3F] rounded text-[11px] font-mono text-[#E8EDF5] px-1.5 py-0.5"
        >
          <option value="all">전체 자산</option>
          <option value="ground_station">위성 지상국</option>
          <option value="power_plant">발전소</option>
          <option value="defense_network">국방망</option>
        </select>
        <select
          value={teamFilter}
          onChange={(e) => setTeamFilter(e.target.value)}
          className="bg-[#111725] border border-[#1E2A3F] rounded text-[11px] font-mono text-[#E8EDF5] px-1.5 py-0.5"
        >
          <option value="all">전체 팀</option>
          {teams.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <div className="flex-1" />
        <button
          onClick={togglePause}
          className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
            paused ? "border-[#F5A623] text-[#F5A623]" : "border-[#1E2A3F] text-[#6B7A99]"
          }`}
        >
          {paused ? "일시정지됨(재개)" : "일시정지"}
        </button>
      </div>
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="p-4 font-mono text-sm text-[#6B7A99]">아직 이벤트가 없습니다.</div>
        ) : (
          filtered.map((e) => <EventRow key={e.event_id} event={e} />)
        )}
      </div>
    </div>
  );
}
