import { useState } from "react";
import { usePolling } from "../../api/client";
import {
  fetchSafetyStatus, emergencyStop, releaseEmergencyStop,
  resetRange, verifyBaseline, snapshotRange, fetchMatches, createMatch,
} from "../../api/rangeControl";

/**
 * 교관용 Range Control 패널 — #11 Safety / #10 Reset·Snapshot / #9 Match.
 * range_control(8055) 백엔드를 호출. 조작 계열은 교관 토큰 필요.
 */
export function RangeControlPanel({ token, reason }: { token: string; reason: string }) {
  const { data: safety } = usePolling(fetchSafetyStatus, 4000);
  const { data: matches, reload: reloadMatches } = usePolling(fetchMatches, 6000);
  const [rangeId, setRangeId] = useState("range_1");
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // 매치 생성 폼
  const [mMatch, setMMatch] = useState("match_A");
  const [mRed, setMRed] = useState("red_alpha");
  const [mBlue, setMBlue] = useState("blue_alpha");
  const [mTwins, setMTwins] = useState("refinery_plant,power_plant");

  async function run(label: string, fn: () => Promise<unknown>, needReason = true) {
    if (needReason && !reason.trim()) { setStatus("사유를 입력해야 합니다(감사 로그)."); return; }
    setBusy(true); setStatus(`${label}…`);
    try {
      const r = await fn();
      setStatus(`${label} ✓ ${typeof r === "object" && r ? JSON.stringify(r).slice(0, 120) : ""}`);
    } catch (e) { setStatus(`${label} 실패: ${e}`); }
    finally { setBusy(false); }
  }

  const s = safety?.safety;
  const estop = s?.active_emergency_stop;

  return (
    <div className="flex flex-col">
      {/* ── #11 Safety Status ── */}
      <div className="p-3 border-b border-[#1E2A3F] flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-[10px] uppercase tracking-widest text-[#6B7A99]">Safety Status</span>
          <span className={`font-mono text-[13px] font-bold ${s?.range_containment_score === "100%" ? "text-[#34D399]" : "text-[#F5A623]"}`}
            title="격리는 compose 설계 의도이며 런타임 실측이 아니다 — isolation_test.py 로 검증 필요">
            {s?.range_containment_score ?? "…"}
          </span>
        </div>
        {s && (
          <div className="grid grid-cols-1 gap-0.5 font-mono text-[10px]">
            <Row k="Internet egress" v={s.internet_egress} good={triState(s.internet_egress, "BLOCKED")} />
            <Row k="Cross-team traffic" v={s.cross_team_traffic} good={triState(s.cross_team_traffic, "BLOCKED")} />
            <Row k="Docker socket" v={s.docker_socket_exposure} good={triState(s.docker_socket_exposure, "NONE")} />
            <Row k="Emergency stop" v={estop ? "ACTIVE" : "off"} good={!estop} />
            {s.paused_teams.length > 0 && <Row k="Paused teams" v={s.paused_teams.join(",")} good={false} />}
          </div>
        )}
        <button disabled={busy}
          onClick={() => estop
            ? run("긴급정지 해제", () => releaseEmergencyStop(reason || "resume", token))
            : run("긴급정지 발동", () => emergencyStop(reason || "emergency", token))}
          className={`text-xs py-1.5 rounded border font-mono uppercase tracking-wider ${
            estop ? "bg-[#34D399]/15 border-[#34D399]/50 text-[#34D399]" : "bg-[#FF4D4D]/15 border-[#FF4D4D]/60 text-[#FF4D4D]"} disabled:opacity-40`}>
          {estop ? "■ 긴급정지 해제" : "⛔ 전역 긴급정지"}
        </button>
      </div>

      {/* ── #10 Reset / Snapshot ── */}
      <div className="p-3 border-b border-[#1E2A3F] flex flex-col gap-2">
        <div className="text-[10px] uppercase tracking-widest text-[#6B7A99]">Range Reset / Baseline</div>
        <input value={rangeId} onChange={(e) => setRangeId(e.target.value)} placeholder="range_id"
          className="bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-xs font-mono text-[#E8EDF5]" />
        <div className="flex gap-1.5">
          <button disabled={busy} onClick={() => run("스냅샷", () => snapshotRange(rangeId, reason || "snapshot", token))}
            className="flex-1 text-[11px] py-1 rounded bg-[#6B7A99]/15 border border-[#6B7A99]/40 text-[#9fb0cc]">스냅샷</button>
          <button disabled={busy} onClick={() => run("초기화", () => resetRange(rangeId, reason || "reset", token))}
            className="flex-1 text-[11px] py-1 rounded bg-[#F5A623]/15 border border-[#F5A623]/50 text-[#F5A623]">초기화</button>
          <button disabled={busy} onClick={() => run("베이스라인 검증", async () => {
            const v = await verifyBaseline(rangeId, token); return v.verdict; }, false)}
            className="flex-1 text-[11px] py-1 rounded bg-[#22D3EE]/15 border border-[#22D3EE]/50 text-[#22D3EE]">검증</button>
        </div>
      </div>

      {/* ── #9 Matches ── */}
      <div className="p-3 border-b border-[#1E2A3F] flex flex-col gap-2">
        <div className="text-[10px] uppercase tracking-widest text-[#6B7A99]">Matches ({matches?.count ?? 0})</div>
        {(matches?.matches ?? []).map((m) => (
          <div key={m.match_id} className="font-mono text-[10px] text-[#9fb0cc] border border-[#1E2A3F] rounded px-2 py-1">
            <span className="text-[#E8EDF5]">{m.match_id}</span> · 🔴{m.red_teams.join(",")} 🔵{m.blue_teams.join(",")}
            <div className="text-[#6B7A99]">twins: {m.twin_set.join(", ") || "—"} · scen: {m.scenario_id}</div>
          </div>
        ))}
        <div className="grid grid-cols-2 gap-1">
          <input value={mMatch} onChange={(e) => setMMatch(e.target.value)} placeholder="match_id"
            className="bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-[10px] font-mono text-[#E8EDF5]" />
          <input value={mTwins} onChange={(e) => setMTwins(e.target.value)} placeholder="twins(콤마)"
            className="bg-[#111725] border border-[#1E2A3F] rounded px-2 py-1 text-[10px] font-mono text-[#E8EDF5]" />
          <input value={mRed} onChange={(e) => setMRed(e.target.value)} placeholder="red teams"
            className="bg-[#111725] border border-[#FB7185]/30 rounded px-2 py-1 text-[10px] font-mono text-[#E8EDF5]" />
          <input value={mBlue} onChange={(e) => setMBlue(e.target.value)} placeholder="blue teams"
            className="bg-[#111725] border border-[#22D3EE]/30 rounded px-2 py-1 text-[10px] font-mono text-[#E8EDF5]" />
        </div>
        <button disabled={busy}
          onClick={() => run("매치 생성", async () => {
            await createMatch({ range_id: rangeId, match_id: mMatch,
              red_teams: mRed.split(",").map((x) => x.trim()).filter(Boolean),
              blue_teams: mBlue.split(",").map((x) => x.trim()).filter(Boolean),
              twin_set: mTwins.split(",").map((x) => x.trim()).filter(Boolean) }, token);
            reloadMatches();
          }, false)}
          className="text-[11px] py-1 rounded bg-[#34D399]/15 border border-[#34D399]/50 text-[#34D399]">+ 매치 생성</button>
      </div>

      {status && <div className="px-3 py-2 font-mono text-[10px] text-[#9fb0cc] border-b border-[#1E2A3F] break-words">{status}</div>}
    </div>
  );
}

// UNKNOWN(미측정)이면 null(중립), 아니면 기대값과 일치 여부로 true/false.
function triState(v: string, ok: string): boolean | null {
  return v === "UNKNOWN" ? null : v === ok;
}

// good: true=녹색(양호) · false=적색(위험) · null/undefined=미측정(회색 중립).
// UNKNOWN(실측 안 함)을 위험(적색)으로 오표시하지 않기 위한 tri-state.
function Row({ k, v, good }: { k: string; v: string; good?: boolean | null }) {
  const color = good == null ? "text-[#6B7A99]" : good ? "text-[#34D399]" : "text-[#FB7185]";
  return (
    <div className="flex items-center justify-between">
      <span className="text-[#6B7A99]">{k}</span>
      <span className={color}>{v}</span>
    </div>
  );
}
