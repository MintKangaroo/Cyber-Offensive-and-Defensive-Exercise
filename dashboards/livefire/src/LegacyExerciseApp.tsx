import { useEffect, useState, type ReactNode } from "react";
import { useRangeStore } from "./store/rangeStore";
import { useEventStream, fetchRecentEvents, fetchDelayedEvents } from "./api/client";

const OBSERVER_DELAY_SEC = 30;   // 관전자 공개정보 지연(P3)
import { AssetMap } from "./components/AssetMap/AssetMap";
import { EventTimeline } from "./components/Timeline/EventTimeline";
import { ScoreBoard } from "./components/Score/ScoreBoard";
import { PatchMatrix } from "./components/PatchStatus/PatchMatrix";
import { FlagList } from "./components/FlagTracker/FlagList";
import { ProcessImpact } from "./components/ProcessImpact/ProcessImpact";
import { InstructorConsole } from "./components/Instructor/InstructorConsole";
import { useAlertSound } from "./hooks/useAlertSound";
import type { Role } from "./api/types";

const ROLE_LABEL: Record<Role, string> = {
  red: "RED TEAM",
  blue: "BLUE TEAM",
  observer: "OBSERVER",
  instructor: "INSTRUCTOR",
};

function RoleSwitcher() {
  const role = useRangeStore((s) => s.role);
  const setRole = useRangeStore((s) => s.setRole);
  return (
    <div className="flex gap-1">
      {(Object.keys(ROLE_LABEL) as Role[]).map((r) => (
        <button
          key={r}
          onClick={() => setRole(r)}
          className={`text-[10px] font-mono uppercase tracking-wider px-2 py-1 rounded border ${
            role === r
              ? "border-[#22D3EE] text-[#22D3EE] bg-[#22D3EE]/10"
              : "border-[#1E2A3F] text-[#6B7A99]"
          }`}
        >
          {ROLE_LABEL[r]}
        </button>
      ))}
    </div>
  );
}

export default function LegacyExerciseApp({ modeControl }: { modeControl?: ReactNode }) {
  const role = useRangeStore((s) => s.role);
  const pushEvent = useRangeStore((s) => s.pushEvent);
  const setInitialEvents = useRangeStore((s) => s.setInitialEvents);
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [soundEnabled, setSoundEnabled] = useState(false); // 기본 off(예상치 못한 소리 방지)

  const { unlock, playCriticalAlert } = useAlertSound(soundEnabled);

  const isObserver = role === "observer";

  // 관전자는 실시간 WS 이벤트를 무시하고(정보 누출 방지) 지연 피드를 폴링한다.
  const { connected } = useEventStream((e) => {
    if (isObserver) return;
    pushEvent(e);
    // critical 신호(유출/목표달성)에만 반응 — 모든 이벤트에 울리면 워룸 몰입감을 오히려 해침
    if (["flag_exfiltrated", "red_objective_success", "asset_compromised"].includes(e.event_type)) {
      playCriticalAlert();
    }
  });

  useEffect(() => {
    if (isObserver) {
      // 관전자: N초 지연 이벤트만 주기적으로 로드
      const load = () => fetchDelayedEvents(OBSERVER_DELAY_SEC, 200)
        .then((r) => setInitialEvents(r.events)).catch(() => {});
      load();
      const t = setInterval(load, 3000);
      return () => clearInterval(t);
    }
    fetchRecentEvents(200)
      .then((r) => setInitialEvents(r.events))
      .catch(() => { /* Event Collector 기동 전이어도 화면은 뜨게 */ });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isObserver]);

  // 07번 문서 2절: 역할별 노출 범위. 실제 치팅 방지는 백엔드 인증이 담당하고,
  // 여기서는 UX 상 불필요한 정보를 안 보여주는 수준(보조 수단).
  const showPatchAndFlag = role !== "red";
  const showInstructor = role === "instructor";

  return (
    <div className="h-screen w-screen bg-[#0A0E1A] text-[#E8EDF5] flex flex-col font-sans">
      <header className="min-h-12 border-b border-[#1E2A3F] flex flex-wrap items-center px-4 py-2 gap-3 shrink-0">
        <div className="flex min-w-0 shrink-0 items-center gap-2">
          <span className="whitespace-nowrap font-mono text-sm tracking-[0.2em] text-[#E8EDF5]">LIVE FIRE RANGE</span>
          <span className="hidden xl:inline-flex whitespace-nowrap text-[10px] uppercase tracking-widest text-[#6B7A99] px-2 py-0.5 rounded border border-[#1E2A3F]">
            training environment
          </span>
        </div>
        {/* 팀별 전용 포털 진입(포털은 별도 dev 서버: Red 5176 / Blue 5177) */}
        <nav aria-label="Team portals" className="flex shrink-0 items-center gap-2">
          <a
            href={`http://${typeof window !== "undefined" ? window.location.hostname : "localhost"}:5176/`}
            target="_blank" rel="noreferrer"
            className="whitespace-nowrap text-[10px] font-mono uppercase tracking-wider px-2 py-1 rounded border border-[#FB7185]/50 text-[#FB7185] hover:bg-[#FB7185]/10"
            title="레드팀 실제 서비스 공격 포털 열기"
          >
            🚩 RED PORTAL
          </a>
          <a
            href={`http://${typeof window !== "undefined" ? window.location.hostname : "localhost"}:5177/`}
            target="_blank" rel="noreferrer"
            className="whitespace-nowrap text-[10px] font-mono uppercase tracking-wider px-2 py-1 rounded border border-[#22D3EE]/50 text-[#22D3EE] hover:bg-[#22D3EE]/10"
            title="블루팀 방어 포털 열기"
          >
            🛡️ BLUE PORTAL
          </a>
        </nav>
        {modeControl && <div className="shrink-0">{modeControl}</div>}
        <div className="flex-1" />
        <button
          onClick={() => {
            unlock();
            setSoundEnabled((v) => !v);
          }}
          className={`text-[10px] font-mono uppercase tracking-wider px-2 py-1 rounded border ${
            soundEnabled ? "border-[#F5A623] text-[#F5A623]" : "border-[#1E2A3F] text-[#6B7A99]"
          }`}
          title="critical 알림 사운드 (기본 꺼짐)"
        >
          {soundEnabled ? "🔊 sound on" : "🔇 sound off"}
        </button>
        <RoleSwitcher />
        {isObserver ? (
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#F5A623] ml-2" title="관전자는 공개정보를 지연 표시받습니다(실시간 정보 누출 방지)">
            <span className="w-1.5 h-1.5 rounded-full bg-[#F5A623]" />
            ⏱ 관전 지연 {OBSERVER_DELAY_SEC}s
          </div>
        ) : (
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#6B7A99] ml-2">
            <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-[#34D399]" : "bg-[#6B7A99]"}`} />
            {connected ? "live" : "reconnecting…"}
          </div>
        )}
      </header>

      <div className="flex-1 flex min-h-0">
        <main className="flex-1 flex flex-col min-w-0 border-r border-[#1E2A3F]">
          <div className="h-1/2 border-b border-[#1E2A3F] p-2">
            <AssetMap onSelectAsset={setSelectedAsset} />
          </div>
          <div className="flex-1 min-h-0">
            <EventTimeline />
          </div>
        </main>

        <aside className="w-80 flex flex-col overflow-y-auto shrink-0">
          <ScoreBoard />
          <div className="border-t border-[#1E2A3F]">
            <ProcessImpact />
          </div>
          {showPatchAndFlag && (
            <>
              <div className="border-t border-[#1E2A3F]">
                <PatchMatrix />
              </div>
              <div className="border-t border-[#1E2A3F]">
                <FlagList />
              </div>
            </>
          )}
        </aside>

        {showInstructor && (
          <aside className="w-96 border-l border-[#1E2A3F] flex flex-col shrink-0">
            <div className="h-10 border-b border-[#1E2A3F] flex items-center px-4 text-[11px] uppercase tracking-widest text-[#6B7A99]">
              Instructor Console
            </div>
            <InstructorConsole />
          </aside>
        )}
      </div>

      {selectedAsset && (
        <div className="absolute bottom-4 right-4 bg-[#111725] border border-[#1E2A3F] rounded px-3 py-2 font-mono text-xs text-[#E8EDF5]">
          선택된 자산: {selectedAsset}
          <button onClick={() => setSelectedAsset(null)} className="ml-3 text-[#6B7A99]">✕</button>
        </div>
      )}
    </div>
  );
}
