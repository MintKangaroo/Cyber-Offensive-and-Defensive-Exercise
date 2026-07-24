import { useEffect, useRef, useState } from "react";
import { fetchScores, fetchScoreHistory, usePolling } from "../../api/client";
import { useRangeStore } from "../../store/rangeStore";
import type { Achievement } from "../../api/types";

/** 숫자가 바뀔 때 부드럽게 카운트업(별도 라이브러리 없이 requestAnimationFrame으로). */
function useCountUp(target: number, durationMs = 500): number {
  const [value, setValue] = useState(target);
  const fromRef = useRef(target);
  const startRef = useRef<number | null>(null);

  useEffect(() => {
    fromRef.current = value;
    startRef.current = null;
    let raf: number;
    const step = (ts: number) => {
      if (startRef.current === null) startRef.current = ts;
      const progress = Math.min(1, (ts - startRef.current) / durationMs);
      setValue(Math.round(fromRef.current + (target - fromRef.current) * progress));
      if (progress < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  return value;
}

function TeamScoreCard({ teamId, red, blue }: { teamId: string; red: number; blue: number }) {
  const redAnim = useCountUp(red);
  const blueAnim = useCountUp(blue);
  return (
    <div className="border border-[#1E2A3F] rounded-lg px-4 py-3 bg-[#111725]">
      <div className="font-mono text-[11px] uppercase tracking-widest text-[#6B7A99] mb-2">{teamId}</div>
      <div className="flex items-end gap-6">
        <div>
          <div className="font-mono text-3xl font-bold text-[#F5A623] tabular-nums">{redAnim}</div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-[#F5A623]/70">RED</div>
        </div>
        <div>
          <div className="font-mono text-3xl font-bold text-[#22D3EE] tabular-nums">{blueAnim}</div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-[#22D3EE]/70">BLUE</div>
        </div>
      </div>
    </div>
  );
}

/** achievements를 시간순 누적합으로 변환한 미니 스파크라인(라이브러리 없이 SVG 직접 렌더). */
function ScoreSparkline({ achievements }: { achievements: Achievement[] }) {
  if (achievements.length === 0) return null;
  const sorted = [...achievements].sort((a, b) => a.created_at - b.created_at);
  let redCum = 0, blueCum = 0;
  const points: { t: number; red: number; blue: number }[] = [];
  for (const a of sorted) {
    if (a.actor === "red") redCum += a.points;
    else blueCum += a.points;
    points.push({ t: a.created_at, red: redCum, blue: blueCum });
  }
  const maxVal = Math.max(1, ...points.map((p) => Math.max(p.red, p.blue)));
  const w = 400, h = 80;
  const toPath = (key: "red" | "blue") =>
    points
      .map((p, i) => {
        const x = (i / Math.max(1, points.length - 1)) * w;
        const y = h - (p[key] / maxVal) * h;
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-20">
      <path d={toPath("red")} fill="none" stroke="#F5A623" strokeWidth="2" />
      <path d={toPath("blue")} fill="none" stroke="#22D3EE" strokeWidth="2" />
    </svg>
  );
}

export function ScoreBoard() {
  const scenarioId = useRangeStore((s) => s.scenarioId);
  const { data: scores } = usePolling(() => fetchScores(scenarioId), 3000, [scenarioId]);
  const { data: history } = usePolling(() => fetchScoreHistory(scenarioId), 5000, [scenarioId]);

  const teamEntries = Object.entries(scores?.teams ?? {});

  return (
    <div className="p-3 flex flex-col gap-3">
      <div className="text-[11px] uppercase tracking-widest text-[#6B7A99]">Score Board</div>
      {teamEntries.length === 0 ? (
        <div className="font-mono text-sm text-[#6B7A99]">아직 점수 없음</div>
      ) : (
        <div className="grid grid-cols-1 gap-2">
          {teamEntries.map(([teamId, s]) => (
            <TeamScoreCard key={teamId} teamId={teamId} red={s.red} blue={s.blue} />
          ))}
        </div>
      )}
      {history?.achievements && history.achievements.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-widest text-[#6B7A99] mb-1">추이 (누적)</div>
          <ScoreSparkline achievements={history.achievements} />
        </div>
      )}
    </div>
  );
}
