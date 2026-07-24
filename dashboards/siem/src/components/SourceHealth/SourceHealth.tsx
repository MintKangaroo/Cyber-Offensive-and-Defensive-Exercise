import { usePolling, fetchSourceHealth } from "../../api/client";

function timeAgo(sec: number | null): string {
  if (sec === null) return "없음";
  if (sec < 60) return `${Math.floor(sec)}초 전`;
  if (sec < 3600) return `${Math.floor(sec / 60)}분 전`;
  return `${Math.floor(sec / 3600)}시간 전`;
}

export function SourceHealth() {
  const { data } = usePolling(fetchSourceHealth, 5000);
  const sources = Object.entries(data?.sources ?? {});

  return (
    <div className="p-3">
      <div className="text-[11px] uppercase tracking-widest text-[#5C6B7A] mb-2">Source Health</div>
      {sources.length === 0 ? (
        <div className="font-mono text-sm text-[#5C6B7A]">아직 수집된 소스 없음</div>
      ) : (
        <div className="flex flex-col gap-1.5">
          {sources.map(([key, info]) => (
            <div
              key={key}
              className="flex items-center gap-2 px-2 py-1.5 rounded border border-[#22303F] bg-[#0E1620]"
            >
              <span
                className={`w-2 h-2 rounded-full shrink-0 ${
                  "status" in info && info.status === "green" ? "bg-[#3FBF7F]" : "bg-[#D64545]"
                }`}
              />
              <span className="font-mono text-[12px] text-[#C7D0DA] flex-1 truncate">{key}</span>
              <span className="font-mono text-[10px] text-[#5C6B7A]">
                {"seconds_since_last" in info ? timeAgo(info.seconds_since_last as number | null) : "-"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
