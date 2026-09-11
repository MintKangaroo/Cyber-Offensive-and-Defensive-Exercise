import { EmptyState, ErrorState, Panel } from "@cyber-range/command-system";
import { usePolling, fetchSourceHealth } from "../../api/client";
import type { Tone } from "@cyber-range/command-system";
import { relativeTime } from "../../severity";

function since(seconds: number | null): string {
  return seconds === null ? "없음" : relativeTime(seconds);
}

export function SourceHealth() {
  const { data, error, reload } = usePolling(fetchSourceHealth, 5000);
  const sources = Object.entries(data?.sources ?? {});

  return (
    <Panel title="Source Health">
      {error ? (
        <ErrorState message={error} retry={reload} />
      ) : sources.length === 0 ? (
        <EmptyState
          title="아직 수집된 소스 없음"
          detail="센서가 로그를 전송하면 여기에 나타납니다."
        />
      ) : (
        <div style={{ padding: 12 }}>
          {sources.map(([key, info]) => {
            const healthy = "status" in info && info.status === "green";
            const tone: Tone = healthy ? "healthy" : "critical";
            const seconds =
              "seconds_since_last" in info
                ? (info.seconds_since_last as number | null)
                : null;
            return (
              <div key={key} className="siem-source">
                <span
                  className={`siem-dot cr-tone-${tone}`}
                  role="img"
                  aria-label={healthy ? "정상" : "이상"}
                />
                <span className="siem-source-name">{key}</span>
                <span className="siem-source-time">{since(seconds)}</span>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}
