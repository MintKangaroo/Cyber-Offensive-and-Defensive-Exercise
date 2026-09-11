import { EmptyState, ErrorState, Panel, StatusBadge } from "@cyber-range/command-system";
import { usePolling, fetchAttackCoverage } from "../../api/client";

export function AttackCoverageView() {
  const { data, error, reload } = usePolling(fetchAttackCoverage, 15000);
  const entries = Object.entries(data?.technique_coverage ?? {});

  return (
    <Panel
      title="ATT&CK Coverage"
      actions={
        <StatusBadge tone="operational">
          {data?.total_rules ?? 0} rules loaded
        </StatusBadge>
      }
    >
      {error ? (
        <ErrorState message={error} retry={reload} />
      ) : entries.length === 0 ? (
        <EmptyState
          title="규칙에 MITRE 태그가 없음"
          detail="탐지 규칙에 ATT&CK 기법이 매핑되면 여기에 표시됩니다."
        />
      ) : (
        <div className="siem-coverage-grid">
          {entries.map(([technique, ruleIds]) => (
            <div
              key={technique}
              className="siem-technique"
              title={`탐지 규칙: ${ruleIds.join(", ")}`}
            >
              <b>{technique}</b>
              <small>{ruleIds.length}개 규칙</small>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
