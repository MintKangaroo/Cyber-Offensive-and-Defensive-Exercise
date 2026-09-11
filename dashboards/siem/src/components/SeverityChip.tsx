import { severityLabel, severityTone } from "../severity";

/** Severity as a design-system badge (tone-colored) with the exact SIEM label. */
export function SeverityChip({ severity }: { severity: number }) {
  return (
    <span className={`cr-badge siem-sev cr-tone-${severityTone(severity)}`}>
      {severityLabel(severity)}
    </span>
  );
}
