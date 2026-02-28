import type { Finding } from "../lib/types";

interface FindingItemProps {
  finding: Finding;
}

export default function FindingItem({ finding }: FindingItemProps) {
  const icon =
    finding.severity === "critical"
      ? "\u26D4"
      : finding.severity === "warning"
        ? "\u26A0\uFE0F"
        : "\u2139\uFE0F";

  return (
    <div className={`finding-item finding-${finding.severity}`}>
      <div className="finding-header">
        <span className="finding-icon">{icon}</span>
        <span className="finding-severity">{finding.severity.toUpperCase()}</span>
        <span className="finding-title">{finding.title}</span>
      </div>
      <p className="finding-description">{finding.description}</p>
    </div>
  );
}
