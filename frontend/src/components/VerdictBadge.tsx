interface VerdictBadgeProps {
  verdict: "PASS" | "FAIL" | "REVIEW";
}

export default function VerdictBadge({ verdict }: VerdictBadgeProps) {
  const className = `verdict-badge verdict-${verdict.toLowerCase()}`;
  return <span className={className}>{verdict}</span>;
}
