import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Search } from "lucide-react";
import { getAnalysisHistory } from "../lib/api";
import type { AnalysisSummary } from "../lib/types";
import VerdictBadge from "../components/VerdictBadge";

export default function HistoryPage() {
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const navigate = useNavigate();

  useEffect(() => {
    setLoading(true);
    getAnalysisHistory()
      .then(setAnalyses)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const filtered = analyses.filter((a) => {
    const matchesText =
      filter === "" ||
      a.apk_filename.toLowerCase().includes(filter.toLowerCase()) ||
      a.package_name.toLowerCase().includes(filter.toLowerCase());
    const matchesVerdict =
      verdictFilter === "all" || a.verdict === verdictFilter;
    return matchesText && matchesVerdict;
  });

  if (loading) {
    return (
      <div className="page loading-page">
        <Loader2 size={32} className="spinner" />
        <p>Loading history...</p>
      </div>
    );
  }

  return (
    <div className="page history-page">
      <h1>Analysis History</h1>

      <div className="history-filters">
        <div className="search-input">
          <Search size={16} />
          <input
            type="text"
            placeholder="Search by filename or package..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <select
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
          className="verdict-select"
        >
          <option value="all">All Verdicts</option>
          <option value="PASS">Pass</option>
          <option value="FAIL">Fail</option>
          <option value="REVIEW">Review</option>
        </select>
      </div>

      {filtered.length === 0 ? (
        <div className="empty-state">
          <p>
            {analyses.length === 0
              ? "No analyses yet. Upload an APK to get started."
              : "No matching analyses found."}
          </p>
        </div>
      ) : (
        <table className="history-table">
          <thead>
            <tr>
              <th>Date</th>
              <th>APK File</th>
              <th>Package</th>
              <th>Version</th>
              <th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <tr
                key={a.id}
                onClick={() => navigate(`/report/${a.id}`)}
                className="clickable-row"
              >
                <td>{new Date(a.created_at).toLocaleDateString()}</td>
                <td>{a.apk_filename}</td>
                <td className="mono">{a.package_name}</td>
                <td>{a.version_name || "N/A"}</td>
                <td>
                  <VerdictBadge verdict={a.verdict} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
