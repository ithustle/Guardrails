import { useState, useEffect, useCallback } from "react";
import { useParams } from "react-router-dom";
import { Download, Loader2 } from "lucide-react";
import { getAnalysisById, exportPdf } from "../lib/api";
import type { AnalysisReport } from "../lib/types";
import VerdictBadge from "../components/VerdictBadge";
import FindingItem from "../components/FindingItem";

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    getAnalysisById(id)
      .then(setReport)
      .catch((e) => setError(`Failed to load report: ${e}`))
      .finally(() => setLoading(false));
  }, [id]);

  const handleExportPdf = useCallback(async () => {
    if (!id) return;
    setExporting(true);
    try {
      const pdfPath = await exportPdf(id);
      alert(`PDF exported to: ${pdfPath}`);
    } catch (e) {
      setError(`PDF export failed: ${e}`);
    } finally {
      setExporting(false);
    }
  }, [id]);

  if (loading) {
    return (
      <div className="page loading-page">
        <Loader2 size={32} className="spinner" />
        <p>Loading report...</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="page">
        <div className="error-message">{error || "Report not found"}</div>
      </div>
    );
  }

  return (
    <div className="page report-page">
      <div className="report-header">
        <div>
          <h1>{report.apk_filename}</h1>
          <p className="report-package">{report.package_name}</p>
        </div>
        <div className="report-actions">
          <VerdictBadge verdict={report.verdict} />
          <button
            className="btn btn-secondary"
            onClick={handleExportPdf}
            disabled={exporting}
          >
            {exporting ? (
              <Loader2 size={16} className="spinner" />
            ) : (
              <Download size={16} />
            )}
            Export PDF
          </button>
        </div>
      </div>

      <div className="report-summary">
        <p>{report.summary}</p>
      </div>

      <Section title="Metadata">
        <div className="metadata-grid">
          <div className="metadata-item">
            <span className="metadata-label">Package</span>
            <span className="metadata-value">{report.metadata.package_name}</span>
          </div>
          <div className="metadata-item">
            <span className="metadata-label">Version</span>
            <span className="metadata-value">
              {report.version_name || "N/A"} ({report.version_code ?? "N/A"})
            </span>
          </div>
          <div className="metadata-item">
            <span className="metadata-label">Min SDK</span>
            <span className="metadata-value">{report.metadata.min_sdk ?? "N/A"}</span>
          </div>
          <div className="metadata-item">
            <span className="metadata-label">Target SDK</span>
            <span className="metadata-value">
              {report.metadata.target_sdk ?? "N/A"} — {report.metadata.target_sdk_status}
            </span>
          </div>
        </div>
      </Section>

      <Section title="Permissions" count={report.permissions.length}>
        {report.permissions.length === 0 ? (
          <p className="no-findings">No flagged permissions found.</p>
        ) : (
          report.permissions.map((f, i) => <FindingItem key={i} finding={f} />)
        )}
      </Section>

      <Section title="Third-Party SDKs" count={report.sdks.length}>
        {report.sdks.length === 0 ? (
          <p className="no-findings">No flagged SDKs found.</p>
        ) : (
          report.sdks.map((f, i) => <FindingItem key={i} finding={f} />)
        )}
      </Section>

      <Section title="Code Patterns" count={report.patterns.length}>
        {report.patterns.length === 0 ? (
          <p className="no-findings">No flagged code patterns found.</p>
        ) : (
          report.patterns.map((f, i) => <FindingItem key={i} finding={f} />)
        )}
      </Section>

      <Section title="Embedded Assets" count={report.assets.length}>
        {report.assets.length === 0 ? (
          <p className="no-findings">No suspicious embedded assets found.</p>
        ) : (
          report.assets.map((f, i) => <FindingItem key={i} finding={f} />)
        )}
      </Section>

      <Section title="VirusTotal Scan">
        {report.virustotal ? (
          <div className="vt-result">
            <p>
              <strong>Status:</strong> {report.virustotal.status}
            </p>
            <p>
              <strong>Detections:</strong> {report.virustotal.detections}/
              {report.virustotal.total_engines} engines
            </p>
            {report.virustotal.scan_date && (
              <p>
                <strong>Scan Date:</strong> {report.virustotal.scan_date}
              </p>
            )}
          </div>
        ) : (
          <p className="no-findings">
            Scan not performed. Configure VirusTotal API key in settings.
          </p>
        )}
      </Section>

      <div className="report-footer">
        <p>
          Analysis performed on {new Date(report.created_at).toLocaleString()}
        </p>
        <p>Generated by Guardrails v1.0</p>
      </div>
    </div>
  );
}

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);

  return (
    <div className="report-section">
      <h2 className="section-header" onClick={() => setOpen(!open)}>
        <span>{open ? "\u25BC" : "\u25B6"}</span>
        {title}
        {count !== undefined && (
          <span className="section-count">{count}</span>
        )}
      </h2>
      {open && <div className="section-content">{children}</div>}
    </div>
  );
}
