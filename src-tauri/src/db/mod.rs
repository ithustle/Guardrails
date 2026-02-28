use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

use crate::models::{AnalysisReport, AnalysisSummary, Finding, Verdict};

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                apk_filename TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version_name TEXT,
                version_code INTEGER,
                min_sdk INTEGER,
                target_sdk INTEGER,
                verdict TEXT NOT NULL,
                report_json TEXT NOT NULL,
                virustotal_status TEXT,
                virustotal_detections INTEGER,
                created_at TEXT NOT NULL,
                pdf_path TEXT
            );
            CREATE TABLE IF NOT EXISTS analysis_findings (
                id TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL REFERENCES analyses(id),
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_analysis ON analysis_findings(analysis_id);"
        ).map_err(|e| format!("Failed to create tables: {}", e))?;

        Ok(Database { conn: Mutex::new(conn) })
    }

    pub fn save_analysis(&self, report: &AnalysisReport) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let report_json = serde_json::to_string(report)
            .map_err(|e| format!("JSON serialize error: {}", e))?;

        let vt_status = report.virustotal.as_ref().map(|v| v.status.clone());
        let vt_detections = report.virustotal.as_ref().map(|v| v.detections);

        conn.execute(
            "INSERT OR REPLACE INTO analyses (id, apk_filename, package_name, version_name, version_code, min_sdk, target_sdk, verdict, report_json, virustotal_status, virustotal_detections, created_at, pdf_path) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                report.id,
                report.apk_filename,
                report.package_name,
                report.version_name,
                report.version_code,
                report.min_sdk,
                report.target_sdk,
                report.verdict.to_string(),
                report_json,
                vt_status,
                vt_detections,
                report.created_at,
                report.pdf_path,
            ],
        ).map_err(|e| format!("Failed to save analysis: {}", e))?;

        // Save individual findings
        let all_findings: Vec<&Finding> = report.permissions.iter()
            .chain(report.sdks.iter())
            .chain(report.patterns.iter())
            .chain(report.assets.iter())
            .collect();

        for finding in all_findings {
            let finding_id = uuid::Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO analysis_findings (id, analysis_id, category, severity, title, description) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    finding_id,
                    report.id,
                    finding.category.to_string(),
                    finding.severity.to_string(),
                    finding.title,
                    finding.description,
                ],
            ).map_err(|e| format!("Failed to save finding: {}", e))?;
        }

        Ok(())
    }

    pub fn get_analysis_history(&self) -> Result<Vec<AnalysisSummary>, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let mut stmt = conn.prepare(
            "SELECT id, apk_filename, package_name, version_name, verdict, created_at FROM analyses ORDER BY created_at DESC"
        ).map_err(|e| format!("Query error: {}", e))?;

        let rows = stmt.query_map([], |row| {
            Ok(AnalysisSummary {
                id: row.get(0)?,
                apk_filename: row.get(1)?,
                package_name: row.get(2)?,
                version_name: row.get(3)?,
                verdict: parse_verdict(&row.get::<_, String>(4)?),
                created_at: row.get(5)?,
            })
        }).map_err(|e| format!("Query error: {}", e))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| format!("Row error: {}", e))?);
        }

        Ok(results)
    }

    pub fn get_analysis_by_id(&self, id: &str) -> Result<AnalysisReport, String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        let json: String = conn.query_row(
            "SELECT report_json FROM analyses WHERE id = ?1",
            params![id],
            |row| row.get(0),
        ).map_err(|e| format!("Analysis not found: {}", e))?;

        serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse report JSON: {}", e))
    }

    pub fn update_pdf_path(&self, id: &str, pdf_path: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        conn.execute(
            "UPDATE analyses SET pdf_path = ?1 WHERE id = ?2",
            params![pdf_path, id],
        ).map_err(|e| format!("Failed to update PDF path: {}", e))?;
        Ok(())
    }

    pub fn update_virustotal(&self, id: &str, status: &str, detections: i32) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("Lock error: {}", e))?;
        conn.execute(
            "UPDATE analyses SET virustotal_status = ?1, virustotal_detections = ?2 WHERE id = ?3",
            params![status, detections, id],
        ).map_err(|e| format!("Failed to update VirusTotal: {}", e))?;
        Ok(())
    }
}

fn parse_verdict(s: &str) -> Verdict {
    match s {
        "PASS" => Verdict::Pass,
        "FAIL" => Verdict::Fail,
        _ => Verdict::Review,
    }
}
