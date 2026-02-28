use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub id: String,
    pub apk_filename: String,
    pub package_name: String,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub verdict: Verdict,
    pub summary: String,
    pub metadata: MetadataSection,
    pub permissions: Vec<Finding>,
    pub sdks: Vec<Finding>,
    pub patterns: Vec<Finding>,
    pub assets: Vec<Finding>,
    pub virustotal: Option<VirusTotalResult>,
    pub created_at: String,
    pub pdf_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub id: String,
    pub apk_filename: String,
    pub package_name: String,
    pub version_name: Option<String>,
    pub verdict: Verdict,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Fail,
    #[serde(rename = "REVIEW")]
    Review,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Pass => write!(f, "PASS"),
            Verdict::Fail => write!(f, "FAIL"),
            Verdict::Review => write!(f, "REVIEW"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataSection {
    pub package_name: String,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub target_sdk_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: FindingCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    Permission,
    Sdk,
    Pattern,
    Asset,
    Virustotal,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::Permission => write!(f, "permission"),
            FindingCategory::Sdk => write!(f, "sdk"),
            FindingCategory::Pattern => write!(f, "pattern"),
            FindingCategory::Asset => write!(f, "asset"),
            FindingCategory::Virustotal => write!(f, "virustotal"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalResult {
    pub status: String,
    pub detections: i32,
    pub total_engines: i32,
    pub scan_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub virustotal_api_key: Option<String>,
    pub rules_path: Option<String>,
}
