use crate::models::{Finding, FindingCategory, Severity};
use std::path::PathBuf;

/// Suspicious file extensions in assets directory
const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".dex", ".so", ".jar", ".sh", ".exe", ".bat", ".bin", ".elf",
];

/// Analyze resource and asset files for suspicious content.
pub fn analyze_resources(
    asset_files: &[PathBuf],
    resource_files: &[PathBuf],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check assets for suspicious embedded binaries
    for file in asset_files {
        let filename = file.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let filename_lower = filename.to_lowercase();

        for ext in SUSPICIOUS_EXTENSIONS {
            if filename_lower.ends_with(ext) {
                findings.push(Finding {
                    category: FindingCategory::Asset,
                    severity: Severity::Critical,
                    title: format!("Suspicious asset: {}", filename),
                    description: format!(
                        "Executable content ({}) found in assets directory. This may violate Play Protect policies.",
                        ext
                    ),
                });
                break;
            }
        }
    }

    // Scan resource files for hardcoded URLs and API keys
    for file in resource_files {
        let filename = file.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Only scan text-like resource files
        if filename.ends_with(".xml") {
            if let Ok(content) = std::fs::read_to_string(file) {
                scan_for_suspicious_content(&content, &filename, &mut findings);
            }
        }
    }

    findings
}

fn scan_for_suspicious_content(content: &str, filename: &str, findings: &mut Vec<Finding>) {
    // Check for hardcoded API keys (common patterns)
    let api_key_patterns = [
        "AIza", // Google API key prefix
        "sk-",  // OpenAI / Stripe key prefix
        "AKIA", // AWS access key prefix
    ];

    for pattern in &api_key_patterns {
        if content.contains(pattern) {
            findings.push(Finding {
                category: FindingCategory::Asset,
                severity: Severity::Warning,
                title: format!("Possible hardcoded API key in {}", filename),
                description: format!(
                    "Found pattern '{}' that resembles a hardcoded API key. Hardcoded credentials are a security risk.",
                    pattern
                ),
            });
        }
    }

    // Check for suspicious URLs
    if content.contains("http://") {
        // Count occurrences of http:// (non-HTTPS)
        let count = content.matches("http://").count();
        if count > 0 {
            findings.push(Finding {
                category: FindingCategory::Asset,
                severity: Severity::Info,
                title: format!("Non-HTTPS URLs in {}", filename),
                description: format!(
                    "Found {} non-HTTPS URL(s). Consider using HTTPS for all network communication.",
                    count
                ),
            });
        }
    }
}
