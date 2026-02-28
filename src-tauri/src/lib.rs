pub mod analyzers;
pub mod db;
pub mod models;
pub mod report;
pub mod rules;
pub mod virustotal;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tauri::Manager;

use db::Database;
use models::*;
use rules::RulesConfig;

pub struct AppState {
    pub db: Database,
    pub rules: Mutex<RulesConfig>,
    pub settings: Mutex<AppSettings>,
    pub data_dir: PathBuf,
}

#[tauri::command]
async fn analyze_apk(
    path: String,
    state: tauri::State<'_, AppState>,
) -> Result<AnalysisReport, String> {
    let apk_path = PathBuf::from(&path);
    if !apk_path.exists() {
        return Err("APK file not found".to_string());
    }

    let apk_filename = apk_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown.apk".to_string());

    // Create work directory for this analysis
    let analysis_id = uuid::Uuid::new_v4().to_string();
    let work_dir = state.data_dir.join("work").join(&analysis_id);
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| format!("Failed to create work dir: {}", e))?;

    // Step 1: Unpack APK
    let unpacked = analyzers::unpacker::unpack_apk(&apk_path, &work_dir)?;

    // Step 2: Parse manifest
    let manifest_info = match &unpacked.manifest_data {
        Some(data) => analyzers::manifest::parse_manifest(data)?,
        None => {
            return Err("AndroidManifest.xml not found in APK".to_string());
        }
    };

    // Step 3: Get rules
    let rules = state
        .rules
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?
        .clone();

    // Step 4: Analyze manifest
    let (metadata, permission_findings) =
        analyzers::manifest::analyze_manifest(&manifest_info, &rules);

    // Step 5: Parse and analyze DEX files
    let mut dex_infos = Vec::new();
    for dex_path in &unpacked.dex_files {
        match analyzers::dex::parse_dex(dex_path) {
            Ok(info) => dex_infos.push(info),
            Err(e) => eprintln!("Warning: Failed to parse DEX file: {}", e),
        }
    }
    let (sdk_findings, pattern_findings) = analyzers::dex::analyze_dex(&dex_infos, &rules);

    // Step 6: Analyze resources
    let asset_findings =
        analyzers::resources::analyze_resources(&unpacked.asset_files, &unpacked.resource_files);

    // Step 7: Determine verdict
    let has_critical = permission_findings
        .iter()
        .chain(sdk_findings.iter())
        .chain(pattern_findings.iter())
        .chain(asset_findings.iter())
        .any(|f| f.severity == Severity::Critical);

    let has_warning = permission_findings
        .iter()
        .chain(sdk_findings.iter())
        .chain(pattern_findings.iter())
        .chain(asset_findings.iter())
        .any(|f| f.severity == Severity::Warning);

    let verdict = if has_critical {
        Verdict::Fail
    } else if has_warning {
        Verdict::Review
    } else {
        Verdict::Pass
    };

    // Step 8: Generate summary
    let summary = generate_summary(
        &verdict,
        &permission_findings,
        &sdk_findings,
        &pattern_findings,
        &asset_findings,
    );

    let now = chrono::Utc::now().to_rfc3339();

    let report = AnalysisReport {
        id: analysis_id,
        apk_filename,
        package_name: manifest_info.package_name.clone(),
        version_name: manifest_info.version_name.clone(),
        version_code: manifest_info.version_code,
        min_sdk: manifest_info.min_sdk,
        target_sdk: manifest_info.target_sdk,
        verdict,
        summary,
        metadata,
        permissions: permission_findings,
        sdks: sdk_findings,
        patterns: pattern_findings,
        assets: asset_findings,
        virustotal: None,
        created_at: now,
        pdf_path: None,
    };

    // Step 9: Save to database
    state.db.save_analysis(&report)?;

    // Clean up work directory
    std::fs::remove_dir_all(&work_dir).ok();

    Ok(report)
}

#[tauri::command]
async fn get_analysis_history(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<AnalysisSummary>, String> {
    state.db.get_analysis_history()
}

#[tauri::command]
async fn get_analysis_by_id(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<AnalysisReport, String> {
    state.db.get_analysis_by_id(&id)
}

#[tauri::command]
async fn export_pdf(
    analysis_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let report = state.db.get_analysis_by_id(&analysis_id)?;

    let pdf_dir = state.data_dir.join("pdfs");
    std::fs::create_dir_all(&pdf_dir)
        .map_err(|e| format!("Failed to create PDF directory: {}", e))?;

    let safe_name = report
        .package_name
        .replace(|c: char| !c.is_alphanumeric() && c != '.', "_");
    let pdf_filename = format!("guardrails_{}_{}.pdf", safe_name, &report.id[..8]);
    let pdf_path = pdf_dir.join(&pdf_filename);

    let result = report::generate_pdf(&report, &pdf_path)?;

    state.db.update_pdf_path(&analysis_id, &result)?;

    Ok(result)
}

#[tauri::command]
async fn get_settings(
    state: tauri::State<'_, AppState>,
) -> Result<AppSettings, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    Ok(settings.clone())
}

#[tauri::command]
async fn save_settings(
    settings: AppSettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let settings_path = state.data_dir.join("settings.json");
    let json = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("Failed to serialize settings: {}", e))?;
    std::fs::write(&settings_path, json)
        .map_err(|e| format!("Failed to save settings: {}", e))?;

    let mut current = state
        .settings
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;
    *current = settings;

    Ok(())
}

#[tauri::command]
async fn check_virustotal_cmd(
    analysis_id: String,
    apk_path: String,
    state: tauri::State<'_, AppState>,
) -> Result<VirusTotalResult, String> {
    let api_key = {
        let settings = state
            .settings
            .lock()
            .map_err(|e| format!("Lock error: {}", e))?;
        settings
            .virustotal_api_key
            .clone()
            .ok_or_else(|| "VirusTotal API key not configured".to_string())?
    };

    let path = Path::new(&apk_path);
    let result = virustotal::check_virustotal(path, &api_key).await?;

    state
        .db
        .update_virustotal(&analysis_id, &result.status, result.detections)?;

    Ok(result)
}

fn generate_summary(
    verdict: &Verdict,
    permissions: &[Finding],
    sdks: &[Finding],
    patterns: &[Finding],
    assets: &[Finding],
) -> String {
    let critical_count = permissions
        .iter()
        .chain(sdks.iter())
        .chain(patterns.iter())
        .chain(assets.iter())
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let warning_count = permissions
        .iter()
        .chain(sdks.iter())
        .chain(patterns.iter())
        .chain(assets.iter())
        .filter(|f| f.severity == Severity::Warning)
        .count();

    match verdict {
        Verdict::Pass => {
            "This APK passed all policy checks. No critical or warning-level issues were detected."
                .to_string()
        }
        Verdict::Fail => {
            format!(
                "This APK has {} critical issue(s) and {} warning(s) that would likely result in Google Play rejection or developer account suspension. Critical items must be resolved before publishing.",
                critical_count, warning_count
            )
        }
        Verdict::Review => {
            format!(
                "This APK has {} warning(s) that require manual review. While no critical violations were found, the flagged items should be addressed or justified before publishing.",
                warning_count
            )
        }
    }
}

pub fn init_app_state(data_dir: &Path) -> Result<AppState, String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("Failed to create data dir: {}", e))?;

    let db_path = data_dir.join("guardrails.db");
    let db = Database::new(&db_path)?;

    let rules_path = data_dir.join("rules.toml");
    let rules = if rules_path.exists() {
        rules::load_rules(&rules_path)?
    } else {
        let default_rules = include_str!("../rules.toml");
        std::fs::write(&rules_path, default_rules)
            .map_err(|e| format!("Failed to write default rules: {}", e))?;
        rules::load_rules(&rules_path)?
    };

    let settings_path = data_dir.join("settings.json");
    let settings = if settings_path.exists() {
        let json = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("Failed to read settings: {}", e))?;
        serde_json::from_str(&json).unwrap_or(AppSettings {
            virustotal_api_key: None,
            rules_path: None,
        })
    } else {
        AppSettings {
            virustotal_api_key: None,
            rules_path: None,
        }
    };

    Ok(AppState {
        db,
        rules: Mutex::new(rules),
        settings: Mutex::new(settings),
        data_dir: data_dir.to_path_buf(),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("Failed to get app data directory");

            let state = init_app_state(&data_dir)
                .expect("Failed to initialize app state");

            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            analyze_apk,
            get_analysis_history,
            get_analysis_by_id,
            export_pdf,
            get_settings,
            save_settings,
            check_virustotal_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
