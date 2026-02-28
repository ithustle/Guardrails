import { invoke } from "@tauri-apps/api/core";
import type {
  AnalysisReport,
  AnalysisSummary,
  AppSettings,
  VirusTotalResult,
} from "./types";

export async function analyzeApk(path: string): Promise<AnalysisReport> {
  return invoke<AnalysisReport>("analyze_apk", { path });
}

export async function getAnalysisHistory(): Promise<AnalysisSummary[]> {
  return invoke<AnalysisSummary[]>("get_analysis_history");
}

export async function getAnalysisById(id: string): Promise<AnalysisReport> {
  return invoke<AnalysisReport>("get_analysis_by_id", { id });
}

export async function exportPdf(analysisId: string): Promise<string> {
  return invoke<string>("export_pdf", { analysisId });
}

export async function getSettings(): Promise<AppSettings> {
  return invoke<AppSettings>("get_settings");
}

export async function saveSettings(settings: AppSettings): Promise<void> {
  return invoke<void>("save_settings", { settings });
}

export async function checkVirusTotal(
  analysisId: string,
  apkPath: string
): Promise<VirusTotalResult> {
  return invoke<VirusTotalResult>("check_virustotal_cmd", {
    analysisId,
    apkPath,
  });
}
