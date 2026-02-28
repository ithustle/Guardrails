export interface AnalysisReport {
  id: string;
  apk_filename: string;
  package_name: string;
  version_name: string | null;
  version_code: number | null;
  min_sdk: number | null;
  target_sdk: number | null;
  verdict: "PASS" | "FAIL" | "REVIEW";
  summary: string;
  metadata: MetadataSection;
  permissions: Finding[];
  sdks: Finding[];
  patterns: Finding[];
  assets: Finding[];
  virustotal: VirusTotalResult | null;
  created_at: string;
  pdf_path: string | null;
}

export interface AnalysisSummary {
  id: string;
  apk_filename: string;
  package_name: string;
  version_name: string | null;
  verdict: "PASS" | "FAIL" | "REVIEW";
  created_at: string;
}

export interface MetadataSection {
  package_name: string;
  version_name: string | null;
  version_code: number | null;
  min_sdk: number | null;
  target_sdk: number | null;
  target_sdk_status: string;
}

export interface Finding {
  category: "permission" | "sdk" | "pattern" | "asset" | "virustotal";
  severity: "critical" | "warning" | "info";
  title: string;
  description: string;
}

export interface VirusTotalResult {
  status: string;
  detections: number;
  total_engines: number;
  scan_date: string | null;
}

export interface AppSettings {
  virustotal_api_key: string | null;
  rules_path: string | null;
}
