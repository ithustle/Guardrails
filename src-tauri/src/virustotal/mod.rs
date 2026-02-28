use crate::models::VirusTotalResult;
use sha2::{Digest, Sha256};
use std::path::Path;

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";

pub async fn check_virustotal(
    apk_path: &Path,
    api_key: &str,
) -> Result<VirusTotalResult, String> {
    if api_key.trim().is_empty() {
        return Err("VirusTotal API key is empty".to_string());
    }

    let data = std::fs::read(apk_path)
        .map_err(|e| format!("Failed to read APK for hashing: {}", e))?;
    let hash = hex::encode(Sha256::digest(&data));

    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/files/{}", VT_API_BASE, hash))
        .header("x-apikey", api_key)
        .send()
        .await
        .map_err(|e| format!("VirusTotal API error: {}", e))?;

    match response.status().as_u16() {
        200 => {
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse VT response: {}", e))?;
            parse_vt_response(&body)
        }
        404 => upload_and_scan(&client, apk_path, api_key).await,
        401 => Err("VirusTotal API key is invalid (401 Unauthorized)".to_string()),
        429 => Err("VirusTotal API rate limit exceeded. Try again later.".to_string()),
        status => Err(format!("VirusTotal API returned status: {}", status)),
    }
}

async fn upload_and_scan(
    client: &reqwest::Client,
    apk_path: &Path,
    api_key: &str,
) -> Result<VirusTotalResult, String> {
    let file_data = std::fs::read(apk_path)
        .map_err(|e| format!("Failed to read APK: {}", e))?;

    let filename = apk_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown.apk".to_string());

    let part = reqwest::multipart::Part::bytes(file_data)
        .file_name(filename)
        .mime_str("application/vnd.android.package-archive")
        .map_err(|e| format!("Failed to create multipart: {}", e))?;

    let form = reqwest::multipart::Form::new().part("file", part);

    let response = client
        .post(format!("{}/files", VT_API_BASE))
        .header("x-apikey", api_key)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("VT upload error: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("VT upload failed with status: {}", response.status()));
    }

    Ok(VirusTotalResult {
        status: "PENDING".to_string(),
        detections: 0,
        total_engines: 0,
        scan_date: None,
    })
}

fn parse_vt_response(body: &serde_json::Value) -> Result<VirusTotalResult, String> {
    let stats = &body["data"]["attributes"]["last_analysis_stats"];

    if stats.is_null() {
        return Err(
            "VirusTotal response missing analysis stats. The file may still be processing."
                .to_string(),
        );
    }

    let malicious = stats["malicious"].as_i64().unwrap_or(0) as i32;
    let suspicious = stats["suspicious"].as_i64().unwrap_or(0) as i32;
    let undetected = stats["undetected"].as_i64().unwrap_or(0) as i32;
    let harmless = stats["harmless"].as_i64().unwrap_or(0) as i32;

    let total = malicious + suspicious + undetected + harmless;
    let flagged = malicious + suspicious;

    if total == 0 {
        return Err("VirusTotal returned zero engine results. Scan may be incomplete.".to_string());
    }

    let status = if flagged == 0 {
        "CLEAN".to_string()
    } else if malicious > 3 {
        "MALICIOUS".to_string()
    } else {
        "SUSPICIOUS".to_string()
    };

    let scan_date = body["data"]["attributes"]["last_analysis_date"]
        .as_i64()
        .and_then(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        });

    Ok(VirusTotalResult {
        status,
        detections: flagged,
        total_engines: total,
        scan_date,
    })
}
