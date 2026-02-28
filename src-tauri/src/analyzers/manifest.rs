use crate::models::{Finding, FindingCategory, MetadataSection, Severity};
use crate::rules::RulesConfig;

/// Manifest data extracted from binary XML.
/// We parse this ourselves from the binary Android XML format.
#[derive(Debug, Clone, Default)]
pub struct ManifestInfo {
    pub package_name: String,
    pub version_name: Option<String>,
    pub version_code: Option<i64>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    pub permissions: Vec<String>,
    pub exported_components: Vec<ExportedComponent>,
    pub meta_data_keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExportedComponent {
    pub component_type: String,
    pub name: String,
}

/// Parse the binary AndroidManifest.xml format.
/// Android binary XML uses a chunked format with string pool, resource IDs, etc.
/// We extract the key attributes we need for policy analysis.
pub fn parse_manifest(data: &[u8]) -> Result<ManifestInfo, String> {
    let mut info = ManifestInfo::default();

    // Try to extract strings from the binary XML string pool
    let strings = extract_string_pool(data);

    // Extract package name, versions, SDKs from attributes
    extract_manifest_attributes(data, &strings, &mut info);

    // Extract permissions
    for s in &strings {
        if s.starts_with("android.permission.") {
            if !info.permissions.contains(s) {
                info.permissions.push(s.clone());
            }
        }
    }

    // Extract meta-data keys and component info from strings
    for s in &strings {
        if s.contains(".") && !s.starts_with("android.permission.")
            && !s.starts_with("http") && !s.contains("/")
            && s.len() > 5
        {
            // Heuristic: looks like a Java package-style key
            if s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-') {
                info.meta_data_keys.push(s.clone());
            }
        }
    }

    // If we couldn't find a package name from attributes, search strings
    if info.package_name.is_empty() {
        for s in &strings {
            // Heuristic: package names typically have 2+ dots and look like reverse domain
            if s.contains('.') && !s.starts_with("android.")
                && !s.starts_with("http") && !s.contains('/')
                && s.split('.').count() >= 3
                && s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_')
            {
                info.package_name = s.clone();
                break;
            }
        }
    }

    if info.package_name.is_empty() {
        info.package_name = "unknown".to_string();
    }

    Ok(info)
}

/// Extract all UTF-8 and UTF-16LE strings from the binary XML string pool.
fn extract_string_pool(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();

    // Method 1: Look for the String Pool chunk (type 0x0001)
    // Binary XML starts with: magic(4) + filesize(4)
    // Then chunks follow: type(2) + headersize(2) + size(4) + ...
    if data.len() > 8 {
        // Try to find string pool chunk
        if let Some(pool_strings) = parse_string_pool_chunk(data) {
            strings.extend(pool_strings);
        }
    }

    // Method 2: Also scan for raw UTF-8 strings as fallback
    let mut i = 0;
    while i < data.len() {
        if data[i] >= 0x20 && data[i] < 0x7f {
            let start = i;
            while i < data.len() && data[i] >= 0x20 && data[i] < 0x7f {
                i += 1;
            }
            if i - start >= 4 {
                let s = String::from_utf8_lossy(&data[start..i]).to_string();
                if !strings.contains(&s) {
                    strings.push(s);
                }
            }
        } else {
            i += 1;
        }
    }

    strings
}

/// Parse the actual string pool chunk from binary XML.
fn parse_string_pool_chunk(data: &[u8]) -> Option<Vec<String>> {
    // Android binary XML format:
    // File header: u32 magic (0x00080003), u32 file_size
    // String pool chunk: u16 type (0x0001), u16 header_size, u32 chunk_size,
    //   u32 string_count, u32 style_count, u32 flags, u32 strings_start, u32 styles_start
    //   Then u32[string_count] offsets, then actual string data

    if data.len() < 8 {
        return None;
    }

    let mut strings = Vec::new();

    // Find string pool chunk - look for type 0x0001
    let mut pos = 8; // Skip file header
    while pos + 8 < data.len() {
        let chunk_type = u16::from_le_bytes([data[pos], data[pos + 1]]);

        if chunk_type == 0x0001 {
            // String Pool chunk
            let header_size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let _chunk_size = u32::from_le_bytes([
                data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
            ]) as usize;

            if pos + header_size > data.len() || header_size < 28 {
                break;
            }

            let string_count = u32::from_le_bytes([
                data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11],
            ]) as usize;

            let flags = u32::from_le_bytes([
                data[pos + 16], data[pos + 17], data[pos + 18], data[pos + 19],
            ]);
            let is_utf8 = (flags & (1 << 8)) != 0;

            let strings_start = u32::from_le_bytes([
                data[pos + 20], data[pos + 21], data[pos + 22], data[pos + 23],
            ]) as usize;

            let offsets_start = pos + header_size;
            let data_start = pos + strings_start;

            for idx in 0..string_count {
                let offset_pos = offsets_start + idx * 4;
                if offset_pos + 4 > data.len() {
                    break;
                }
                let offset = u32::from_le_bytes([
                    data[offset_pos], data[offset_pos + 1],
                    data[offset_pos + 2], data[offset_pos + 3],
                ]) as usize;

                let str_pos = data_start + offset;
                if str_pos >= data.len() {
                    continue;
                }

                let extracted = if is_utf8 {
                    extract_utf8_string(data, str_pos)
                } else {
                    extract_utf16_string(data, str_pos)
                };

                if let Some(s) = extracted {
                    if !s.is_empty() {
                        strings.push(s);
                    }
                }
            }

            return Some(strings);
        }

        // Move to next chunk
        if pos + 4 >= data.len() {
            break;
        }
        let chunk_size = u32::from_le_bytes([
            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
        ]) as usize;
        if chunk_size == 0 || chunk_size > data.len() {
            break;
        }
        pos += chunk_size;
    }

    Some(strings)
}

fn extract_utf8_string(data: &[u8], pos: usize) -> Option<String> {
    if pos + 2 >= data.len() {
        return None;
    }
    // UTF-8 format: u16 char_count, u16 byte_count, then string bytes, then 0x00
    // Actually in practice it's: u8/u16 char_len, u8/u16 byte_len, bytes, null
    let char_len = data[pos] as usize;
    let byte_len_offset = if char_len > 0x7f { pos + 2 } else { pos + 1 };
    if byte_len_offset >= data.len() {
        return None;
    }
    let byte_len = data[byte_len_offset] as usize;
    let str_start = if char_len > 0x7f {
        byte_len_offset + 2
    } else if byte_len > 0x7f {
        byte_len_offset + 2
    } else {
        byte_len_offset + 1
    };

    let actual_len = byte_len.min(data.len().saturating_sub(str_start));
    if str_start + actual_len > data.len() {
        return None;
    }

    String::from_utf8(data[str_start..str_start + actual_len].to_vec()).ok()
}

fn extract_utf16_string(data: &[u8], pos: usize) -> Option<String> {
    if pos + 2 >= data.len() {
        return None;
    }
    let char_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    let str_start = pos + 2;

    if char_count == 0 || char_count > 4096 {
        return None;
    }

    let byte_len = char_count * 2;
    if str_start + byte_len > data.len() {
        return None;
    }

    let u16_chars: Vec<u16> = (0..char_count)
        .filter_map(|i| {
            let offset = str_start + i * 2;
            if offset + 2 <= data.len() {
                Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
            } else {
                None
            }
        })
        .collect();

    String::from_utf16(&u16_chars).ok()
}

/// Try to extract attributes directly from binary XML attribute chunks.
fn extract_manifest_attributes(data: &[u8], strings: &[String], info: &mut ManifestInfo) {
    // Look for known attribute patterns in string pool
    for (i, s) in strings.iter().enumerate() {
        match s.as_str() {
            "package" => {
                // The value might be the next meaningful string
                if let Some(val) = find_attribute_value(strings, i) {
                    if val.contains('.') && !val.starts_with("android.") {
                        info.package_name = val;
                    }
                }
            }
            "versionName" => {
                if let Some(val) = find_attribute_value(strings, i) {
                    info.version_name = Some(val);
                }
            }
            _ => {}
        }
    }

    // Scan for SDK version numbers in the binary data
    // Look for minSdkVersion and targetSdkVersion resource IDs
    // Resource ID for minSdkVersion: 0x0101020c
    // Resource ID for targetSdkVersion: 0x01010270
    let min_sdk_id: [u8; 4] = [0x0c, 0x02, 0x01, 0x01];
    let target_sdk_id: [u8; 4] = [0x70, 0x02, 0x01, 0x01];

    for i in 0..data.len().saturating_sub(20) {
        if data[i..i + 4] == min_sdk_id {
            // The value is typically nearby in the attribute structure
            // In binary XML attribute: ns(4), name(4), rawValue(4), typedValue(8)
            // Look for int value after the resource ID
            if i + 16 < data.len() {
                let val = u32::from_le_bytes([
                    data[i + 12], data[i + 13], data[i + 14], data[i + 15],
                ]);
                if val > 0 && val < 100 {
                    info.min_sdk = Some(val as i32);
                }
            }
        }
        if data[i..i + 4] == target_sdk_id {
            if i + 16 < data.len() {
                let val = u32::from_le_bytes([
                    data[i + 12], data[i + 13], data[i + 14], data[i + 15],
                ]);
                if val > 0 && val < 100 {
                    info.target_sdk = Some(val as i32);
                }
            }
        }
    }
}

fn find_attribute_value(strings: &[String], key_idx: usize) -> Option<String> {
    // Look at nearby strings for a plausible value
    for offset in 1..5 {
        if key_idx + offset < strings.len() {
            let candidate = &strings[key_idx + offset];
            if !candidate.is_empty()
                && candidate != "manifest"
                && candidate != "uses-permission"
                && candidate != "application"
                && candidate != "activity"
                && candidate != "service"
                && candidate != "receiver"
                && candidate != "provider"
            {
                return Some(candidate.clone());
            }
        }
    }
    None
}

pub fn analyze_manifest(
    manifest_info: &ManifestInfo,
    rules: &RulesConfig,
) -> (MetadataSection, Vec<Finding>) {
    let mut findings = Vec::new();

    // Check target SDK
    let target_sdk_status = match manifest_info.target_sdk {
        Some(sdk) if sdk >= rules.meta.google_min_target_sdk => "OK".to_string(),
        Some(sdk) => {
            let msg = format!(
                "BELOW MINIMUM (found: {}, required: {})",
                sdk, rules.meta.google_min_target_sdk
            );
            findings.push(Finding {
                category: FindingCategory::Permission,
                severity: Severity::Critical,
                title: "Target SDK below minimum".to_string(),
                description: format!(
                    "Target SDK {} is below Google Play minimum of {}. App will be rejected.",
                    sdk, rules.meta.google_min_target_sdk
                ),
            });
            msg
        }
        None => "UNKNOWN".to_string(),
    };

    let metadata = MetadataSection {
        package_name: manifest_info.package_name.clone(),
        version_name: manifest_info.version_name.clone(),
        version_code: manifest_info.version_code,
        min_sdk: manifest_info.min_sdk,
        target_sdk: manifest_info.target_sdk,
        target_sdk_status,
    };

    // Check permissions against rules
    for perm in &manifest_info.permissions {
        for rule in &rules.permissions.critical {
            if perm == &rule.name {
                findings.push(Finding {
                    category: FindingCategory::Permission,
                    severity: Severity::Critical,
                    title: perm.clone(),
                    description: rule.reason.clone(),
                });
            }
        }
        for rule in &rules.permissions.warning {
            if perm == &rule.name {
                findings.push(Finding {
                    category: FindingCategory::Permission,
                    severity: Severity::Warning,
                    title: perm.clone(),
                    description: rule.reason.clone(),
                });
            }
        }
    }

    (metadata, findings)
}
