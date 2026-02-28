use crate::models::{Finding, FindingCategory, Severity};
use crate::rules::RulesConfig;
use std::path::Path;

/// DEX file header constants
const DEX_MAGIC: &[u8] = b"dex\n";
const HEADER_SIZE: usize = 112;

/// Parsed DEX file information
#[derive(Debug, Default)]
pub struct DexInfo {
    pub class_names: Vec<String>,
    pub method_refs: Vec<String>,
    pub string_constants: Vec<String>,
}

/// Read a DEX file and extract class names, method refs, and strings.
/// We implement a minimal DEX parser since available crates may be unreliable.
pub fn parse_dex(path: &Path) -> Result<DexInfo, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("Failed to read DEX file: {}", e))?;

    if data.len() < HEADER_SIZE {
        return Err("DEX file too small".to_string());
    }

    if &data[0..4] != DEX_MAGIC {
        return Err("Invalid DEX magic bytes".to_string());
    }

    let mut info = DexInfo::default();

    // Parse string IDs from DEX header
    let string_ids_size = read_u32(&data, 56) as usize;
    let string_ids_off = read_u32(&data, 60) as usize;

    // Parse type IDs
    let type_ids_size = read_u32(&data, 64) as usize;
    let type_ids_off = read_u32(&data, 68) as usize;

    // Parse method IDs
    let method_ids_size = read_u32(&data, 88) as usize;
    let method_ids_off = read_u32(&data, 92) as usize;

    // Extract all strings from string table
    let strings = extract_dex_strings(&data, string_ids_size, string_ids_off);
    info.string_constants = strings.clone();

    // Extract type names (class names)
    for i in 0..type_ids_size {
        let offset = type_ids_off + i * 4;
        if offset + 4 > data.len() {
            break;
        }
        let descriptor_idx = read_u32(&data, offset) as usize;
        if descriptor_idx < strings.len() {
            let type_name = &strings[descriptor_idx];
            // Convert DEX type descriptor to Java class name
            // e.g., "Lcom/example/MyClass;" -> "com.example.MyClass"
            if type_name.starts_with('L') && type_name.ends_with(';') {
                let class_name = type_name[1..type_name.len() - 1].replace('/', ".");
                info.class_names.push(class_name);
            }
        }
    }

    // Extract method references
    for i in 0..method_ids_size {
        let offset = method_ids_off + i * 8;
        if offset + 8 > data.len() {
            break;
        }
        let class_idx = read_u16(&data, offset) as usize;
        let name_idx = read_u32(&data, offset + 4) as usize;

        let class_name = if class_idx < info.class_names.len() {
            info.class_names[class_idx].clone()
        } else if class_idx < type_ids_size {
            // Look up type directly
            let type_offset = type_ids_off + class_idx * 4;
            if type_offset + 4 <= data.len() {
                let desc_idx = read_u32(&data, type_offset) as usize;
                if desc_idx < strings.len() {
                    let desc = &strings[desc_idx];
                    if desc.starts_with('L') && desc.ends_with(';') {
                        desc[1..desc.len() - 1].replace('/', ".")
                    } else {
                        desc.clone()
                    }
                } else {
                    "unknown".to_string()
                }
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        };

        let method_name = if name_idx < strings.len() {
            strings[name_idx].clone()
        } else {
            "unknown".to_string()
        };

        info.method_refs.push(format!("{}.{}", class_name, method_name));
    }

    Ok(info)
}

fn extract_dex_strings(data: &[u8], count: usize, offset: usize) -> Vec<String> {
    let mut strings = Vec::with_capacity(count);

    for i in 0..count {
        let id_offset = offset + i * 4;
        if id_offset + 4 > data.len() {
            break;
        }
        let string_data_off = read_u32(data, id_offset) as usize;
        if string_data_off >= data.len() {
            strings.push(String::new());
            continue;
        }

        // Read MUTF-8 encoded string
        // First comes the size as ULEB128, then the string data
        let (_, size_bytes) = read_uleb128(data, string_data_off);
        let str_start = string_data_off + size_bytes;

        if str_start >= data.len() {
            strings.push(String::new());
            continue;
        }

        // Find null terminator
        let mut end = str_start;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }

        let s = String::from_utf8_lossy(&data[str_start..end]).to_string();
        strings.push(s);
    }

    strings
}

fn read_uleb128(data: &[u8], offset: usize) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut bytes_read = 0;
    let mut pos = offset;

    loop {
        if pos >= data.len() {
            break;
        }
        let byte = data[pos];
        pos += 1;
        bytes_read += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            break;
        }
    }

    (result, bytes_read)
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub fn analyze_dex(dex_infos: &[DexInfo], rules: &RulesConfig) -> (Vec<Finding>, Vec<Finding>) {
    let mut sdk_findings = Vec::new();
    let mut pattern_findings = Vec::new();

    for dex in dex_infos {
        // Check for blocked/warning SDKs
        for class in &dex.class_names {
            for rule in &rules.sdks.blocked {
                if class.starts_with(&rule.package_prefix) {
                    let finding = Finding {
                        category: FindingCategory::Sdk,
                        severity: Severity::Critical,
                        title: format!("Blocked SDK: {}", rule.package_prefix),
                        description: rule.reason.clone(),
                    };
                    if !sdk_findings.iter().any(|f: &Finding| f.title == finding.title) {
                        sdk_findings.push(finding);
                    }
                }
            }
            for rule in &rules.sdks.warning {
                if class.starts_with(&rule.package_prefix) {
                    let finding = Finding {
                        category: FindingCategory::Sdk,
                        severity: Severity::Warning,
                        title: format!("SDK warning: {}", rule.package_prefix),
                        description: rule.reason.clone(),
                    };
                    if !sdk_findings.iter().any(|f: &Finding| f.title == finding.title) {
                        sdk_findings.push(finding);
                    }
                }
            }
        }

        // Check for critical patterns
        for method in &dex.method_refs {
            for rule in &rules.patterns.critical {
                if method.contains(&rule.signature) {
                    let finding = Finding {
                        category: FindingCategory::Pattern,
                        severity: Severity::Critical,
                        title: format!("Critical pattern: {}", rule.signature),
                        description: format!("{} Found in method reference: {}", rule.reason, method),
                    };
                    if !pattern_findings.iter().any(|f: &Finding| f.title == finding.title) {
                        pattern_findings.push(finding);
                    }
                }
            }
            for rule in &rules.patterns.warning {
                if method.contains(&rule.signature) {
                    let finding = Finding {
                        category: FindingCategory::Pattern,
                        severity: Severity::Warning,
                        title: format!("Warning pattern: {}", rule.signature),
                        description: format!("{} Found in method reference: {}", rule.reason, method),
                    };
                    if !pattern_findings.iter().any(|f: &Finding| f.title == finding.title) {
                        pattern_findings.push(finding);
                    }
                }
            }
            for rule in &rules.patterns.info {
                if method.contains(&rule.signature) {
                    let finding = Finding {
                        category: FindingCategory::Pattern,
                        severity: Severity::Info,
                        title: format!("Info: {}", rule.signature),
                        description: format!("{} Found in method reference: {}", rule.reason, method),
                    };
                    if !pattern_findings.iter().any(|f: &Finding| f.title == finding.title) {
                        pattern_findings.push(finding);
                    }
                }
            }
        }

        // Also check string constants for patterns
        for s in &dex.string_constants {
            for rule in &rules.patterns.critical {
                if s.contains(&rule.signature) {
                    let finding = Finding {
                        category: FindingCategory::Pattern,
                        severity: Severity::Critical,
                        title: format!("Critical pattern: {}", rule.signature),
                        description: format!("{} Found in string constant.", rule.reason),
                    };
                    if !pattern_findings.iter().any(|f: &Finding| f.title == finding.title) {
                        pattern_findings.push(finding);
                    }
                }
            }
        }
    }

    (sdk_findings, pattern_findings)
}
