use crate::models::{Finding, FindingCategory, Severity};
use crate::rules::RulesConfig;
use std::collections::HashSet;
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

    let string_ids_size = read_u32(&data, 56) as usize;
    let string_ids_off = read_u32(&data, 60) as usize;
    let type_ids_size = read_u32(&data, 64) as usize;
    let type_ids_off = read_u32(&data, 68) as usize;
    let method_ids_size = read_u32(&data, 88) as usize;
    let method_ids_off = read_u32(&data, 92) as usize;

    let strings = extract_dex_strings(&data, string_ids_size, string_ids_off);
    info.string_constants = strings.clone();

    // Build type name lookup: type_idx -> resolved class name
    let mut type_names: Vec<String> = Vec::with_capacity(type_ids_size);
    for i in 0..type_ids_size {
        let offset = type_ids_off + i * 4;
        if offset + 4 > data.len() {
            type_names.push(String::new());
            continue;
        }
        let descriptor_idx = read_u32(&data, offset) as usize;
        if descriptor_idx < strings.len() {
            let type_desc = &strings[descriptor_idx];
            if type_desc.starts_with('L') && type_desc.ends_with(';') {
                type_names.push(type_desc[1..type_desc.len() - 1].replace('/', "."));
            } else {
                type_names.push(type_desc.clone());
            }
        } else {
            type_names.push(String::new());
        }
    }

    info.class_names = type_names.iter()
        .filter(|s| !s.is_empty() && s.contains('.'))
        .cloned()
        .collect();

    // Parse method_id_item: class_idx(u16) + proto_idx(u16) + name_idx(u32) = 8 bytes
    for i in 0..method_ids_size {
        let offset = method_ids_off + i * 8;
        if offset + 8 > data.len() {
            break;
        }
        let class_idx = read_u16(&data, offset) as usize;
        // proto_idx at offset+2 — not needed for policy analysis
        let name_idx = read_u32(&data, offset + 4) as usize;

        let class_name = type_names.get(class_idx).map(|s| s.as_str()).unwrap_or("unknown");
        let method_name = strings.get(name_idx).map(|s| s.as_str()).unwrap_or("unknown");

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

        let (_, size_bytes) = read_uleb128(data, string_data_off);
        let str_start = string_data_off + size_bytes;

        if str_start >= data.len() {
            strings.push(String::new());
            continue;
        }

        let mut end = str_start;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }

        strings.push(String::from_utf8_lossy(&data[str_start..end]).into_owned());
    }

    strings
}

fn read_uleb128(data: &[u8], offset: usize) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut bytes_read = 0;
    let mut pos = offset;

    loop {
        if pos >= data.len() { break; }
        let byte = data[pos];
        pos += 1;
        bytes_read += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if (byte & 0x80) == 0 { break; }
        shift += 7;
        if shift >= 35 { break; }
    }

    (result, bytes_read)
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub fn analyze_dex(dex_infos: &[DexInfo], rules: &RulesConfig) -> (Vec<Finding>, Vec<Finding>) {
    let mut sdk_findings = Vec::new();
    let mut pattern_findings = Vec::new();
    let mut seen_sdk: HashSet<String> = HashSet::new();
    let mut seen_pattern: HashSet<String> = HashSet::new();

    for dex in dex_infos {
        for class in &dex.class_names {
            for rule in &rules.sdks.blocked {
                if class.starts_with(&rule.package_prefix) {
                    let title = format!("Blocked SDK: {}", rule.package_prefix);
                    if seen_sdk.insert(title.clone()) {
                        sdk_findings.push(Finding {
                            category: FindingCategory::Sdk,
                            severity: Severity::Critical,
                            title,
                            description: rule.reason.clone(),
                        });
                    }
                }
            }
            for rule in &rules.sdks.warning {
                if class.starts_with(&rule.package_prefix) {
                    let title = format!("SDK warning: {}", rule.package_prefix);
                    if seen_sdk.insert(title.clone()) {
                        sdk_findings.push(Finding {
                            category: FindingCategory::Sdk,
                            severity: Severity::Warning,
                            title,
                            description: rule.reason.clone(),
                        });
                    }
                }
            }
        }

        for method in &dex.method_refs {
            check_patterns(method, rules, &mut pattern_findings, &mut seen_pattern, "method reference");
        }

        for s in &dex.string_constants {
            check_patterns(s, rules, &mut pattern_findings, &mut seen_pattern, "string constant");
        }
    }

    (sdk_findings, pattern_findings)
}

fn check_patterns(
    haystack: &str,
    rules: &RulesConfig,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
    source: &str,
) {
    for rule in &rules.patterns.critical {
        if haystack.contains(&rule.signature) {
            let title = format!("Critical pattern: {}", rule.signature);
            if seen.insert(title.clone()) {
                findings.push(Finding {
                    category: FindingCategory::Pattern,
                    severity: Severity::Critical,
                    title,
                    description: format!("{} Found in {}.", rule.reason, source),
                });
            }
        }
    }
    for rule in &rules.patterns.warning {
        if haystack.contains(&rule.signature) {
            let title = format!("Warning pattern: {}", rule.signature);
            if seen.insert(title.clone()) {
                findings.push(Finding {
                    category: FindingCategory::Pattern,
                    severity: Severity::Warning,
                    title,
                    description: format!("{} Found in {}.", rule.reason, source),
                });
            }
        }
    }
    for rule in &rules.patterns.info {
        if haystack.contains(&rule.signature) {
            let title = format!("Info: {}", rule.signature);
            if seen.insert(title.clone()) {
                findings.push(Finding {
                    category: FindingCategory::Pattern,
                    severity: Severity::Info,
                    title,
                    description: format!("{} Found in {}.", rule.reason, source),
                });
            }
        }
    }
}
