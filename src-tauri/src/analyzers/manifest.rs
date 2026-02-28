use crate::models::{Finding, FindingCategory, MetadataSection, Severity};
use crate::rules::RulesConfig;
use std::collections::HashSet;

/// Manifest data extracted from binary XML.
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

// Android binary XML chunk types
const CHUNK_STRINGPOOL: u16 = 0x0001;
const CHUNK_RESOURCEIDS: u16 = 0x0180;
const CHUNK_START_ELEMENT: u16 = 0x0102;


// Android resource IDs for manifest attributes
const RES_NAME: u32 = 0x01010003;
const RES_VERSION_CODE: u32 = 0x0101021b;
const RES_VERSION_NAME: u32 = 0x0101021c;
const RES_MIN_SDK: u32 = 0x0101020c;
const RES_TARGET_SDK: u32 = 0x01010270;
const RES_EXPORTED: u32 = 0x01010010;

// Typed value types
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

/// Parse the binary AndroidManifest.xml with proper chunk-based parsing.
pub fn parse_manifest(data: &[u8]) -> Result<ManifestInfo, String> {
    if data.len() < 8 {
        return Err("Manifest data too small".to_string());
    }

    let mut info = ManifestInfo::default();
    let mut strings: Vec<String> = Vec::new();
    let mut resource_ids: Vec<u32> = Vec::new();

    let mut pos: usize = 8; // skip file header (magic + size)

    // First pass: extract string pool and resource IDs
    while pos + 8 <= data.len() {
        let chunk_type = read_u16(data, pos);
        let chunk_header_size = read_u16(data, pos + 2) as usize;
        let chunk_size = read_u32(data, pos + 4) as usize;

        if chunk_size < 8 || pos + chunk_size > data.len() {
            break;
        }

        match chunk_type {
            CHUNK_STRINGPOOL => {
                strings = parse_string_pool(data, pos, chunk_header_size);
            }
            CHUNK_RESOURCEIDS => {
                let count = (chunk_size - 8) / 4;
                for i in 0..count {
                    let off = pos + 8 + i * 4;
                    if off + 4 <= data.len() {
                        resource_ids.push(read_u32(data, off));
                    }
                }
            }
            _ => {}
        }

        pos += chunk_size;
    }

    // Second pass: parse XML elements
    pos = 8;
    let mut seen_permissions: HashSet<String> = HashSet::new();

    while pos + 8 <= data.len() {
        let chunk_type = read_u16(data, pos);
        let chunk_size = read_u32(data, pos + 4) as usize;

        if chunk_size < 8 || pos + chunk_size > data.len() {
            break;
        }

        if chunk_type == CHUNK_START_ELEMENT {
            parse_start_element(
                data, pos, &strings, &resource_ids,
                &mut info, &mut seen_permissions,
            );
        }

        pos += chunk_size;
    }

    if info.package_name.is_empty() {
        info.package_name = "unknown".to_string();
    }

    Ok(info)
}

/// Parse a START_ELEMENT chunk to extract tag name and attributes.
fn parse_start_element(
    data: &[u8],
    pos: usize,
    strings: &[String],
    resource_ids: &[u32],
    info: &mut ManifestInfo,
    seen_permissions: &mut HashSet<String>,
) {
    // START_ELEMENT layout:
    // header: type(2) + header_size(2) + chunk_size(4)
    // ext: line_number(4) + comment(4)
    // ns(4) + name(4) + attr_start(2) + attr_size(2) + attr_count(2)
    // + id_idx(2) + class_idx(2) + style_idx(2)
    if pos + 36 > data.len() {
        return;
    }

    let name_idx = read_u32(data, pos + 20) as usize;
    let attr_count = read_u16(data, pos + 28) as usize;

    let element_name = strings.get(name_idx).cloned().unwrap_or_default();

    let attr_start = pos + 36;
    let mut attrs: Vec<(u32, AttrValue)> = Vec::new();

    for i in 0..attr_count {
        let attr_off = attr_start + i * 20;
        if attr_off + 20 > data.len() {
            break;
        }

        let attr_ns = read_u32(data, attr_off);
        let attr_name_idx = read_u32(data, attr_off + 4) as usize;
        let raw_value_idx = read_u32(data, attr_off + 8);
        // Typed value: size(2) + res0(1) + type(1) + data(4)
        let typed_type = data[attr_off + 15];
        let typed_data = read_u32(data, attr_off + 16);

        // Resolve resource ID for this attribute name
        let res_id = if attr_ns != 0xFFFFFFFF && attr_name_idx < resource_ids.len() {
            resource_ids[attr_name_idx]
        } else {
            0
        };

        let value = match typed_type {
            TYPE_STRING => {
                let str_idx = typed_data as usize;
                AttrValue::Str(strings.get(str_idx).cloned().unwrap_or_default())
            }
            TYPE_INT_DEC | TYPE_INT_HEX => AttrValue::Int(typed_data as i64),
            TYPE_INT_BOOLEAN => AttrValue::Bool(typed_data != 0),
            _ => {
                if raw_value_idx != 0xFFFFFFFF {
                    AttrValue::Str(strings.get(raw_value_idx as usize).cloned().unwrap_or_default())
                } else {
                    AttrValue::Int(typed_data as i64)
                }
            }
        };

        attrs.push((res_id, value));
    }

    match element_name.as_str() {
        "manifest" => {
            for (res_id, value) in &attrs {
                match *res_id {
                    RES_NAME => {
                        if let AttrValue::Str(s) = value {
                            if !s.is_empty() && s.contains('.') {
                                info.package_name = s.clone();
                            }
                        }
                    }
                    RES_VERSION_CODE => {
                        if let AttrValue::Int(v) = value {
                            info.version_code = Some(*v);
                        }
                    }
                    RES_VERSION_NAME => {
                        if let AttrValue::Str(s) = value {
                            info.version_name = Some(s.clone());
                        }
                    }
                    _ => {
                        // Fallback: package name may appear as unresolved string attr
                        if info.package_name.is_empty() {
                            if let AttrValue::Str(s) = value {
                                if s.contains('.') && !s.starts_with("http")
                                    && s.split('.').count() >= 2
                                    && s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_')
                                {
                                    info.package_name = s.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
        "uses-sdk" => {
            for (res_id, value) in &attrs {
                match *res_id {
                    RES_MIN_SDK => {
                        if let AttrValue::Int(v) = value {
                            info.min_sdk = Some(*v as i32);
                        }
                    }
                    RES_TARGET_SDK => {
                        if let AttrValue::Int(v) = value {
                            info.target_sdk = Some(*v as i32);
                        }
                    }
                    _ => {}
                }
            }
        }
        "uses-permission" => {
            for (res_id, value) in &attrs {
                if *res_id == RES_NAME || *res_id == 0 {
                    if let AttrValue::Str(s) = value {
                        if s.starts_with("android.permission.") && seen_permissions.insert(s.clone()) {
                            info.permissions.push(s.clone());
                        }
                    }
                }
            }
        }
        "activity" | "service" | "receiver" | "provider" => {
            let mut comp_name = String::new();
            let mut exported = None;
            for (res_id, value) in &attrs {
                if *res_id == RES_NAME {
                    if let AttrValue::Str(s) = value {
                        comp_name = s.clone();
                    }
                }
                if *res_id == RES_EXPORTED {
                    match value {
                        AttrValue::Bool(b) => exported = Some(*b),
                        AttrValue::Int(v) => exported = Some(*v != 0),
                        _ => {}
                    }
                }
            }
            if exported == Some(true) && !comp_name.is_empty() {
                info.exported_components.push(ExportedComponent {
                    component_type: element_name.clone(),
                    name: comp_name,
                });
            }
        }
        "meta-data" => {
            for (res_id, value) in &attrs {
                if *res_id == RES_NAME {
                    if let AttrValue::Str(s) = value {
                        if !s.is_empty() {
                            info.meta_data_keys.push(s.clone());
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

#[derive(Debug, Clone)]
enum AttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

/// Parse the string pool chunk.
fn parse_string_pool(data: &[u8], pos: usize, header_size: usize) -> Vec<String> {
    let mut strings = Vec::new();

    if pos + header_size > data.len() || header_size < 28 {
        return strings;
    }

    let string_count = read_u32(data, pos + 8) as usize;
    let flags = read_u32(data, pos + 16);
    let is_utf8 = (flags & (1 << 8)) != 0;
    let strings_start = read_u32(data, pos + 20) as usize;

    let offsets_start = pos + header_size;
    let data_start = pos + strings_start;

    for idx in 0..string_count {
        let offset_pos = offsets_start + idx * 4;
        if offset_pos + 4 > data.len() {
            break;
        }
        let offset = read_u32(data, offset_pos) as usize;
        let str_pos = data_start + offset;
        if str_pos >= data.len() {
            strings.push(String::new());
            continue;
        }

        let extracted = if is_utf8 {
            extract_utf8_string(data, str_pos)
        } else {
            extract_utf16_string(data, str_pos)
        };

        strings.push(extracted.unwrap_or_default());
    }

    strings
}

fn extract_utf8_string(data: &[u8], pos: usize) -> Option<String> {
    if pos + 2 >= data.len() {
        return None;
    }
    let first = data[pos];
    let char_len_bytes: usize = if first & 0x80 != 0 { 2 } else { 1 };

    let byte_len_pos = pos + char_len_bytes;
    if byte_len_pos >= data.len() {
        return None;
    }
    let bl_first = data[byte_len_pos];
    let (byte_len_bytes, byte_len) = if bl_first & 0x80 != 0 {
        let second = *data.get(byte_len_pos + 1).unwrap_or(&0) as usize;
        (2usize, ((bl_first as usize & 0x7f) << 8) | second)
    } else {
        (1usize, bl_first as usize)
    };

    let str_start = byte_len_pos + byte_len_bytes;
    let str_end = str_start + byte_len;
    if str_end > data.len() {
        return None;
    }

    Some(String::from_utf8_lossy(&data[str_start..str_end]).into_owned())
}

fn extract_utf16_string(data: &[u8], pos: usize) -> Option<String> {
    if pos + 4 >= data.len() {
        return None;
    }
    let char_count = read_u16(data, pos) as usize;
    let str_start = pos + 2;

    if char_count == 0 {
        return Some(String::new());
    }
    if char_count > 32768 {
        return None;
    }

    let byte_len = char_count * 2;
    if str_start + byte_len > data.len() {
        return None;
    }

    let u16_chars: Vec<u16> = (0..char_count)
        .filter_map(|i| {
            let off = str_start + i * 2;
            if off + 2 <= data.len() {
                Some(u16::from_le_bytes([data[off], data[off + 1]]))
            } else {
                None
            }
        })
        .collect();

    Some(String::from_utf16_lossy(&u16_chars))
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() { return 0; }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub fn analyze_manifest(
    manifest_info: &ManifestInfo,
    rules: &RulesConfig,
) -> (MetadataSection, Vec<Finding>) {
    let mut findings = Vec::new();

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
