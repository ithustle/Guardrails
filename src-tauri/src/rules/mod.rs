use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct RulesConfig {
    pub meta: MetaConfig,
    pub permissions: PermissionsConfig,
    pub sdks: SdksConfig,
    pub patterns: PatternsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetaConfig {
    pub google_min_target_sdk: i32,
    pub last_updated: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PermissionsConfig {
    pub critical: Vec<PermissionRule>,
    pub warning: Vec<PermissionRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PermissionRule {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SdksConfig {
    pub blocked: Vec<SdkRule>,
    pub warning: Vec<SdkRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SdkRule {
    pub package_prefix: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternsConfig {
    pub critical: Vec<PatternRule>,
    pub warning: Vec<PatternRule>,
    #[serde(default)]
    pub info: Vec<PatternRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternRule {
    pub signature: String,
    pub reason: String,
}

pub fn load_rules(path: &Path) -> Result<RulesConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read rules file: {}", e))?;
    let config: RulesConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse rules TOML: {}", e))?;
    Ok(config)
}
