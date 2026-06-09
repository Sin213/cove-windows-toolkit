use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyTier {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    Warning,
    Info,
    Ok,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegValue {
    Dword(u32),
    Qword(u64),
    String(String),
    Binary(Vec<u8>),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryHive {
    HKCU,
    HKLM,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub metric: Option<MetricValue>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Integer(i64),
    Float(f64),
    Text(String),
    Bytes(u64),
    Percent(f32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub module: String,
    pub findings: Vec<Finding>,
    pub severity: Severity,
}
