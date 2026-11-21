use crate::domain::Observation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Policy {
    pub download: bool,
    pub hsts_min: Option<u64>,
    pub sri: bool,
    pub expected_form: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub base: String,
    pub expires: i64,
    pub challenge: String,
    pub verified: bool,
    pub demo: bool,
    #[serde(default)]
    pub upgrade: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub project: String,
    pub release: String,
    #[serde(default)]
    pub environment: String,
    pub target: String,
    pub policy: Policy,
    pub version: String,
    pub at: i64,
    #[serde(default)]
    pub observed_at: i64,
    pub status: String,
    pub results: Vec<Observation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Review {
    pub scan: String,
    pub rule: String,
    pub reviewer: String,
    pub decision: String,
    pub rationale: String,
    pub evidence: String,
    pub at: i64,
}
