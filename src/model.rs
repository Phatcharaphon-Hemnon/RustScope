use crate::domain::{EvaluationProvenance, Observation, RULESET_VERSION};
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
    #[serde(default)]
    pub provenance: EvaluationProvenance,
    pub at: i64,
    #[serde(default)]
    pub observed_at: i64,
    pub status: String,
    pub results: Vec<Observation>,
}

impl Scan {
    pub fn record_web_evaluation(&mut self) {
        // Old queued records have a known dependency evaluator, but no snapshot fingerprint.
        self.provenance
            .dependency_rules
            .get_or_insert_with(|| self.version.clone());
        self.provenance.record_web_evaluation();
        self.version = RULESET_VERSION.into();
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finishing_a_legacy_queued_scan_preserves_known_dependency_revision_only() {
        let mut scan: Scan = serde_json::from_value(serde_json::json!({
            "id": "s", "project": "p", "release": "r", "target": "t",
            "policy": {"download": false, "sri": false},
            "version": "1", "at": 100, "status": "queued", "results": []
        }))
        .unwrap();
        assert_eq!(scan.provenance, EvaluationProvenance::default());
        scan.record_web_evaluation();
        assert_eq!(scan.version, RULESET_VERSION);
        assert_eq!(scan.provenance.dependency_rules.as_deref(), Some("1"));
        assert!(scan.provenance.rustsec.is_none());
        assert_eq!(scan.provenance.web_rules.as_deref(), Some(RULESET_VERSION));
        assert!(scan.provenance.retirejs.is_some());
    }
}
