use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::LazyLock;

pub const RULESET_VERSION: &str = "2";

static RUSTSEC_DIGEST: LazyLock<String> = LazyLock::new(|| {
    hex::encode(Sha256::digest(include_bytes!(
        "../fixtures/advisories/rustsec.json"
    )))
});
static RETIREJS_DIGEST: LazyLock<String> = LazyLock::new(|| {
    hex::encode(Sha256::digest(include_bytes!(
        "../fixtures/advisories/retirejs.json"
    )))
});

/// Dependency and web evidence can be evaluated by different builds of the worker.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EvaluationProvenance {
    pub dependency_rules: Option<String>,
    pub rustsec: Option<String>,
    pub web_rules: Option<String>,
    pub retirejs: Option<String>,
}

impl EvaluationProvenance {
    pub fn at_enqueue() -> Self {
        Self {
            dependency_rules: Some(RULESET_VERSION.into()),
            rustsec: Some(RUSTSEC_DIGEST.clone()),
            ..Self::default()
        }
    }

    pub fn record_web_evaluation(&mut self) {
        self.web_rules = Some(RULESET_VERSION.into());
        self.retirejs = Some(RETIREJS_DIGEST.clone());
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub rule: String,
    /// Stable redacted resource or form identity, independent of its observed value.
    pub item: String,
    pub outcome: Outcome,
    pub observed: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Finding,
    Review,
    Passed,
    Na,
    Insufficient,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Finding => "Finding",
            Self::Review => "Needs review",
            Self::Passed => "Passed this check",
            Self::Na => "Not applicable",
            Self::Insufficient => "Insufficient evidence",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub category: &'static str,
    pub method: &'static str,
    pub name: &'static str,
    pub evidence: &'static str,
    pub remediation: &'static str,
    pub version: &'static str,
    pub inputs: &'static str,
    pub applicability: &'static str,
    pub closure: &'static str,
    pub impact: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub implemented: bool,
}

pub fn catalog() -> Vec<Rule> {
    parse_catalog(include_str!("catalog.tsv"))
}

pub fn extensions() -> Vec<Rule> {
    parse_catalog(include_str!("extensions.tsv"))
}

fn parse_catalog(rows: &'static str) -> Vec<Rule> {
    rows.lines()
        .filter_map(|line| {
            let columns = line.split('\t').collect::<Vec<_>>();
            let &[category, id, method, name, evidence, remediation] = columns.as_slice() else {
                return None;
            };
            let (inputs, applicability, closure, impact, severity) = match id {
                "A02-01" => (
                    "HTTP headers",
                    "Designated download",
                    "A successful response for the same download includes nosniff",
                    "The browser may misinterpret the file type",
                    "Medium",
                ),
                "A02-02" => (
                    "HTTPS headers, HSTS policy",
                    "HTTPS host with a configured minimum max-age",
                    "Valid HSTS meets the original minimum max-age",
                    "The browser may connect over HTTP",
                    "Medium",
                ),
                "A03-01" => (
                    "Cargo.lock, RustSec",
                    "Packages from supported sources",
                    "The same package is present at a version outside the advisory's affected range",
                    "The installed version falls within the advisory's affected range",
                    "Per advisory",
                ),
                "A03-02" => (
                    "Cargo.lock, RustSec",
                    "Packages from supported sources",
                    "The same package is outside the range covered by the unmaintained advisory",
                    "The package may no longer be maintained",
                    "Low",
                ),
                "A04-01" => (
                    "HTML, final URL",
                    "Document containing a password form",
                    "The same form is present in a document served over HTTPS",
                    "Someone on the network path could alter the form",
                    "High",
                ),
                "A04-02" => (
                    "HTML, final URL",
                    "Password form and its submit controls",
                    "The same form is present and every assessable destination uses HTTPS",
                    "Passwords may be sent over HTTP",
                    "High",
                ),
                "A04-03" => (
                    "HTML, final URL",
                    "HTTPS document declaring script sources",
                    "The same script is declared with an HTTPS destination",
                    "Scripts may be blocked or altered in transit",
                    "Medium",
                ),
                "A08-04" => (
                    "HTML, SRI policy",
                    "External scripts subject to the SRI policy",
                    "The same item has a well-formed integrity attribute under the same policy",
                    "The browser lacks the information it needs to check integrity",
                    "Medium",
                ),
                "X03-01" => (
                    "HTML, final URL, Retire.js",
                    "HTML that declares a script filename or URL with an identifiable version",
                    "The same item has a comparable version outside the advisory's affected range",
                    "The declared version is within the affected range",
                    "Per advisory",
                ),
                _ => (
                    evidence,
                    evidence,
                    "Review new release evidence for the same item against the decision criteria",
                    name,
                    "Context-dependent",
                ),
            };
            let implemented = matches!(
                id,
                "A02-01"
                    | "A02-02"
                    | "A03-01"
                    | "A03-02"
                    | "A04-01"
                    | "A04-02"
                    | "A04-03"
                    | "A08-04"
                    | "X03-01"
            );
            Some(Rule {
                id,
                category,
                method,
                name,
                evidence,
                remediation,
                version: "1",
                inputs,
                applicability,
                closure,
                impact,
                severity,
                confidence: if id == "X03-01" {
                    "Checks declared filenames and URLs only"
                } else if implemented {
                    "Based on directly observed evidence"
                } else {
                    "Requires manual review of evidence"
                },
                implemented,
            })
        })
        .collect()
}

pub struct Round<'a> {
    pub project: &'a str,
    pub target: &'a str,
    pub policy: &'a str,
    pub version: &'a str,
    pub provenance: &'a EvaluationProvenance,
    pub observations: &'a [Observation],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ChangeStatus {
    New,
    Persistent,
    VerifiedFixed,
    NotComparable,
    AdvisoryChanged,
}

impl ChangeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Persistent => "Persistent",
            Self::VerifiedFixed => "Verified fixed",
            Self::NotComparable => "Not comparable",
            Self::AdvisoryChanged => "Advisory data changed · Review required",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    pub rule: String,
    pub item: String,
    pub status: ChangeStatus,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdvisoryContext<'a> {
    Independent,
    Snapshot(Option<&'a str>),
}

impl AdvisoryContext<'_> {
    fn compare(self, previous: Self, matched: ChangeStatus) -> ChangeStatus {
        if self == Self::Snapshot(None) || previous == Self::Snapshot(None) {
            ChangeStatus::NotComparable
        } else if self == previous {
            matched
        } else {
            ChangeStatus::AdvisoryChanged
        }
    }
}

impl<'a> Round<'a> {
    fn evaluator(&self, rule: &str) -> (&'a str, AdvisoryContext<'a>) {
        let provenance = self.provenance;
        let (revision, context) = match rule {
            "A03-01" | "A03-02" => (
                &provenance.dependency_rules,
                AdvisoryContext::Snapshot(provenance.rustsec.as_deref()),
            ),
            "X03-01" => (
                &provenance.web_rules,
                AdvisoryContext::Snapshot(provenance.retirejs.as_deref()),
            ),
            _ => (&provenance.web_rules, AdvisoryContext::Independent),
        };
        (revision.as_deref().unwrap_or(self.version), context)
    }
}

/// Replay the open findings so a missing observation in an intermediate scan cannot erase one.
pub fn compare(history: &[Round<'_>]) -> Vec<Change> {
    let Some(last) = history.last() else {
        return vec![];
    };
    // Keep the snapshot from the latest positive finding in each evaluation context.
    let mut open = BTreeMap::new();
    let mut last_pass = BTreeMap::new();
    let mut changes = BTreeMap::new();
    for round in history
        .iter()
        .filter(|r| r.project == last.project && r.target == last.target)
    {
        changes.clear();
        for &(rule, item, _, _) in open.keys() {
            changes.insert((rule, item), ChangeStatus::NotComparable);
        }
        let mut current = BTreeMap::new();
        for obs in round.observations {
            let outcome = current
                .entry((obs.rule.as_str(), obs.item.as_str()))
                .or_insert(obs.outcome);
            if *outcome != obs.outcome {
                *outcome = Outcome::Insufficient;
            }
        }
        for ((rule, item), outcome) in current {
            let (revision, context) = round.evaluator(rule);
            let key = (rule, item, revision, round.policy);
            match outcome {
                Outcome::Finding => {
                    let previous = open.insert(key, context);
                    let passed = last_pass.remove(&key);
                    let status = if let Some(prior) = previous {
                        context.compare(prior, ChangeStatus::Persistent)
                    } else if changes.contains_key(&(rule, item)) {
                        ChangeStatus::NotComparable
                    } else if let Some(prior) = passed {
                        context.compare(prior, ChangeStatus::New)
                    } else {
                        ChangeStatus::New
                    };
                    changes.insert((rule, item), status);
                }
                Outcome::Passed => {
                    if context != AdvisoryContext::Independent {
                        last_pass.insert(key, context);
                    }
                    if let Some(&prior) = open.get(&key) {
                        let status = context.compare(prior, ChangeStatus::VerifiedFixed);
                        if status == ChangeStatus::VerifiedFixed {
                            open.remove(&key);
                            if open.keys().any(|k| k.0 == rule && k.1 == item) {
                                continue;
                            }
                        }
                        changes.insert((rule, item), status);
                    }
                }
                _ => {}
            }
        }
    }
    changes
        .into_iter()
        .map(|((rule, item), status)| Change {
            rule: rule.into(),
            item: item.into(),
            status,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn canonical_inventory() {
        let rules = catalog();
        let ids: BTreeSet<_> = rules.iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), 60);
        for c in 1..=10 {
            for n in 1..=6 {
                assert!(ids.contains(format!("A{c:02}-{n:02}").as_str()));
            }
        }
        assert_eq!(
            rules
                .iter()
                .map(|r| r.category)
                .collect::<BTreeSet<_>>()
                .len(),
            10
        );
        assert_eq!(rules.iter().filter(|r| r.implemented).count(), 8);
        for (m, n) in [("A", 18), ("S", 6), ("E", 36)] {
            assert_eq!(rules.iter().filter(|r| r.method == m).count(), n);
        }
    }

    #[test]
    fn forbidden_then_persistent_then_fixed() {
        let outcomes = [
            (Outcome::Finding, "HTTP"),
            (Outcome::Insufficient, "403"),
            (Outcome::Finding, "HTTP"),
            (Outcome::Passed, "HTTPS"),
        ];
        let evidence: Vec<_> = outcomes
            .into_iter()
            .map(|(outcome, msg)| {
                [Observation {
                    rule: "A04-02".into(),
                    item: "form/login".into(),
                    outcome,
                    observed: msg.into(),
                }]
            })
            .collect();
        let mut rounds = vec![];
        let provenance = EvaluationProvenance::default();
        for (obs, status) in evidence.iter().zip([
            ChangeStatus::New,
            ChangeStatus::NotComparable,
            ChangeStatus::Persistent,
            ChangeStatus::VerifiedFixed,
        ]) {
            rounds.push(Round {
                project: "p",
                target: "t",
                policy: "p1",
                version: "1",
                provenance: &provenance,
                observations: obs,
            });
            assert_eq!(compare(&rounds)[0].status, status);
        }
        rounds[3].policy = "changed";
        assert_eq!(compare(&rounds)[0].status, ChangeStatus::NotComparable);
        rounds[3].project = "other";
        assert!(compare(&rounds).is_empty());
    }

    #[test]
    fn compares_each_advisory_rule_only_with_its_recorded_snapshot() {
        let first = EvaluationProvenance {
            dependency_rules: Some("d1".into()),
            web_rules: Some("w1".into()),
            rustsec: Some("rust-a".into()),
            retirejs: Some("js-a".into()),
        };
        let rust_update = EvaluationProvenance {
            rustsec: Some("rust-b".into()),
            ..first.clone()
        };
        let js_update = EvaluationProvenance {
            retirejs: Some("js-b".into()),
            ..first.clone()
        };
        let outcomes = |outcome| {
            ["A02-01", "A03-01", "A03-02", "X03-01"].map(|rule| Observation {
                rule: rule.into(),
                item: "same declared item".into(),
                outcome,
                observed: "same input".into(),
            })
        };
        let findings = outcomes(Outcome::Finding);
        let passes = outcomes(Outcome::Passed);
        fn round<'a>(
            observations: &'a [Observation],
            provenance: &'a EvaluationProvenance,
        ) -> Round<'a> {
            Round {
                project: "p",
                target: "t",
                policy: "same",
                version: "2",
                provenance,
                observations,
            }
        }
        use ChangeStatus::{AdvisoryChanged, VerifiedFixed};
        for (update, expected) in [
            (&first, [VerifiedFixed; 4]),
            (
                &rust_update,
                [
                    VerifiedFixed,
                    AdvisoryChanged,
                    AdvisoryChanged,
                    VerifiedFixed,
                ],
            ),
            (
                &js_update,
                [VerifiedFixed, VerifiedFixed, VerifiedFixed, AdvisoryChanged],
            ),
        ] {
            let history = [round(&findings, &first), round(&passes, update)];
            assert_eq!(
                compare(&history)
                    .iter()
                    .map(|change| change.status)
                    .collect::<Vec<_>>(),
                expected
            );
        }
        let history = [round(&passes, &first), round(&findings, &rust_update)];
        let changes = compare(&history);
        assert_eq!(changes[1].status, AdvisoryChanged);
        assert_eq!(changes[2].status, AdvisoryChanged);
        // A new positive observation establishes a baseline under the new database.
        let history = [
            round(&findings, &first),
            round(&passes, &rust_update),
            round(&findings, &rust_update),
            round(&passes, &rust_update),
        ];
        assert!(
            compare(&history)
                .iter()
                .all(|change| change.status == VerifiedFixed)
        );
        let legacy = EvaluationProvenance::default();
        for (before, after) in [(&legacy, &legacy), (&legacy, &first), (&first, &legacy)] {
            let history = [round(&findings, before), round(&passes, after)];
            assert!(
                compare(&history)
                    .iter()
                    .filter(|c| c.rule != "A02-01")
                    .all(|c| c.status == ChangeStatus::NotComparable)
            );
        }
    }

    #[test]
    fn queued_dependency_provenance_survives_web_worker_upgrade() {
        let mut provenance = EvaluationProvenance::at_enqueue();
        assert_eq!(provenance.rustsec.as_ref().unwrap().len(), 64);
        assert!(provenance.web_rules.is_none() && provenance.retirejs.is_none());
        provenance.dependency_rules = Some("earlier evaluator".into());
        provenance.rustsec = Some("earlier snapshot".into());
        provenance.record_web_evaluation();
        assert_eq!(
            provenance.dependency_rules.as_deref(),
            Some("earlier evaluator")
        );
        assert_eq!(provenance.rustsec.as_deref(), Some("earlier snapshot"));
        assert_eq!(provenance.web_rules.as_deref(), Some(RULESET_VERSION));
        assert_eq!(provenance.retirejs.unwrap().len(), 64);
    }
}
