use crate::domain::{Observation, Outcome};
use semver::{BuildMetadata, Version, VersionReq};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

const VULNERABILITIES: &str = "A03-01";
const MAINTENANCE: &str = "A03-02";
const RULES: [&str; 2] = [VULNERABILITIES, MAINTENANCE];

static OFFLINE_SNAPSHOT: LazyLock<Option<Snapshot>> = LazyLock::new(|| {
    serde_json::from_str::<Snapshot>(include_str!("../fixtures/advisories/rustsec.json"))
        .ok()
        .filter(|snapshot| !snapshot.advisories.is_empty())
});

#[derive(Deserialize)]
struct Snapshot {
    commit: String,
    date: String,
    advisories: BTreeMap<String, Vec<Advisory>>,
}

#[derive(Deserialize)]
struct Advisory {
    id: String,
    kind: Kind,
    withdrawn: bool,
    excluded: Vec<VersionReq>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Vulnerability,
    Unmaintained,
}

#[derive(Deserialize)]
struct Lockfile {
    version: Option<u32>,
    #[serde(rename = "package")]
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: Version,
    source: Option<String>,
}

pub fn evaluate(lock: Option<&str>) -> Vec<Observation> {
    evaluate_snapshot(lock, OFFLINE_SNAPSHOT.as_ref())
}

fn evaluate_snapshot(lock: Option<&str>, snapshot: Option<&Snapshot>) -> Vec<Observation> {
    let Some(lock) = lock else {
        return insufficient("ไม่มีไฟล์ Cargo.lock");
    };
    let Ok(lockfile) = toml::from_str::<Lockfile>(lock) else {
        return insufficient("อ่านข้อมูลแพ็กเกจจาก Cargo.lock ไม่ได้");
    };
    if lockfile
        .version
        .is_some_and(|version| !(1..=4).contains(&version))
        || lockfile.packages.is_empty()
        || lockfile.packages.iter().any(|package| {
            package.name.is_empty()
                || package.name.len() > 64
                || !package
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        return insufficient("รูปแบบหรือข้อมูลแพ็กเกจใน Cargo.lock อยู่นอกขอบเขตที่รองรับ");
    }
    let Some(snapshot) = snapshot else {
        return insufficient("ไม่มีข้อมูล RustSec สำหรับการตรวจครั้งนี้");
    };

    let mut public = BTreeMap::<String, BTreeSet<Version>>::new();
    let mut unsupported = BTreeSet::new();
    for package in lockfile.packages {
        if !matches!(
            package.source.as_deref(),
            Some(
                "registry+https://github.com/rust-lang/crates.io-index"
                    | "sparse+https://index.crates.io/"
            )
        ) {
            unsupported.insert(package.name);
            continue;
        }
        let mut version = package.version;
        version.build = BuildMetadata::EMPTY;
        public.entry(package.name).or_default().insert(version);
    }

    let mut results = Vec::new();
    if !unsupported.is_empty() {
        let summary = format!(
            "มีชื่อแพ็กเกจ {} รายการจากแหล่งอื่นนอกเหนือจาก crates.io",
            unsupported.len()
        );
        for rule in RULES {
            results.push(observation(
                rule,
                "Cargo.lock:unsupported",
                Outcome::Na,
                &summary,
            ));
        }
    }

    let snapshot_id = format!("RustSec {} ({})", snapshot.commit, snapshot.date);
    for (name, versions) in public {
        let item = format!("crates.io:{name}");
        let versions_summary = versions
            .iter()
            .filter(|version| version.pre.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let package_summary = format!("{name} {versions_summary}");
        let package_summary = package_summary.trim_end();
        for (rule, kind) in [
            (VULNERABILITIES, Kind::Vulnerability),
            (MAINTENANCE, Kind::Unmaintained),
        ] {
            let mut matches = Vec::new();
            let mut prerelease = false;
            for version in &versions {
                // shortcut: prerelease ranges require RustSec's OSV evaluator before enabling closure.
                if !version.pre.is_empty() {
                    prerelease = true;
                    continue;
                }

                for advisory in snapshot.advisories.get(&name).into_iter().flatten() {
                    if advisory.kind == kind
                        && !advisory.withdrawn
                        && !advisory.excluded.iter().any(|range| range.matches(version))
                    {
                        matches.push(format!("{version}: {}", advisory.id));
                    }
                }
            }

            let (outcome, summary) = if !matches.is_empty() {
                let label = if kind == Kind::Vulnerability {
                    "พบประกาศช่องโหว่สำหรับรุ่นที่ล็อก"
                } else {
                    "พบประกาศเลิกดูแลสำหรับรุ่นที่ล็อก"
                };
                (Outcome::Finding, format!("{label} {}", matches.join(", ")))
            } else if prerelease {
                (Outcome::Insufficient, "มีรุ่นก่อนเผยแพร่ที่ยังตรวจไม่ได้".to_string())
            } else {
                let label = if kind == Kind::Vulnerability {
                    "ไม่พบประกาศช่องโหว่ที่มีผลกับรุ่นที่ล็อก"
                } else {
                    "ไม่พบประกาศเลิกดูแลที่มีผลกับรุ่นที่ล็อก"
                };
                (Outcome::Passed, label.to_string())
            };
            results.push(observation(
                rule,
                &item,
                outcome,
                &format!("{summary} · {package_summary} · {snapshot_id}"),
            ));
        }
    }
    results
}

fn insufficient(reason: &str) -> Vec<Observation> {
    RULES
        .iter()
        .map(|rule| observation(rule, "Cargo.lock", Outcome::Insufficient, reason))
        .collect()
}

fn observation(rule: &str, item: &str, outcome: Outcome, observed: &str) -> Observation {
    Observation {
        rule: rule.to_string(),
        item: item.to_string(),
        outcome,
        observed: observed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn package(name: &str, version: &str, source: &str) -> String {
        format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"{source}\"\n")
    }

    fn result<'a>(results: &'a [Observation], rule: &str) -> &'a Observation {
        results.iter().find(|result| result.rule == rule).unwrap()
    }

    #[test]
    fn checks_affected_fixed_and_unaffected_versions() {
        for (version, source, expected) in [
            ("0.3.46", PUBLIC, Outcome::Finding),
            ("0.3.47", "sparse+https://index.crates.io/", Outcome::Passed),
            ("0.3.1", PUBLIC, Outcome::Passed),
        ] {
            let lock = package("time", version, source);
            let results = evaluate(Some(&lock));
            let observed = result(&results, VULNERABILITIES);
            assert_eq!(observed.outcome, expected);
            assert_eq!(observed.item, "crates.io:time");
            assert!(observed.observed.contains("2026-11-20"));
        }
    }

    #[test]
    fn distinguishes_maintenance_and_withdrawn_notices() {
        let lock = package("atty", "0.2.14", PUBLIC) + &package("atty", "0.2.13", PUBLIC);
        let results = evaluate(Some(&lock));
        assert_eq!(results.len(), 2);
        assert_eq!(result(&results, VULNERABILITIES).outcome, Outcome::Passed);
        assert_eq!(result(&results, MAINTENANCE).outcome, Outcome::Finding);
        assert!(
            result(&results, MAINTENANCE)
                .observed
                .contains("RUSTSEC-2024-0375")
        );

        let lock = package("telemetry", "0.1.0", PUBLIC);
        assert_eq!(
            result(&evaluate(Some(&lock)), VULNERABILITIES).outcome,
            Outcome::Passed
        );
    }

    #[test]
    fn unsupported_and_missing_inputs_cannot_pass() {
        let lock = package("time", "0.3.46", "git+https://test.invalid/SECRET");
        let results = evaluate(Some(&lock));
        assert!(
            results
                .iter()
                .all(|result| result.outcome == Outcome::Na && !result.observed.contains("SECRET"))
        );
        for results in [
            evaluate(None),
            evaluate(Some("invalid!")),
            evaluate(Some(&package("time", "0.3.47-beta.1", PUBLIC))),
            evaluate_snapshot(Some(&package("time", "0.3.47", PUBLIC)), None),
        ] {
            assert!(
                results
                    .iter()
                    .all(|result| result.outcome == Outcome::Insufficient)
            );
        }
    }
}
