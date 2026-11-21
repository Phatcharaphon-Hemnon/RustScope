use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    pub fn thai(self) -> &'static str {
        match self {
            Self::Finding => "พบตามกฎ",
            Self::Review => "ต้องทบทวน",
            Self::Passed => "ผ่านเฉพาะกฎ",
            Self::Na => "ไม่เกี่ยวข้อง",
            Self::Insufficient => "ข้อมูลไม่พอ",
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
                    "ไฟล์ที่ระบุให้ดาวน์โหลด",
                    "พบ nosniff ในคำตอบสำเร็จของไฟล์เดิม",
                    "เบราว์เซอร์อาจตีความชนิดไฟล์ผิด",
                    "ปานกลาง",
                ),
                "A02-02" => (
                    "HTTPS headers, HSTS policy",
                    "โฮสต์ HTTPS ที่กำหนดอายุขั้นต่ำ",
                    "พบ HSTS ที่ถูกต้องและมีอายุถึงขั้นต่ำเดิม",
                    "เบราว์เซอร์อาจเชื่อมต่อผ่าน HTTP",
                    "ปานกลาง",
                ),
                "A03-01" => (
                    "Cargo.lock, RustSec",
                    "แพ็กเกจจากแหล่งที่รองรับ",
                    "พบแพ็กเกจเดิมในรุ่นที่พ้นช่วงได้รับผลกระทบตามประกาศ",
                    "รุ่นที่ติดตั้งอยู่ในช่วงที่ประกาศระบุ",
                    "ตามประกาศ",
                ),
                "A03-02" => (
                    "Cargo.lock, RustSec",
                    "แพ็กเกจจากแหล่งที่รองรับ",
                    "ยืนยันว่าแพ็กเกจเดิมพ้นช่วงที่ประกาศเลิกดูแลครอบคลุม",
                    "อาจไม่ได้รับการบำรุงรักษา",
                    "ต่ำ",
                ),
                "A04-01" => (
                    "HTML, final URL",
                    "เอกสารที่มีฟอร์มรหัสผ่าน",
                    "พบฟอร์มเดิมในเอกสารที่ส่งผ่าน HTTPS",
                    "บุคคลบนทางผ่านอาจเปลี่ยนฟอร์มได้",
                    "สูง",
                ),
                "A04-02" => (
                    "HTML, final URL",
                    "ฟอร์มรหัสผ่านและปุ่มส่งของฟอร์ม",
                    "พบฟอร์มเดิมและทุกปลายทางที่ตรวจได้ใช้ HTTPS",
                    "รหัสผ่านอาจถูกส่งผ่าน HTTP",
                    "สูง",
                ),
                "A04-03" => (
                    "HTML, final URL",
                    "เอกสาร HTTPS ที่ประกาศแหล่งสคริปต์",
                    "พบสคริปต์เดิมที่ประกาศปลายทาง HTTPS",
                    "สคริปต์อาจถูกบล็อกหรือเปลี่ยนระหว่างทาง",
                    "ปานกลาง",
                ),
                "A08-04" => (
                    "HTML, SRI policy",
                    "สคริปต์ภายนอกที่นโยบายกำหนดให้ใช้ SRI",
                    "พบ integrity ที่มีรูปแบบถูกต้องสำหรับรายการเดิมตามนโยบายเดิม",
                    "ขาดข้อมูลที่เบราว์เซอร์ใช้ตรวจความสมบูรณ์",
                    "ปานกลาง",
                ),
                "X03-01" => (
                    "HTML, final URL, Retire.js",
                    "HTML ที่ประกาศชื่อไฟล์หรือ URL สคริปต์พร้อมรุ่นที่ตรวจได้",
                    "พบรายการเดิมพร้อมรุ่นที่เปรียบเทียบได้และพ้นช่วงตามประกาศ",
                    "รุ่นที่ประกาศอยู่ในช่วงที่ได้รับผลกระทบ",
                    "ตามประกาศ",
                ),
                _ => (
                    evidence,
                    evidence,
                    "ทบทวนหลักฐานรุ่นใหม่ของรายการเดิมตามเกณฑ์ตัดสิน",
                    name,
                    "ประเมินตามบริบท",
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
                    "ตรวจจากชื่อไฟล์และ URL ที่ประกาศเท่านั้น"
                } else if implemented {
                    "ตามหลักฐานที่สังเกตได้โดยตรง"
                } else {
                    "ต้องตรวจหลักฐานโดยผู้ทบทวน"
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
    pub observations: &'a [Observation],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ChangeStatus {
    New,
    Persistent,
    VerifiedFixed,
    NotComparable,
}

impl ChangeStatus {
    pub fn thai(self) -> &'static str {
        match self {
            Self::New => "พบใหม่",
            Self::Persistent => "ยังพบอยู่",
            Self::VerifiedFixed => "ยืนยันการแก้ไขแล้ว",
            Self::NotComparable => "ยังเปรียบเทียบไม่ได้",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    pub rule: String,
    pub item: String,
    pub status: ChangeStatus,
}

/// Replay the open findings so a missing observation in an intermediate scan cannot erase one.
pub fn compare(history: &[Round<'_>]) -> Vec<Change> {
    let Some(last) = history.last() else {
        return vec![];
    };
    let mut open = BTreeSet::new();
    let mut changes = BTreeMap::new();
    for round in history
        .iter()
        .filter(|r| r.project == last.project && r.target == last.target)
    {
        changes.clear();
        for &(rule, item, _, _) in &open {
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
            let key = (rule, item, round.version, round.policy);
            match outcome {
                Outcome::Finding => {
                    let status = if !open.insert(key) {
                        ChangeStatus::Persistent
                    } else if changes.contains_key(&(rule, item)) {
                        ChangeStatus::NotComparable
                    } else {
                        ChangeStatus::New
                    };
                    changes.insert((rule, item), status);
                }
                Outcome::Passed
                    if open.remove(&key) && !open.iter().any(|k| k.0 == rule && k.1 == item) =>
                {
                    changes.insert((rule, item), ChangeStatus::VerifiedFixed);
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
                observations: obs,
            });
            assert_eq!(compare(&rounds)[0].status, status);
        }
        rounds[3].policy = "changed";
        assert_eq!(compare(&rounds)[0].status, ChangeStatus::NotComparable);
        rounds[3].project = "other";
        assert!(compare(&rounds).is_empty());
    }
}
