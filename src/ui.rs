use crate::{
    REASONS,
    domain::{Change, Observation, Outcome, Round, Rule, catalog, compare},
    model::{Project, Review, Scan},
    scope::{Scope, safe_url},
    web::redacted_location,
};
use askama::Template;

#[derive(Template)]
#[template(path = "login.html")]
struct Login;

pub fn login() -> anyhow::Result<String> {
    Ok(Login.render()?)
}

#[derive(Template)]
#[template(path = "home.html")]
struct Home<'a> {
    projects: &'a [Project],
    csrf: &'a str,
    form: ProjectForm<'a>,
}

#[derive(Default)]
pub struct ProjectForm<'a> {
    pub name: &'a str,
    pub base: &'a str,
    pub days: &'a str,
    pub live: bool,
    pub upgrade: bool,
    pub error: &'a str,
}

pub fn home(projects: &[Project], csrf: &str, form: ProjectForm<'_>) -> anyhow::Result<String> {
    Ok(Home {
        projects,
        csrf,
        form,
    }
    .render()?)
}

#[derive(Template)]
#[template(path = "project.html")]
struct ProjectPage<'a> {
    p: &'a Project,
    owner: bool,
    role_label: &'static str,
    scope_url: String,
    challenge_url: String,
    verification_error: &'a str,
    active: bool,
    scans: &'a [Scan],
    csrf: &'a str,
    request_id: &'a str,
    rules: Vec<Rule>,
}

pub fn project(
    p: &Project,
    role: &str,
    scans: &[Scan],
    csrf: &str,
    request_id: &str,
    verification_error: &str,
) -> anyhow::Result<String> {
    let owner = role == "owner";
    let scope = Scope::new(&p.base, p.expires).ok();
    let challenge_url = if owner && !p.demo && !p.verified {
        scope.as_ref().map(Scope::challenge_url).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(ProjectPage {
        p,
        owner,
        role_label: match role {
            "owner" => "เจ้าของ",
            "reviewer" => "ผู้ทบทวน",
            _ => "ผู้ดูรายงาน",
        },
        scope_url: if owner {
            p.base.clone()
        } else {
            safe_url(&p.base)
        },
        challenge_url,
        verification_error,
        active: scope.is_some(),
        scans,
        csrf,
        request_id,
        rules: catalog(),
    }
    .render()?)
}

struct Coverage {
    method: &'static str,
    description: &'static str,
    total: usize,
    assessed: usize,
    executed: usize,
}

#[derive(Template)]
#[template(path = "report.html")]
struct Report<'a> {
    p: &'a Project,
    scan: &'a Scan,
    target: String,
    csrf: &'a str,
    pending: bool,
    may_review: bool,
    reasons: &'static [&'static str],
    rules: Vec<Rule>,
    coverage: Vec<Coverage>,
    assessed_total: usize,
    observations: Vec<(&'a Observation, Rule)>,
    changes: Vec<Change>,
    previous: Option<&'a Scan>,
    reviews: Vec<(&'a Review, Rule)>,
}

pub fn report(
    p: &Project,
    role: &str,
    scan: &Scan,
    history: &[Scan],
    reviews: &[Review],
    csrf: &str,
) -> anyhow::Result<String> {
    let pending = in_progress(scan);
    let mut changes = Vec::new();
    if !pending {
        let finished: Vec<_> = history.iter().filter(|scan| !in_progress(scan)).collect();
        let policies = finished
            .iter()
            .map(|scan| serde_json::to_string(&(&scan.policy, &scan.environment)))
            .collect::<Result<Vec<_>, _>>()?;
        let rounds: Vec<_> = finished
            .iter()
            .zip(&policies)
            .map(|(scan, policy)| Round {
                project: &scan.project,
                target: &scan.target,
                policy,
                version: &scan.version,
                observations: &scan.results,
            })
            .collect();
        changes = compare(&rounds);
    }
    let rules = catalog();
    let observations: Vec<_> = scan
        .results
        .iter()
        .filter(|_| !pending)
        .filter_map(|obs| {
            rules
                .iter()
                .find(|rule| rule.implemented && rule.id == obs.rule)
                .map(|rule| (obs, rule.clone()))
        })
        .collect();
    let reviews = reviews
        .iter()
        .filter(|review| review.scan == scan.id && !pending)
        .filter_map(|review| {
            rules
                .iter()
                .find(|rule| rule.method == "E" && rule.id == review.rule)
                .map(|rule| (review, rule.clone()))
        })
        .collect::<Vec<_>>();
    let coverage = [
        ("A", "ตรวจหลักฐานโดยตรง"),
        ("S", "วิเคราะห์ซอร์สโค้ด"),
        ("E", "ทบทวนหลักฐานโดยคน"),
    ]
    .into_iter()
    .map(|(method, description)| {
        let mut coverage = Coverage {
            method,
            description,
            total: 0,
            assessed: 0,
            executed: 0,
        };
        for rule in rules.iter().filter(|rule| rule.method == method) {
            coverage.total += 1;
            if observations.iter().any(|(_, r)| r.id == rule.id) {
                coverage.executed += 1;
            }
            if observations.iter().any(|(obs, r)| {
                r.id == rule.id
                    && matches!(
                        obs.outcome,
                        Outcome::Finding | Outcome::Review | Outcome::Passed
                    )
            }) || (method == "E"
                && reviews.iter().any(|(review, r)| {
                    r.id == rule.id
                        && matches!(review.decision.as_str(), "Finding" | "Review" | "Passed")
                }))
            {
                coverage.assessed += 1;
            }
        }
        coverage
    })
    .collect::<Vec<_>>();
    let assessed_total = coverage.iter().map(|row| row.assessed).sum();
    Ok(Report {
        p,
        scan,
        target: report_target(p, scan),
        csrf,
        pending,
        may_review: matches!(scan.status.as_str(), "complete" | "partial")
            && matches!(role, "owner" | "reviewer"),
        reasons: &REASONS,
        rules,
        coverage,
        assessed_total,
        observations,
        changes,
        previous: history.iter().rev().find(|prior| {
            prior.id != scan.id
                && prior.project == scan.project
                && prior.target == scan.target
                && !in_progress(prior)
        }),
        reviews,
    }
    .render()?)
}

#[derive(Template)]
#[template(path = "preview.html")]
struct Preview<'a> {
    p: &'a Project,
    scan: &'a Scan,
    target: String,
    rows: Vec<(Rule, &'a str)>,
}

pub fn preview(p: &Project, scan: &Scan) -> anyhow::Result<String> {
    let rows = catalog()
        .into_iter()
        .filter(|rule| rule.implemented)
        .map(|rule| {
            let readiness = match rule.id {
                "A02-01" if !scan.policy.download => "ไม่เกี่ยวข้องตามนโยบายดาวน์โหลด",
                "A02-01" => "รอ HTTP headers ของไฟล์ดาวน์โหลด",
                "A02-02" if scan.policy.hsts_min.is_none() => "ไม่กำหนดอายุขั้นต่ำของ HSTS",
                "A02-02" => "รอ HTTP headers จากปลายทาง HTTPS",
                "A03-01" | "A03-02" => dependency_readiness(scan, rule.id),
                "A04-01" | "A04-02" if scan.policy.expected_form.is_some() => {
                    "รอ HTML ตอบกลับและฟอร์มที่ระบุ"
                }
                "A04-01" | "A04-02" => "รอ HTML ตอบกลับและตรวจว่ามีฟอร์มรหัสผ่านหรือไม่",
                "A04-03" => "รอเอกสาร HTTPS และ URL สคริปต์ที่ประกาศ",
                "A08-04" if !scan.policy.sri => "ไม่เกี่ยวข้องตามนโยบาย SRI",
                "A08-04" => "รอรายการสคริปต์ภายนอกและแอตทริบิวต์ integrity",
                _ => unreachable!("preflight entry for every implemented rule"),
            };
            (rule, readiness)
        })
        .collect();
    Ok(Preview {
        p,
        scan,
        target: report_target(p, scan),
        rows,
    }
    .render()?)
}

fn dependency_readiness<'a>(scan: &'a Scan, rule: &str) -> &'a str {
    let mut observations = scan.results.iter().filter(|obs| obs.rule == rule);
    if observations
        .clone()
        .any(|obs| matches!(obs.outcome, Outcome::Finding | Outcome::Passed))
    {
        if observations.any(|obs| matches!(obs.outcome, Outcome::Insufficient | Outcome::Na)) {
            "มี Cargo.lock และข้อมูลประกาศสำหรับแพ็กเกจที่รองรับบางส่วน"
        } else {
            "มี Cargo.lock และข้อมูลประกาศสำหรับแพ็กเกจที่รองรับ"
        }
    } else if let Some(obs) = observations
        .clone()
        .find(|obs| obs.outcome == Outcome::Insufficient)
    {
        &obs.observed
    } else if observations.any(|obs| obs.outcome == Outcome::Na) {
        "ไม่พบแพ็กเกจจากแหล่งที่รองรับใน Cargo.lock"
    } else {
        "ยังไม่มีหลักฐานจาก Cargo.lock"
    }
}

fn report_target(p: &Project, scan: &Scan) -> String {
    if p.demo {
        scan.target.clone()
    } else {
        url::Url::parse(&scan.target)
            .map(|url| redacted_location(&url))
            .unwrap_or_else(|_| safe_url(&scan.target))
    }
}

fn in_progress(scan: &Scan) -> bool {
    matches!(scan.status.as_str(), "queued" | "running")
}

fn scan_status(status: &str) -> &'static str {
    match status {
        "queued" => "รอคิว",
        "running" => "กำลังตรวจ",
        "complete" => "ตรวจเสร็จ",
        "partial" => "เสร็จบางส่วน",
        _ => "ตรวจไม่สำเร็จ",
    }
}

fn decision_label(decision: &str) -> &'static str {
    match decision {
        "Finding" => Outcome::Finding.thai(),
        "Review" => Outcome::Review.thai(),
        "Passed" => Outcome::Passed.thai(),
        "Na" => Outcome::Na.thai(),
        _ => Outcome::Insufficient.thai(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Policy;

    fn example() -> (Project, Scan) {
        let project = Project {
            id: "project-1".into(),
            name: "<svg onload=example>".into(),
            base: "https://example.org/private".into(),
            expires: i64::MAX,
            challenge: "owner-only-proof".into(),
            verified: false,
            demo: false,
            upgrade: false,
        };
        let scan = Scan {
            id: "s1".into(),
            project: project.id.clone(),
            release: "v1".into(),
            target: "https://example.org/private/login".into(),
            policy: Policy {
                download: false,
                hsts_min: None,
                sri: false,
                expected_form: None,
            },
            environment: "test".into(),
            version: "1".into(),
            at: 1,
            observed_at: 2,
            status: "complete".into(),
            results: vec![Observation {
                rule: "A04-02".into(),
                item: "form/1".into(),
                outcome: Outcome::Finding,
                observed: "<img src=example>".into(),
            }],
        };
        (project, scan)
    }

    #[test]
    fn templates_escape_evidence_and_hide_owner_actions() {
        let (p, scan) = example();
        let viewer = project(&p, "viewer", &[], "csrf", "request", "").unwrap();
        assert!(!viewer.contains(&p.challenge));
        assert!(!viewer.contains("/verify"));
        assert!(!viewer.contains("/member"));
        assert!(viewer.contains("A10-06"));
        let owner = project(&p, "owner", &[], "csrf", "request", "").unwrap();
        assert!(owner.contains(&p.challenge));
        assert!(owner.contains("/verify"));

        let history = [scan.clone()];
        let body = report(&p, "viewer", &scan, &history, &[], "csrf").unwrap();
        assert!(!body.contains(&p.name));
        assert!(!body.contains(&scan.results[0].observed));
        assert!(!body.contains(&scan.target));
        assert!(!body.contains("/s/s1/review"));
        assert!(body.contains("data-change=\"New\""));
        assert!(body.contains("lang=\"th\""));
        assert!(body.contains("@media print"));
    }

    #[test]
    fn preflight_lists_implemented_rules_and_missing_inputs() {
        let (p, mut scan) = example();
        scan.results = vec![Observation {
            rule: "A03-01".into(),
            item: "Cargo.lock".into(),
            outcome: Outcome::Insufficient,
            observed: "ไม่มีไฟล์ Cargo.lock".into(),
        }];
        let body = preview(&p, &scan).unwrap();
        assert_eq!(body.matches("data-rule=").count(), 8);
        assert!(body.contains("ไม่มีไฟล์ Cargo.lock"));
        assert!(body.contains("รอ HTML ตอบกลับ"));
        assert!(body.contains("ไม่เกี่ยวข้องตามนโยบาย SRI"));
    }

    #[test]
    fn progress_and_noncomparable_environment_do_not_present_a_fix() {
        let (p, first) = example();
        let mut second = first.clone();
        second.id = "s2".into();
        second.release = "v2".into();
        second.environment = "staging".into();
        second.status = "queued".into();
        second.results[0].outcome = Outcome::Passed;
        let body = report(
            &p,
            "owner",
            &second,
            &[first.clone(), second.clone()],
            &[],
            "csrf",
        )
        .unwrap();
        assert!(body.contains("data-status=\"queued\""));
        assert!(!body.contains("data-change="));
        assert!(!body.contains("/s/s2/review"));

        second.status = "complete".into();
        let body = report(
            &p,
            "reviewer",
            &second,
            &[first, second.clone()],
            &[],
            "csrf",
        )
        .unwrap();
        assert!(body.contains("data-change=\"NotComparable\""));
        assert!(!body.contains("data-change=\"VerifiedFixed\""));
        assert!(body.contains("/s/s2/review"));
    }
}
