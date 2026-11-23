pub(crate) mod report;

use crate::{
    dependencies::{MAINTENANCE, VULNERABILITIES},
    domain::{Outcome, Rule, catalog, extensions},
    model::{Project, Scan},
    preflight::Draft,
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
#[template(path = "register.html")]
struct Registration<'a> {
    user: &'a str,
    error: &'a str,
}

pub fn registration(user: &str, error: &str) -> anyhow::Result<String> {
    Ok(Registration { user, error }.render()?)
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
#[template(path = "catalog-page.html")]
struct CatalogPage {
    rules: Vec<Rule>,
}

pub fn catalog_page() -> anyhow::Result<String> {
    Ok(CatalogPage {
        rules: visible_rules(),
    }
    .render()?)
}

fn visible_rules() -> Vec<Rule> {
    catalog().into_iter().chain(extensions()).collect()
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
    evidence: EvidenceGroups<'a>,
    scan_form: ScanForm<'a>,
}

struct ScanForm<'a> {
    release: &'a str,
    target: &'a str,
    environment: &'a str,
    fixture: &'a str,
    download: bool,
    hsts_min: Option<u64>,
    expected_form: &'a str,
    sri: bool,
    previewed: bool,
    lockfile_used: bool,
}

impl<'a> ScanForm<'a> {
    fn new(project: &'a Project, draft: Option<&'a Draft>) -> Self {
        if let Some(draft) = draft {
            let scan = &draft.scan;
            return Self {
                release: &scan.release,
                target: &scan.target,
                environment: &scan.environment,
                fixture: &draft.fixture,
                download: scan.policy.download,
                hsts_min: scan.policy.hsts_min,
                expected_form: scan.policy.expected_form.as_deref().unwrap_or_default(),
                sri: scan.policy.sri,
                previewed: true,
                lockfile_used: draft.lockfile_used,
            };
        }
        Self {
            release: "",
            target: if project.demo {
                "https://fixture.invalid/login"
            } else {
                &project.base
            },
            environment: "test",
            fixture: "issue",
            download: project.demo,
            hsts_min: project.demo.then_some(3600),
            expected_form: if project.demo { "login" } else { "" },
            sri: project.demo,
            previewed: false,
            lockfile_used: false,
        }
    }
}

pub fn project(
    p: &Project,
    role: &str,
    scans: &[Scan],
    csrf: &str,
    request_id: &str,
    verification_error: &str,
    draft: Option<&Draft>,
) -> anyhow::Result<String> {
    let owner = role == "owner";
    let scope = Scope::new(&p.base, p.expires).ok();
    let challenge_url = if owner && !p.demo && !p.verified {
        scope.as_ref().map(Scope::challenge_url).unwrap_or_default()
    } else {
        String::new()
    };
    let rules = visible_rules();
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
        evidence: evidence_groups(&rules, draft.map(|draft| &draft.scan)),
        scan_form: ScanForm::new(p, draft),
        rules,
    }
    .render()?)
}

struct EvidenceRow<'a> {
    rule: Rule,
    additional_input: Option<&'static str>,
    readiness: Option<&'a str>,
}

#[derive(Default)]
struct EvidenceGroups<'a> {
    url: Vec<EvidenceRow<'a>>,
    additional: Vec<EvidenceRow<'a>>,
}

fn evidence_groups<'a>(rules: &[Rule], scan: Option<&'a Scan>) -> EvidenceGroups<'a> {
    let mut groups = EvidenceGroups::default();
    for rule in rules.iter().filter(|rule| rule.implemented) {
        let (additional_input, readiness) = match rule.id {
            "A02-01" => (
                Some("ระบุว่าเป็นไฟล์ดาวน์โหลด"),
                scan.map(|scan| {
                    if scan.policy.download {
                        "รอ HTTP headers ของไฟล์ดาวน์โหลด"
                    } else {
                        "ไม่เกี่ยวข้องตามนโยบายดาวน์โหลด"
                    }
                }),
            ),
            "A02-02" => (
                Some("กำหนดอายุขั้นต่ำของ HSTS"),
                scan.map(|scan| {
                    if scan.policy.hsts_min.is_some() {
                        "รอ HTTP headers จากปลายทาง HTTPS"
                    } else {
                        "ไม่กำหนดอายุขั้นต่ำของ HSTS"
                    }
                }),
            ),
            VULNERABILITIES | MAINTENANCE => (
                Some("Cargo.lock สำหรับโปรเจกต์ Rust"),
                scan.map(|scan| dependency_readiness(scan, rule.id)),
            ),
            "A04-01" | "A04-02" => (
                None,
                scan.map(|scan| {
                    if scan.policy.expected_form.is_some() {
                        "รอ HTML ตอบกลับและฟอร์มที่ระบุ"
                    } else {
                        "รอ HTML ตอบกลับและตรวจว่ามีฟอร์มรหัสผ่านหรือไม่"
                    }
                }),
            ),
            "A04-03" => (None, scan.map(|_| "รอเอกสาร HTTPS และ URL สคริปต์ที่ประกาศ")),
            "X03-01" => (None, scan.map(|_| "รอ HTML และรุ่นที่ประกาศใน URL สคริปต์")),
            "A08-04" => (
                Some("เปิดนโยบาย SRI"),
                scan.map(|scan| {
                    if scan.policy.sri {
                        "รอรายการสคริปต์ภายนอกและแอตทริบิวต์ integrity"
                    } else {
                        "ไม่เกี่ยวข้องตามนโยบาย SRI"
                    }
                }),
            ),
            _ => unreachable!("preflight entry for every implemented rule"),
        };
        let bucket = if additional_input.is_some() {
            &mut groups.additional
        } else {
            &mut groups.url
        };
        bucket.push(EvidenceRow {
            rule: rule.clone(),
            additional_input,
            readiness,
        });
    }
    groups
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

fn utc_date(seconds: &i64) -> String {
    chrono::DateTime::from_timestamp(*seconds, 0)
        .map_or_else(|| "—".into(), |date| date.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::Observation, model::Policy};

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
        let mut provenance = crate::domain::EvaluationProvenance::at_enqueue();
        provenance.record_web_evaluation();
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
            version: crate::domain::RULESET_VERSION.into(),
            provenance,
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
        let viewer = project(&p, "viewer", &[], "csrf", "request", "", None).unwrap();
        assert!(!viewer.contains(&p.challenge));
        assert!(!viewer.contains("/verify"));
        assert!(!viewer.contains("/member"));
        assert!(viewer.contains("A10-06"));
        let owner = project(&p, "owner", &[], "csrf", "request", "", None).unwrap();
        assert!(owner.contains(&p.challenge));
        assert!(owner.contains("/verify"));

        let history = [scan.clone()];
        let body = report::render(
            &p,
            "viewer",
            &scan,
            &history,
            &[],
            "csrf",
            Default::default(),
        )
        .unwrap();
        assert!(!body.contains(&p.name));
        assert!(!body.contains(&scan.results[0].observed));
        assert!(!body.contains(&scan.target));
        assert!(!body.contains("/s/s1/review"));
        assert!(body.contains("data-change=\"New\""));
        assert!(body.contains("lang=\"th\""));
        assert!(body.contains("@media print"));
    }

    #[test]
    fn compact_report_groups_items_and_expands_or_filters_on_request() {
        use scraper::{Html, Selector};

        let (p, mut scan) = example();
        scan.results = [
            ("fixed", Outcome::Passed),
            ("missing", Outcome::Insufficient),
            ("first", Outcome::Finding),
            ("second", Outcome::Finding),
            ("unrelated", Outcome::Na),
        ]
        .into_iter()
        .map(|(item, outcome)| Observation {
            rule: "A04-02".into(),
            item: item.into(),
            outcome,
            observed: format!("Evidence for {item}"),
        })
        .collect();
        let render = |view| {
            Html::parse_document(
                &report::render(&p, "viewer", &scan, &[], &[], "csrf", view).unwrap(),
            )
        };
        let compact = render(report::ReportView::default());
        let observations = Selector::parse("#results details[data-rule]").unwrap();
        let badges = Selector::parse("[data-outcome]").unwrap();
        let outcomes: Vec<_> = compact
            .select(&badges)
            .filter_map(|badge| badge.attr("data-outcome"))
            .collect();
        assert_eq!(
            outcomes,
            ["Finding", "Finding", "Insufficient", "Passed", "Na"]
        );
        assert_eq!(compact.select(&observations).count(), 5);
        assert_eq!(
            compact
                .select(&Selector::parse(".group-observations [data-rule]").unwrap())
                .count(),
            2
        );
        assert_eq!(
            compact
                .select(&Selector::parse("#results .report-reference").unwrap())
                .count(),
            1
        );
        assert_eq!(
            compact
                .select(&Selector::parse("#results details[data-rule][open]").unwrap())
                .count(),
            2
        );
        assert_eq!(
            compact
                .select(&Selector::parse(".result-bucket:not([open])").unwrap())
                .count(),
            1
        );

        let full = render(report::ReportView {
            full: true,
            findings_only: false,
        });
        assert!(
            full.select(&Selector::parse("article details:not([open])").unwrap())
                .next()
                .is_none()
        );
        let findings = render(report::ReportView {
            full: false,
            findings_only: true,
        });
        assert_eq!(findings.select(&observations).count(), 2);
        assert!(
            findings
                .select(&Selector::parse("#catalog a[href='/catalog']").unwrap())
                .next()
                .is_some()
        );
    }

    #[test]
    fn preflight_lists_implemented_rules_and_missing_inputs() {
        let (mut p, mut scan) = example();
        p.verified = true;
        scan.results = vec![Observation {
            rule: "A03-01".into(),
            item: "Cargo.lock".into(),
            outcome: Outcome::Insufficient,
            observed: "ไม่มีไฟล์ Cargo.lock".into(),
        }];
        let draft = Draft {
            scan,
            fixture: String::new(),
            lockfile_used: false,
        };
        let body = project(&p, "owner", &[], "csrf", "request", "", Some(&draft)).unwrap();
        assert!(body.contains("id=\"scan-readiness\""));
        assert_eq!(body.matches("data-rule=").count(), 9);
        assert!(body.contains("ไม่มีไฟล์ Cargo.lock"));
        assert!(body.contains("รอ HTML ตอบกลับ"));
        assert!(body.contains("ไม่เกี่ยวข้องตามนโยบาย SRI"));
    }

    #[test]
    fn report_lists_extension_coverage_outside_the_canonical_totals() {
        let (p, mut scan) = example();
        let response = crate::scope::HttpEvidence {
            final_url: "https://shop.example/checkout".into(),
            status: 200,
            headers: [("content-type".into(), "text/html".into())].into(),
            body: include_str!("../fixtures/evaluation/javascript-vulnerable.html").into(),
        };
        scan.results = crate::web::evaluate(Ok(&response), &scan.policy);
        let body =
            report::render(&p, "viewer", &scan, &[], &[], "csrf", Default::default()).unwrap();
        assert!(body.contains("/ 60 กฎมาตรฐาน"));
        assert!(body.contains("ส่วนขยาย</th><td>1 / 1</td><td>1</td>"));
        assert!(body.contains("data-rule=\"X03-01\""));
        assert!(body.contains("CVE-2020-11022"));
    }

    #[test]
    fn url_only_scans_group_optional_evidence_and_summarize_missing_lockfile() {
        use scraper::{Html, Selector};

        let (mut p, mut scan) = example();
        p.verified = true;
        scan.results = crate::dependencies::evaluate(None);
        let selector = |expression| Selector::parse(expression).unwrap();
        let form = project(&p, "owner", &[], "csrf", "request", "", None).unwrap();
        assert!(form.contains("aria-describedby=\"lock-hint\""));
        let draft = Draft {
            scan: scan.clone(),
            fixture: String::new(),
            lockfile_used: false,
        };
        let readiness = project(&p, "owner", &[], "csrf", "request", "", Some(&draft)).unwrap();
        for page in [form, readiness] {
            let html = Html::parse_document(&page);
            let rules = |group| {
                html.select(&selector(group))
                    .filter_map(|node| node.attr("data-rule"))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                rules("[data-evidence=url] [data-rule]"),
                ["A04-01", "A04-02", "A04-03", "X03-01"]
            );
            assert_eq!(
                rules("[data-evidence=additional] [data-rule]"),
                ["A02-01", "A02-02", VULNERABILITIES, MAINTENANCE, "A08-04"]
            );
        }

        let body =
            report::render(&p, "viewer", &scan, &[], &[], "csrf", Default::default()).unwrap();
        assert_eq!(body.matches("ไม่ได้ตรวจ: ไม่มี Cargo.lock").count(), 1);
        let html = Html::parse_document(&body);
        let missing: Vec<_> = html
            .select(&selector(
                ".missing-input [data-rule][data-outcome=Insufficient]",
            ))
            .filter_map(|node| node.attr("data-rule"))
            .collect();
        assert_eq!(missing, [VULNERABILITIES, MAINTENANCE]);
        assert_eq!(
            html.select(&selector("#results details[data-rule]"))
                .count(),
            0
        );
        assert!(!body.contains("data-outcome=\"Passed\""));
        assert!(
            scan.results
                .iter()
                .all(|obs| obs.outcome == Outcome::Insufficient)
        );

        scan.results = crate::dependencies::evaluate(Some("invalid lockfile"));
        let body =
            report::render(&p, "viewer", &scan, &[], &[], "csrf", Default::default()).unwrap();
        assert!(!body.contains("ไม่ได้ตรวจ: ไม่มี Cargo.lock"));
        let html = Html::parse_document(&body);
        assert_eq!(
            html.select(&selector("#results details[data-rule]"))
                .count(),
            2
        );
        assert!(body.contains("อ่านข้อมูลแพ็กเกจจาก Cargo.lock ไม่ได้"));
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
        let body = report::render(
            &p,
            "owner",
            &second,
            &[first.clone(), second.clone()],
            &[],
            "csrf",
            Default::default(),
        )
        .unwrap();
        assert!(body.contains("data-status=\"queued\""));
        assert!(!body.contains("data-change="));
        assert!(!body.contains("/s/s2/review"));

        second.status = "complete".into();
        let body = report::render(
            &p,
            "reviewer",
            &second,
            &[first, second.clone()],
            &[],
            "csrf",
            Default::default(),
        )
        .unwrap();
        assert!(body.contains("data-change=\"NotComparable\""));
        assert!(!body.contains("data-change=\"VerifiedFixed\""));
        assert!(body.contains("/s/s2/review"));
    }

    #[test]
    fn failed_scan_does_not_present_results_or_allow_review() {
        let (p, mut scan) = example();
        scan.status = "failed".into();
        let body =
            report::render(&p, "owner", &scan, &[], &[], "csrf", Default::default()).unwrap();
        assert!(body.contains("data-status=\"failed\""));
        assert!(body.contains("ตรวจไม่สำเร็จ"));
        assert!(!body.contains("id=\"results\""));
        assert!(!body.contains("/s/s1/review"));
    }
}
