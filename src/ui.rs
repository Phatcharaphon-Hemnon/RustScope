pub(crate) mod report;

use crate::{
    auth::Session,
    dependencies::{MAINTENANCE, VULNERABILITIES},
    domain::{Outcome, Rule, catalog, extensions},
    model::{Project, Scan},
    preflight::Draft,
    scope::{Scope, safe_url},
    web::redacted_location,
};
use askama::Template;

mod filters {
    use askama::Values;

    pub fn legacy_evidence(value: impl AsRef<str>, _: &dyn Values) -> askama::Result<String> {
        Ok(crate::legacy_evidence::evidence(value.as_ref()))
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct Login<'a> {
    user: &'a str,
    error: &'a str,
}

pub fn login(user: &str, error: &str) -> anyhow::Result<String> {
    Ok(Login { user, error }.render()?)
}

#[derive(Template)]
#[template(path = "register.html")]
struct Registration<'a> {
    error_field: &'a str,
    user: &'a str,
    error: &'a str,
}

pub fn registration(user: &str, error_field: &str, error: &str) -> anyhow::Result<String> {
    Ok(Registration {
        user,
        error_field,
        error,
    }
    .render()?)
}

#[derive(Template)]
#[template(path = "home.html")]
struct Home<'a> {
    projects: &'a [Project],
    session: &'a Session,
    form: ProjectForm<'a>,
}

#[derive(Default)]
pub struct ProjectForm<'a> {
    pub name: &'a str,
    pub base: &'a str,
    pub days: &'a str,
    pub live: bool,
    pub upgrade: bool,
    pub error_field: &'a str,
    pub error: &'a str,
}

pub fn home(
    projects: &[Project],
    session: &Session,
    form: ProjectForm<'_>,
) -> anyhow::Result<String> {
    Ok(Home {
        projects,
        session,
        form,
    }
    .render()?)
}

#[derive(Template)]
#[template(path = "catalog-page.html")]
struct CatalogPage<'a> {
    session: &'a Session,
    rules: Vec<Rule>,
}

pub fn catalog_page(session: &Session) -> anyhow::Result<String> {
    Ok(CatalogPage {
        session,
        rules: visible_rules(),
    }
    .render()?)
}

fn visible_rules() -> Vec<Rule> {
    catalog().into_iter().chain(extensions()).collect()
}

#[derive(Default)]
pub struct Feedback<'a> {
    pub field: &'a str,
    pub message: &'a str,
    pub values: Option<&'a crate::Fields>,
}

impl Feedback<'_> {
    fn checked(&self, name: &str, default: &bool) -> bool {
        self.value(name, if *default { "on" } else { "" }) == "on"
    }

    fn value<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        if matches!(self.field, "user" | "role") != matches!(name, "user" | "role") {
            return default;
        }
        self.values.map_or(default, |values| {
            values.get(name).map_or("", String::as_str)
        })
    }
}

#[derive(Template)]
#[template(path = "project.html")]
struct ProjectPage<'a> {
    p: &'a Project,
    owner: bool,
    role_label: &'static str,
    scope_url: String,
    challenge_url: String,
    feedback: Feedback<'a>,
    active: bool,
    scans: &'a [Scan],
    session: &'a Session,
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
    hsts_min: String,
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
                hsts_min: scan
                    .policy
                    .hsts_min
                    .map(|age| age.to_string())
                    .unwrap_or_default(),
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
            hsts_min: if project.demo {
                "3600".into()
            } else {
                String::new()
            },
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
    session: &Session,
    request_id: &str,
    feedback: Feedback<'_>,
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
            "owner" => "Owner",
            "reviewer" => "Reviewer",
            _ => "Viewer",
        },
        scope_url: if owner {
            p.base.clone()
        } else {
            safe_url(&p.base)
        },
        challenge_url,
        feedback,
        active: scope.is_some(),
        scans,
        session,
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
                Some("Mark the target as a download"),
                scan.map(|scan| {
                    if scan.policy.download {
                        "Awaiting download HTTP headers"
                    } else {
                        "Not applicable under the download policy"
                    }
                }),
            ),
            "A02-02" => (
                Some("Set a minimum HSTS max-age"),
                scan.map(|scan| {
                    if scan.policy.hsts_min.is_some() {
                        "Awaiting HTTPS response headers"
                    } else {
                        "No minimum HSTS max-age configured"
                    }
                }),
            ),
            VULNERABILITIES | MAINTENANCE => (
                Some("Cargo.lock for a Rust project"),
                scan.map(|scan| dependency_readiness(scan, rule.id)),
            ),
            "A04-01" | "A04-02" => (
                None,
                scan.map(|scan| {
                    if scan.policy.expected_form.is_some() {
                        "Awaiting HTML and the specified form"
                    } else {
                        "Awaiting HTML to check for a password form"
                    }
                }),
            ),
            "A04-03" => (
                None,
                scan.map(|_| "Awaiting the HTTPS document and declared script URLs"),
            ),
            "X03-01" => (
                None,
                scan.map(|_| "Awaiting HTML and versions declared in script URLs"),
            ),
            "A08-04" => (
                Some("Enable the SRI policy"),
                scan.map(|scan| {
                    if scan.policy.sri {
                        "Awaiting external scripts and integrity attributes"
                    } else {
                        "Not applicable under the SRI policy"
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
            "Cargo.lock and advisory data are available for some supported packages"
        } else {
            "Cargo.lock and advisory data are available for supported packages"
        }
    } else if let Some(obs) = observations
        .clone()
        .find(|obs| obs.outcome == Outcome::Insufficient)
    {
        &obs.observed
    } else if observations.any(|obs| obs.outcome == Outcome::Na) {
        "No packages from supported sources were found in Cargo.lock"
    } else {
        "Cargo.lock evidence is unavailable"
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
    chrono::DateTime::from_timestamp(*seconds, 0).map_or_else(
        || "—".into(),
        |date| date.format("%d %b %Y, %H:%M UTC").to_string(),
    )
}

fn scan_status(status: &str) -> &'static str {
    match status {
        "queued" => "Queued",
        "running" => "Running",
        "complete" => "Complete",
        "partial" => "Partially complete",
        _ => "Scan failed",
    }
}

fn environment_label(environment: &str) -> &str {
    match environment {
        "test" => "Test",
        "staging" => "Staging",
        "production" => "Production",
        _ => environment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::Observation, model::Policy};

    fn session() -> Session {
        Session {
            user: "reader".into(),
            csrf: "csrf".into(),
            expires: i64::MAX,
        }
    }
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
            version: crate::domain::RULESET_VERSION.into(),
            provenance: {
                let mut provenance = crate::domain::EvaluationProvenance::at_enqueue();
                provenance.record_web_evaluation();
                provenance
            },
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
        let viewer = project(
            &p,
            "viewer",
            &[],
            &session(),
            "request",
            Feedback::default(),
            None,
        )
        .unwrap();
        assert!(!viewer.contains(&p.challenge));
        assert!(!viewer.contains("/verify"));
        assert!(!viewer.contains("/member"));
        assert!(viewer.contains("A10-06"));
        let owner = project(
            &p,
            "owner",
            &[],
            &session(),
            "request",
            Feedback::default(),
            None,
        )
        .unwrap();
        assert!(owner.contains(&p.challenge));
        assert!(owner.contains("/verify"));

        let history = [scan.clone()];
        let body = report::render(
            &p,
            "viewer",
            &scan,
            &history,
            &[],
            &session(),
            Default::default(),
        )
        .unwrap();
        assert!(!body.contains(&p.name));
        assert!(!body.contains(&scan.results[0].observed));
        assert!(!body.contains(&scan.target));
        assert!(!body.contains("/s/s1/review"));
        assert!(body.contains("data-change=\"New\""));
        assert!(body.contains("lang=\"en\""));
        assert!(body.contains("@media print"));
    }

    #[test]
    fn findings_are_counted_per_observation_and_prioritized_by_severity_then_id() {
        use scraper::{Html, Selector};
        let (p, mut scan) = example();
        let template = scan.results[0].clone();
        scan.results.clear();
        let observation = |rule: &str, outcome, item: &str| Observation {
            rule: rule.into(),
            outcome,
            item: item.into(),
            ..template.clone()
        };
        scan.results.extend([
            observation("A04-01", Outcome::Passed, "page"),
            observation("A02-02", Outcome::Finding, "host"),
            observation("A02-01", Outcome::Finding, "download/b"),
            observation("A02-01", Outcome::Finding, "download/a"),
        ]);
        let render = |scan: &Scan| {
            Html::parse_document(
                &report::render(&p, "viewer", scan, &[], &[], &session(), Default::default())
                    .unwrap(),
            )
        };
        let severity = Selector::parse(".severity-counts li").unwrap();
        let html = render(&scan);
        let counts: Vec<_> = html
            .select(&severity)
            .map(|node| node.text().collect::<String>())
            .collect();
        assert_eq!(counts, ["3 Medium"]);
        scan.results
            .push(observation("A04-02", Outcome::Finding, "form"));
        let html = render(&scan);
        let selector = Selector::parse("#results [data-rule][open]").unwrap();
        let rules: Vec<_> = html
            .select(&selector)
            .filter_map(|node| node.attr("data-rule"))
            .collect();
        assert_eq!(rules, ["A04-02", "A02-01", "A02-02"]);
    }

    #[test]
    fn polling_is_limited_to_queued_and_running_scans() {
        let (p, mut scan) = example();
        for (status, title) in [
            ("queued", "Queued"),
            ("running", "Running"),
            ("failed", ""),
            ("partial", ""),
            ("complete", ""),
        ] {
            scan.status = status.into();
            let html = report::render(
                &p,
                "viewer",
                &scan,
                &[],
                &[],
                &session(),
                Default::default(),
            )
            .unwrap();
            assert_eq!(html.contains("http-equiv=\"refresh\""), !title.is_empty());
            if !title.is_empty() {
                assert!(html.contains(&format!("<h1>{title}</h1>")));
                assert!(html.contains("Check status now"));
            }
        }
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
                &report::render(&p, "viewer", &scan, &[], &[], &session(), view).unwrap(),
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
        assert_eq!(compact.select(&observations).count(), 1);
        assert_eq!(
            compact
                .select(&Selector::parse("#results .report-reference").unwrap())
                .count(),
            1
        );
        assert!(
            compact
                .root_element()
                .text()
                .collect::<String>()
                .contains("Outcomes: 2 findings · 1 passed")
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
        assert_eq!(findings.select(&observations).count(), 1);
        assert_eq!(findings.select(&badges).count(), 2);
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
            observed: "Cargo.lock was not supplied".into(),
        }];
        let draft = Draft {
            scan,
            fixture: String::new(),
            lockfile_used: false,
        };
        let body = project(
            &p,
            "owner",
            &[],
            &session(),
            "request",
            Feedback::default(),
            Some(&draft),
        )
        .unwrap();
        assert!(body.contains("id=\"scan-readiness\""));
        assert_eq!(body.matches("data-rule=").count(), 9);
        assert!(body.contains("Cargo.lock was not supplied"));
        assert!(body.contains("Awaiting HTML"));
        assert!(body.contains("Not applicable under the SRI policy"));
    }

    #[test]
    fn preview_feedback_preserves_edits_and_keeps_the_lockfile_private() {
        use scraper::{Html, Selector};

        let (mut p, scan) = example();
        p.verified = true;
        let draft = Draft {
            scan,
            fixture: String::new(),
            lockfile_used: true,
        };
        let values = [
            ("lock", "# private lockfile comment"),
            ("preview", "on"),
            ("release", "edited release"),
            ("target", "https://example.org/private/login"),
            ("environment", "staging"),
            ("sri", "on"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
        for existing in [None, Some(&draft)] {
            let body = project(
                &p,
                "owner",
                &[],
                &session(),
                "request",
                Feedback {
                    field: "release",
                    message: "Enter a valid release",
                    values: Some(&values),
                },
                existing,
            )
            .unwrap();
            assert!(!body.contains("# private lockfile comment"));
            let html = Html::parse_document(&body);
            let contains = |selector| {
                html.select(&Selector::parse(selector).unwrap())
                    .next()
                    .is_some()
            };
            assert!(contains(
                "input[name=release][value='edited release'][aria-invalid=true]"
            ));
            assert!(contains("#release-error[role=alert]"));
            assert!(contains(
                "select[name=environment] option[value=staging][selected]"
            ));
            assert!(contains("input[name=sri][checked]"));
            assert_eq!(
                contains("input[name=has_preview][value=on]"),
                existing.is_some()
            );
            assert_eq!(
                contains("input[name=discard_preview_lock]"),
                existing.is_some()
            );
        }
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
        let body = report::render(
            &p,
            "viewer",
            &scan,
            &[],
            &[],
            &session(),
            Default::default(),
        )
        .unwrap();
        assert!(body.contains("/ 60 standard rules"));
        assert!(body.contains("Extensions</th><td data-label=\"Rules assessed / total\">1 / 1</td><td data-label=\"Automated rules with recorded results\">1</td>"));
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
        let form = project(
            &p,
            "owner",
            &[],
            &session(),
            "request",
            Feedback::default(),
            None,
        )
        .unwrap();
        assert!(form.contains("aria-describedby=\"lock-hint\""));
        let draft = Draft {
            scan: scan.clone(),
            fixture: String::new(),
            lockfile_used: false,
        };
        let ready = project(
            &p,
            "owner",
            &[],
            &session(),
            "request",
            Feedback::default(),
            Some(&draft),
        )
        .unwrap();
        for page in [form, ready] {
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

        let body = report::render(
            &p,
            "viewer",
            &scan,
            &[],
            &[],
            &session(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(body.matches("Cargo.lock was not supplied").count(), 1);
        let html = Html::parse_document(&body);
        assert_eq!(
            html.select(&selector("#results [data-outcome=Insufficient]"))
                .count(),
            2
        );
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

        let full = report::render(
            &p,
            "viewer",
            &scan,
            &[],
            &[],
            &session(),
            report::ReportView {
                full: true,
                findings_only: false,
            },
        )
        .unwrap();
        assert_eq!(full.matches("Cargo.lock was not supplied").count(), 2);
        let full = Html::parse_document(&full);
        assert_eq!(
            full.select(&selector("#results details[data-rule][open]"))
                .count(),
            2
        );

        scan.results = crate::dependencies::evaluate(Some("invalid lockfile"));
        let body = report::render(
            &p,
            "viewer",
            &scan,
            &[],
            &[],
            &session(),
            Default::default(),
        )
        .unwrap();
        assert!(!body.contains("Skipped: Cargo.lock missing"));
        let html = Html::parse_document(&body);
        assert_eq!(
            html.select(&selector("#results details[data-rule]"))
                .count(),
            2
        );
        assert!(body.contains("Could not read package data from Cargo.lock"));
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
            &session(),
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
            &session(),
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
            report::render(&p, "owner", &scan, &[], &[], &session(), Default::default()).unwrap();
        assert!(body.contains("data-status=\"failed\""));
        assert!(body.contains("Scan failed"));
        assert!(!body.contains("id=\"results\""));
        assert!(!body.contains("/s/s1/review"));
    }

    #[test]
    fn changed_advisory_data_uses_the_previous_assessed_round() {
        use scraper::{Html, Selector};

        let (p, mut first) = example();
        first.results[0].rule = VULNERABILITIES.into();
        let mut failed = first.clone();
        failed.id = "failed".into();
        failed.status = "failed".into();
        failed.results[0].outcome = Outcome::Passed;
        let mut latest = first.clone();
        latest.id = "latest".into();
        latest.results[0].outcome = Outcome::Passed;
        latest.provenance.rustsec = Some("b".repeat(64));
        let history = [first, failed, latest.clone()];
        let body = report::render(
            &p,
            "viewer",
            &latest,
            &history,
            &[],
            &session(),
            Default::default(),
        )
        .unwrap();
        let html = Html::parse_document(&body);
        let exists = |selector| {
            html.select(&Selector::parse(selector).unwrap())
                .next()
                .is_some()
        };
        assert!(exists(".report-head a[href='/p/project-1/s/s1']"));
        assert!(exists("#compare [data-change=AdvisoryChanged]"));
        assert!(!exists("#compare [data-change=VerifiedFixed]"));
        assert!(
            html.select(&Selector::parse(".counts a").unwrap())
                .any(|n| n
                    .text()
                    .collect::<String>()
                    .contains("Advisory data changed"))
        );
        assert!(body.contains("Cargo.lock evaluator version"));
        assert!(body.contains("Web evaluator version"));
        assert!(body.contains("RustSec SHA-256") && body.contains(&"b".repeat(64)));
        assert!(body.contains("Retire.js SHA-256"));
    }
}
