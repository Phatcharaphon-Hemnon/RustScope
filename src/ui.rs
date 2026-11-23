use crate::auth::Session;
use crate::{
    app::{Fields, REASONS},
    dependencies::{MAINTENANCE, VULNERABILITIES},
    domain::{
        Change, ChangeStatus, Observation, Outcome, Round, Rule, catalog, compare, extensions,
    },
    model::{Project, Review, Scan},
    scope::{Scope, safe_url},
    web::redacted_location,
};
use askama::Template;
use std::collections::BTreeMap;

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
    pub values: Option<&'a Fields>,
}

impl Feedback<'_> {
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
}

impl ProjectPage<'_> {
    fn demo_default<'a>(&self, value: &'a str) -> &'a str {
        if self.p.demo { value } else { "" }
    }
}

pub fn project(
    p: &Project,
    role: &str,
    scans: &[Scan],
    session: &Session,
    request_id: &str,
    feedback: Feedback<'_>,
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
        evidence: evidence_groups(&rules, None),
        rules,
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

#[derive(Default)]
struct OutcomeCounts {
    findings: usize,
    insufficient: usize,
    passed: usize,
    review: usize,
    na: usize,
}

struct ChangedItem<'a> {
    change: Change,
    observations: Vec<(usize, &'a Observation)>,
    rule_gap: Option<&'a str>,
}

struct ResultGroup<'a> {
    rule: Rule,
    observations: Vec<(usize, &'a Observation)>,
    summary: String,
    finding: bool,
}

#[derive(Default)]
pub struct ReportView {
    pub full: bool,
    pub findings_only: bool,
}

#[derive(Template)]
#[template(path = "report.html")]
struct Report<'a> {
    p: &'a Project,
    scan: &'a Scan,
    target: String,
    session: &'a Session,
    pending: bool,
    may_review: bool,
    view: ReportView,
    reasons: &'static [&'static str],
    rules: Vec<Rule>,
    coverage: Vec<Coverage>,
    assessed_total: usize,
    canonical_total: usize,
    outcome_counts: OutcomeCounts,
    severity_counts: Vec<(&'static str, usize)>,
    groups: Vec<ResultGroup<'a>>,
    totals: Vec<(ChangeStatus, usize, usize)>,
    changes: Vec<ChangedItem<'a>>,
    previous: Option<&'a Scan>,
    reviews: Vec<(&'a Review, Rule)>,
}

pub fn report(
    p: &Project,
    role: &str,
    scan: &Scan,
    history: &[Scan],
    reviews: &[Review],
    session: &Session,
) -> anyhow::Result<String> {
    report_with_view(
        p,
        role,
        scan,
        history,
        reviews,
        session,
        ReportView::default(),
    )
}

pub fn report_with_view(
    p: &Project,
    role: &str,
    scan: &Scan,
    history: &[Scan],
    reviews: &[Review],
    session: &Session,
    view: ReportView,
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
    let rules = visible_rules();
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
        ("A", "Direct evidence"),
        ("S", "Source analysis"),
        ("E", "Manual evidence review"),
        ("X", "Extensions"),
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
    let canonical = coverage.iter().filter(|row| row.method != "X");
    let assessed_total = canonical.clone().map(|row| row.assessed).sum();
    let canonical_total = canonical.map(|row| row.total).sum();
    let mut outcome_counts = OutcomeCounts::default();
    let mut severity_counts = BTreeMap::new();
    let mut groups = BTreeMap::new();
    let mut items = BTreeMap::new();
    let mut gaps = BTreeMap::new();
    for (index, (obs, rule)) in observations.into_iter().enumerate() {
        items
            .entry((obs.rule.clone(), obs.item.clone()))
            .or_insert_with(Vec::new)
            .push((index, obs));
        match obs.outcome {
            Outcome::Finding => {
                outcome_counts.findings += 1;
                *severity_counts.entry(rule.severity).or_default() += 1;
            }
            Outcome::Insufficient => {
                outcome_counts.insufficient += 1;
                gaps.entry(rule.id).or_insert(obs.observed.as_str());
            }
            Outcome::Passed => outcome_counts.passed += 1,
            Outcome::Review => outcome_counts.review += 1,
            Outcome::Na => outcome_counts.na += 1,
        }
        if !view.findings_only || obs.outcome == Outcome::Finding {
            let group = groups.entry(rule.id).or_insert_with(|| ResultGroup {
                rule,
                observations: Vec::new(),
                summary: String::new(),
                finding: false,
            });
            group.finding |= obs.outcome == Outcome::Finding;
            group.observations.push((index, obs));
        }
    }
    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by_key(|g| (!g.finding, severity_rank(g.rule.severity), g.rule.id));
    for group in &mut groups {
        let mut parts = Vec::new();
        for (outcome, noun) in [
            (Outcome::Finding, "finding"),
            (Outcome::Passed, "passed"),
            (Outcome::Insufficient, "insufficient evidence"),
            (Outcome::Review, "needs review"),
            (Outcome::Na, "not applicable"),
        ] {
            let n = group
                .observations
                .iter()
                .filter(|(_, o)| o.outcome == outcome)
                .count();
            if n > 0 {
                parts.push(format!(
                    "{n} {noun}{}",
                    if n > 1 && outcome == Outcome::Finding {
                        "s"
                    } else {
                        ""
                    }
                ));
            }
        }
        group.summary = if parts.len() == 1 {
            format!("Outcome: {}", group.observations[0].1.outcome.label())
        } else {
            format!("Outcomes: {}", parts.join(" · "))
        };
    }
    let totals = [
        ChangeStatus::New,
        ChangeStatus::Persistent,
        ChangeStatus::VerifiedFixed,
        ChangeStatus::NotComparable,
    ]
    .into_iter()
    .map(|status| {
        let first = changes.iter().position(|c| c.status == status).unwrap_or(0);
        (
            status,
            changes.iter().filter(|c| c.status == status).count(),
            first,
        )
    })
    .collect();
    let changes = changes
        .into_iter()
        .map(|change| {
            let observed = items
                .remove(&(change.rule.clone(), change.item.clone()))
                .unwrap_or_default();
            let rule_gap = observed
                .is_empty()
                .then(|| gaps.get(change.rule.as_str()).copied())
                .flatten();
            ChangedItem {
                change,
                observations: observed,
                rule_gap,
            }
        })
        .collect();
    let mut severity_counts: Vec<_> = severity_counts.into_iter().collect();
    severity_counts.sort_by_key(|(severity, _)| (severity_rank(severity), *severity));
    Ok(Report {
        p,
        scan,
        target: report_target(p, scan),
        session,
        pending,
        view,
        may_review: matches!(scan.status.as_str(), "complete" | "partial")
            && matches!(role, "owner" | "reviewer"),
        reasons: &REASONS,
        rules,
        coverage,
        assessed_total,
        canonical_total,
        outcome_counts,
        severity_counts,
        groups,
        totals,
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

#[derive(Template)]
#[template(path = "preview.html")]
struct Preview<'a> {
    session: &'a Session,
    p: &'a Project,
    scan: &'a Scan,
    target: String,
    evidence: EvidenceGroups<'a>,
}

pub fn preview(p: &Project, scan: &Scan, session: &Session) -> anyhow::Result<String> {
    Ok(Preview {
        session,
        p,
        scan,
        target: report_target(p, scan),
        evidence: evidence_groups(&visible_rules(), Some(scan)),
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

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "High" => 0,
        "Medium" => 1,
        "Low" => 2,
        "Per advisory" => 3,
        "Context-dependent" => 4,
        _ => 5,
    }
}

fn in_progress(scan: &Scan) -> bool {
    matches!(scan.status.as_str(), "queued" | "running")
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

fn decision_label(decision: &str) -> &'static str {
    match decision {
        "Finding" => Outcome::Finding.label(),
        "Review" => Outcome::Review.label(),
        "Passed" => Outcome::Passed.label(),
        "Na" => Outcome::Na.label(),
        _ => Outcome::Insufficient.label(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Policy;

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
        let viewer = project(
            &p,
            "viewer",
            &[],
            &session(),
            "request",
            Feedback::default(),
        )
        .unwrap();
        assert!(!viewer.contains(&p.challenge));
        assert!(!viewer.contains("/verify"));
        assert!(!viewer.contains("/member"));
        assert!(viewer.contains("A10-06"));
        let owner = project(&p, "owner", &[], &session(), "request", Feedback::default()).unwrap();
        assert!(owner.contains(&p.challenge));
        assert!(owner.contains("/verify"));

        let history = [scan.clone()];
        let body = report(&p, "viewer", &scan, &history, &[], &session()).unwrap();
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
            Html::parse_document(&report(&p, "viewer", scan, &[], &[], &session()).unwrap())
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
            let html = report(&p, "viewer", &scan, &[], &[], &session()).unwrap();
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
                &report_with_view(&p, "viewer", &scan, &[], &[], &session(), view).unwrap(),
            )
        };
        let compact = render(ReportView::default());
        let observations = Selector::parse("#results details[data-rule]").unwrap();
        let badges = Selector::parse("[data-outcome]").unwrap();
        let outcomes: Vec<_> = compact
            .select(&badges)
            .filter_map(|badge| badge.attr("data-outcome"))
            .collect();
        assert_eq!(
            outcomes,
            ["Passed", "Insufficient", "Finding", "Finding", "Na"]
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
        let full = render(ReportView {
            full: true,
            findings_only: false,
        });
        assert!(
            full.select(&Selector::parse("article details:not([open])").unwrap())
                .next()
                .is_none()
        );
        let findings = render(ReportView {
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
        let (p, mut scan) = example();
        scan.results = vec![Observation {
            rule: "A03-01".into(),
            item: "Cargo.lock".into(),
            outcome: Outcome::Insufficient,
            observed: "Cargo.lock was not supplied".into(),
        }];
        let body = preview(&p, &scan, &session()).unwrap();
        assert_eq!(body.matches("data-rule=").count(), 9);
        assert!(body.contains("Cargo.lock was not supplied"));
        assert!(body.contains("Awaiting HTML"));
        assert!(body.contains("Not applicable under the SRI policy"));
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
        let body = report(&p, "viewer", &scan, &[], &[], &session()).unwrap();
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
        let project =
            project(&p, "owner", &[], &session(), "request", Feedback::default()).unwrap();
        assert!(project.contains("aria-describedby=\"lock-hint\""));
        for page in [project, preview(&p, &scan, &session()).unwrap()] {
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

        let body = report(&p, "viewer", &scan, &[], &[], &session()).unwrap();
        assert_eq!(body.matches("Cargo.lock was not supplied").count(), 2);
        let html = Html::parse_document(&body);
        assert_eq!(
            html.select(&selector("#results [data-outcome=Insufficient]"))
                .count(),
            2
        );
        assert!(!body.contains("data-outcome=\"Passed\""));
        assert!(
            scan.results
                .iter()
                .all(|obs| obs.outcome == Outcome::Insufficient)
        );

        scan.results = crate::dependencies::evaluate(Some("invalid lockfile"));
        let body = report(&p, "viewer", &scan, &[], &[], &session()).unwrap();
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
        let body = report(
            &p,
            "owner",
            &second,
            &[first.clone(), second.clone()],
            &[],
            &session(),
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
            &session(),
        )
        .unwrap();
        assert!(body.contains("data-change=\"NotComparable\""));
        assert!(!body.contains("data-change=\"VerifiedFixed\""));
        assert!(body.contains("/s/s2/review"));
    }
}
