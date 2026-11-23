use super::{report_target, visible_rules};
use crate::{
    REASONS,
    dependencies::is_missing_lockfile,
    domain::{Change, Observation, Outcome, Round, Rule, compare},
    model::{Project, Review, Scan},
};
use askama::Template;
use std::collections::{BTreeMap, BTreeSet};

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
    other: usize,
}

struct ResultGroup<'a> {
    rule: Rule,
    observations: Vec<&'a Observation>,
    show_guidance: bool,
}

#[derive(Default)]
pub(crate) struct ReportView {
    pub full: bool,
    pub findings_only: bool,
}

#[derive(Template)]
#[template(path = "report.html")]
struct Report<'a> {
    p: &'a Project,
    scan: &'a Scan,
    target: String,
    csrf: &'a str,
    pending: bool,
    failed: bool,
    may_review: bool,
    view: ReportView,
    reasons: &'static [&'static str],
    rules: Vec<Rule>,
    coverage: Vec<Coverage>,
    assessed_total: usize,
    canonical_total: usize,
    outcome_counts: OutcomeCounts,
    severity_counts: BTreeMap<&'static str, usize>,
    finding_groups: Vec<ResultGroup<'a>>,
    insufficient_groups: Vec<ResultGroup<'a>>,
    missing_lockfile_rules: Vec<&'static str>,
    passed_groups: Vec<ResultGroup<'a>>,
    other_groups: Vec<ResultGroup<'a>>,
    changes: Vec<Change>,
    previous: Option<&'a Scan>,
    reviews: Vec<(&'a Review, Rule)>,
}

pub(crate) fn render(
    p: &Project,
    role: &str,
    scan: &Scan,
    history: &[Scan],
    reviews: &[Review],
    csrf: &str,
    view: ReportView,
) -> anyhow::Result<String> {
    let pending = in_progress(scan);
    let failed = scan.status == "failed";
    let mut changes = Vec::new();
    if !pending && !failed {
        let finished: Vec<_> = history.iter().filter(|scan| assessed(scan)).collect();
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
                provenance: &scan.provenance,
                observations: &scan.results,
            })
            .collect();
        changes = compare(&rounds);
    }
    let rules = visible_rules();
    let observations: Vec<_> = scan
        .results
        .iter()
        .filter(|_| assessed(scan))
        .filter_map(|obs| {
            rules
                .iter()
                .find(|rule| rule.implemented && rule.id == obs.rule)
                .map(|rule| (obs, rule.clone()))
        })
        .collect();
    let reviews = reviews
        .iter()
        .filter(|review| review.scan == scan.id && assessed(scan))
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
        ("X", "ส่วนขยาย"),
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
    let mut groups = [const { BTreeMap::new() }; 4];
    let mut missing_lockfile_rules = Vec::new();
    for (obs, rule) in observations {
        let (count, rank) = match obs.outcome {
            Outcome::Finding => (&mut outcome_counts.findings, 0),
            Outcome::Insufficient => (&mut outcome_counts.insufficient, 1),
            Outcome::Passed => (&mut outcome_counts.passed, 2),
            Outcome::Na | Outcome::Review => (&mut outcome_counts.other, 3),
        };
        *count += 1;
        *severity_counts.entry(rule.severity).or_default() += 1;
        if is_missing_lockfile(obs) {
            missing_lockfile_rules.push(rule.id);
            continue;
        }
        groups[rank]
            .entry(rule.id)
            .or_insert_with(|| ResultGroup {
                rule,
                observations: Vec::new(),
                show_guidance: false,
            })
            .observations
            .push(obs);
    }
    let mut guidance_shown = BTreeSet::new();
    let [
        finding_groups,
        insufficient_groups,
        passed_groups,
        other_groups,
    ] = groups.map(|bucket| {
        bucket
            .into_values()
            .map(|mut group| {
                group.show_guidance = guidance_shown.insert(group.rule.id);
                group
            })
            .collect()
    });
    Ok(Report {
        p,
        scan,
        target: report_target(p, scan),
        csrf,
        pending,
        failed,
        view,
        may_review: assessed(scan) && matches!(role, "owner" | "reviewer"),
        reasons: &REASONS,
        rules,
        coverage,
        assessed_total,
        canonical_total,
        outcome_counts,
        severity_counts,
        finding_groups,
        insufficient_groups,
        missing_lockfile_rules,
        passed_groups,
        other_groups,
        changes,
        previous: history.iter().rev().find(|prior| {
            assessed(scan)
                && prior.id != scan.id
                && prior.project == scan.project
                && prior.target == scan.target
                && assessed(prior)
        }),
        reviews,
    }
    .render()?)
}

fn in_progress(scan: &Scan) -> bool {
    matches!(scan.status.as_str(), "queued" | "running")
}

fn assessed(scan: &Scan) -> bool {
    matches!(scan.status.as_str(), "complete" | "partial")
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
