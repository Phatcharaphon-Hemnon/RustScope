use super::{filters, report_target, visible_rules};
use crate::{
    REASONS,
    auth::Session,
    dependencies::is_missing_lockfile,
    domain::{Change, ChangeStatus, Observation, Outcome, Round, Rule, compare},
    model::{Project, Review, Scan},
};
use askama::Template;
use std::collections::BTreeMap;

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
    session: &'a Session,
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
    severity_counts: Vec<(&'static str, usize)>,
    groups: Vec<ResultGroup<'a>>,
    missing_lockfile_rules: Vec<(usize, &'static str)>,
    totals: Vec<(ChangeStatus, usize, usize)>,
    changes: Vec<ChangedItem<'a>>,
    previous: Option<&'a Scan>,
    reviews: Vec<(&'a Review, Rule)>,
}

pub(crate) fn render(
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
    if assessed(scan) {
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
    let mut missing_lockfile_rules = Vec::new();
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
        if !view.full && !view.findings_only && is_missing_lockfile(obs) {
            missing_lockfile_rules.push((index, rule.id));
        } else if !view.findings_only || obs.outcome == Outcome::Finding {
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
        group
            .observations
            .sort_by_key(|(_, observation)| match observation.outcome {
                Outcome::Finding => 0,
                Outcome::Insufficient => 1,
                Outcome::Passed => 2,
                Outcome::Review | Outcome::Na => 3,
            });
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
        ChangeStatus::AdvisoryChanged,
    ]
    .into_iter()
    .filter(|status| {
        *status != ChangeStatus::AdvisoryChanged
            || changes.iter().any(|change| change.status == *status)
    })
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
        failed: scan.status == "failed",
        may_review: assessed(scan) && matches!(role, "owner" | "reviewer"),
        reasons: &REASONS,
        rules,
        coverage,
        assessed_total,
        canonical_total,
        outcome_counts,
        severity_counts,
        groups,
        missing_lockfile_rules,
        totals,
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

fn assessed(scan: &Scan) -> bool {
    matches!(scan.status.as_str(), "complete" | "partial")
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
