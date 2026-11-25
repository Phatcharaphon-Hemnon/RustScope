use super::{
    Answer, Fields, Shared, denied, field, invalid, mutation,
    projects::{owner, project_error},
    session,
};
use crate::{
    auth::{label, now, token},
    dependencies, domain,
    model::{Policy, Review, Scan},
    scope::Scope,
    ui,
};
use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;

pub(super) async fn scan(
    State(app): State<Shared>,
    Path(id): Path<String>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Response> {
    let s = mutation(&app, &h, &f)?;
    let p = owner(&app, &s, &id).await?;
    let target = field(&f, "target");
    let scope = Scope::new(&p.base, p.expires)
        .and_then(|s| s.with_upgrade(p.upgrade))
        .map_err(|_| denied())?;
    if !p.verified || (p.demo && !app.demo_enabled) {
        return Err(denied());
    }
    let form_error = |name, message| project_error(&app, &s, &p, &f, name, message);
    if !scope.contains(target) {
        return form_error("target", "Enter a target within the verified scope").await;
    }
    let release = field(&f, "release");
    let request = field(&f, "request_id");
    if !label(release) {
        return form_error(
            "release",
            "Use 1–80 bytes of letters, numbers, periods, hyphens or underscores",
        )
        .await;
    }
    if !label(request) {
        return Err(invalid());
    }
    let fixture = if p.demo { field(&f, "fixture") } else { "" };
    if p.demo
        && (target != "https://fixture.invalid/login"
            || !matches!(fixture, "issue" | "forbidden" | "persistent" | "fixed"))
    {
        return form_error("fixture", "Choose a demo fixture and its fixed target").await;
    }
    let expected = field(&f, "expected_form");
    if !expected.is_empty() && !label(expected) {
        return form_error("expected_form", "Enter a valid form ID").await;
    }
    let hsts = field(&f, "hsts_min");
    let policy = Policy {
        download: field(&f, "download") == "on",
        sri: field(&f, "sri") == "on",
        expected_form: (!expected.is_empty()).then(|| expected.to_owned()),
        hsts_min: if hsts.is_empty() {
            None
        } else {
            match hsts.parse() {
                Ok(age) => Some(age),
                Err(_) => {
                    return form_error("hsts_min", "Enter a nonnegative whole number of seconds")
                        .await;
                }
            }
        },
    };
    let lock = f.get("lock").map_or("", String::as_str);
    // HTML form encoding serializes textarea line breaks as CRLF.
    let normalized;
    let lock = if lock.contains("\r\n") {
        normalized = lock.replace("\r\n", "\n");
        normalized.as_str()
    } else {
        lock
    };
    if lock.len() > 256 * 1024 {
        return form_error("lock", "Cargo.lock exceeds 262,144 bytes").await;
    }
    let input = if !lock.trim().is_empty() {
        Some(lock)
    } else if p.demo {
        Some(include_str!("../../fixtures/demo/dependencies.lock"))
    } else {
        None
    };
    let results = dependencies::evaluate(input);
    let environment = f.get("environment").map(String::as_str).unwrap_or("test");
    if !matches!(environment, "test" | "staging" | "production") {
        return form_error("environment", "Choose a listed environment").await;
    }
    let scan = Scan {
        id: token(),
        project: id.clone(),
        release: release.into(),
        environment: environment.into(),
        target: target.into(),
        policy,
        version: "1".into(),
        at: now(),
        observed_at: 0,
        status: "queued".into(),
        results,
    };
    if field(&f, "preview") == "on" {
        let page = if p.demo {
            ui::preview(&p, &scan, &s)?
        } else {
            ui::project(
                &p,
                "owner",
                &[],
                &s,
                request,
                ui::Feedback {
                    values: Some(&f),
                    section: "scan",
                    readiness: Some(&scan),
                    ..Default::default()
                },
            )?
        };
        return Ok(Html(page).into_response());
    }
    let actual = app
        .store
        .enqueue(&s.user, &id, &scan, fixture, request)
        .await?;
    app.wake.notify_one();
    Ok(Redirect::to(&format!("/p/{id}/s/{actual}")).into_response())
}

#[derive(Deserialize)]
pub(super) struct ReportQuery {
    view: Option<String>,
    show: Option<String>,
}

pub(super) async fn report(
    State(app): State<Shared>,
    Path((id, sid)): Path<(String, String)>,
    Query(query): Query<ReportQuery>,
    h: HeaderMap,
) -> Answer<Html<String>> {
    let s = session(&app, &h)?;
    let (p, role) = app.store.access(&s.user, &id).await.map_err(|_| denied())?;
    let history = app.store.scans(&s.user, &id).await?;
    let index = history
        .iter()
        .position(|v| v.id == sid)
        .ok_or_else(denied)?;
    let reviews = app.store.reviews(&s.user, &id, &sid).await?;
    let view = ui::ReportView {
        full: query.view.as_deref() == Some("full"),
        findings_only: query.view.as_deref() != Some("full")
            && query.show.as_deref() == Some("findings"),
    };
    let scan = &history[index];
    let rounds = &history[..=index];
    let html = if view.full || view.findings_only {
        ui::report_with_view(&p, &role, scan, rounds, &reviews, &s, view)?
    } else {
        ui::report(&p, &role, scan, rounds, &reviews, &s)?
    };
    Ok(Html(html))
}

pub(crate) const REASONS: [&str; 5] = [
    "Release evidence contradicts the criteria",
    "Release evidence meets the criteria",
    "Evidence conflicts",
    "Evidence does not cover the scope",
    "Requirement is outside this release's scope",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ci {
    case_id: String,
    commit: String,
    environment: String,
    expected: String,
    actual: String,
    timestamp: i64,
}

// Retain structured comparisons and a document fingerprint; free-form source evidence stays with the reviewer.
fn reviewed_evidence(raw: &str, scan: &Scan) -> Answer<String> {
    use sha2::{Digest, Sha256};
    if raw.is_empty() || raw.len() > 8192 {
        return Err(invalid());
    }
    let fingerprint = hex::encode(Sha256::digest(raw.as_bytes()));
    if !raw.starts_with('{') {
        return Ok(format!("Document SHA-256 {fingerprint}"));
    }
    let ci: Ci = serde_json::from_str(raw).map_err(|_| invalid())?;
    let valid_state = |s: &str| {
        matches!(
            s,
            "allow" | "deny" | "pass" | "fail" | "enabled" | "disabled"
        )
    };
    if !label(&ci.case_id)
        || !(7..=64).contains(&ci.commit.len())
        || !ci.commit.bytes().all(|b| b.is_ascii_hexdigit())
        || !matches!(ci.environment.as_str(), "test" | "staging" | "production")
        || !valid_state(&ci.expected)
        || !valid_state(&ci.actual)
        || ci.timestamp <= 0
        || ci.timestamp > now()
    {
        return Err(invalid());
    }
    // Keep conventional public case numbers readable. Fingerprint other source identifiers.
    let case = if ci.case_id.split_once('-').is_some_and(|(suite, n)| {
        (1..=8).contains(&suite.len())
            && suite.bytes().all(|c| c.is_ascii_uppercase())
            && (1..=6).contains(&n.len())
            && n.bytes().all(|c| c.is_ascii_digit())
    }) {
        ci.case_id
    } else {
        format!(
            "sha256/{}",
            hex::encode(Sha256::digest(ci.case_id.as_bytes()))
        )
    };
    let binding = if ci.environment != scan.environment {
        "Environment differs from the scanned environment"
    } else if scan.release.len() >= 7 && ci.commit.starts_with(&scan.release) {
        "Commit matches the scanned release"
    } else {
        "The reviewer must confirm that the commit corresponds to the release"
    };
    Ok(format!(
        "{binding} · CI {} · {} · {} · Expected {} · Observed {} · {} · SHA-256 {}",
        case, ci.commit, ci.environment, ci.expected, ci.actual, ci.timestamp, fingerprint
    ))
}

pub(super) async fn review(
    State(app): State<Shared>,
    Path((id, sid)): Path<(String, String)>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Redirect> {
    let s = mutation(&app, &h, &f)?;
    let (_, role) = app.store.access(&s.user, &id).await.map_err(|_| denied())?;
    if !matches!(role.as_str(), "owner" | "reviewer") {
        return Err(denied());
    }
    let decision = field(&f, "decision");
    let rule = field(&f, "rule");
    let rationale = field(&f, "rationale");
    if !matches!(
        decision,
        "Passed" | "Finding" | "Insufficient" | "Na" | "Review"
    ) || !REASONS.contains(&rationale)
        || !domain::catalog()
            .iter()
            .any(|r| r.id == rule && r.method == "E")
    {
        return Err(invalid());
    }
    let scan = app
        .store
        .scans(&s.user, &id)
        .await?
        .into_iter()
        .find(|s| s.id == sid && matches!(s.status.as_str(), "complete" | "partial"))
        .ok_or_else(invalid)?;
    let r = Review {
        scan: sid.clone(),
        rule: rule.into(),
        reviewer: s.user.clone(),
        decision: decision.into(),
        rationale: rationale.into(),
        evidence: reviewed_evidence(field(&f, "evidence"), &scan)?,
        at: now(),
    };
    app.store
        .review(&s.user, &id, &r)
        .await
        .map_err(|_| invalid())?;
    Ok(Redirect::to(&format!("/p/{id}/s/{sid}")))
}
