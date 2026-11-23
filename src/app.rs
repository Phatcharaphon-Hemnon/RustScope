mod accounts;
use accounts::{login, login_page, logout, register, registration_page};
mod worker;
use crate::auth::{self, Session, Sessions, label, now, token};
use crate::model::{Policy, Project, Review, Scan};
use crate::scope::Scope;
use crate::storage::Store;
use crate::{dependencies, domain, ui};
use anyhow::Context;
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{collections::HashMap, fs, net::Ipv4Addr, path::PathBuf, sync::Arc};
use worker::worker;

pub(crate) type Fields = HashMap<String, String>;
struct App {
    store: Store,
    accounts: PathBuf,
    sessions: Sessions,
    hosts: [String; 2],
    wake: tokio::sync::Notify,
}
type Shared = Arc<App>;
struct Error(StatusCode, &'static str);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}
impl From<anyhow::Error> for Error {
    fn from(_: anyhow::Error) -> Self {
        Error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The request could not be completed",
        )
    }
}
type Answer<T> = Result<T, Error>;
fn invalid() -> Error {
    Error(StatusCode::BAD_REQUEST, "Check the form and try again")
}
fn denied() -> Error {
    Error(StatusCode::FORBIDDEN, "Access denied")
}
fn field<'a>(f: &'a Fields, k: &str) -> &'a str {
    f.get(k).map(String::as_str).unwrap_or_default().trim()
}
fn session(app: &App, h: &HeaderMap) -> Answer<Session> {
    app.sessions
        .get(h)
        .ok_or(Error(StatusCode::UNAUTHORIZED, "Sign in at /login"))
}
fn mutation(app: &App, h: &HeaderMap, f: &Fields) -> Answer<Session> {
    let s = session(app, h)?;
    if field(f, "csrf") != s.csrf {
        return Err(denied());
    }
    Ok(s)
}

async fn guard(State(app): State<Shared>, req: Request, next: Next) -> Response {
    let h = req.headers();
    let host = h.get("host").and_then(|v| v.to_str().ok());
    let origin_host = h
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("http://"));
    if !app
        .hosts
        .iter()
        .any(|allowed| host == Some(allowed.as_str()))
        || (*req.method() == Method::POST && origin_host != host)
    {
        return denied().into_response();
    }
    let mut res = next.run(req).await;
    for (k, v) in [
        ("cache-control", "no-store"),
        ("content-language", "en"),
        ("x-content-type-options", "nosniff"),
        // no-referrer also suppresses Origin on browser form submissions.
        ("referrer-policy", "same-origin"),
        (
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    ] {
        res.headers_mut().insert(k, HeaderValue::from_static(v));
    }
    res
}

async fn home(State(app): State<Shared>, h: HeaderMap) -> Answer<Response> {
    let Ok(s) = session(&app, &h) else {
        return Ok(Redirect::to("/login").into_response());
    };
    let form = ui::ProjectForm {
        days: "7",
        ..Default::default()
    };
    Ok(Html(ui::home(&app.store.projects(&s.user).await?, &s, form)?).into_response())
}
async fn catalog_page(State(app): State<Shared>, h: HeaderMap) -> Answer<Html<String>> {
    let s = session(&app, &h)?;
    Ok(Html(ui::catalog_page(&s)?))
}

async fn create(
    State(app): State<Shared>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Response> {
    let s = mutation(&app, &h, &f)?;
    let project = match project_input(&f) {
        Ok(project) => project,
        Err((error_field, error)) => {
            let form = ui::ProjectForm {
                name: field(&f, "name"),
                base: field(&f, "base"),
                days: field(&f, "days"),
                live: field(&f, "mode") == "live",
                upgrade: field(&f, "upgrade") == "on",
                error_field,
                error,
            };
            let html = ui::home(&app.store.projects(&s.user).await?, &s, form)?;
            return Ok((StatusCode::BAD_REQUEST, Html(html)).into_response());
        }
    };
    app.store.create(&s.user, &project).await?;
    Ok(Redirect::to(&format!("/p/{}", project.id)).into_response())
}

fn project_input(f: &Fields) -> Result<Project, (&'static str, &'static str)> {
    let name = field(f, "name");
    let demo = match field(f, "mode") {
        "demo" => true,
        "live" => false,
        _ => return Err(("mode", "Choose a project mode")),
    };
    let days = field(f, "days")
        .parse::<i64>()
        .ok()
        .filter(|days| (1..=30).contains(days))
        .ok_or(("days", "The scope duration must be between 1 and 30 days"))?;
    let valid_name = (1..=40).contains(&name.chars().count()) && name.chars().all(|c| c.is_alphanumeric() || matches!(c,' '|'_'|'-'|'.'|'\u{0e31}'|'\u{0e34}'..='\u{0e3a}'|'\u{0e47}'..='\u{0e4e}'));
    if !valid_name {
        return Err((
            "name",
            "Use 1 to 40 characters for the project name. Letters, numbers, spaces, periods, hyphens, and underscores are allowed.",
        ));
    }
    let base = if demo {
        "https://fixture.invalid"
    } else {
        field(f, "base")
    };
    let expires = now() + days * 86400;
    if base.is_empty() {
        return Err(("base", "Enter a scope URL such as https://example.org/app"));
    }
    let scope = Scope::new(base, expires).map_err(
        |_| ("base", "Use an HTTP or HTTPS URL with a simple path and omit query parameters, fragments, and credentials."),
    )?;
    let upgrade = !demo && !scope.is_https() && field(f, "upgrade") == "on";
    scope.with_upgrade(upgrade).map_err(|_| {
        (
            "upgrade",
            "Adding HTTPS is available for HTTP URLs on port 80",
        )
    })?;
    Ok(Project {
        id: token(),
        name: name.into(),
        base: base.into(),
        expires,
        challenge: token(),
        verified: demo,
        upgrade,
        demo,
    })
}
async fn project(
    State(app): State<Shared>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Answer<Html<String>> {
    let s = session(&app, &h)?;
    let (p, role) = app.store.access(&s.user, &id).await.map_err(|_| denied())?;
    Ok(Html(ui::project(
        &p,
        &role,
        &app.store.scans(&s.user, &id).await?,
        &s,
        &token(),
        ui::Feedback::default(),
    )?))
}
async fn owner(app: &App, s: &Session, id: &str) -> Answer<Project> {
    let (p, role) = app.store.access(&s.user, id).await.map_err(|_| denied())?;
    if role != "owner" {
        return Err(denied());
    }
    Ok(p)
}
async fn verify(
    State(app): State<Shared>,
    Path(id): Path<String>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Response> {
    let s = mutation(&app, &h, &f)?;
    let p = owner(&app, &s, &id).await?;
    if !p.demo {
        let result = match Scope::new(&p.base, p.expires).and_then(|s| s.with_upgrade(p.upgrade)) {
            Ok(scope) => scope.verify(&p.challenge).await,
            Err(error) => Err(error),
        };
        if let Err(reason) = result {
            let message = match reason {
                "verification file missing" => {
                    "Verification file not found (HTTP 404). Publish it at the URL below."
                }
                "verification redirected" => {
                    "The verification file redirects. Serve it directly with HTTP 200 at the URL below."
                }
                "verification forbidden" => {
                    "The site denied access to the verification file. Make the URL below accessible without signing in."
                }
                "verification response too large" => {
                    "The site returned too much data, such as an HTML page. Serve only the verification code as plain text."
                }
                "control verification failed" | "unsupported text encoding" => {
                    "The verification file does not match the code below. Save only the code as UTF-8 text."
                }
                "public IPv4 destination required" => {
                    "The website must be reachable through a public IPv4 address"
                }
                "scope expired" => {
                    "The scope expired. Create a new project to request a new scope."
                }
                _ => {
                    "The verification file could not be reached. Check the URL and site configuration and try again."
                }
            };
            let html = ui::project(
                &p,
                "owner",
                &app.store.scans(&s.user, &id).await?,
                &s,
                &token(),
                ui::Feedback {
                    field: "verification",
                    message,
                    values: None,
                },
            )?;
            return Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response());
        }
        app.store.verify(&s.user, &id).await?;
    }
    Ok(Redirect::to(&format!("/p/{id}")).into_response())
}
async fn project_error(
    app: &App,
    s: &Session,
    p: &Project,
    f: &Fields,
    field_name: &str,
    message: &str,
) -> Answer<Response> {
    let request = f
        .get("request_id")
        .filter(|id| label(id))
        .cloned()
        .unwrap_or_else(token);
    let page = ui::project(
        p,
        "owner",
        &app.store.scans(&s.user, &p.id).await?,
        s,
        &request,
        ui::Feedback {
            field: field_name,
            message,
            values: Some(f),
        },
    )?;
    Ok((StatusCode::BAD_REQUEST, Html(page)).into_response())
}
async fn member(
    State(app): State<Shared>,
    Path(id): Path<String>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Response> {
    let s = mutation(&app, &h, &f)?;
    let p = owner(&app, &s, &id).await?;
    let user = field(&f, "user");
    let role = field(&f, "role");
    if !label(user)
        || user.starts_with('.')
        || user == s.user
        || !app.accounts.join("accounts").join(user).is_file()
    {
        return project_error(
            &app,
            &s,
            &p,
            &f,
            "user",
            "Choose an existing account other than the owner",
        )
        .await;
    }
    if !matches!(role, "viewer" | "reviewer") {
        return project_error(&app, &s, &p, &f, "role", "Choose Viewer or Reviewer").await;
    }
    app.store.member(&s.user, &id, user, role).await?;
    Ok(Redirect::to(&format!("/p/{id}#members")).into_response())
}
async fn scan(
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
    if !p.verified {
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
        Some(include_str!("../fixtures/demo/dependencies.lock"))
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
        return Ok(Html(ui::preview(&p, &scan, &s)?).into_response());
    }
    let actual = app
        .store
        .enqueue(&s.user, &id, &scan, fixture, request)
        .await?;
    app.wake.notify_one();
    Ok(Redirect::to(&format!("/p/{id}/s/{actual}")).into_response())
}

#[derive(Deserialize)]
struct ReportQuery {
    view: Option<String>,
    show: Option<String>,
}

async fn report(
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
        findings_only: query.show.as_deref() == Some("findings"),
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

async fn review(
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

pub async fn run() -> anyhow::Result<()> {
    let dir = PathBuf::from(std::env::var_os("RUSTSCOPE_STATE").unwrap_or_else(|| "state".into()));
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let [cmd, user] = args.as_slice()
        && cmd == "account"
    {
        return auth::add_account(&dir, user);
    }
    anyhow::ensure!(args.is_empty(), "usage: rustscope [account USER]");
    auth::state_dir(&dir)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("server.lock"))?;
    lock.try_lock()
        .context("another server is using this state directory")?;
    let port = std::env::var("RUSTSCOPE_PORT")
        .unwrap_or_else(|_| "3100".into())
        .parse::<u16>()?;
    let bind = std::env::var("RUSTSCOPE_BIND")
        .map_or(Ok(Ipv4Addr::LOCALHOST), |value| value.parse())
        .context("invalid RUSTSCOPE_BIND IPv4 address")?;
    let listener = tokio::net::TcpListener::bind((bind, port)).await?;
    let address = listener.local_addr()?;
    let app = Arc::new(App {
        store: Store::open(&dir.join("rustscope.sqlite")).await?,
        accounts: dir,
        sessions: Sessions::default(),
        hosts: [
            format!("127.0.0.1:{}", address.port()),
            format!("localhost:{}", address.port()),
        ],
        wake: Default::default(),
    });
    let router = Router::new()
        .route("/", get(home))
        .route("/login", get(login_page).post(login))
        .route("/register", get(registration_page).post(register))
        .route(
            "/sample-report.pdf",
            get(async || {
                (
                    [("content-type", "application/pdf")],
                    include_bytes!("../examples/reports/fixed.pdf").as_slice(),
                )
            }),
        )
        .route("/logout", post(logout))
        .route(
            "/ui.js",
            get(async || {
                (
                    [("content-type", "application/javascript")],
                    include_str!("../templates/ui.js"),
                )
            }),
        )
        .route(
            "/fonts/ibm-plex-sans.woff2",
            get(async || {
                (
                    [("content-type", "font/woff2")],
                    include_bytes!("../templates/fonts/ibm-plex-sans.woff2").as_slice(),
                )
            }),
        )
        .route(
            "/fonts/jetbrains-mono.woff2",
            get(async || {
                (
                    [("content-type", "font/woff2")],
                    include_bytes!("../templates/fonts/jetbrains-mono.woff2").as_slice(),
                )
            }),
        )
        .route("/catalog", get(catalog_page))
        .route("/projects", post(create))
        .route("/p/{id}", get(project))
        .route("/p/{id}/member", post(member))
        .route("/p/{id}/verify", post(verify))
        .route("/p/{id}/scan", post(scan))
        .route("/p/{id}/s/{sid}", get(report))
        .route("/p/{id}/s/{sid}/review", post(review))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app.clone());
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        terminate.recv().await;
    });
    println!("RustScope http://{address}");
    tokio::select! {
        result=server.into_future()=>result?,
        result=worker(&app)=>result?,
    }
    Ok(())
}
