mod auth;
mod dependencies;
mod domain;
mod model;
mod scope;
mod storage;
mod ui;
mod web;

use anyhow::Context;
use auth::{Session, Sessions, label, now, token};
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use model::{Policy, Project, Review, Scan};
use scope::{HttpEvidence, Scope};
use serde::Deserialize;
use std::{collections::HashMap, fs, net::Ipv4Addr, path::PathBuf, sync::Arc, time::Duration};
use storage::Store;

type Fields = HashMap<String, String>;
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
        Error(StatusCode::INTERNAL_SERVER_ERROR, "ดำเนินการไม่สำเร็จ")
    }
}
type Answer<T> = Result<T, Error>;
fn invalid() -> Error {
    Error(StatusCode::BAD_REQUEST, "ข้อมูลไม่ถูกต้อง กรุณาตรวจแบบฟอร์มอีกครั้ง")
}
fn denied() -> Error {
    Error(StatusCode::FORBIDDEN, "ไม่มีสิทธิ์เข้าถึง")
}
fn field<'a>(f: &'a Fields, k: &str) -> &'a str {
    f.get(k).map(String::as_str).unwrap_or_default().trim()
}
fn session(app: &App, h: &HeaderMap) -> Answer<Session> {
    app.sessions
        .get(h)
        .ok_or(Error(StatusCode::UNAUTHORIZED, "กรุณาเข้าสู่ระบบที่ /login"))
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
        ("x-content-type-options", "nosniff"),
        // no-referrer also suppresses Origin on browser form submissions.
        ("referrer-policy", "same-origin"),
        (
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    ] {
        res.headers_mut().insert(k, HeaderValue::from_static(v));
    }
    res
}

async fn login_page() -> Answer<Html<String>> {
    Ok(Html(ui::login()?))
}
async fn login(State(app): State<Shared>, Form(f): Form<Fields>) -> Answer<Response> {
    let key = app
        .sessions
        .login(&app.accounts, field(&f, "user"), field(&f, "password"))
        .ok_or_else(denied)?;
    let mut res = Redirect::to("/").into_response();
    res.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "rustscope={key}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600"
        ))
        .unwrap(),
    );
    Ok(res)
}
async fn home(State(app): State<Shared>, h: HeaderMap) -> Answer<Response> {
    let Ok(s) = session(&app, &h) else {
        return Ok(Redirect::to("/login").into_response());
    };
    Ok(Html(ui::home(&app.store.projects(&s.user).await?, &s.csrf)?).into_response())
}
async fn create(
    State(app): State<Shared>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Redirect> {
    let s = mutation(&app, &h, &f)?;
    let name = field(&f, "name");
    let demo = match field(&f, "mode") {
        "demo" => true,
        "live" => false,
        _ => return Err(invalid()),
    };
    let days = field(&f, "days").parse::<i64>().map_err(|_| invalid())?;
    let valid_name = (1..=40).contains(&name.chars().count()) && name.chars().all(|c| c.is_alphanumeric() || matches!(c,' '|'_'|'-'|'.'|'\u{0e31}'|'\u{0e34}'..='\u{0e3a}'|'\u{0e47}'..='\u{0e4e}'));
    if !valid_name || !(1..=30).contains(&days) {
        return Err(invalid());
    }
    let base = if demo {
        "https://fixture.invalid"
    } else {
        field(&f, "base")
    };
    let expires = now() + days * 86400;
    let upgrade = !demo && field(&f, "upgrade") == "on";
    Scope::new(base, expires)
        .and_then(|s| s.with_upgrade(upgrade))
        .map_err(|_| invalid())?;
    let p = Project {
        id: token(),
        name: name.into(),
        base: base.into(),
        expires,
        challenge: token(),
        verified: demo,
        upgrade,
        demo,
    };
    app.store.create(&s.user, &p).await?;
    Ok(Redirect::to(&format!("/p/{}", p.id)))
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
        &s.csrf,
        &token(),
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
) -> Answer<Redirect> {
    let s = mutation(&app, &h, &f)?;
    let p = owner(&app, &s, &id).await?;
    if !p.demo {
        Scope::new(&p.base, p.expires)
            .and_then(|s| s.with_upgrade(p.upgrade))
            .map_err(|_| invalid())?
            .verify(&p.challenge)
            .await
            .map_err(|reason| Error(StatusCode::UNPROCESSABLE_ENTITY, reason))?;
        app.store.verify(&s.user, &id).await?;
    }
    Ok(Redirect::to(&format!("/p/{id}")))
}
async fn member(
    State(app): State<Shared>,
    Path(id): Path<String>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Redirect> {
    let s = mutation(&app, &h, &f)?;
    owner(&app, &s, &id).await?;
    let user = field(&f, "user");
    let role = field(&f, "role");
    if !label(user)
        || user.starts_with('.')
        || !matches!(role, "viewer" | "reviewer")
        || !app.accounts.join("accounts").join(user).is_file()
    {
        return Err(invalid());
    }
    app.store.member(&s.user, &id, user, role).await?;
    Ok(Redirect::to(&format!("/p/{id}")))
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
    if !p.verified || !scope.contains(target) {
        return Err(denied());
    }
    let release = field(&f, "release");
    let request = field(&f, "request_id");
    if !label(release) || !label(request) {
        return Err(invalid());
    }
    let fixture = if p.demo { field(&f, "fixture") } else { "" };
    if p.demo
        && (target != "https://fixture.invalid/login"
            || !matches!(fixture, "issue" | "forbidden" | "persistent" | "fixed"))
    {
        return Err(invalid());
    }
    let expected = field(&f, "expected_form");
    if !expected.is_empty() && !label(expected) {
        return Err(invalid());
    }
    let hsts = field(&f, "hsts_min");
    let policy = Policy {
        download: field(&f, "download") == "on",
        sri: field(&f, "sri") == "on",
        expected_form: (!expected.is_empty()).then(|| expected.to_owned()),
        hsts_min: if hsts.is_empty() {
            None
        } else {
            Some(hsts.parse().map_err(|_| invalid())?)
        },
    };
    let lock = field(&f, "lock");
    if lock.len() > 256 * 1024 {
        return Err(invalid());
    }
    let input = if !lock.is_empty() {
        Some(lock)
    } else if p.demo {
        Some(include_str!("../fixtures/demo/dependencies.lock"))
    } else {
        None
    };
    let results = dependencies::evaluate(input);
    let environment = f.get("environment").map(String::as_str).unwrap_or("test");
    if !matches!(environment, "test" | "staging" | "production") {
        return Err(invalid());
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
        return Ok(Html(ui::preview(&p, &scan)?).into_response());
    }
    let actual = app
        .store
        .enqueue(&s.user, &id, &scan, fixture, request)
        .await?;
    app.wake.notify_one();
    Ok(Redirect::to(&format!("/p/{id}/s/{actual}")).into_response())
}

async fn report(
    State(app): State<Shared>,
    Path((id, sid)): Path<(String, String)>,
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
    Ok(Html(ui::report(
        &p,
        &role,
        &history[index],
        &history[..=index],
        &reviews,
        &s.csrf,
    )?))
}

const REASONS: [&str; 5] = [
    "หลักฐานของรุ่นนี้ขัดกับเกณฑ์",
    "หลักฐานของรุ่นนี้ตรงตามเกณฑ์",
    "หลักฐานขัดแย้งกัน",
    "หลักฐานไม่ครอบคลุมขอบเขต",
    "ข้อกำหนดอยู่นอกขอบเขตของรุ่นนี้",
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
        return Ok(format!("เอกสาร SHA-256 {fingerprint}"));
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
        "สภาพแวดล้อมต่างจากรอบที่ตรวจ"
    } else if scan.release.len() >= 7 && ci.commit.starts_with(&scan.release) {
        "commit ตรงกับรุ่นที่ตรวจ"
    } else {
        "ผู้ทบทวนต้องตรวจความสัมพันธ์ระหว่าง commit กับรุ่น"
    };
    Ok(format!(
        "{binding} · CI {} · {} · {} · คาด {} · พบ {} · {} · SHA-256 {}",
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

fn fixture_response(name: &str) -> Result<HttpEvidence, &'static str> {
    let (status, body) = match name {
        "issue" | "persistent" => (200, include_str!("../fixtures/demo/issue.html")),
        "forbidden" => (403, ""),
        "fixed" => (200, include_str!("../fixtures/demo/fixed.html")),
        _ => return Err("unknown fixture"),
    };
    Ok(HttpEvidence {
        final_url: "https://fixture.invalid/login".into(),
        status,
        headers: [
            ("content-type".into(), "text/html".into()),
            ("strict-transport-security".into(), "max-age=86400".into()),
            ("x-content-type-options".into(), "nosniff".into()),
        ]
        .into(),
        body: body.into(),
    })
}

async fn run_one(app: &App) -> anyhow::Result<bool> {
    let Some((p, mut scan, fixture)) = app.store.claim().await? else {
        return Ok(false);
    };
    let response = match Scope::new(&p.base, p.expires).and_then(|s| s.with_upgrade(p.upgrade)) {
        Ok(scope) if p.verified && scope.contains(&scan.target) => {
            if p.demo {
                fixture_response(&fixture)
            } else {
                scope.fetch(&scan.target).await
            }
        }
        _ => Err("scope unavailable"),
    };
    scan.observed_at = now();
    scan.results.extend(web::evaluate(
        response.as_ref().map_err(|e| *e),
        &scan.policy,
    ));
    scan.status = if scan
        .results
        .iter()
        .any(|v| v.outcome == domain::Outcome::Insufficient)
    {
        "partial"
    } else {
        "complete"
    }
    .into();
    app.store.finish(&scan).await?;
    Ok(true)
}

async fn worker(app: &App) -> anyhow::Result<()> {
    loop {
        if !run_one(app).await? {
            tokio::select! { _=app.wake.notified()=>{}, _=tokio::time::sleep(Duration::from_secs(5))=>{} }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    let address = listener.local_addr()?;
    let app = Arc::new(App {
        store: Store::open(&dir.join("rustscope.sqlite")).await?,
        accounts: dir,
        sessions: Sessions::default(),
        hosts: [address.to_string(), format!("localhost:{}", address.port())],
        wake: Default::default(),
    });
    let router = Router::new()
        .route("/", get(home))
        .route("/login", get(login_page).post(login))
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
    println!("RustScope http://{address}");
    tokio::select! {
        result=axum::serve(listener,router).into_future()=> result?,
        result=worker(&app)=>result?,
    }
    Ok(())
}

#[cfg(test)]
mod evaluation;
