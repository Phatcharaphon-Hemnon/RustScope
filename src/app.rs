mod accounts;
mod evidence;
mod projects;
mod scans;
mod worker;

use crate::auth::{self, Session, Sessions};
use crate::storage::Store;
use accounts::{login, login_page, logout, register, registration_page};
use anyhow::Context;
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use projects::{catalog_page, create, home, member, project, verify};
pub(crate) use scans::REASONS;
use scans::{report, review, scan};
use std::{collections::HashMap, fs, net::Ipv4Addr, path::PathBuf, sync::Arc};
use worker::worker;

pub(crate) type Fields = HashMap<String, String>;
struct App {
    store: Store,
    accounts: PathBuf,
    sessions: Sessions,
    hosts: [String; 2],
    wake: tokio::sync::Notify,
    demo_enabled: bool,
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
        demo_enabled: std::env::var("RUSTSCOPE_DEMO").as_deref() == Ok("1"),
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
        .route(
            "/p/{id}/evidence",
            get(evidence::page).post(evidence::analyze),
        )
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
