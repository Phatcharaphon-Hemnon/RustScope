use super::{Answer, App, Fields, Shared, denied, field, mutation, session};
use crate::{
    auth::{Session, label, now, token},
    model::Project,
    scope::Scope,
    ui,
};
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};

pub(super) async fn home(State(app): State<Shared>, h: HeaderMap) -> Answer<Response> {
    let Ok(s) = session(&app, &h) else {
        return Ok(Redirect::to("/login").into_response());
    };
    let form = ui::ProjectForm {
        days: "7",
        ..Default::default()
    };
    Ok(Html(ui::home(&app.store.projects(&s.user).await?, &s, form)?).into_response())
}
pub(super) async fn catalog_page(State(app): State<Shared>, h: HeaderMap) -> Answer<Html<String>> {
    let s = session(&app, &h)?;
    Ok(Html(ui::catalog_page(&s)?))
}

pub(super) async fn create(
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
pub(super) async fn project(
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
pub(super) async fn owner(app: &App, s: &Session, id: &str) -> Answer<Project> {
    let (p, role) = app.store.access(&s.user, id).await.map_err(|_| denied())?;
    if role != "owner" {
        return Err(denied());
    }
    Ok(p)
}
pub(super) async fn verify(
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
pub(super) async fn project_error(
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
pub(super) async fn member(
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
