use super::{Answer, Fields, Shared, denied, field, mutation};
use crate::{
    auth::{self, label},
    ui,
};
use anyhow::Context;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};

pub(super) async fn login_page() -> Answer<Html<String>> {
    Ok(Html(ui::login("", "")?))
}
pub(super) async fn login(State(app): State<Shared>, Form(f): Form<Fields>) -> Answer<Response> {
    let user = field(&f, "user").to_owned();
    let key = tokio::task::spawn_blocking(move || {
        app.sessions.login(
            &app.accounts,
            field(&f, "user"),
            f.get("password").map_or("", String::as_str),
        )
    })
    .await
    .context("login task failed")?;
    match key {
        Some(key) => signed_in(&key),
        None => Ok((
            StatusCode::FORBIDDEN,
            Html(ui::login(&user, "Invalid username or password.")?),
        )
            .into_response()),
    }
}
pub(super) async fn logout(
    State(app): State<Shared>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> Answer<Response> {
    mutation(&app, &h, &f)?;
    app.sessions.end(&h).ok_or_else(denied)?;
    let mut res = Redirect::to("/login").into_response();
    res.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_static("rustscope=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(res)
}
fn signed_in(key: &str) -> Answer<Response> {
    let mut res = Redirect::to("/").into_response();
    res.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "rustscope={key}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600"
        ))
        .context("invalid session cookie")?,
    );
    Ok(res)
}
pub(super) async fn registration_page() -> Answer<Html<String>> {
    Ok(Html(ui::registration("", "", "")?))
}
pub(super) async fn register(State(app): State<Shared>, Form(f): Form<Fields>) -> Answer<Response> {
    let user = field(&f, "user");
    let password = f.get("password").map_or("", String::as_str);
    let error_response = |status, name, message| -> Answer<Response> {
        Ok((status, Html(ui::registration(user, name, message)?)).into_response())
    };
    if !auth::valid_registration(user, password) {
        let (field, message) = if !label(user) || user.starts_with('.') {
            ("user", "Enter a valid username")
        } else {
            ("password", "At least 12 characters, up to 256 bytes")
        };
        return error_response(StatusCode::BAD_REQUEST, field, message);
    }
    if f.get("password") != f.get("confirm_password") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "confirm_password",
            "Passwords do not match",
        );
    }
    let dir = app.accounts.clone();
    let account = user.to_owned();
    let password = password.to_owned();
    match tokio::task::spawn_blocking(move || auth::register(&dir, &account, &password))
        .await
        .context("registration task failed")?
    {
        Ok(()) => {
            let key = app
                .sessions
                .start(user)
                .context("could not start session")?;
            signed_in(&key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            error_response(StatusCode::CONFLICT, "user", "Username already taken")
        }
        Err(error) => Err(anyhow::Error::from(error).into()),
    }
}
