use super::{Answer, Fields, Shared, field, mutation, projects::owner, session};
use crate::{domain::Outcome, model::Policy, scope::HttpEvidence, ui, web};
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use std::collections::BTreeMap;
use url::Url;

const MAX_HEADERS: usize = 16 * 1024;
const HSTS: &str = "strict-transport-security";
const NOSNIFF: &str = "x-content-type-options";

pub(super) async fn page(
    State(app): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Answer<Html<String>> {
    let session = session(&app, &headers)?;
    let project = owner(&app, &session, &id).await?;
    Ok(Html(ui::imported_evidence(&project, &session, None, "")?))
}

pub(super) async fn analyze(
    State(app): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<Fields>,
) -> Answer<Response> {
    let session = mutation(&app, &headers, &form)?;
    let project = owner(&app, &session, &id).await?;
    match assess(&form) {
        Ok(report) => {
            Ok(Html(ui::imported_evidence(&project, &session, Some(report), "")?).into_response())
        }
        Err(error) => Ok((
            StatusCode::BAD_REQUEST,
            Html(ui::imported_evidence(&project, &session, None, error)?),
        )
            .into_response()),
    }
}

fn assess(form: &Fields) -> Result<ui::ImportedEvidence, &'static str> {
    let input = field(form, "url");
    let mut url = Url::parse(input).map_err(|_| "Enter the final HTTP or HTTPS URL")?;
    if input.len() > 2048
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Enter the final HTTP or HTTPS URL without credentials");
    }
    url.set_query(None);
    url.set_fragment(None);
    let status = field(form, "status")
        .parse::<u16>()
        .ok()
        .filter(|status| (100..=599).contains(status))
        .ok_or("Enter an HTTP status from 100 to 599")?;
    let raw = form.get("headers").map_or("", String::as_str);
    if raw.len() > MAX_HEADERS {
        return Err("Response headers must fit within 16 KiB");
    }
    let mut headers = BTreeMap::new();
    for line in raw.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let name = if name.eq_ignore_ascii_case(HSTS) {
            HSTS
        } else if name.eq_ignore_ascii_case(NOSNIFF) {
            NOSNIFF
        } else {
            continue;
        };
        let value = value.trim();
        if value.len() > 1024 || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err("A supported response header has an invalid value");
        }
        if headers.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err("Enter at most one line for each supported response header");
        }
    }
    let response = HttpEvidence {
        final_url: url.to_string(),
        status,
        headers,
        body: String::new(),
    };
    let policy = Policy {
        download: field(form, "download") == "on",
        hsts_min: Some(1),
        expected_form: None,
        sri: false,
    };
    let complete = field(form, "complete") == "on";
    let observations = web::evaluate(Ok(&response), &policy)
        .into_iter()
        .filter_map(|mut observation| {
            let header = match observation.rule.as_str() {
                "A02-01" => NOSNIFF,
                "A02-02" => HSTS,
                _ => return None,
            };
            if observation.outcome == Outcome::Finding
                && !complete
                && !response.headers.contains_key(header)
            {
                observation.outcome = Outcome::Insufficient;
                observation.observed =
                    "This header was omitted from an incomplete submission".into();
            }
            Some(observation)
        })
        .collect();
    Ok(ui::ImportedEvidence {
        target: web::redacted_location(&url),
        status,
        observations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assesses_only_supported_headers_and_treats_omissions_conservatively() {
        let mut form = Fields::from([
            (
                "url".into(),
                "https://example.org/private?secret=hidden#secret".into(),
            ),
            ("status".into(), "200".into()),
            (
                "headers".into(),
                "Set-Cookie: private=secret\nX-Content-Type-Options: nosniff".into(),
            ),
            ("download".into(), "on".into()),
        ]);
        let report = assess(&form).unwrap();
        assert_eq!(report.observations.len(), 2);
        assert!(
            report
                .observations
                .iter()
                .any(|o| o.rule == "A02-01" && o.outcome == Outcome::Passed)
        );
        assert!(
            report
                .observations
                .iter()
                .any(|o| o.rule == "A02-02" && o.outcome == Outcome::Insufficient)
        );
        assert!(!report.target.contains("private") && !report.target.contains("secret"));
        form.insert("complete".into(), "on".into());
        assert!(
            assess(&form)
                .unwrap()
                .observations
                .iter()
                .any(|o| o.rule == "A02-02" && o.outcome == Outcome::Finding)
        );
        form.insert("status".into(), "403".into());
        assert!(
            assess(&form)
                .unwrap()
                .observations
                .iter()
                .all(|o| o.outcome == Outcome::Insufficient)
        );
    }
}
