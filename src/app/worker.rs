use super::App;
use crate::{
    auth::now,
    domain,
    scope::{HttpEvidence, Scope},
    web,
};
use std::time::Duration;

fn fixture_response(name: &str) -> Result<HttpEvidence, &'static str> {
    let (status, body) = match name {
        "issue" | "persistent" => (200, include_str!("../../fixtures/demo/issue.html")),
        "forbidden" => (403, ""),
        "fixed" => (200, include_str!("../../fixtures/demo/fixed.html")),
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

pub(super) async fn worker(app: &App) -> anyhow::Result<()> {
    loop {
        if !run_one(app).await? {
            tokio::select! { _=app.wake.notified()=>{}, _=tokio::time::sleep(Duration::from_secs(5))=>{} }
        }
    }
}
