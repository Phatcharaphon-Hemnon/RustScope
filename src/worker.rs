use crate::{
    auth::now,
    domain::Outcome,
    model::{Project, Scan},
    scope::{HttpEvidence, Scope},
    storage::Store,
    web,
};
use std::time::Duration;
use tokio::sync::Notify;

fn fixture_response(name: &str) -> Option<HttpEvidence> {
    let (status, body) = match name {
        "issue" | "persistent" => (200, include_str!("../fixtures/demo/issue.html")),
        "forbidden" => (403, ""),
        "fixed" => (200, include_str!("../fixtures/demo/fixed.html")),
        _ => return None,
    };
    Some(HttpEvidence {
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

async fn evaluate(p: Project, mut scan: Scan, fixture: &str) -> Scan {
    scan.status = "failed".into();
    let Some(scope) = Scope::new(&p.base, p.expires)
        .and_then(|scope| scope.with_upgrade(p.upgrade))
        .ok()
        .filter(|scope| p.verified && scope.contains(&scan.target))
    else {
        return scan;
    };
    let response = if p.demo {
        let Some(response) = fixture_response(fixture) else {
            return scan;
        };
        Ok(response)
    } else {
        scope.fetch(&scan.target).await
    };
    scan.observed_at = now();
    scan.record_web_evaluation();
    scan.results.extend(web::evaluate(
        response.as_ref().map_err(|e| *e),
        &scan.policy,
    ));
    scan.status = if scan
        .results
        .iter()
        .any(|v| v.outcome == Outcome::Insufficient)
    {
        "partial"
    } else {
        "complete"
    }
    .into();
    scan
}

async fn run_one(store: &Store, pending: &mut Option<Scan>) -> anyhow::Result<bool> {
    let scan = match pending {
        Some(scan) => scan,
        None => {
            let Some((project, scan, fixture)) = store.claim().await? else {
                return Ok(false);
            };
            pending.insert(evaluate(project, scan, &fixture).await)
        }
    };
    if !store.finish(scan).await? {
        eprintln!("Could not save scan outcome because the scan is no longer running");
    }
    *pending = None;
    Ok(true)
}

pub(crate) async fn run(store: &Store, wake: &Notify) -> anyhow::Result<()> {
    const POLL_DELAY: Duration = Duration::from_secs(5);
    const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
    let mut backoff = INITIAL_BACKOFF;
    let mut pending = None;
    loop {
        match run_one(store, &mut pending).await {
            Ok(progress) => {
                backoff = INITIAL_BACKOFF;
                if !progress {
                    tokio::select! {
                        _ = wake.notified() => {}
                        _ = tokio::time::sleep(POLL_DELAY) => {}
                    }
                }
            }
            Err(_) => {
                if backoff == INITIAL_BACKOFF {
                    eprintln!("Scan queue storage operation failed, retrying");
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(POLL_DELAY);
            }
        }
    }
}
