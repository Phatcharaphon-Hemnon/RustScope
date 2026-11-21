//! Held-out, labelled examples. Metrics are per target/rule, with abstentions counted separately.
use super::*;
use domain::Outcome;
use std::collections::BTreeMap;

#[derive(Default)]
struct Counts {
    tp: u32,
    fp: u32,
    fn_: u32,
    tn: u32,
    unknown: u32,
}

#[test]
fn held_out_cases() {
    use Outcome::{Finding as F, Insufficient as I, Na as N, Passed as P};
    let policy = Policy {
        download: true,
        hsts_min: Some(900),
        sri: true,
        expected_form: Some("checkout".into()),
    };
    let before = include_str!("../fixtures/evaluation/before.html");
    let after = include_str!("../fixtures/evaluation/after.html");
    let rules = [
        "A02-01", "A02-02", "A03-01", "A03-02", "A04-01", "A04-02", "A04-03", "A08-04",
    ];
    let mut counts = BTreeMap::<&str, Counts>::new();
    for (scheme, body, status, lock, secured, labels) in [
        (
            "https",
            before,
            200,
            Some(include_str!("../fixtures/evaluation/before.lock")),
            false,
            [F, F, F, F, P, F, F, F],
        ),
        (
            "http",
            before,
            200,
            Some(include_str!("../fixtures/evaluation/before.lock")),
            false,
            [F, N, F, F, F, F, N, F],
        ),
        (
            "https",
            after,
            200,
            Some(include_str!("../fixtures/evaluation/after.lock")),
            true,
            [P, P, P, P, P, P, P, P],
        ),
        ("https", "", 403, None, false, [I, I, I, I, I, I, I, I]),
    ] {
        let mut headers = BTreeMap::from([("content-type".into(), "text/html".into())]);
        if secured {
            headers.insert("x-content-type-options".into(), "nosniff".into());
            headers.insert("strict-transport-security".into(), "max-age=1200".into());
        }
        let response = HttpEvidence {
            final_url: format!("{scheme}://shop.example/checkout"),
            status,
            headers,
            body: body.into(),
        };
        let mut results = web::evaluate(Ok(&response), &policy);
        results.extend(dependencies::evaluate(lock));
        for (rule, expected) in rules.iter().zip(labels) {
            let observed: Vec<_> = results
                .iter()
                .filter(|v| v.rule == *rule)
                .map(|r| r.outcome)
                .collect();
            let predicted = [F, I, P, N]
                .into_iter()
                .find(|v| observed.contains(v))
                .expect("rule returned an outcome");
            let c = counts.entry(rule).or_default();
            match (expected, predicted) {
                (F, F) => c.tp += 1,
                (F, _) => c.fn_ += 1,
                (_, F) => c.fp += 1,
                (_, I) => c.unknown += 1,
                (P, P) => c.tn += 1,
                _ => {}
            }
            assert_eq!(expected, predicted, "{scheme} {status} {rule}");
        }
    }
    for (rule, c) in counts {
        println!(
            "{rule} TP={} FP={} FN={} TN={} precision={:.2} recall={:.2} insufficient={}",
            c.tp,
            c.fp,
            c.fn_,
            c.tn,
            c.tp as f64 / (c.tp + c.fp) as f64,
            c.tp as f64 / (c.tp + c.fn_) as f64,
            c.unknown
        );
    }
}

#[test]
fn missing_url_and_lockfile_preserve_open_findings() {
    let policy = Policy {
        download: false,
        hsts_min: None,
        sri: true,
        expected_form: Some("checkout".into()),
    };
    let evidence = HttpEvidence {
        final_url: "https://shop.example/checkout".into(),
        status: 200,
        headers: [("content-type".into(), "text/html".into())].into(),
        body: include_str!("../fixtures/evaluation/before.html").into(),
    };
    let mut before = web::evaluate(Ok(&evidence), &policy);
    before.extend(dependencies::evaluate(Some(include_str!(
        "../fixtures/evaluation/before.lock"
    ))));
    let mut after = web::evaluate(Err("unavailable"), &policy);
    after.extend(dependencies::evaluate(None));
    let rounds = [before.as_slice(), after.as_slice()].map(|observations| domain::Round {
        project: "evaluation",
        target: "checkout",
        policy: "same",
        version: "1",
        observations,
    });
    let changes = domain::compare(&rounds);
    assert!(changes.iter().any(|c| c.rule == "A04-02"));
    assert!(changes.iter().any(|c| c.rule == "A03-01"));
    assert!(
        changes
            .iter()
            .all(|c| c.status == domain::ChangeStatus::NotComparable)
    );
    println!(
        "Missing URL and lockfile: 0 false closures across {} open findings",
        changes.len()
    );
}
