# RustScope

RustScope assesses owner-approved web resources and release evidence, produces Thai reports, and compares rescans. It uses Rust, Axum, Tokio, reqwest, scraper, Askama and SQLx/SQLite. All eight automated checks run inside the application. The offline demo requires no target website, advisory service or ZAP installation.

[Product context](PRODUCT.md) covers users and workflows. [Design system](DESIGN.md) documents the current interface and its shared styles.

## Start from a clean checkout

Use Linux, a current stable Rust toolchain with Cargo, a C toolchain, and Python 3 for the demo. The verified build used rustc 1.99.1. The first build needs access to crates.io. After fetching the locked dependencies, builds and tests can run with Cargo’s `--offline` flag.

```sh
cargo run --locked
```

Open **http://localhost:3100**, choose **สมัครบัญชี**, and create an account with a username and password. RustScope signs you in automatically. On later visits, use **เข้าสู่ระบบ** with the same credentials. Each account starts with access to its own projects and can be invited to other projects by their owners.

Existing accounts can sign in with their current credentials. To provision an account from the terminal, run `cargo run --locked -- account USER`. The command prints its generated password once.

Set `RUSTSCOPE_STATE` to select the private state directory (default `./state`) and `RUSTSCOPE_PORT` to change the port. Run one server per state directory. Keep the SQLite database and its mode-0600 encryption key together in a protected backup with the account files. Losing the key prevents URL recovery.

## Update the interface styles

Edit the Askama files in `templates/` or the Tailwind rules in `styles/tailwind.css`. Install the [Tailwind CSS v4.1.18 standalone CLI](https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.1.18) for your platform and make it available as `tailwindcss`. From the repository root, regenerate the checked-in stylesheet and rebuild the app.

```sh
tailwindcss -i styles/tailwind.css -o templates/style.css --minify
cargo build --locked
```

Askama includes the compiled CSS in each page. The normal Cargo build and the running server require only the committed stylesheet.

## Reproduce the four-round demo

```sh
python3 tests/demo.py --rounds-dir /tmp/rustscope-rounds
```

This starts a temporary instance on loopback, creates three accounts, exercises the HTML form endpoints, and saves four Thai HTML reports. The built-in fixtures supply HTTP evidence in memory and never contact the illustrative hosts. The app uses the production evaluator, queue, database and comparison logic. A separate Rust test also fetches all four responses over a real isolated loopback HTTP connection.

| Round | Evidence for the same A04-02 form | Comparison |
|---|---|---|
| issue | HTML declares an HTTP destination | New finding |
| forbidden | HTTP 403 prevents observation | Not comparable. The finding stays open |
| persistent | The form still declares an HTTP destination | Persistent finding |
| fixed | The same form and all its submit destinations resolve to HTTPS | Verified fixed |

To repeat the exercise in the browser, create an offline project. On the project screen, keep the demo target, environment and policy defaults. Enter a release name, select the first fixture and preview readiness. The preview appears on the project form and keeps the selected inputs for submission. Repeat for the three remaining fixtures in the order above. The comparison links back to the preceding report. Use the browser’s Print command to save an A4 PDF.

The two sample PDFs show why a 403 cannot close the issue and what evidence finally closed it. Other findings, including the unchanged package risks, have independent outcomes. [403 report](examples/reports/forbidden.pdf) · [Verified fix report](examples/reports/fixed.pdf)

## Live collection and evidence review

1. Create a live project with an approved HTTP(S) base URL and an expiry of 1–30 days. Place the displayed challenge at the specified path and verify control. A paired HTTP-to-HTTPS scope requires the challenge on both origins. After expiry, the owner can renew the same project for another 1–30 days, then publish and verify the new challenge to resume scanning. Existing reports and project membership carry forward. Use public, non-sensitive project, account, release and resource labels.
2. Select the exact resource, release and environment. Set the minimum HSTS age, designated-download flag, expected password form ID and cross-origin SRI policy as applicable. Paste the release’s Cargo.lock if available (256 KiB maximum). The inline readiness preview lists applicable rules and missing inputs. It keeps evaluated lockfile results in the current session for that release and environment. Paste a new lockfile to replace them or clear them under advanced settings. An absent or malformed lockfile produces insufficient evidence.
3. Only the owner can submit scans and assign existing accounts as viewers or reviewers. A reviewer or owner can append an E decision to a completed or partially completed scan. The reviewer chooses a rule, disposition and rationale, then supplies a document reference, document contents or a CI record.
4. Confirm provenance and release applicability against the original evidence. Document inputs become SHA-256 fingerprints immediately. Keep the originals under the project’s own retention policy. CI inputs retain a constrained summary and a fingerprint. Each review references the immutable scan and release and records the authenticated reviewer and server timestamp. A later review adds a row. Machine findings remain available for comparison.

A supported CI record has this shape. Use the actual build commit and timestamp in Unix seconds. The report flags environment or release links that need confirmation.

```json
{"case_id":"ACL-01","commit":"abc1234","environment":"test","expected":"deny","actual":"deny","timestamp":1700000000}
```

Supported environments are `test`, `staging` and `production`. Supported comparison values are `allow`, `deny`, `pass`, `fail`, `enabled` and `disabled`. Other policy evidence can use the document-fingerprint workflow. Readers can open reports only inside their assigned projects. Opening a report records an audit event.

## Rule coverage

The Thai catalog has six requirements in each of ten OWASP categories. All 60 ID, method, name, evidence and remediation rows were compared with the supplied Thai brief. The catalog contains 18 A, 6 S and 36 E requirements. Eight A rules are automated. Ten more A rules and all six S rules are planned. All 36 E rules have a human-review workflow. The Thai coverage table distinguishes executed automation, assessable outcomes and catalog totals. [Canonical catalog](src/catalog.tsv)

| Rule | Implemented decision |
|---|---|
| A02-01 | Check nosniff on a designated download |
| A02-02 | Validate HSTS syntax and minimum lifetime for a configured HTTPS host |
| A03-01 | Match resolved crates.io versions against active vulnerability advisories |
| A03-02 | Identify applicable unmaintained notices and aggregate duplicate package observations |
| A04-01 | Check the final document scheme for an HTML password form |
| A04-02 | Resolve form actions and submitter overrides against the document and base URL |
| A04-03 | Identify HTTP script declarations in HTTPS HTML |
| A08-04 | Check integrity metadata syntax on policy-covered cross-origin script declarations |

X03-01 appears on the **ส่วนขยาย** coverage row. It compares JavaScript library
versions declared in script URL paths and filenames with the offline Retire.js
snapshot. A comparable declaration outside all known affected ranges passes
for that declaration. Missing declarations and versions that cannot be compared
yield insufficient evidence. [Extension catalog](src/extensions.tsv)

The bundled RustSec snapshot is dated **2026-11-20**, revision `f291af9b1cc0d21dfcea1709d6b037963cef262b`. The report identifies the snapshot used. Updating it is a deliberate rebuild with the supplied generator and tests. [Snapshot provenance and licensing](fixtures/advisories/README.md)

## Verification

```sh
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked evaluation:: -- --nocapture
cargo build --locked
python3 tests/demo.py --rounds-dir /tmp/rustscope-rounds
```

The HTTP acceptance test covers the four A04-02 transitions, renewal with the same project history, readiness draft reuse, access control, CSRF rejection, retry deduplication, redaction, and preservation of machine evidence after review. Rust tests also cover failed-job isolation, legacy scan records, advisory changes, JavaScript version matching, download header evidence, key loss, and out-of-scope redirects. The missing-URL and missing-lockfile case produced **zero false closures across five open findings**. Chromium printed the sample Thai reports to A4 PDF.

The evaluation fixtures cover six hand-labelled target scenarios across eight canonical rules and X03-01. The evaluation test prints each rule’s precision, recall, confusion counts and insufficient-evidence count for these fixtures. [Evaluation fixtures](fixtures/evaluation) · [Scoring code](src/evaluation.rs)

## Agent assignments

Root owned the manifest and lockfile, routes, authentication, worker integration, fixtures, end-to-end acceptance, and final handoff. Each worker below was dispatched with an explicit model selection. The runtime returned these task-path identifiers and did not expose a separate field confirming the serving model.

| Returned agent ID | Selected model | Work delivered |
|---|---|---|
| /root/architecture | gpt-6.2-astra | Thai catalog, domain contracts and rescan comparison |
| /root/security_review | gpt-6.2-astra | Verified scope, bounded collector, redirect regressions and independent closure/privacy review |
| /root/web_checks | gpt-6.2-sol | Six HTTP/HTML checks, redaction and semantic item identities |
| /root/dependency_checks | gpt-6.2-sol | Two dependency rules, real offline snapshot, generator and version fixtures |
| /root/storage_worker | gpt-6.2-sol | Scoped SQLite persistence, queue recovery, audit events, append-only reviews and encrypted operational URLs |
| /root/ui_reports | gpt-6.2-sol | Thai project pages, preflight, reports, comparison, review forms and print layout |

## Operating limits

- The web service binds to loopback and lets local users register accounts. Sessions expire after one hour and on process restart. The worker handles one job at a time.
- Collection uses explicit public IPv4 destinations, simple query-free paths, and up to four GET requests within 12 seconds. Headers can still be assessed when the response has no HTML or its HTML exceeds the 512 KiB limit. HTTP ownership challenges depend on the integrity of the network path. Collector tests use isolated fixtures.
- The checks inspect server-rendered evidence. JavaScript execution, actual browser loading of scripts, digest verification against fetched script bytes, and vulnerability reachability require separate evidence. RustSec coverage is bounded by the pinned snapshot, supported crates.io sources and supported version semantics. Prerelease-only input yields insufficient evidence.
- Cross-round matching requires the same approved target, comparable policy, environment, evaluator version and resource identity. Advisory rules also record snapshot hashes. A changed snapshot is reported separately from verified remediation, and missing provenance or ambiguous resource identity can keep a finding unresolved. X03-01 can match a version-only script URL change when it uniquely identifies the same declaration.
- An unreadable queued scan is marked failed and audited. A failed run remains visible in history and is excluded from evidence comparisons and reviewer decisions.
- The human workflow was exercised with synthetic accounts. Inter-reviewer agreement and mean time for a human to identify the repair location remain unmeasured. Those metrics require independent reviewers working from the same release evidence and timed report-reading sessions.
