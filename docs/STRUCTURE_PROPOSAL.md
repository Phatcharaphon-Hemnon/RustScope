# RustScope structure proposal

Keep the existing domain, collection, persistence and presentation modules. Split the binary root where responsibility actually changes. A maintainer tracing a request would start at the route in `app.rs`, open one handler module, and follow calls into the same checks, store and renderer used today.

## Proposed tree

Version-controlled files and the two review documents are shown below. Cargo discovers both targets under the existing package name. Generated directories and Git internals are in the physical baseline inventory.

```text
RustScope/
|-- .dockerignore  # Docker build-context exclusions
|-- .github/  # GitHub configuration
|   `-- workflows/  # GitHub Actions workflows
|       `-- docker-hub.yml  # Build and conditionally publish the Docker image
|-- .gitignore  # Local data, build and graph exclusions
|-- Cargo.lock  # Pinned Rust dependency resolution
|-- Cargo.toml  # Package manifest and existing dependencies
|-- Dockerfile  # Build and package the release binary
|-- README.md  # Setup, demo, verification and coverage guide
|-- compose.yaml  # Loopback service and persistent state volume
|-- docs/  # Structure review documents
|   |-- STRUCTURE_ANALYSIS.md  # Baseline tree, dependencies and path inventory
|   `-- STRUCTURE_PROPOSAL.md  # Proposed layout, mapping and verification gates
|-- examples/  # Reader-facing example outputs
|   `-- reports/  # Printable example assessments
|       |-- fixed.pdf  # Verified-fix sample and downloadable PDF
|       `-- forbidden.pdf  # HTTP 403 comparison sample
|-- fixtures/  # Pinned inputs and labelled examples
|   |-- advisories/  # Offline advisory snapshots and provenance
|   |   |-- LICENSE.txt  # RustSec licensing and attribution notice
|   |   |-- LICENSES/  # Bundled upstream license texts
|   |   |   |-- Apache-2.0.txt  # Apache-2.0 license text
|   |   |   |-- CC-BY-4.0.txt  # CC-BY-4.0 license text
|   |   |   `-- CC0-1.0.txt  # CC0-1.0 license text
|   |   |-- README.md  # Snapshot provenance and regeneration instructions
|   |   |-- generate.py  # Normalize committed RustSec data
|   |   |-- generate_retire.py  # Filter Retire.js advisory data
|   |   |-- retirejs.json  # Pinned JavaScript advisory snapshot
|   |   |-- rustsec.json  # Pinned Rust package advisory snapshot
|   |   `-- test_generate_retire.py  # Check Retire.js filtering
|   |-- demo/  # Offline demo responses and package evidence
|   |   |-- dependencies.lock  # Default demo lockfile
|   |   |-- fixed.html  # Fixed form response
|   |   `-- issue.html  # Finding and persistent form response
|   `-- evaluation/  # Held-out inputs for rule scoring
|       |-- after.html  # Post-fix web evidence
|       |-- after.lock  # Post-fix dependency evidence
|       |-- before.html  # Pre-fix web evidence
|       |-- before.lock  # Pre-fix dependency evidence
|       |-- javascript-fixed.html  # Fixed JavaScript version fixture
|       `-- javascript-vulnerable.html  # Affected JavaScript version fixture
|-- frontend/  # Editable frontend stylesheet
|   `-- tailwind.css  # Tailwind source and print styles
|-- migrations/  # SQLite schema initialization
|   `-- 0001_storage.sql  # Schema, indexes and constraints
|-- src/  # Rust library and binary
|   |-- app.rs  # CLI, shared state, router, guard and server lifecycle
|   |-- app/  # Application handlers and worker
|   |   |-- accounts.rs  # Registration, sign-in, sign-out and cookie responses
|   |   |-- projects.rs  # Project list, catalog page, creation, membership and scope verification
|   |   |-- scans.rs  # Scan preparation, queue submission, reports and appended reviewer decisions
|   |   `-- worker.rs  # Claim, collect, evaluate and finish a scan, including offline responses
|   |-- auth.rs  # Manage account files, password verification, session cookies, tokens and expiry
|   |-- catalog.tsv  # Define the 60 canonical rules in stable catalog order
|   |-- dependencies.rs  # Evaluate locked Rust packages against bundled RustSec advisories
|   |-- domain.rs  # Parse rule catalogs, define outcomes and compare observations across rounds
|   |-- evaluation.rs  # Score held-out fixtures and verify that absent evidence preserves open findings
|   |-- extensions.tsv  # Define additional rules outside the canonical inventory
|   |-- legacy_evidence.rs  # Translate known historical evidence messages when displaying stored results
|   |-- legacy_evidence.tsv  # Map historical Thai messages and patterns to English
|   |-- lib.rs  # Module declarations and reusable core exports
|   |-- main.rs  # Tokio binary entry point delegating to the library
|   |-- model.rs  # Define serialized policy, project, scan and reviewer-decision records
|   |-- scope.rs  # Validate scope and destinations, verify ownership and collect bounded HTTP evidence
|   |-- storage.rs  # Persist projects, memberships, jobs, reviews and audit records with SQLx/SQLite
|   |-- storage/  # Storage-private implementation
|   |   `-- sealed.rs  # Manage the SQLite key sidecar and seal/open operational values with authenticated encryption
|   |-- ui.rs  # Prepare project, catalog, readiness and report view data and render Askama pages
|   |-- web.rs  # Evaluate HTTP headers and HTML, derive stable item identities and redact locations
|   `-- web/  # Passive web-check implementation
|       `-- javascript.rs  # Evaluate declared JavaScript versions using bundled Retire.js matchers and advisory bounds
|-- templates/  # Askama pages, fragments and bundled browser assets
|   |-- account.html  # Signed-in account controls
|   |-- base.html  # Shared shell and embedded styles
|   |-- catalog-page.html  # Standalone catalog page
|   |-- catalog.html  # Reusable rule catalog
|   |-- fonts/  # Local font assets and licenses
|   |   |-- ibm-plex-sans-LICENSE.txt  # ibm-plex-sans distribution license
|   |   |-- ibm-plex-sans.woff2  # ibm-plex-sans typeface
|   |   |-- jetbrains-mono-LICENSE.txt  # jetbrains-mono distribution license
|   |   `-- jetbrains-mono.woff2  # jetbrains-mono typeface
|   |-- home.html  # Project list and creation form
|   |-- login.html  # Sign-in form
|   |-- preview.html  # Scan readiness preview
|   |-- project.html  # Project overview and owner controls
|   |-- register.html  # Account registration form
|   |-- report-groups.html  # Rule-level result disclosures
|   |-- report-guidance.html  # Shared rule impact and remediation
|   |-- report-reference.html  # Rule reference and closure details
|   |-- report-result.html  # One observation row
|   |-- report.html  # Assessment, comparison, print and review layout
|   |-- scan-evidence.html  # Readiness tables by input type
|   |-- style.css  # Checked-in compiled CSS
|   `-- ui.js  # Progressive browser interactions
`-- tests/  # End-to-end acceptance driver
    `-- demo.py  # Four-round CLI/HTTP acceptance test and HTML export
```

## Old path → new path

| Current source | Proposed destination | Contents |
|---|---|---|
| `src/main.rs` | `src/app.rs` | Use `git mv` for the original file. Keep CLI argument handling, startup, shared state, error/CSRF helpers, host/origin guard, router, signal handling and worker/server selection here. Expose the startup body as an async library function named `run`. |
| `src/main.rs` | `src/main.rs` (new thin entry) | Keep `#[tokio::main]` on `main`, forwarding its `anyhow::Result<()>` from `rustscope::run().await`. One runtime per invocation. |
| `src/main.rs` | `src/lib.rs` | Move crate-level module declarations, including `#[cfg(test)] mod evaluation`. Re-export `app::run`. Expose existing domain/model types through their modules as approved below. |
| `src/main.rs` | `src/app/accounts.rs` | Move `login_page` through `register`, including logout and `signed_in`. Credential storage and sessions stay in `auth.rs`. |
| `src/main.rs` | `src/app/projects.rs` | Move `home` through `member`, including `project_input`, `owner` and `project_error`. The scan handler shares the two existing project helpers. |
| `src/main.rs` | `src/app/scans.rs` | Move `scan` through `review`, including `ReportQuery`, CI parsing, evidence handling and the decision reasons. |
| `src/main.rs` | `src/app/worker.rs` | Move `fixture_response`, `run_one` and `worker`. Keep the claim, evaluate, finish and wake sequence intact. |
| All other existing paths in the tree above | Same path | Retain their contents except for the Rust path adjustments described below. |
| No predecessor | `docs/STRUCTURE_ANALYSIS.md`, `docs/STRUCTURE_PROPOSAL.md` | Phase 1 inventory and Phase 2 decision record. |

## Why these boundaries

- The binary currently owns private names used by the UI and evaluation tests. Compile the module tree once in the library. Import `Fields` from `app` in the UI and give the UI crate-level access to the existing `REASONS` through `app`. Replace the evaluation module’s parent glob with explicit imports for the same types and checks. Keep the `evaluation::` test filter working.
- Router wiring belongs beside startup and middleware so route methods, layer order, limits and state can be reviewed together. Handler entry points and shared project helpers need only parent-module visibility. Keep Tokio workers and the store on the same shared state and notification object.
- Only the code moved below `src/app/` gains a directory level. Change the demo lockfile include in `scans.rs` to `../../fixtures/demo/dependencies.lock`, and the two demo HTML includes in `worker.rs` to `../../fixtures/demo/{issue,fixed}.html` respectively. The PDF, script and two font handlers stay in `src/app.rs`, at the original include depth.
- The catalog and comparison code share types and work independently of Axum. Keeping `domain.rs`, `catalog.tsv` and `extensions.tsv` together preserves both embedded paths and documented links. The package and JavaScript checks already have distinct data sources. A second set of folders for checks, collection and evaluation would add paths to change without separating any mixed responsibility.
- `web.rs` evaluates collected evidence. HTTP request handlers live under `app/`. `scope.rs` keeps collection and its outbound restrictions together. `storage.rs` owns transactions spanning membership, queue operations and audit records, with key handling in its private child. Splitting storage by table would obscure those transaction boundaries.
- Askama templates call `crate::ui`, `crate::auth` and `crate::domain` directly. Keeping those module names and defining the derives in the library preserves lookup. Keep the English rendering, legacy Thai translation, root assets, compiled stylesheet, fixtures, sample PDFs, migrations and demo script byte-for-byte wherever a Rust import does not need adjustment. The proposed moves require no dependency, manifest, README command, DB or Docker path change.

## Execution after approval

1. Create the library and binary boundaries with the whole-file move to `app.rs`. Keep handler bodies together for this commit. Update library imports, test imports and the UI’s references to shared application names.
2. Extract the three worker functions using the existing bodies. Correct the two HTML includes.
3. Extract the account handlers.
4. Extract the project handlers and share the existing owner/error helpers with the scan handler.
5. Extract the scan/report/review handlers. Correct the lockfile include and the internal decision-reasons import.

Use one independently buildable commit per step. Function extractions are partial-file moves. Plain edits preserve readable diffs there; `git log -L` or `git blame -C` can trace the extracted lines. After each commit, from the root, run:

```sh
cargo fmt --check
cargo check --locked
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/demo.py --rounds-dir /tmp/rustscope-rounds
```

The explicit build refreshes the exact debug executable that Python launches. Check the run produced fresh `issue.html`, `forbidden.html`, `persistent.html` and `fixed.html`, with the expected New, NotComparable, Persistent and VerifiedFixed A04-02 transitions. Require at least the observed **29 Rust tests**, with the original test cases present exactly once across targets. Compare route/guard wiring and hash the unchanged migration, template and report assets against the baseline. Refresh the local Graphify index after source moves.

## Decisions and verification notes

- **Library API.** The approved public surface is `run`, `domain` and `model`. The collector and checks are crate-private. There are no Rust integration tests in `tests/`.
- **Report equivalence.** Independent demo runs generate fresh IDs and timestamps. For exact HTML comparisons, use the same stored records, session/view inputs and clock-dependent scope state on both revisions. For fresh-run comparisons, compare evidence, ordering, reviewer decisions and comparison results while accounting for generated values. The committed PDFs themselves can be compared byte-for-byte.

## Baseline and approval

At `61bc439`, formatting, locked check, strict all-targets Clippy, locked tests and a locked debug build passed. The HTTP demo passed and exported four reports to a fresh temporary directory. This is the pre-move baseline. The approved gate requires these same 29 tests and four fresh demo reports after each commit.
