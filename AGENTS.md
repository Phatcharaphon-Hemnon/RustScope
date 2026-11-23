# RustScope contributor guide

Read [PRODUCT.md](PRODUCT.md) before changing scan or review behavior. Use [DESIGN.md](DESIGN.md) for interface work. The [README](README.md) is the quick start for people trying the app.

## Where to work

| Area | Source |
| --- | --- |
| HTTP routes and account handling | `src/main.rs`, `src/auth.rs` |
| Scope verification and collection | `src/scope.rs` |
| Rule definitions, evaluation, and rescan comparison | `src/catalog.tsv`, `src/extensions.tsv`, `src/web.rs`, `src/dependencies.rs`, `src/domain.rs` |
| Queue and database | `src/worker.rs`, `src/storage.rs`, `migrations/` |
| Views and reports | `src/ui.rs`, `src/ui/report.rs`, `templates/` |

## Build and test

Use the [development guide](docs/development.md) for Linux or WSL setup, stylesheet generation, the offline HTTP demo, and Docker publishing. Regenerate `templates/style.css` whenever source CSS or template utility classes change.

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

## Preserve assessment behavior

- Keep live collection bounded and within the verified scope. Use synthetic fixtures for automated tests.
- Preserve project isolation, append-only review decisions, and the ability to read older reports.
- Require comparable evidence of the same item for verified fixes. Keep unavailable evidence and advisory changes distinct from remediation. Failed runs stay in history and remain ineligible for comparison or review.
- Keep raw lockfiles out of readiness responses and preserve separation between the canonical catalog and extension results.
