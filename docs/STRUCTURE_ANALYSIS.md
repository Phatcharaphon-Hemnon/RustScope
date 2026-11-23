# RustScope structure analysis

Snapshot of `main` at `61bc439`, before adding the two planning documents. The package builds one binary from Cargo’s conventional `src/main.rs` entry point. It has no library target yet. The largest concentration of unrelated work is the 850-line binary root. The similarly large `ui.rs` includes substantial rendering tests and already has a coherent presentation responsibility.

## Files and direct dependencies

The last column lists in-repository dependencies, embedded data and material test-only edges. External Rust dependencies are declared in the root Cargo manifest.

| File | Responsibility | Direct dependencies or consumer |
|---|---|---|
| `src/auth.rs` | Manage account files, password verification, session cookies, tokens and expiry. | No sibling module |
| `src/catalog.tsv` | Define the 60 canonical rules in stable catalog order. | Data read by domain::catalog |
| `src/dependencies.rs` | Evaluate locked Rust packages against bundled RustSec advisories. | domain |
| `src/domain.rs` | Parse rule catalogs, define outcomes and compare observations across rounds. | catalog.tsv, extensions.tsv |
| `src/evaluation.rs` | Score held-out fixtures and verify that absent evidence preserves open findings. | Test only. domain, model::Policy, scope::HttpEvidence, web, dependencies via parent imports |
| `src/extensions.tsv` | Define additional rules outside the canonical inventory. | Data read by domain::extensions |
| `src/legacy_evidence.rs` | Translate known historical evidence messages when displaying stored results. | legacy_evidence.tsv |
| `src/legacy_evidence.tsv` | Map historical Thai messages and patterns to English. | Data read by legacy_evidence |
| `src/main.rs` | Start the CLI/server, assemble routes, handle forms and run the scan worker. | auth, model, scope, storage, ui, dependencies, web, domain (review validation), test-only evaluation. Declares legacy_evidence for ui |
| `src/model.rs` | Define serialized policy, project, scan and reviewer-decision records. | domain::Observation |
| `src/scope.rs` | Validate scope and destinations, verify ownership and collect bounded HTTP evidence. | No sibling in production. Tests use domain, model and web |
| `src/storage.rs` | Persist projects, memberships, jobs, reviews and audit records with SQLx/SQLite. | domain, model, scope, storage::sealed and migration SQL |
| `src/storage/sealed.rs` | Manage the SQLite key sidecar and seal/open operational values with authenticated encryption. | No sibling module |
| `src/ui.rs` | Prepare project, catalog, readiness and report view data and render Askama pages. | auth, dependencies, domain, legacy_evidence, model, scope, web and root Fields/REASONS |
| `src/web.rs` | Evaluate HTTP headers and HTML, derive stable item identities and redact locations. | domain, model, scope, web::javascript |
| `src/web/javascript.rs` | Evaluate declared JavaScript versions using bundled Retire.js matchers and advisory bounds. | domain and retirejs.json |

## Embedded paths

Rust resolves each literal from the directory of the Rust source file containing the macro. Each row is one invocation, including test code and repeated paths. Moving a handler inside a file can therefore change its required literal.

| Call site | Macro and literal | Repository target |
|---|---|---|
| `src/dependencies.rs:13` | `include_str!("../fixtures/advisories/rustsec.json")` | `fixtures/advisories/rustsec.json` |
| `src/domain.rs:53` | `include_str!("catalog.tsv")` | `src/catalog.tsv` |
| `src/domain.rs:57` | `include_str!("extensions.tsv")` | `src/extensions.tsv` |
| `src/evaluation.rs:24` | `include_str!("../fixtures/evaluation/before.html")` | `fixtures/evaluation/before.html` |
| `src/evaluation.rs:25` | `include_str!("../fixtures/evaluation/after.html")` | `fixtures/evaluation/after.html` |
| `src/evaluation.rs:35` | `include_str!("../fixtures/evaluation/before.lock")` | `fixtures/evaluation/before.lock` |
| `src/evaluation.rs:43` | `include_str!("../fixtures/evaluation/before.lock")` | `fixtures/evaluation/before.lock` |
| `src/evaluation.rs:51` | `include_str!("../fixtures/evaluation/after.lock")` | `fixtures/evaluation/after.lock` |
| `src/evaluation.rs:58` | `include_str!("../fixtures/evaluation/javascript-vulnerable.html")` | `fixtures/evaluation/javascript-vulnerable.html` |
| `src/evaluation.rs:66` | `include_str!("../fixtures/evaluation/javascript-fixed.html")` | `fixtures/evaluation/javascript-fixed.html` |
| `src/evaluation.rs:134` | `include_str!("../fixtures/evaluation/before.html")` | `fixtures/evaluation/before.html` |
| `src/evaluation.rs:137` | `include_str!("../fixtures/evaluation/before.lock")` | `fixtures/evaluation/before.lock` |
| `src/legacy_evidence.rs:5` | `include_str!("legacy_evidence.tsv")` | `src/legacy_evidence.tsv` |
| `src/legacy_evidence.rs:22` | `include_str!("legacy_evidence.tsv")` | `src/legacy_evidence.tsv` |
| `src/main.rs:500` | `include_str!("../fixtures/demo/dependencies.lock")` | `fixtures/demo/dependencies.lock` |
| `src/main.rs:690` | `include_str!("../fixtures/demo/issue.html")` | `fixtures/demo/issue.html` |
| `src/main.rs:692` | `include_str!("../fixtures/demo/fixed.html")` | `fixtures/demo/fixed.html` |
| `src/main.rs:794` | `include_bytes!("../examples/reports/fixed.pdf")` | `examples/reports/fixed.pdf` |
| `src/main.rs:804` | `include_str!("../templates/ui.js")` | `templates/ui.js` |
| `src/main.rs:813` | `include_bytes!("../templates/fonts/ibm-plex-sans.woff2")` | `templates/fonts/ibm-plex-sans.woff2` |
| `src/main.rs:822` | `include_bytes!("../templates/fonts/jetbrains-mono.woff2")` | `templates/fonts/jetbrains-mono.woff2` |
| `src/storage.rs:26` | `include_str!("../migrations/0001_storage.sql")` | `migrations/0001_storage.sql` |
| `src/ui.rs:912` | `include_str!("../fixtures/evaluation/javascript-vulnerable.html")` | `fixtures/evaluation/javascript-vulnerable.html` |
| `src/web/javascript.rs:14` | `include_str!("../../fixtures/advisories/retirejs.json")` | `fixtures/advisories/retirejs.json` |

SQLite initialization uses `sqlx::raw_sql(include_str!(…))` in `Store::open`. There is no `sqlx::migrate!` invocation, external migration loader or `askama.toml`. Askama uses the default package-root `templates/` directory.

## Askama lookup and Rust paths

| Consumer | Paths relative to templates/ |
|---|---|
| `src/ui.rs:24` (Login) | `login.html` |
| `src/ui.rs:35` (Registration) | `register.html` |
| `src/ui.rs:52` (Home) | `home.html` |
| `src/ui.rs:84` (CatalogPage) | `catalog-page.html` |
| `src/ui.rs:121` (ProjectPage) | `project.html` |
| `src/ui.rs:221` (Report) | `report.html` |
| `src/ui.rs:573` (Preview) | `preview.html` |
| `templates/base.html` | include `style.css` |
| `templates/catalog-page.html` | extends `base.html`, include `account.html`, include `catalog.html` |
| `templates/home.html` | extends `base.html`, include `account.html` |
| `templates/login.html` | extends `base.html` |
| `templates/preview.html` | extends `base.html`, include `account.html`, include `scan-evidence.html` |
| `templates/project.html` | extends `base.html`, include `account.html`, include `scan-evidence.html`, include `catalog.html` |
| `templates/register.html` | extends `base.html` |
| `templates/report-groups.html` | include `report-result.html`, include `report-guidance.html`, include `report-reference.html` |
| `templates/report.html` | extends `base.html`, include `account.html`, include `report-groups.html` |

Askama also compiles these Rust paths written in template expressions.

- `templates/home.html` — `crate::auth::now`, `crate::ui::utc_date`.
- `templates/preview.html` — `crate::ui::environment_label`.
- `templates/project.html` — `crate::ui::scan_status`, `crate::ui::utc_date`.
- `templates/report.html` — `crate::domain::ChangeStatus::New`, `crate::domain::ChangeStatus::NotComparable`, `crate::domain::ChangeStatus::Persistent`, `crate::domain::ChangeStatus::VerifiedFixed`, `crate::ui::decision_label`, `crate::ui::environment_label`, `crate::ui::scan_status`, `crate::ui::utc_date`.

The local Askama filter resolves through `ui::filters` to `legacy_evidence::evidence`. Rendering is English. Historical Thai evidence is translated at display time.

## Build, demo and filesystem contracts

| Consumer | Dependency on location |
|---|---|
| Cargo | `Cargo.toml`, `Cargo.lock`, conventional binary `src/main.rs`, prospective library `src/lib.rs`. Each external `mod` looks beside its declaring module or in that module’s directory. Today `web.rs → web/javascript.rs`, `storage.rs → storage/sealed.rs`, and the binary root declares the other modules. |
| Tailwind | `frontend/tailwind.css` imports `tailwindcss/theme.css` and `tailwindcss/utilities.css`, scans `../templates/*.html` and builds `templates/style.css`. Askama embeds that compiled stylesheet. The source and generated CSS use the two public `/fonts/*.woff2` routes listed below. |
| HTTP wiring | The PDF, script and fonts are embedded, then served at fixed URLs. Templates and the demo depend on those URLs and the form routes. They are independent of the source directory name. |
| SQLx and account storage | The working-directory default `state` can be overridden with `RUSTSCOPE_STATE`. Keep `server.lock`, `rustscope.sqlite`, its appended `.key` sidecar, `accounts/<username>` and temporary `accounts/.<token>` relative to that state directory. The storage test uses the OS temp directory and `rustscope-<uuid>.sqlite` with the same key convention. |
| Verification | The remote file `rustscope-verification.txt` is relative to the authorized scope, including any permitted HTTPS upgrade. The project template, collector and demo assertions must agree. This file does not live in the checkout. |
| Python demo | Run from the repo root. `tests/demo.py` resolves `target/debug/rustscope`, compares the served PDF against `examples/reports/fixed.pdf`, and accesses `rustscope.sqlite` under a temporary `rustscope-demo-*` state directory. `--report` accepts a caller-selected file. `--rounds-dir` writes `issue.html`, `forbidden.html`, `persistent.html` and `fixed.html` under the supplied directory. |
| Advisory tooling | `fixtures/advisories/generate.py` reads the external checkout supplied in argv and archives its committed `crates/` subtree. `generate_retire.py` operates on stdin/stdout. `test_generate_retire.py` imports its sibling `generate_retire`. The advisory README names `/path/to/advisory-db`, `/path/to/jsrepository.json`, `/tmp/rustscope-rustsec.json`, `/tmp/retirejs.json`, and replacement files `rustsec.json` and `retirejs.json`. |
| Licenses and provenance | Paths from `fixtures/advisories/README.md` include `LICENSE.txt`, `LICENSES/Apache-2.0.txt` and `retirejs.json`. `LICENSE.txt` names `LICENSES/CC0-1.0.txt` and `LICENSES/CC-BY-4.0.txt`. Font license files travel with the two font files. |
| Docker build | Build context is the repository root. In `/build`, Docker copies `Cargo.toml Cargo.lock ./`, `src/ src/`, `templates/ templates/`, `migrations/ migrations/`, `fixtures/ fixtures/` and `examples/reports/fixed.pdf examples/reports/fixed.pdf`. The final stage copies `/build/target/release/rustscope` to `/usr/local/bin/rustscope` (also the entrypoint) and creates `/var/lib/rustscope` for state. |
| Compose and CI | `compose.yaml` uses `build: .` and mounts `rustscope-state:/var/lib/rustscope`. GitHub discovers `.github/workflows/docker-hub.yml`; the workflow runs `docker build --tag "rustscope:$GITHUB_SHA" .` against the root Dockerfile. |

### Router literals

`/`, `/login`, `/register`, `/sample-report.pdf`, `/logout`, `/ui.js`, `/fonts/ibm-plex-sans.woff2`, `/fonts/jetbrains-mono.woff2`, `/catalog`, `/projects`, `/p/{id}`, `/p/{id}/member`, `/p/{id}/verify`, `/p/{id}/scan`, `/p/{id}/s/{sid}`, `/p/{id}/s/{sid}/review`. Preserve methods, middleware, form fields, redirect targets and query parameters.

### README commands and links

Run the documented commands from the package root. The advisory generation commands require their documented upstream inputs.

**README.md**

- `docker compose up --build -d`
- `docker compose logs -f`
- `docker compose down`
- `cargo run --locked`
- `cargo run --locked -- account USER`
- `tailwindcss -i frontend/tailwind.css -o templates/style.css --minify`
- `cargo build --locked`
- `python3 tests/demo.py --rounds-dir /tmp/rustscope-rounds`
- `cargo fmt --check`
- `cargo check --locked`
- `cargo test --locked`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo test --locked evaluation:: -- --nocapture`

Relative links: `examples/reports/forbidden.pdf`, `examples/reports/fixed.pdf`, `src/catalog.tsv`, `src/extensions.tsv`, `fixtures/advisories/README.md`, `fixtures/evaluation`, `src/evaluation.rs`.

**fixtures/advisories/README.md**

- `python3 fixtures/advisories/generate.py /path/to/advisory-db > /tmp/rustscope-rustsec.json`
- `python3 fixtures/advisories/generate_retire.py < /path/to/jsrepository.json > /tmp/retirejs.json`
- `python3 -B -m unittest discover -s fixtures/advisories -p test_generate_retire.py`
- `cargo test --locked javascript`

Relative links: `LICENSE.txt`, `retirejs.json`, `LICENSES/Apache-2.0.txt`.

**.gitignore** — `/target/`, `/state/`, `/graphify-out/`.

**.dockerignore** — `.git`, `.cargo`, `target`, `state`, `graphify-out`, `**/node_modules`, `**/__pycache__`, `**/.env`, `**/.env.*`, `**/.git-credentials`, `**/.netrc`, `**/.npmrc`, `**/.ssh`, `**/.aws`, `**/accounts`, `**/credentials`, `**/credentials.*`, `**/secrets`, `**/*.pem`, `**/*.key`, `**/*.sqlite*`, `**/*.db`, `**/*.db-*`.

## Full current tree

Captured with `tree -a --charset=ASCII -I 'target|state'` before creating `docs/`. This physical inventory includes Git metadata and the local Graphify cache. Their contents vary by checkout. The proposal describes the version-controlled project.

<details><summary>Expand the complete pre-analysis tree</summary>

```text
.
|-- .dockerignore
|-- .git
|   |-- COMMIT_EDITMSG
|   |-- FETCH_HEAD
|   |-- HEAD
|   |-- ORIG_HEAD
|   |-- config
|   |-- description
|   |-- hooks
|   |   |-- applypatch-msg.sample
|   |   |-- commit-msg.sample
|   |   |-- fsmonitor-watchman.sample
|   |   |-- post-update.sample
|   |   |-- pre-applypatch.sample
|   |   |-- pre-commit.sample
|   |   |-- pre-merge-commit.sample
|   |   |-- pre-push.sample
|   |   |-- pre-rebase.sample
|   |   |-- pre-receive.sample
|   |   |-- prepare-commit-msg.sample
|   |   |-- push-to-checkout.sample
|   |   |-- sendemail-validate.sample
|   |   `-- update.sample
|   |-- index
|   |-- info
|   |   `-- exclude
|   |-- logs
|   |   |-- HEAD
|   |   `-- refs
|   |       |-- heads
|   |       |   `-- main
|   |       `-- remotes
|   |           `-- origin
|   |               `-- main
|   |-- objects
|   |   |-- 00
|   |   |   |-- 1972e1af3ecd0658b6371f037c58cbdc2eb8ae
|   |   |   `-- f3f0aef03461b8fc64d28e64af33fd7e4a73c6
|   |   |-- 02
|   |   |   |-- 27c3e44a1c6b24f90d1a2ef9421eebe7fb15cd
|   |   |   |-- 752d9d214ea3957f32f16d760d3646188a91f6
|   |   |   `-- b99d6cdc0df09aba910f76781f451516cb0e6b
|   |   |-- 05
|   |   |   `-- cb8db6e6364bc31940d6ccd1eac9af88ef0327
|   |   |-- 06
|   |   |   `-- 9d480af87f20f6f091d7fc0698b53994acfa79
|   |   |-- 07
|   |   |   |-- 2ee2e577c44f7d009fa9c4f9c27910d47eee44
|   |   |   |-- 46aad87c9510c74867b894d77299c59c8b0bee
|   |   |   |-- abd4707b81354c4c0979b8b163f06145f31b7e
|   |   |   `-- cba25d8923f1eb1e3ae0403c921a4cc77512c6
|   |   |-- 0a
|   |   |   `-- 79005fa71fc40aa017db12850d4a92a8e86952
|   |   |-- 0e
|   |   |   `-- 259d42c996742e9e3cba14c677129b2c1b6311
|   |   |-- 0f
|   |   |   |-- 11c14e274898c3b52b8a4248d0cbae8d7df076
|   |   |   |-- 51fa2121b6bae65ede83eee211a3c1674e6c30
|   |   |   `-- b53ae027d0925d8ed36c69c3b4e416b7157bb0
|   |   |-- 11
|   |   |   `-- 6937521a7b40956e56d5bafa85b143a1169486
|   |   |-- 12
|   |   |   `-- c9e84f854fa4530ceb5fd66e845cc13029888f
|   |   |-- 13
|   |   |   `-- 295adecf6fc982988c692774d78364ac63a36e
|   |   |-- 14
|   |   |   `-- b0827dfb19781f2459ae1d3eb2143673236501
|   |   |-- 15
|   |   |   `-- 6f6b52d774859360f944dfa2a8fca42ad2d45b
|   |   |-- 16
|   |   |   |-- 36ec92447b045a237d855e9807382867d5b20a
|   |   |   `-- 6a86b2597a88e41f74670235725d10f23e3c56
|   |   |-- 17
|   |   |   `-- 8cf232010b049a8a0b9ee720af2eec4647be9f
|   |   |-- 18
|   |   |   |-- 5bd3f5e95dcc362ec6feffeba66a4bcbdfb36e
|   |   |   `-- 99aaa63eeb7d3cd047cf3b4e697058b08caccb
|   |   |-- 19
|   |   |   |-- 07d9669f69bc9bfad2e051f3c66d4c14ee4911
|   |   |   `-- 0aec115b91294963f4eccd8afac939f7f73c8f
|   |   |-- 1a
|   |   |   `-- 1b9b780d300cd4f67024a00d36ff663f3bf69c
|   |   |-- 1b
|   |   |   `-- c14b232e7caf2613f7a81aa627731fd1a551fe
|   |   |-- 1c
|   |   |   `-- 038bcd677b540ef85eff22e81d1d818446ae37
|   |   |-- 1d
|   |   |   `-- 401f2b9fd7ae798c15127f905aef9beae07eda
|   |   |-- 1f
|   |   |   `-- 00285e2a00d21ee834da107e7b76963a522e26
|   |   |-- 21
|   |   |   |-- 5a31d5fab3cd422eea97567599598e4341bd46
|   |   |   `-- 78f527d877340612023a9f3d8dc5d4f5308b74
|   |   |-- 23
|   |   |   |-- 035389cc17f7deb81e3524ea6872090c007e10
|   |   |   `-- 5969264abd02f9b774fd036098405e8c2b750d
|   |   |-- 24
|   |   |   |-- 3d9a08af3ab2aba58f4bcf4bc017cdb086c43b
|   |   |   |-- 439fb0bab9ba0091776fd8e94889166ca60de6
|   |   |   `-- 4686d53026f49da5f73a6f0c6de2503fbe8fb1
|   |   |-- 25
|   |   |   `-- 8d7f3e2141b6e5fa728b9f71ae77f841f3c71b
|   |   |-- 26
|   |   |   `-- 1eeb9e9f8b2b4b0d119366dda99c6fd7d35c64
|   |   |-- 27
|   |   |   |-- 2dcfe82c68533f469f80a0fc8742d010cd0f7d
|   |   |   `-- 80a1c3037c33669a60df096c88fa7d599e6486
|   |   |-- 28
|   |   |   `-- 89cd03d1c6c66dbc7db66fb87d10bfc7089a9f
|   |   |-- 29
|   |   |   `-- 430327811784591459d225327f9ee07de610ff
|   |   |-- 2a
|   |   |   |-- 3f1e3fdf2ffcf3e70ff540f1987ef16f9e9672
|   |   |   `-- e8ef3cc4a742c2ac6046175e04704fc5e2b58e
|   |   |-- 2d
|   |   |   |-- 58298e6eda10e7204abb52722efbc840db2390
|   |   |   |-- c6577d5b8f000106bc27ce7b82796d7b21fd8a
|   |   |   `-- fecf79f162c231a9cea7d1d35c71fa01557d3c
|   |   |-- 2f
|   |   |   |-- 1c8c65d37b4e43dfb0990c27218b6379feab09
|   |   |   `-- 55f85cbe26e0587e11cf55b98774ba2a70daf8
|   |   |-- 33
|   |   |   `-- 698d8b1b8d3d2cf2e3afab49685725c9ca7fb5
|   |   |-- 34
|   |   |   `-- e24eb8152d7bc148fa96eef50b3246dbb1ebcd
|   |   |-- 36
|   |   |   |-- 2ff27739539b437883354df655119f173de044
|   |   |   `-- 7b5432ff22853058b8d2d155cafc89791b537f
|   |   |-- 37
|   |   |   `-- 0669b12b31829563d9fc040e222e84ce5c9fbb
|   |   |-- 3a
|   |   |   `-- 14a0173e751edfc3a03fb00449358ff7f58cc4
|   |   |-- 3b
|   |   |   |-- 7fb180ad6893a6815cc8e9940f37df234d829c
|   |   |   `-- 952bff4e3873228c3ba565bb47c5421afb75eb
|   |   |-- 3c
|   |   |   |-- 44cdca889549076607c3af3b70d229d6105aec
|   |   |   `-- 872b7ef69aec26447a8dbcefbc5b787fa59525
|   |   |-- 3e
|   |   |   |-- 6c743140604b5093c4c86ec446ecb2f45fe2a2
|   |   |   |-- 98d64c20d2d593069be9e10320d09a55c65612
|   |   |   `-- a42a71bd2a63ccbd4e1aea312d042e27843e47
|   |   |-- 3f
|   |   |   `-- a8de21f018757793757e63f56e4d7403cab9b1
|   |   |-- 40
|   |   |   `-- e328dbf598f08873fab4770255b9daffade103
|   |   |-- 41
|   |   |   `-- 41051c61c8a422632fc99da7591aee0e40aeac
|   |   |-- 42
|   |   |   |-- 40f1903a75101e7e41f3d68d80d151dae8d004
|   |   |   `-- 910755fad949dae959e90143b1348848243939
|   |   |-- 44
|   |   |   |-- 7d7e0190e3b72a49fd76afa951ba16c6dd1560
|   |   |   `-- 957e65fb678252d238742043ed440f721eede2
|   |   |-- 46
|   |   |   |-- 3b0bcdba04ecde8e5a51af500ae0be741bcbd1
|   |   |   |-- 92c7dfdacc1083290876ad343afcd412f011b5
|   |   |   `-- a771e12be5240551e733b66daeb9c51acc997e
|   |   |-- 4b
|   |   |   `-- 66616cfe5489dc4b21e602b4bf88cfd5ae7dfa
|   |   |-- 4c
|   |   |   `-- f3eaff21bcf74e6d973691e90a42f69fdde26e
|   |   |-- 51
|   |   |   `-- 6a8f0800574fa7f6d7d1a279d6a8891cdcfd2a
|   |   |-- 52
|   |   |   |-- 9e56ad25d38d8ddbcd958187b6b2b9fb100cf7
|   |   |   `-- b21727b8152909a9d9ee98260b2b1a02ecdfbb
|   |   |-- 53
|   |   |   `-- fc1fc384cca586b53487d6558330e5c8a089e6
|   |   |-- 54
|   |   |   |-- 4c883ac216e5614734415fd48363d9a511dd66
|   |   |   `-- f4134f6857201624b186a0fa5b5b1bb3c716d9
|   |   |-- 56
|   |   |   `-- a7794f4aeffa768b231dfc30e6c3901c8ab89e
|   |   |-- 57
|   |   |   `-- 9a97234f9ddc3434fcb6dfd771095181365c3d
|   |   |-- 58
|   |   |   `-- ab5c4fddec2de8ece930696c513e59af31fe33
|   |   |-- 59
|   |   |   |-- 3cd59fe87d0aafb9c95f398ed5d4b0efbe2118
|   |   |   `-- 4f8451d56a05bb75c37bb8dd9e704c4a29f93d
|   |   |-- 5a
|   |   |   `-- d6c6f6f7f8e8f51f3bbb54bf1680e158ed16bf
|   |   |-- 5b
|   |   |   |-- 0e08373539f7f6cfda25de52e07bce8876f9bb
|   |   |   `-- 28453a4d2cd8bde24ba3e54a546205cd787446
|   |   |-- 5c
|   |   |   `-- fb2fe2298e9d1616953d32cc3ceee99dee7870
|   |   |-- 5d
|   |   |   `-- 8d2febb091ac42ad1a405771e0cc8b2759a6b6
|   |   |-- 5e
|   |   |   |-- 1cdc279e75c53af2c69612ec7ae01f940e4b88
|   |   |   `-- d135c5909eabf929a876d632135dff28360e27
|   |   |-- 60
|   |   |   `-- 1ca0667cab47f006765bbad1bf6d03039fc75f
|   |   |-- 61
|   |   |   `-- bc4397ecbd742c41f4bf91ae1be9485b050107
|   |   |-- 62
|   |   |   `-- b4dce49929777a979e8feaa7ce2e58308d4054
|   |   |-- 66
|   |   |   |-- 17bf8f2bf70bcb63e28b7a0dadb597728d308a
|   |   |   `-- cbbec6b9edba615692975ba7b0bfc5f91afb09
|   |   |-- 67
|   |   |   |-- 041a56a11a33477438fb38a66a026e83520f36
|   |   |   `-- da65a8a81d068041626f998c3297e917a2522d
|   |   |-- 69
|   |   |   `-- 061a0d5da96acef6f89e1ecb1a565e5d36951f
|   |   |-- 6a
|   |   |   |-- 60a12445dc12e4e5ce27b93a9ff7c7f2ee8aab
|   |   |   |-- a1a158725ed967def83e472a31f76460b988f0
|   |   |   `-- fdd03d85d8e285efeace066016c22258512825
|   |   |-- 6b
|   |   |   `-- b8161c55295e5399f3a8193be2b3210e3ce742
|   |   |-- 6c
|   |   |   `-- ead9c98beaa2f0ff50e9403c83c806f5b9d798
|   |   |-- 6f
|   |   |   `-- 2fdd9038741a9c68c5716a9949498d02898504
|   |   |-- 71
|   |   |   |-- 24a4d7630b2c395b06f375797b67b0df7cfbf4
|   |   |   `-- 905d05444a0f7aedf283dfd0c337dee6b60e73
|   |   |-- 73
|   |   |   |-- 466aa8d46452ce18e67f84dd7311474c7b0906
|   |   |   `-- 50bd79d6b4b09d04a42199acc16b52a9dc4780
|   |   |-- 74
|   |   |   |-- 0204c23e25591ec81655c43b46d395dff72f3c
|   |   |   |-- 6f7538a671c623f5039d5d4084bb114f6e12de
|   |   |   `-- ce26560e067124925c5ff97720a5d9a0e733a6
|   |   |-- 75
|   |   |   `-- 0882f10381a81910233cd36ea4c4042fb7df5c
|   |   |-- 76
|   |   |   |-- 055e6e68436e28900990954f6e21d9204a99b2
|   |   |   `-- 42292c6c9a997f55e891810cb86cc0f5169a8f
|   |   |-- 78
|   |   |   `-- 64ccf738d0f13fbf21ac28b2e083c15c82aece
|   |   |-- 79
|   |   |   |-- 6e3f6578a91dc2adefa077331f044d876ffde0
|   |   |   |-- ba98df9cb21ed0649ad651a5856928370f3442
|   |   |   `-- e29bac64813e415094d00b0e170b5951cada77
|   |   |-- 7a
|   |   |   |-- 2097771aa48d81e83dbc037da9f65accaa45af
|   |   |   `-- bb5152f3e1ce6cddba363446e6b5fe62a7f702
|   |   |-- 7b
|   |   |   `-- 9740f3a660b0acbfc8dd166361baf8c9f8fa68
|   |   |-- 7d
|   |   |   `-- a0769a2b673d78573eaf483ad49c4f679f039b
|   |   |-- 7e
|   |   |   `-- 0fe9688708b4d2a74a0966339f060adc2882f2
|   |   |-- 80
|   |   |   `-- 2b145bf3f2edfc8e76a7c64962e630fde2c478
|   |   |-- 81
|   |   |   `-- f294ef1c4c183289862256d6d5729343fad3d4
|   |   |-- 83
|   |   |   |-- 6643cafcc29d186902e259c1803d502cb6a794
|   |   |   `-- a9855e22c9c183736fd4396c579c131a13163c
|   |   |-- 84
|   |   |   |-- 574519b97f3f131af0bc3d14d8d955c968e292
|   |   |   `-- f752c2a1d2777f2297a9fb877011754ef3427b
|   |   |-- 86
|   |   |   |-- 47ce4343ba9d30086d5815db3f1291dec1d584
|   |   |   |-- 6e3e57249dd2e48b28e5cc6bf3ad97762f866f
|   |   |   `-- ed09dd635da1d24d0f79933c510a09e3b10985
|   |   |-- 87
|   |   |   `-- 89ff6174f36a32beaac707bde0610515b7c969
|   |   |-- 8a
|   |   |   |-- 4046e53868e52d97dc7cbc9aaa4d9c407f5d80
|   |   |   `-- 6005323943f26851bb0e359eacfe5898d04c42
|   |   |-- 8e
|   |   |   |-- 474e40fb5277bf72fd913cb79a76b17958a470
|   |   |   `-- e9f8587bd4b3c4efc0bb2ce3b5e9e58e00234a
|   |   |-- 8f
|   |   |   |-- 7ed671137e7a27c646ead86f45d5cb4875f459
|   |   |   `-- 9e6d2650669f8c6df2cd20d8386410d9a213be
|   |   |-- 91
|   |   |   `-- 7e7a38c0403eae4a49ab44fea565b9e0711d8d
|   |   |-- 93
|   |   |   `-- 4459313a056f965f0133fb0f26f0293529e926
|   |   |-- 95
|   |   |   `-- 50ff6494374e5951f6403e81334c13b11830ad
|   |   |-- 96
|   |   |   |-- 8760910ca201d162d2ff1cc0e3dda3e6c592aa
|   |   |   `-- e24b3ea38bcd232cbcb9bfccb2c69ba434cdff
|   |   |-- 97
|   |   |   `-- f1497bd79ff88c38789493549a4f61906d338b
|   |   |-- 99
|   |   |   `-- 2f6b6cbbf456019d1e436ab5a22d9d8ef41259
|   |   |-- 9a
|   |   |   |-- 1fe22405254ec3eb089a867792b4826a011f5b
|   |   |   `-- 6a2d5edab5df13f69eec8547e7342494cf74bf
|   |   |-- 9b
|   |   |   `-- ef084eba04b3c0f0c4e633d53902b1dea5ec12
|   |   |-- 9e
|   |   |   |-- 768b3f56f74abe005c5e061082e5b198b79029
|   |   |   `-- 9a7033b74b54c5a45f36cb33ef0d1c42a6790b
|   |   |-- 9f
|   |   |   `-- c3f1780d8bbfdc9a091acf83fe26f74d352327
|   |   |-- a2
|   |   |   |-- 391634d56f8e45a83a1451b8065b7f65a9ec67
|   |   |   |-- ad21ea51ea0c743d9a525fbbc93c486a3ad501
|   |   |   `-- eed22ce496bc5a4a5fcef5fb3899a1b110cf9e
|   |   |-- a3
|   |   |   `-- 0ea89c9390c922d6845edd2f23b0e5c3fb4e1b
|   |   |-- a5
|   |   |   `-- b9fe6028acd4ca8b1bfb8ae0c64f2571c26ead
|   |   |-- a6
|   |   |   `-- b3840443c64a2f3ccd8dd31ceaff9ff271b894
|   |   |-- a8
|   |   |   |-- 1548e791c07e9920d060be64c42ea13df6b667
|   |   |   `-- 356fcb9d513a96b4fe669fd2c5044010858e86
|   |   |-- aa
|   |   |   `-- bec09f95f54886ad6f8e94755c55656ff32a54
|   |   |-- ab
|   |   |   |-- 12bf5ff44c8b84a72f5a73c17c9d08f08865c2
|   |   |   `-- 99c5806986599e9f393d870477a9fef631b68c
|   |   |-- af
|   |   |   |-- 39eff7b33e89c02a65da793dc40d1f68c0096b
|   |   |   `-- c082e3c4e9a95f78db572c1d221434eeba3d8f
|   |   |-- b0
|   |   |   |-- 89075d7e4444b5e84843399a9c78254d56a246
|   |   |   `-- fa843947e9d9e06a7183a7d8f717e430b51527
|   |   |-- b1
|   |   |   `-- d00f59a567c8bee0571abbedc503a8660e05d5
|   |   |-- b2
|   |   |   `-- ab5ba94e58349c0c3e6f6adb5b0efb86403939
|   |   |-- b3
|   |   |   `-- 992a3d0d3463c1c8fa98ae917e80e13ac069ef
|   |   |-- b4
|   |   |   |-- 0ba6392063483de3154cc895e4dd06144101c7
|   |   |   `-- 8231891a5ad6c29ca8cbca498a89373ff9cd33
|   |   |-- b5
|   |   |   `-- 11189bf1343058dc23fe26a491fef8bed1a0f2
|   |   |-- b7
|   |   |   |-- 11a4defe92732351290fffac53f43d13cdcd01
|   |   |   |-- 57bc5ca2d8845a5b8d5349c860553f1772dd69
|   |   |   `-- c930deaad6ea0c099712dc4d64e2c9c2be8ac4
|   |   |-- b9
|   |   |   `-- 8f7a86bb580cc048f12b0913df64f3d3cdb85c
|   |   |-- bc
|   |   |   |-- 05576900f075af50894cc77efd22028e331820
|   |   |   `-- 83618e17da5d9ff62a5a7e99c8b782aad46649
|   |   |-- bd
|   |   |   `-- d344ef4ba852fdb67c04713fdaf11f2cd35895
|   |   |-- be
|   |   |   `-- 33f02763fc7dd7811247b7a5356aa8b61062bc
|   |   |-- bf
|   |   |   `-- 277eaa246a93d58af9e676f16dc148f8f8ae9a
|   |   |-- c0
|   |   |   `-- a8df1d9b3f5e6de7dd660b771a6efbfc251b64
|   |   |-- c1
|   |   |   |-- c970c1f5b82a60305998a5ce2301fe17611761
|   |   |   `-- ff0b1258829f46c62e0873f272f848bbadeb98
|   |   |-- c3
|   |   |   `-- 5df61e78b38682a37506d1376bdec522bbad79
|   |   |-- c4
|   |   |   `-- 5e0661fb0d69d2e658be7e168ad6fa014674f9
|   |   |-- ca
|   |   |   |-- 8fc056846163c1c1dc93ea474af71583f7aebd
|   |   |   `-- 9e5e50db2c961a451d1372f5005896c13d0cf4
|   |   |-- cb
|   |   |   `-- 6680b99dcd148dd06476629291560c1079ef77
|   |   |-- cc
|   |   |   `-- ea4780a70e1082a425fcb445658fe53adc4463
|   |   |-- cd
|   |   |   `-- 5102a44c763f1cfe9f2b199fd5d7257491c0dd
|   |   |-- ce
|   |   |   |-- 38687e165c2e6b7094d82f61dc79c383ca816a
|   |   |   `-- a89fc4cef3aeb89f51d5c9ba4d728a55063707
|   |   |-- d1
|   |   |   |-- 0c7cc269f9e5f1f42676e104fdca46eaaaa193
|   |   |   |-- a08b496727e86287818153570a97d735d6537e
|   |   |   `-- eed9ac5ca68c58ecf032b74661249e12053eb0
|   |   |-- d4
|   |   |   `-- e5a235723503c2d04e5c9b7a1eaad644dd13d7
|   |   |-- d5
|   |   |   `-- 5e9487cf46c35600c61907622c1459061d08a0
|   |   |-- d6
|   |   |   |-- c5c8985ddebb332365593adccc4ffc4165a315
|   |   |   `-- cf0fc3ea769a8f69858d799fb1a6cde39e5bc3
|   |   |-- d7
|   |   |   |-- 9464fc2abdf697bc76836d6f84f21a20fda6ef
|   |   |   `-- 9aba3deab4a888a367c77aca0eff47d410b2c6
|   |   |-- d9
|   |   |   |-- 1125a1c1fe8a757d0a45563a936bfcf283713c
|   |   |   `-- fa1cb227c4e0ba17e8643b383eb207b21e6a0c
|   |   |-- da
|   |   |   `-- 90511251b8c68429988871fb9da2825bbae5e0
|   |   |-- dc
|   |   |   |-- 19c8e108d0d0b5770cd9fe2cc274f21cb3126c
|   |   |   |-- a1896bea5b90f37f1ca3cfb5b2e66bc5c3affe
|   |   |   `-- ccac8eae52218a9463ec78bd1c7f8c2a3e6718
|   |   |-- e1
|   |   |   |-- 40dc12129e5d1f73431d588a27e85c5bbc7fb9
|   |   |   |-- 867e11710871b090cf8dbe057dd8eeb4a780d5
|   |   |   `-- baa0c9e24fd6ca13330860d5fcaceda6bf187c
|   |   |-- e4
|   |   |   |-- 946c626d942b581e6fa7550e1f6ebbef97f23c
|   |   |   `-- fa42aa932c3755fe8bda965e64636c734c4135
|   |   |-- e8
|   |   |   `-- 8ac0951ac06d2aa1eb426f8e685d28ae3c147f
|   |   |-- e9
|   |   |   `-- df827b7b1c80180d0049bbb39a1003f3506223
|   |   |-- ea
|   |   |   `-- 598b44e91f6ea9073d5b0241983ca1cb0fa987
|   |   |-- eb
|   |   |   |-- a70d7522756386e99dbaad687c93d4420697a3
|   |   |   `-- f9279b6261723a344fd3ce28b47bdf0dd34827
|   |   |-- f1
|   |   |   `-- fd29bc6a8b107e0ec8f62caac252cc09e3e51e
|   |   |-- f2
|   |   |   `-- f93497998dd68144334666244609f91e98cfe4
|   |   |-- f5
|   |   |   `-- e9b06a2d18e3d1cfbb6b0e80f9442278c817ce
|   |   |-- f6
|   |   |   `-- 37f62172ff0027e06699b4286fad854932537c
|   |   |-- f7
|   |   |   `-- dceb1e9998cd07c27637e4fd9257d303a8f388
|   |   |-- f9
|   |   |   `-- 42b4d8d4fa5b984ecc06a729ae1332c2932ef3
|   |   |-- fd
|   |   |   `-- 4a64c1f7b063580b10b847e9ba4e606436a80a
|   |   |-- fe
|   |   |   |-- 1f4c67c0759afe3545b05e711f4f4a9fc53653
|   |   |   `-- 6f4b2d0f94f65fa2d7a6b5159458b9550f775e
|   |   |-- info
|   |   `-- pack
|   `-- refs
|       |-- heads
|       |   `-- main
|       |-- remotes
|       |   `-- origin
|       |       `-- main
|       `-- tags
|-- .github
|   `-- workflows
|       `-- docker-hub.yml
|-- .gitignore
|-- Cargo.lock
|-- Cargo.toml
|-- Dockerfile
|-- README.md
|-- compose.yaml
|-- examples
|   `-- reports
|       |-- fixed.pdf
|       `-- forbidden.pdf
|-- fixtures
|   |-- advisories
|   |   |-- LICENSE.txt
|   |   |-- LICENSES
|   |   |   |-- Apache-2.0.txt
|   |   |   |-- CC-BY-4.0.txt
|   |   |   `-- CC0-1.0.txt
|   |   |-- README.md
|   |   |-- generate.py
|   |   |-- generate_retire.py
|   |   |-- retirejs.json
|   |   |-- rustsec.json
|   |   `-- test_generate_retire.py
|   |-- demo
|   |   |-- dependencies.lock
|   |   |-- fixed.html
|   |   `-- issue.html
|   `-- evaluation
|       |-- after.html
|       |-- after.lock
|       |-- before.html
|       |-- before.lock
|       |-- javascript-fixed.html
|       `-- javascript-vulnerable.html
|-- frontend
|   `-- tailwind.css
|-- graphify-out
|   |-- .graphify_analysis.json
|   |-- .graphify_build.json
|   |-- .graphify_build_state.json
|   |-- .graphify_labels.json
|   |-- .graphify_labels.json.sig
|   |-- .graphify_labels.pending.json
|   |-- .graphify_root
|   |-- GRAPH_REPORT.md
|   |-- cache
|   |   |-- ast
|   |   |   `-- v0.9.111-s47-g460503b3f2a4
|   |   |       |-- 0e8f7157a628357443654586b58cb6cd12445fd964a13fcc93a5facff568d741.json
|   |   |       |-- 10bf19c96c970e698544f4dd8102c370291736d8dc4e59855a44ca6e8d63a272.json
|   |   |       |-- 1d30fef4b9d36e4ae8b91940c08a48cc2028ba3b7ce69c6859db331ca7e41658.json
|   |   |       |-- 21b2a1e6310c86a414261ba9ed849b81e746c206e100f2fec8dbe8d82c86c665.json
|   |   |       |-- 291c974be66840ae813a55208e92073ddd285a8a95459548ff3bcf1ad55410c6.json
|   |   |       |-- 2c4bcb818e540ea88beebcadc45151543444f6e187b99b8d3cfd44787ee5d016.json
|   |   |       |-- 2c5393641b67b08778c35a2601cc04db160b7486a82b5ff6fc9a52c58c3d38e1.json
|   |   |       |-- 2ed1c52e8ee1930830ba04dfd392db49265100ac1f27fa55d6b42e0fbbe16eaa.json
|   |   |       |-- 3c54bf760cd59ff66dbe3fde8044b21c09db58b7fe974a6e17df3dd834c51ae8.json
|   |   |       |-- 44442b795eb23e3b4d66c8bda986a88179c85ffb0c051b5fc5339badae9f0751.json
|   |   |       |-- 5776535f7911670b3750a6c56a5920bc3aea74885893747ad2367007acdefc37.json
|   |   |       |-- 64a20149a29f9a0bc4cc56f2a9d58371452fe836684d5cb87a9debbaeb5a8d2e.json
|   |   |       |-- 666096435fa7b1d9019657b8603275af35a48ba4e1c8214d45460477fd3aed49.json
|   |   |       |-- 688c1c21454e8aca901b2b216882b1a761564b0dbd6e1c55374838881101e084.json
|   |   |       |-- 6b9d2e800e916ae9b9e6847a7ddc1f1c3dc4c26fee8a134e4dfa0c7fa2e60546.json
|   |   |       |-- 71c10eaec691320e3e34d20eaf321618bb03d4e48ad3121e531147be39c56247.json
|   |   |       |-- 747d796cbc76b589db32d191ecc75d4acc8baa4fe3edf13b3556d2bcd770b314.json
|   |   |       |-- 78e24565784622a26c15a4243476016fb535e354a4ae66d2eeee0a84859ef834.json
|   |   |       |-- 7ab19be8951ebc4e934521a94dddecf7323918bca9fcfd42bd4a2ce2a2adf52c.json
|   |   |       |-- 7ad83f3c6078fe78b6e90360173a41c442f33b179718965078443ec8676b1266.json
|   |   |       |-- 8421ae29f3f652366c5d60a4dad3be68a37c932b36e2624ae3fb6f58db3db6b9.json
|   |   |       |-- 8537a89b2251429d48ef8ef31c2c5f38958ec5600574a25cc83ff7f8d26a0b8f.json
|   |   |       |-- 87a02cd43ebad869e74c2fbe00bae39bc3569dd9f3ba25e0498f2459583acdec.json
|   |   |       |-- 8c4e892b3d0466776a029c3ef03587d7c1c8973c3c354eda5a2a6635b1166551.json
|   |   |       |-- 9332b9a17472f0fb9c5367dc391df3727aff9468f755ff7ea7e913c8e2c433ae.json
|   |   |       |-- 9455b000aecde55783268a5d5e67abe735367e07afc0e423c2494751160b99d6.json
|   |   |       |-- 956c4f66b96d1b779b2c7e598442719a1b719ab3757e0408b8a378d62943096d.json
|   |   |       |-- 9703762b7bcf6f344beb2b2e17b5a1988b0462a727d1f150692119bd642a6f8b.json
|   |   |       |-- 9ac4baaed70a0b1324fd78e85383dce48bcf6d9a5bb8c2e0aba83d4a0a2596a0.json
|   |   |       |-- 9ef9fb7ef04587eb30665d547128795ffca887fd66d830715a42cb27cca4c033.json
|   |   |       |-- a40a6d3517e781e033f442a46a6c059fcefd0ee2652ab6050dd4679e69a22569.json
|   |   |       |-- bf8c9006808d15865823d63e9837a439dd088f0922b10fa1c489fb31c0eb7a7f.json
|   |   |       |-- c6bae2dc865b55d0b8b6c82b9817c127162c7376c08bd296435de98469165b2d.json
|   |   |       |-- cb099388aeb1a1425b4ec266ac1c11cf7c607eac72ed4a16b8e87c93645d6ee6.json
|   |   |       |-- d634b5886c4e3b0d26f26afd1f542b8b20e9b6da30ef72f4188020372cf97a0f.json
|   |   |       |-- d843cd7eb8318d5d33a00f673e6dfa14a8a1ad7edcd9e648149883a47144aab6.json
|   |   |       |-- e11f534067c494b430bd9d2ddae1e257223b91337edba4f1ccf6c4bcbe333e9c.json
|   |   |       |-- e2206ffe733c339184e12e3b9aa677e646641d08a5353000ade2dff73bcd30f8.json
|   |   |       |-- e645718e8706095674ea31d05072467ec6517ec03210feb9c85416c48e603280.json
|   |   |       |-- e98ed6e67ee092d2e79e2460cd76989f099add537f156f66bb9d81456e17af70.json
|   |   |       |-- ee9677bb3e4160ae8f931074184900ff1688bc7b99a0476e81a84474d235798b.json
|   |   |       |-- f336b6348c33b7b6476304d125827ef12c1fe845ea494728788d299a4632ab80.json
|   |   |       `-- ffa92cefc3ae0edffff4f10ef88f8a6fb5804d4e700f8307a295501d83d1aed8.json
|   |   |-- last_query_stamp
|   |   `-- stat-index.json
|   |-- graph.html
|   |-- graph.json
|   `-- manifest.json
|-- migrations
|   `-- 0001_storage.sql
|-- src
|   |-- auth.rs
|   |-- catalog.tsv
|   |-- dependencies.rs
|   |-- domain.rs
|   |-- evaluation.rs
|   |-- extensions.tsv
|   |-- legacy_evidence.rs
|   |-- legacy_evidence.tsv
|   |-- main.rs
|   |-- model.rs
|   |-- scope.rs
|   |-- storage
|   |   `-- sealed.rs
|   |-- storage.rs
|   |-- ui.rs
|   |-- web
|   |   `-- javascript.rs
|   `-- web.rs
|-- templates
|   |-- account.html
|   |-- base.html
|   |-- catalog-page.html
|   |-- catalog.html
|   |-- fonts
|   |   |-- ibm-plex-sans-LICENSE.txt
|   |   |-- ibm-plex-sans.woff2
|   |   |-- jetbrains-mono-LICENSE.txt
|   |   `-- jetbrains-mono.woff2
|   |-- home.html
|   |-- login.html
|   |-- preview.html
|   |-- project.html
|   |-- register.html
|   |-- report-groups.html
|   |-- report-guidance.html
|   |-- report-reference.html
|   |-- report-result.html
|   |-- report.html
|   |-- scan-evidence.html
|   |-- style.css
|   `-- ui.js
`-- tests
    `-- demo.py

191 directories, 386 files

```

</details>
