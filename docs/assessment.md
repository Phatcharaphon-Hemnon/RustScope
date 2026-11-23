# Assessment guide

## Capabilities and constraints

- The catalog contains 60 requirements. Eight canonical rules run automatically, 36 evidence-review rules have a human workflow, and the other 16 rules are planned. The report lists the JavaScript advisory extension separately from canonical coverage.
- Live collection uses bounded, read-only requests for the approved resource. Web checks use server-rendered evidence. Dependency and script advisory results reflect bundled snapshots and the evidence supplied for the scan.
- The application uses an in-process worker and private SQLite state. It binds to loopback by default, and Docker Compose publishes the container port on loopback. The worker processes one job at a time. Sessions expire after one hour or when the process restarts.

## Live assessment

1. Create a live project for an approved HTTP(S) scope and choose a duration of 1–30 days. Publish the challenge at the displayed URL and verify control. Paired HTTP and HTTPS scopes require verification on both origins. Renew an expired scope within the project to keep its scan history, then verify the fresh challenge.
2. Select the exact resource, release, and environment. Set any relevant HSTS, download, password form, and cross-origin SRI policies. Add the release's `Cargo.lock` if available (up to 256 KiB). **Check readiness** shows missing evidence and preserves the evaluated lockfile results for the current session and scan inputs. Use the form to replace or discard those results.
3. Select **Start scan**. The owner can grant existing accounts viewer or reviewer access. Reports are scoped to project members, and each report view is audited.

Use non-sensitive labels for projects, accounts, releases, and resources. Live collection is limited to public IPv4 destinations, query-free paths, up to four GET requests, and 12 seconds per collection. HTML bodies are capped at 512 KiB. Response headers can still be assessed when the HTML body is unavailable.

Checks use server-rendered evidence and bundled [RustSec and Retire.js snapshots](../fixtures/advisories/README.md). Browser execution, script digest verification, and vulnerability reachability require separate evidence. The [canonical catalog](../src/catalog.tsv) and [extension catalog](../src/extensions.tsv) contain individual rule definitions.

Rescan comparisons require the same approved target, environment, and item with comparable policy and evaluator versions. Advisory rules also record snapshot hashes. If inputs are missing or identity is ambiguous, the finding can stay unresolved. Failed runs remain visible in history.

## Evidence review

Owners and reviewers can append a decision to a completed or partially completed scan. Choose an evidence-review rule, disposition, and rationale. Attach a document reference, document contents, or a structured CI record. Confirm the evidence applies to the original release and environment.

Document evidence becomes a SHA-256 fingerprint. Retain the source documents under the project's own retention policy. CI evidence retains a constrained summary and a fingerprint. Each decision records the scan, release, reviewer, and timestamp.

Reports render supported older Thai evidence in English. Use **Print / Save PDF** for the full A4 report.

Use the actual commit and Unix timestamp for CI records. The supported environments are `test`, `staging`, and `production`. Values for `expected` and `actual` are `allow`, `deny`, `pass`, `fail`, `enabled`, and `disabled`.

```json
{"case_id":"ACL-01","commit":"abc1234","environment":"test","expected":"deny","actual":"deny","timestamp":1700000000}
```
