# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

| Role | Job |
| --- | --- |
| Project owner | Verify control of a web scope, prepare and run release scans, compare findings across releases, and manage project access. |
| Reviewer | Read the report and record decisions on evidence-review rules for a specific scan and release. |
| Viewer | Read reports and understand what was found, what changed, and what remains unresolved. |

These are the roles implemented in the application. Use the project owner as the working primary user for the scan flow. The repository leaves the wider audience and deployment plans open.

## Product Purpose

RustScope turns approved web observations and release evidence into Thai security assessment reports. A successful report lets readers identify the affected item, see the evidence behind its outcome, and understand what would verify a fix.

## Operating Context

- **Live assessment.** The owner verifies control of a time-limited scope, selects one resource, and identifies the release and environment. Optional policy settings and `Cargo.lock` provide evidence for additional checks. The owner can preview readiness before starting a scan.
- **Offline demo.** Built-in fixtures walk users through a finding, a 403 that leaves it open, a persistent finding, and a verified fix. The fixtures run through the same evaluation, persistence, and comparison flow.
- **Review and reporting.** Owners and reviewers can append a decision on an evidence-review rule. Document inputs are fingerprinted and CI records use a constrained summary. Project members can read the Thai report. The full view is designed for A4 printing.

## Capabilities and Constraints

- The catalog contains 60 requirements. Eight canonical rules run automatically, 36 evidence-review rules have a human workflow, and the other 16 rules are planned. A separate JavaScript extension checks versions declared in script URLs against the bundled advisory data. Show the extension separately from canonical coverage.
- Live collection uses bounded, read-only requests for the approved resource. Web checks use server-rendered evidence. Dependency and script advisory results reflect bundled snapshots and the evidence supplied for the scan.
- The current application runs on loopback with an in-process worker and private SQLite state. The [README](README.md) contains setup, operating limits, and the demo commands.

## Product Principles

1. **Make each outcome traceable.** Tie results to a rule, an item, and the evidence for that release and environment.
2. **Keep uncertainty visible.** Distinguish insufficient evidence, a rule passing, and a verified fix. Closure requires a comparable passing observation of the same item.
3. **Preserve assessment history.** Keep automated observations and append-only human decisions attributable to their original scan.
4. **Use Thai for the workflow.** Keep standard technical identifiers such as rule IDs, HTTP status codes, `Cargo.lock`, HSTS, and SRI recognizable in forms and reports.

## Evidence on Hand

The [four-round demo](tests/demo.py) exercises the workflow. The [403 example](examples/reports/forbidden.pdf) and [verified-fix example](examples/reports/fixed.pdf) show the intended difference in outcomes. The PDFs are examples from an earlier report layout.
