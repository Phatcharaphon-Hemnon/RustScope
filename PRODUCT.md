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

The project owner is the primary user for the scan flow.

## Product Purpose

RustScope turns approved web observations and release evidence into English security assessment reports. A successful report lets readers identify the affected item, see the evidence behind its outcome, and understand what would verify a fix.

## Operating Context

- **Live assessment.** Owners verify and renew scopes, prepare releases, and submit scans with approved web and dependency evidence.
- **Offline demo.** Built-in evidence shows a new finding, an inconclusive 403, a persistent finding, and a verified fix.
- **Review and reporting.** Owners and reviewers can record evidence decisions. Reports render in English and offer an A4 print view.

See the [assessment guide](docs/assessment.md) for live setup, evidence review, and collection limits.

## Product Principles

1. **Make each outcome traceable.** Tie results to a rule, an item, and the evidence for that release and environment.
2. **Keep uncertainty visible.** Distinguish insufficient evidence, a rule passing, an advisory update, and a verified fix. Closure requires a comparable passing observation of the same item.
3. **Preserve assessment history.** Keep automated observations and append-only human decisions attributable to their original scan.
4. **Use consistent report language.** Keep standard technical identifiers such as rule IDs, HTTP status codes, `Cargo.lock`, HSTS, and SRI recognizable in forms and reports.

## Evidence on Hand

The [four-round demo](tests/demo.py) exercises the workflow. The [403 example](examples/reports/forbidden.pdf) and [verified-fix example](examples/reports/fixed.pdf) show the difference in outcomes.
