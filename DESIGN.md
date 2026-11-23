---
name: RustScope
description: English interface for security assessments, evidence reviews, and rescan reports.
colors:
  canvas: "#181a1c"
  surface: "#222528"
  raised: "#2b2f32"
  ink: "#f2f1ed"
  muted: "#bec3c5"
  line: "#42484c"
  edge: "#81898d"
  action: "#f39769"
  focus: "#b9dcff"
  verified: "#8ed4a7"
  pending: "#f0c675"
  finding: "#ffa39c"
  info: "#9dcbff"
typography:
  body:
    fontFamily: "IBM Plex Sans, sans-serif"
    fontSize: "16px"
    lineHeight: 1.5
  page-title:
    fontSize: "28px"
    lineHeight: "34px"
    letterSpacing: "-0.025em"
  section-title:
    fontSize: "20px"
    fontWeight: 600
    lineHeight: "26px"
  technical:
    fontFamily: "JetBrains Mono, monospace"
    fontSize: "14px"
    lineHeight: 1.5
rounded:
  control: "6px"
spacing:
  compact: "8px"
  form: "12px"
  section: "16px"
  grid: "24px"
components:
  button-primary:
    backgroundColor: "{colors.action}"
    textColor: "{colors.canvas}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
  button-secondary:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
  text-field:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "9px 12px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "24px"
---

# RustScope design system

## Overview

RustScope uses a dark workspace for preparing scans and reading evidence. The project page presents scope and verification status before scan setup and history. Reports put an outcome summary and section navigation above the evidence. [Tailwind source](styles/tailwind.css) · [Askama shell](templates/base.html)

## Colors

- Use the warm action color for primary actions and the current section. Fields and dividers use the neutral palette.
- Green marks verified or passed states, amber marks pending or insufficient states, and red marks findings or errors. Pair status colors with readable labels.
- Keyboard focus uses a light blue outline (3px with a 3px offset). The information color also serves progress and text selection.

## Typography

IBM Plex Sans sets the English interface, with JetBrains Mono for code, file input, and technical data. Both fonts are served locally. Use tabular numerals for outcome counts. The base template declares `lang="en"`.

## Layout

The shared content width caps at 1200px. Owner views place setup and scan history in a two-column grid on wide screens, then stack them at 960px. At 600px, forms stack and actions span the available width. Reports keep related counts, filters, and evidence close together. Narrow tables surface row labels beside their values.

Full report printing uses A4 with 14mm margins. Interactive elements and navigation are hidden, evidence disclosures expand, and findings and table rows stay together where they fit.

## Elevation & Depth

Use the canvas, panel surfaces, and raised controls to separate layers. Dividers mark table rows and evidence disclosures.

## Shapes

Panels, buttons, and fields use 6px corners. Buttons, fields, and interactive summaries use at least 44px of height. Keep native form and disclosure controls available to keyboard users.

## Components

| Pattern | Implementation and use |
| --- | --- |
| Page shell | `templates/base.html` owns the shared masthead, account slot, stylesheet, and skip link. |
| Projects | `templates/project.html` shows verification, scope renewal, scan setup, and history. |
| Readiness | Reuse `templates/scan-evidence.html` on the scan form and keep the reviewed inputs in place. |
| Reports | Use the shared report components for outcome counts, observation details, comparison, and review evidence. Failed runs get a dedicated state. |
| Catalog | Use the existing search and filters to navigate rules, with native disclosures for their details. |

## Do's and Don'ts

- Keep shared component styles in `styles/tailwind.css` and rebuild `templates/style.css` with the [README command](README.md#update-the-interface-styles).
- Give rule outcomes, advisory updates, and verified fixes separate text labels.
- When changing reports, check narrow screens, keyboard focus, and A4 print with long identifiers and older stored evidence.
