---
name: RustScope
description: Thai interface for security assessment, evidence review, and rescan reports.
colors:
  masthead: "#10203b"
  accent: "#164ab8"
  accent-strong: "#123784"
  accent-soft: "#edf3ff"
  focus: "#245bd3"
  canvas: "#f4f6f9"
  surface: "#ffffff"
  ink: "#14243a"
  muted: "#47586d"
  line: "#d8e0e9"
  control: "#748499"
  danger: "#8d2433"
  danger-soft: "#fff1f3"
  insufficient: "#683c08"
  insufficient-soft: "#fff1d2"
  passed: "#145640"
  passed-soft: "#e5f5eb"
typography:
  body:
    fontFamily: '"Noto Sans Thai", Tahoma, system-ui, sans-serif'
    fontSize: "1rem"
    lineHeight: 1.625
  page-title:
    fontSize: "1.875rem"
    fontWeight: 700
    lineHeight: 1.25
  section-title:
    fontSize: "1.25rem"
    fontWeight: 700
    lineHeight: 1.25
rounded:
  badge: "4px"
  control: "6px"
  panel: "8px"
spacing:
  compact: "8px"
  control: "12px"
  section: "16px"
  grid: "24px"
  panel-wide: "24px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
  button-preview:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.accent}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
  text-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
    padding: "16px"
---

# RustScope design system

## Overview

RustScope uses a navy masthead, a cool neutral canvas, and white form surfaces. The scan form anchors the project page. Scope and history sit alongside it. Reports use a compact outcome summary and dividers to help readers find evidence and guidance. [Tailwind source](styles/tailwind.css) · [Askama shell](templates/base.html)

## Colors

- The navy masthead anchors navigation. Blue accent identifies actions, links, and disclosure markers. The pale accent surface groups metadata and supporting information.
- Use ink for content, muted text for hints, line for panel and table boundaries, and the stronger control border for fields.
- Findings use red, insufficient evidence uses amber, and passes use green. High severity also uses red. Pair each color with a Thai label. Outcome badges use tinted backgrounds and severity badges use borders.
- The focus outline is 3px with a 3px offset. The masthead uses a lighter focus color against navy.

## Typography

Use the Thai font stack across headings, forms, and reports. The base template declares `lang="th"`. Page titles grow to 2.25rem at 40rem. Subsection headings use 1.125rem. Hints and report badges use 0.875rem. Use regular weight for field values, monospace for technical identifiers, and tabular numerals for report counters.

## Layout

The shared shell leaves 1.25rem on each side and caps content at 72rem. Home and the owner’s project page stack on narrow screens and switch to two columns at 48rem. The project form gets the wider column and comes first in reading order. Sign-in and registration use a centered narrow panel. Reports use one reading column, and long resource identifiers wrap below the outcome and severity labels.

Print reports use A4 with 14mm margins. Hide navigation and interactive controls, expose report details in the full view, and repeat table headers across pages where supported. Keep findings and comparison statuses readable in grayscale.

## Elevation & Depth

Forms use white surfaces and light borders. Project records and report observations use horizontal dividers. Tinted surfaces mark optional form sections, supporting evidence, and outcomes.

## Shapes

Use 8px corners for main panels, 6px for fields and buttons, and 4px for report badges. Buttons and standard form fields have a 44px minimum height. Keep native checkboxes, selects, and disclosures available to keyboard users.

## Components

| Pattern | Implementation and use |
| --- | --- |
| Page shell | `templates/base.html` owns the masthead, content width, and stylesheet include. Pages extend it through Askama. |
| Forms and actions | Start from the shared labels, field styles, and button treatment in `styles/tailwind.css`. Use the filled button for submission and the outlined treatment for readiness preview. Associate hints with fields and place feedback near the relevant form. |
| Lists and disclosures | Use lists for projects, scan history, and grouped observations. Use native `details` for optional inputs, catalog entries, and evidence reference material. |
| Report observations | Reuse `templates/report-result.html` for one observation and `templates/report-groups.html` for grouped evidence. Keep rule ID, outcome, severity, and inspected item visible in the summary. Put observed evidence and guidance in the expanded body. |
| Readiness | Reuse `templates/scan-evidence.html` for evidence requirements and show their evaluated readiness on the scan form with the submit action still available. |

## Do's and Don'ts

- Keep color, spacing, and shared component declarations in `styles/tailwind.css`. Regenerate `templates/style.css` using the [README command](README.md#update-the-interface-styles) after styling changes.
- Keep progress, insufficient evidence, and verified fixes readable as text. Preserve the distinction between a rule pass and verified remediation when writing report labels.
- Use existing template includes for repeated workflow patterns. Extract a new include when multiple pages need the same markup and behavior.
- When changing a report component, check narrow screens, keyboard focus, and A4 print. Exercise long Thai labels and resource identifiers in each affected view.
