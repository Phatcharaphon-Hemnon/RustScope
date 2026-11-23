---
version: alpha
name: RustScope
description: "A Carbon-inspired assessment workspace with white panels, gray work surfaces, square controls, and IBM Blue primary actions."
colors:
  primary: "#0f62fe"
  on-primary: "#ffffff"
  ink: "#161616"
  ink-muted: "#525252"
  canvas: "#f4f4f4"
  surface-1: "#ffffff"
  surface-2: "#e0e0e0"
  inverse-canvas: "#161616"
  inverse-hover: "#353535"
  inverse-ink: "#ffffff"
  inverse-ink-muted: "#c6c6c6"
  hairline: "#e0e0e0"
  hairline-strong: "#8d8d8d"
  blue-hover: "#0050e6"
  focus: "#0f62fe"
  focus-inverse: "#a6c8ff"
  auth-canvas: "#001141"
  auth-ink-muted: "#d0e2ff"
  semantic-success: "#0e6027"
  semantic-warning: "#684e00"
  semantic-error: "#a2191f"
  semantic-info: "#0043ce"
  print-ink: "#000000"
typography:
  display:
    fontFamily: IBM Plex Sans
    fontSize: 64px
    fontWeight: 300
    lineHeight: 1.2
    letterSpacing: -0.01em
  headline:
    fontFamily: IBM Plex Sans
    fontSize: 42px
    fontWeight: 300
    lineHeight: 1.2
    letterSpacing: -0.01em
  headline-small:
    fontFamily: IBM Plex Sans
    fontSize: 28px
    fontWeight: 300
    lineHeight: 1.2
  account-title:
    fontFamily: IBM Plex Sans
    fontSize: 32px
    fontWeight: 300
    lineHeight: 1.2
  section:
    fontFamily: IBM Plex Sans
    fontSize: 24px
    fontWeight: 400
    lineHeight: 1.3
  body:
    fontFamily: IBM Plex Sans
    fontSize: 16px
    fontWeight: 400
    lineHeight: 1.5
  body-sm:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.5
  brand:
    fontFamily: IBM Plex Sans
    fontSize: 18px
    fontWeight: 600
  caption:
    fontFamily: IBM Plex Sans
    fontSize: 12px
    lineHeight: 1.5
  button:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: 500
    lineHeight: 1.5
  technical:
    fontFamily: JetBrains Mono
    fontSize: 14px
    lineHeight: 1.5
rounded:
  none: 0px
spacing:
  xxs: 4px
  xs: 8px
  sm: 12px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.button}"
    rounded: "{rounded.none}"
    padding: 10px 16px
  button-secondary:
    backgroundColor: "{colors.surface-1}"
    textColor: "{colors.ink}"
    typography: "{typography.button}"
    rounded: "{rounded.none}"
    padding: 10px 16px
  text-input:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: 10px 12px
  panel:
    backgroundColor: "{colors.surface-1}"
    rounded: "{rounded.none}"
    padding: 24px
---

# RustScope design system

Adapted from the IBM design analysis by VoltAgent. [Upstream IBM DESIGN.md](https://github.com/VoltAgent/awesome-design-md/blob/main/design-md/ibm/DESIGN.md) · [MIT license](docs/LICENSE-ibm-design.txt)

## Overview

RustScope is a workspace for preparing approved assessments, comparing releases, and reading evidence. The shared shell uses charcoal navigation above a light canvas. Square panels and thin dividers organize forms, history, and results. Align report totals with the evidence below them and let each nonzero total take the reader to the corresponding change.

## Colors

### Brand & Accent

Reserve IBM Blue for primary actions, section selection, and keyboard focus. Use the darker information blue for links and advisory changes on light surfaces. The account screens use a navy introduction beside the white form.

### Surface & Text

Place white panels over the gray canvas. Use gray for table headings, fields inside panels, and expanded evidence rows. Ink and muted ink distinguish body text from supporting metadata. Use white text and a lighter blue focus outline on dark surfaces.

### Semantic

Use green for verified outcomes, amber for pending or insufficient evidence, and red for findings and errors. Pair color with a text label. Distinguish advisory changes and unavailable evidence from verified fixes.

## Typography

IBM Plex Sans sets the interface. Use weight 300 for page titles and the account introduction, weight 400 for reading and section headings, and weight 600 for table headings and evidence labels. Use JetBrains Mono for URLs, rule IDs, hashes, and evidence inputs. Use tabular numerals for report totals. Both fonts ship with the application.

Scale the account introduction heading with the panel width, from 24 to 42px by default and up to 64px on wide sign-in screens. Break separate sentences at their boundaries and let long text wrap within each phrase at narrow sizes.

## Layout

- The shared content width caps at 1312px, with 32px gutters at wide sizes and 16px on phones.
- Projects uses a row-based list alongside the creation form. The project view puts scope status and section navigation above scan setup and history. Put optional lockfile and policy settings in disclosures, opening them when their fields need attention.
- Reports start with the project and release, then lead with a row of comparison totals. Keep related evidence in tables and native disclosures.
- Use 24px for major gaps and panel padding, 12px between fields, and 4px between a field and its label or helper text.

## Elevation & Depth

Use surface changes and 1px dividers to separate regions. Preserve visible focus rings and border contrast on fields and secondary buttons.

## Shapes

Buttons, fields, data panels, and tabs use square corners. Fields and actions are at least 48px high. Use native form and disclosure controls, reachable by keyboard.

## Components

| Pattern | Treatment |
| --- | --- |
| Global navigation | A 48px charcoal masthead with links to Projects and Rule catalog, plus account controls. |
| Section navigation | A white row of anchors with a blue underline on the current section. |
| Primary action | A solid blue button with white text. Use it for saving, verifying, or starting the main task. |
| Secondary action | A white button with a visible gray border, or a text link for navigation. |
| Inputs | Gray field surfaces with a bottom border and visible keyboard focus. Use a semantic border and text for errors. |
| Tables and disclosures | Gray headings, aligned columns, thin dividers, and a light active row. Keep evidence details accessible on narrow screens. |
| Report totals | A flat row of cells with labeled numbers. Link populated totals to matching evidence and use status colors consistently. |

## Responsive Behavior

At 960px, stack project setup and history and show table labels next to cell values. At 760px, stack account panels with the form first. At 600px, stack remaining form grids, wrap actions, and keep report totals in two columns. Keep section navigation horizontally scrollable when it cannot fit. Let long identifiers and URLs wrap.

Full reports print on A4 with 14mm margins. Hide navigation and controls, expand report evidence, repeat table headings, and keep findings and short rows together where possible.

## Iteration Guide

Edit [the shared stylesheet](styles/tailwind.css) and [Askama templates](templates/). Rebuild the embedded CSS using the [development guide](docs/development.md#update-interface-styles). Check the empty project list, live and demo scope states, readiness, completed and failed reports, catalog filters, keyboard focus, mobile layout, and A4 report output as applicable.
