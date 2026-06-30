# Axiom Sample Report Viewer Design

## Goal

Make the existing Axiom sample report easy to inspect from the Axiom project overview page.

## Design

Add a `Sample Report` section to `content/projects/Axiom/Overview.md`. The section will contain:

- A full-width HTML `iframe` that loads `/files/sample_report.pdf`.
- A descriptive iframe title for accessibility.
- A fixed, readable viewer height that does not require JavaScript.
- A normal link below the viewer that opens the PDF in a new browser tab, providing a fallback for browsers that do not render PDFs inline.

The PDF remains at `static/files/sample_report.pdf`; Hugo serves it at `/files/sample_report.pdf`. No shortcode or reusable component will be added because this is currently a single-use presentation.

## Compatibility and Failure Handling

Hugo's Goldmark configuration permits raw HTML, so the iframe can live directly in Markdown. If a browser cannot display the embedded PDF, the explicit link still gives the user access to the report.

## Verification

- Build the Hugo site successfully.
- Confirm the generated Axiom overview contains the iframe and fallback link.
- Confirm `/files/sample_report.pdf` is present in the generated site output.
