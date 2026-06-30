# Axiom Sample Report Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an embedded viewer and fallback link for the existing Axiom sample PDF.

**Architecture:** Keep the PDF at its existing Hugo static path and add one self-contained raw-HTML iframe to the Axiom overview Markdown. Use an ordinary link beneath it as the browser compatibility fallback.

**Tech Stack:** Hugo, Goldmark Markdown, HTML

---

### Task 1: Add and verify the sample report viewer

**Files:**
- Modify: `content/projects/Axiom/Overview.md`
- Verify: `static/files/sample_report.pdf`

- [ ] **Step 1: Verify the source PDF and establish the content check fails**

Run:

```bash
test -s static/files/sample_report.pdf
! rg -q 'src="/files/sample_report.pdf"' content/projects/Axiom/Overview.md
```

Expected: both commands exit successfully, confirming the PDF exists and the viewer is not yet present.

- [ ] **Step 2: Add the viewer section**

Append this exact content to `content/projects/Axiom/Overview.md`:

```html
## Sample Report

View an example of the client-ready PDF report produced by Axiom.

<iframe
  src="/files/sample_report.pdf"
  title="Axiom sample penetration testing report"
  style="width: 100%; height: 75vh; min-height: 640px; border: 1px solid currentColor; border-radius: 0.5rem;"
></iframe>

<a href="/files/sample_report.pdf" class="md-link" target="_blank" rel="noopener">Open the sample report in a new tab</a>
```

- [ ] **Step 3: Verify the source content**

Run:

```bash
rg -n 'Sample Report|src="/files/sample_report.pdf"|title="Axiom sample penetration testing report"|target="_blank" rel="noopener"' content/projects/Axiom/Overview.md
```

Expected: one match for the heading, iframe source, iframe title, and fallback-link text.

- [ ] **Step 4: Build the Hugo site**

Run:

```bash
hugo --destination /tmp/security-buffor-public
```

Expected: exit code 0 with no build errors.

- [ ] **Step 5: Verify generated output and static asset**

Run:

```bash
rg -U '<a[^>]*href="/files/sample_report.pdf"[^>]*target="_blank"[^>]*rel="noopener"[^>]*>Open the sample report in a new tab</a>' /tmp/security-buffor-public/projects/axiom/overview/index.html
test -s /tmp/security-buffor-public/files/sample_report.pdf
```

Expected: the generated overview contains the viewer and link, and the copied PDF is non-empty.

- [ ] **Step 6: Record completion**

This workspace has no Git repository, so no commit can be created. Report the modified content file and verification results to the user.
