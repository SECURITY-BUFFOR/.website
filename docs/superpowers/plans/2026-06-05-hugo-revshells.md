# Hugo Reverse Shell Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Hugo-native interactive reverse shell generator at `content/lair/revshells/`.

**Architecture:** Add a dedicated Lair template that renders the generator inside the existing docs shell. Keep all runtime behavior in one local browser script with a data-driven payload catalog and a small exported test API.

**Tech Stack:** Hugo templates, static CSS, vanilla JavaScript, Node built-in `assert`, Hugo CLI.

---

### Task 1: Generator Logic Test Harness

**Files:**
- Create: `tests/revshells.test.js`
- Create: `static/js/revshells.js`

- [ ] **Step 1: Write failing tests**

Create `tests/revshells.test.js` that loads `static/js/revshells.js` in Node and asserts:
- `{ip}`, `{port}`, and `{shell}` placeholders render.
- URL and double URL encoding transform spaces and shell metacharacters.
- Base64 encoding returns a non-empty encoded payload.
- Filtering by OS and type returns matching payloads.
- Listener generation uses the selected port.

- [ ] **Step 2: Run tests to verify failure**

Run: `node tests/revshells.test.js`
Expected: FAIL because `static/js/revshells.js` and `RevShells` do not exist.

- [ ] **Step 3: Implement minimal generator API**

Create `static/js/revshells.js` with a browser-safe IIFE that exports `window.RevShells` and `module.exports` when available. Include `payloads`, `listeners`, `renderTemplate`, `encodeValue`, `filterPayloads`, and `renderListener`.

- [ ] **Step 4: Run tests to verify pass**

Run: `node tests/revshells.test.js`
Expected: PASS.

### Task 2: Hugo Template And Page Assets

**Files:**
- Modify: `content/lair/revshells/_index.md`
- Create: `themes/minimal-black-modified/layouts/lair/revshells.html`
- Create: `static/css/revshells.css`
- Modify: `themes/minimal-black-modified/layouts/partials/project-docs/shell.html`

- [ ] **Step 1: Add frontmatter layout**

Set `layout = "revshells"` in `content/lair/revshells/_index.md` and update title/description for the generator.

- [ ] **Step 2: Add dedicated template**

Create `themes/minimal-black-modified/layouts/lair/revshells.html` that renders the sidebar and an article containing the generator controls, output panels, and page-specific asset tags for `/css/revshells.css` and `/js/revshells.js`.

- [ ] **Step 3: Keep shell partial unchanged unless needed**

Do not alter shared `project-docs/shell.html` unless the dedicated template needs a reusable docs-root calculation. Prefer copying the small docs-root setup into the new layout to keep the change scoped.

- [ ] **Step 4: Build Hugo**

Run: `hugo`
Expected: Generated `public/lair/revshells/index.html` contains the generator markup and no template errors.

### Task 3: Browser Interactivity

**Files:**
- Modify: `static/js/revshells.js`
- Modify: `static/css/revshells.css`

- [ ] **Step 1: Wire DOM state**

Initialize the tool on `[data-revshells-app]`. Bind IP, port, shell, type tabs, OS filter, encoding, advanced fields, and payload search to a single state object.

- [ ] **Step 2: Render payload list and outputs**

Update payload options and generated output whenever state changes. Persist state to `localStorage` under `security-buffor:revshells`.

- [ ] **Step 3: Implement controls**

Add copy buttons, download button, port increment, reset, and status messages. Use Clipboard API when available and fallback to selecting output text.

- [ ] **Step 4: Run tests and Hugo build**

Run: `node tests/revshells.test.js`
Expected: PASS.

Run: `hugo`
Expected: PASS.

### Task 4: Visual Smoke Test

**Files:**
- No source files unless issues are found.

- [ ] **Step 1: Start Hugo server**

Run: `hugo server --bind 127.0.0.1 --port 1313 --disableFastRender`
Expected: Server prints a local URL.

- [ ] **Step 2: Check page manually or with browser tooling**

Open `http://127.0.0.1:1313/lair/revshells/`. Verify controls fit on desktop and mobile widths, changing IP/port updates output, copy status appears, and download works.

- [ ] **Step 3: Stop server**

Stop the Hugo server before finishing.
