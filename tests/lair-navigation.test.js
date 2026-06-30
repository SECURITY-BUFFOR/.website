const assert = require("assert");
const fs = require("fs");

const html = fs.readFileSync("public/lair/index.html", "utf8");

const categoryMatches = Array.from(
  html.matchAll(/<span class="project-docs-category-label">([^<]+)<\/span>/g),
  (match) => match[1]
);

assert.ok(
  categoryMatches.includes("Cheatsheets"),
  "LAIR sidebar should include a single Cheatsheets category"
);
assert.ok(
  !categoryMatches.includes("Reverse Shell Generator"),
  "Reverse Shell Generator should be a page inside Cheatsheets, not its own category"
);
assert.ok(
  !categoryMatches.includes("Pentest Cheatsheet"),
  "Pentest Cheatsheet should be a page inside Cheatsheets, not its own category"
);

const cheatsheetsIndex = html.indexOf(
  '<span class="project-docs-category-label">Cheatsheets</span>'
);
const reverseShellIndex = html.indexOf(
  '<span class="project-docs-link-title">Reverse Shell Generator</span>',
  cheatsheetsIndex
);
const pentestIndex = html.indexOf(
  '<span class="project-docs-link-title">Pentest Cheatsheet</span>',
  cheatsheetsIndex
);
const sectionOverviewIndex = html.indexOf(
  '<span class="project-docs-link-title">Overview</span>',
  cheatsheetsIndex
);
const rootOverviewIndex = html.indexOf(
  '<span class="project-docs-link-title">Overview</span>'
);

assert.ok(reverseShellIndex > cheatsheetsIndex);
assert.ok(pentestIndex > cheatsheetsIndex);
assert.ok(
  sectionOverviewIndex === -1 || sectionOverviewIndex > pentestIndex,
  "Cheatsheets category should not render an _index Overview child link"
);
assert.strictEqual(
  rootOverviewIndex,
  -1,
  "LAIR documentation sidebar should not render an _index Overview link"
);

console.log("lair navigation tests passed");
