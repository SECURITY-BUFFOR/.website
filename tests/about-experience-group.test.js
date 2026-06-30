const assert = require("assert");
const fs = require("fs");

const html = fs.readFileSync("public/about/index.html", "utf8");
const layout = fs.readFileSync(
  "themes/minimal-black-modified/layouts/_default/about-alternative.html",
  "utf8"
);
const shortcode = fs.readFileSync(
  "themes/minimal-black-modified/layouts/_default/_shortcodes/experience-group.html",
  "utf8"
);

assert.ok(
  html.includes('class="about-alt-experience-card about-alt-experience-group"'),
  "About page should render grouped experience cards"
);

const groupStart = html.indexOf("about-alt-experience-company\">KPMG Poland");
assert.ok(groupStart !== -1, "KPMG Poland should render as a grouped company");

const groupEnd = html.indexOf("</article>", groupStart);
const groupHtml = html.slice(groupStart, groupEnd);

[
  "Cyber Security Intern",
  "Cyber Security Junior Consultant",
  "Cyber Security Consultant",
  "Senior Cyber Security Consultant",
].forEach((role) => {
  assert.ok(groupHtml.includes(role), `Grouped KPMG card should include ${role}`);
});

const sharedDescription =
  "Progressed from security internship to senior consulting responsibilities across enterprise penetration testing, red team engagements, vulnerability assessments, and stakeholder-facing security reporting.";

assert.ok(
  groupHtml.includes(sharedDescription),
  "Grouped KPMG card should render one shared company description"
);

assert.strictEqual(
  (groupHtml.match(/about-alt-experience-summary/g) || []).length,
  1,
  "Grouped KPMG card should not duplicate the shared description for each role"
);

assert.strictEqual(
  (groupHtml.match(/about-alt-experience-role-note/g) || []).length,
  0,
  "Grouped KPMG card should not render empty per-role notes"
);

assert.ok(
  !layout.includes("KPMG"),
  "Experience grouping should be opt-in through content, not hardcoded for one company"
);

assert.ok(
  shortcode.includes('.Get "notes"') &&
    shortcode.includes("about-alt-experience-role-note"),
  "Experience grouping should support optional role-specific notes"
);

console.log("about experience group tests passed");
