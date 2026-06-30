const assert = require("assert");
const fs = require("fs");

const html = fs.readFileSync("public/about/index.html", "utf8");

assert.ok(
  html.includes('class="cert-gallery"'),
  "About page should render certificates in the certificate gallery"
);

const certCards = Array.from(html.matchAll(/class="cert-gallery-card"/g));
assert.strictEqual(
  certCards.length,
  7,
  "Certificate gallery should render one card for each certification image"
);

assert.ok(
  html.includes('href="/images/certs/crt_CRTP.webp"') &&
    html.includes('class="cert-gallery-link glightbox"'),
  "Certificate gallery cards should open certificate images in the lightbox"
);

assert.ok(
  !html.includes('data-glightbox="description:'),
  "Certificate gallery should not render GLightbox description panels"
);

assert.ok(
  html.includes("Certified Red Team Professional") &&
    html.includes("Certified Penetration Testing Specialist") &&
    html.includes("Certified Red Team Analyst") &&
    html.includes("Certified Red Team Lead"),
  "Certificate gallery should expose readable certificate names"
);

const css = fs.readFileSync("public/css/main.css", "utf8");

assert.ok(
  css.includes("aspect-ratio: 1.43 / 1"),
  "Certificate gallery thumbnail frame should match certificate proportions"
);

const previewImageRule = css.match(/\.cert-gallery-image-frame img\s*\{([\s\S]*?)\n\}/);
assert.ok(
  previewImageRule,
  "Certificate gallery should define preview image styles"
);

assert.ok(
  previewImageRule[1].includes("object-fit: contain"),
  "Certificate gallery preview images should preserve certificate proportions"
);

assert.ok(
  previewImageRule[1].includes("background: transparent"),
  "Certificate gallery preview images should not add a white preview background"
);

assert.ok(
  !css.includes(".cert-gallery-image-frame {\n  display: grid;\n  place-items: center;\n  aspect-ratio: 4 / 3;"),
  "Certificate gallery should not use the old 4:3 frame that adds vertical whitespace"
);

console.log("about certificate gallery tests passed");
