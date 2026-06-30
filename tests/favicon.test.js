const assert = require('node:assert');
const fs = require('node:fs');

const html = fs.readFileSync('public/index.html', 'utf8');

assert.match(
  html,
  /<link rel=(?:"icon"|icon) type=(?:"image\/x-icon"|image\/x-icon) href=(?:"\/favicon\.ico"|\/favicon\.ico)\s*\/?>/,
  'Home page should reference the root favicon.ico'
);
assert.ok(fs.existsSync('public/favicon.ico'), 'Build should emit public/favicon.ico');
