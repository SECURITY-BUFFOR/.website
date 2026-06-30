const assert = require("assert");
const Cheatsheet = require("../static/js/cheatsheet.js");

const vars = {
  LHOST: "10.10.14.3",
  RHOST: "10.10.10.5",
  LPORT: "4444",
  RPORT: "80",
  DOMAIN: "lab.local",
  DC: "10.10.10.10",
  USER: "alice",
  PASS: "Password123!",
  HASH: "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
  URL: "http://target.local",
};

const crawledCategoryIds = [
  "recon",
  "web",
  "api",
  "shells",
  "lpe",
  "wpe",
  "tunnel",
  "transfer",
  "bof",
  "cloud",
  "pivot",
  "osint",
  "wifi",
  "adrecon",
  "adatk",
  "adlat",
  "adpst",
  "adcerts",
  "adextra",
  "evasion",
  "inject",
  "c2",
  "vba",
  "binary",
  "crack",
  "misc",
  "passatk",
  "postex",
];

const suppliedCommandCounts = {
  recon: 36,
  web: 55,
  api: 29,
  shells: 26,
  lpe: 48,
  wpe: 56,
  tunnel: 13,
  transfer: 11,
  bof: 10,
  cloud: 21,
  pivot: 21,
  osint: 29,
  wifi: 11,
  adrecon: 13,
  adatk: 26,
  adlat: 14,
  adpst: 5,
  adcerts: 11,
  adextra: 15,
  evasion: 11,
  inject: 6,
  c2: 10,
  vba: 12,
  binary: 16,
  crack: 17,
  misc: 10,
  passatk: 23,
  postex: 31,
};

assert.deepStrictEqual(
  Cheatsheet.categories
    .filter((category) => category.id !== "all" && category.id !== "custom")
    .map((category) => category.id),
  crawledCategoryIds
);

assert.strictEqual(Cheatsheet.commands.length, 586);

crawledCategoryIds.forEach((categoryId) => {
  assert.strictEqual(
    Cheatsheet.commandCountForCategory(categoryId),
    suppliedCommandCounts[categoryId],
    `wrong command count for ${categoryId}`
  );
});

assert.strictEqual(
  Cheatsheet.renderCommand("nmap -sV -p {RPORT} {RHOST}", vars),
  "nmap -sV -p 80 10.10.10.5"
);

const recon = Cheatsheet.filterCommands({
  category: "recon",
  query: "nmap",
  commands: Cheatsheet.commands,
});
assert.ok(recon.length > 0);
assert.ok(recon.every((command) => command.category === "recon"));

const webSql = Cheatsheet.filterCommands({
  category: "all",
  query: "sqlmap",
  commands: Cheatsheet.commands,
});
assert.ok(webSql.some((command) => command.id === "web-sql-injection-sqlmap-get"));

assert.strictEqual(typeof Cheatsheet.toggleFavorite, "undefined");
assert.strictEqual(typeof Cheatsheet.pushHistory, "undefined");
assert.strictEqual(typeof Cheatsheet.addCustomCommand, "undefined");
assert.strictEqual(typeof Cheatsheet.exportIntel, "undefined");

console.log("cheatsheet tests passed");
