const assert = require("assert");
const fs = require("fs");

const toolStyles = [
  {
    name: "Reverse Shell Generator",
    path: "static/css/revshells.css",
    root: ".revshells-page",
    vars: ["--rs-black", "--rs-panel", "--rs-panel-2", "--rs-line", "--rs-muted", "--rs-text", "--rs-signal"],
  },
  {
    name: "Pentest Cheatsheet",
    path: "static/css/cheatsheet.css",
    root: ".cheatsheet-page",
    vars: ["--cs-black", "--cs-panel", "--cs-panel-2", "--cs-line", "--cs-muted", "--cs-text", "--cs-signal"],
  },
];

for (const style of toolStyles) {
  const css = fs.readFileSync(style.path, "utf8");
  const lightBlockPattern = new RegExp(
    `html\\[data-theme="light"\\]\\s+${style.root.replace(".", "\\.")}\\s*\\{([\\s\\S]*?)\\}`
  );
  const lightBlock = css.match(lightBlockPattern);

  assert.ok(lightBlock, `${style.name} should define light theme tokens`);

  for (const variable of style.vars) {
    assert.ok(
      lightBlock[1].includes(variable),
      `${style.name} light theme should override ${variable}`
    );
  }
}

console.log("tool light theme tests passed");
