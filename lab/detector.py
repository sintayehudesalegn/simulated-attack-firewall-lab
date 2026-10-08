"""Firewall detection engine: signatures + heuristics. Classifies from packet content only."""
import copy
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import unquote_plus

from .common import in_range, valid_ipv4

DEFAULT_CONFIG = {
    "protected_start": "196.102.21.0",
    "protected_end": "196.102.21.13",
    "thresholds": {
        "port_scan_ports": 10, "port_scan_window": 10,
        "web_discovery_paths": 12, "web_discovery_window": 10,
        "bruteforce_attempts": 5, "bruteforce_window": 30,
        "stuffing_users": 5,
        "syn_flood": 50, "http_flood": 50, "udp_flood": 50, "icmp_flood": 30, "flood_window": 5,
        "slowloris": 10, "slowloris_window": 10,
    },
}


def _sig(sid, name, category, severity, pattern, flags=re.I):
    return {"id": sid, "name": name, "category": category, "severity": severity,
            "re": re.compile(pattern, flags)}


SIGNATURES = [
    # Malware / test artifacts
    _sig("SIG-MAL-001", "EICAR antivirus test file", "Malware", "high", r"eicar-standard-antivirus-test-file"),
    _sig("SIG-MAL-002", "Simulated malware sample (LABSIM)", "Malware", "high", r"labsim-malware-sig-[0-9a-f]+"),
    _sig("SIG-MAL-003", "Simulated ransomware note (LABSIM)", "Malware", "critical", r"labsim-ransom-note"),
    _sig("SIG-C2-001", "Simulated C2 beacon (LABSIM)", "Malware", "critical", r"labsim-c2-beacon"),
    # Scanner tool fingerprints
    _sig("SIG-SCAN-NMAP", "Nmap Scripting Engine fingerprint", "Network Scan", "medium", r"nmap scripting engine|nmap\.org"),
    _sig("SIG-SCAN-NIKTO", "Nikto scanner fingerprint", "Network Scan", "medium", r"nikto/\d|\(nikto"),
    _sig("SIG-SCAN-SQLMAP", "sqlmap fingerprint", "Network Scan", "high", r"sqlmap/\d|sqlmap\.org"),
    # Injection & web payloads
    _sig("SIG-JNDI-001", "Log4Shell-style JNDI lookup", "Payload", "critical", r"\$\{\s*(jndi|lower|upper|env)\s*:"),
    _sig("SIG-SHOCK-001", "Shellshock-style function definition", "Payload", "critical", r"\(\)\s*\{\s*:\s*;\s*\}\s*;"),
    _sig("SIG-XXE-001", "XML external entity (XXE)", "Payload", "high", r"<!entity\s+\w+\s+system|<!doctype[^>]*\["),
    _sig("SIG-SSRF-001", "SSRF to metadata/localhost", "Payload", "high",
         r"169\.254\.169\.254|metadata\.google\.internal|url=https?://(localhost|127\.|0\.0\.0\.0)"),
    _sig("SIG-SSTI-001", "Template injection (SSTI)", "Payload", "medium",
         r"\{\{\s*\d+\s*[*+]\s*\d+\s*\}\}|<%=\s*\d+\s*\*\s*\d+\s*%>"),
    _sig("SIG-SQLI-001", "SQL injection (UNION SELECT)", "Payload", "high", r"\bunion\b\s+(all\s+)?select\b"),
    _sig("SIG-SQLI-003", "SQL injection (time-based blind)", "Payload", "high",
         r"\bsleep\s*\(\s*\d+|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\("),
    _sig("SIG-SQLI-002", "SQL injection (boolean tautology)", "Payload", "high",
         r"['\"]\s*or\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*|\bor\s+\d+\s*=\s*\d+"),
    _sig("SIG-XSS-001", "Cross-site scripting (<script>)", "Payload", "high", r"<\s*script\b"),
    _sig("SIG-XSS-002", "XSS (event handler / javascript: URI)", "Payload", "medium",
         r"\bon(error|load|click|mouseover)\s*=|javascript\s*:"),
    _sig("SIG-CMDI-001", "OS command injection", "Payload", "critical",
         r"(?:;|\||&&|\$\(|`)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b"),
    _sig("SIG-LFI-003", "PHP stream wrapper (LFI)", "Payload", "high", r"php://(filter|input)|data://text/plain|expect://"),
    _sig("SIG-LFI-001", "Path traversal", "Payload", "high", r"\.\./|\.\.\\|\.\.%2f"),
    _sig("SIG-LFI-002", "Sensitive file access", "Payload", "medium", r"/etc/(passwd|shadow)|\bboot\.ini|\bwin\.ini"),
    # Other protocol abuse
    _sig("SIG-DNS-001", "DNS tunneling (long encoded label)", "Other", "medium", r"dns query \w+ [a-z0-9]{40,}\."),
    _sig("SIG-SMUGGLE-001", "HTTP request smuggling (CL + TE)", "Other", "high",
         r"(?=.*content-length:)(?=.*transfer-encoding:\s*chunked)", re.I | re.S),
]

FLAG_SIGNATURES = {
    "FPU": ("SIG-SCAN-XMAS", "XMAS scan (FIN+PSH+URG)"),
    "NONE": ("SIG-SCAN-NULL", "NULL scan (no TCP flags)"),
    "F": ("SIG-SCAN-FIN", "FIN scan (lone FIN)"),
}

_HTTP_START = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+(\S+)\s+HTTP/1\.[01]")
_BF_NAMES = {"ssh": ("BF-SSH-001", "SSH brute force"), "ftp": ("BF-FTP-001", "FTP brute force"),
             "mysql": ("BF-SQL-001", "MySQL brute force"), "http": ("BF-HTTP-001", "HTTP login brute force")}
_FLOOD = {"syn": ("DOS-SYN-001", "SYN flood", "syn_flood"),
          "http": ("DOS-HTTP-001", "HTTP request flood", "http_flood"),
          "udp": ("DOS-UDP-001", "UDP flood", "udp_flood"),
          "icmp": ("DOS-ICMP-001", "ICMP (ping) flood", "icmp_flood")}


def signature_catalog():
    rows = [{"id": s["id"], "name": s["name"], "category": s["category"], "severity": s["severity"],
             "type": "signature"} for s in SIGNATURES]
    rows += [{"id": i, "name": n, "category": "Network Scan", "severity": "medium", "type": "tcp-flag"}
             for i, n in FLAG_SIGNATURES.values()]
    rows += [
        {"id": "SCAN-PORTS-001", "name": "Port scan (many distinct ports)", "category": "Network Scan", "severity": "medium", "type": "heuristic"},
        {"id": "SCAN-WEB-001", "name": "Web content discovery (many distinct paths)", "category": "Network Scan", "severity": "medium", "type": "heuristic"},
        {"id": "BF-STUFF-001", "name": "Credential stuffing", "category": "Brute Force", "severity": "high", "type": "heuristic"},
        {"id": "DOS-SLOW-001", "name": "Slowloris (incomplete HTTP requests)", "category": "DoS", "severity": "high", "type": "heuristic"},
    ]
    rows += [{"id": v[0], "name": v[1], "category": "Brute Force", "severity": "high", "type": "heuristic"} for v in _BF_NAMES.values()]
    rows += [{"id": v[0], "name": v[1], "category": "DoS", "severity": "high", "type": "heuristic"} for v in _FLOOD.values()]
    return rows


def _g(pattern, text):
    m = re.search(pattern, text)
    return m.group(1) if m else "?"


def _kind(ev):
    proto = (ev.get("protocol") or "TCP").upper()
    payload = ev.get("payload") or ""
    if proto == "ICMP":
        return "icmp", None
    if proto == "UDP":
        return "udp", None
    m = _HTTP_START.match(payload)
    if m:
        path = m.group(2).split("?")[0]
        return ("http" if "\r\n\r\n" in payload else "slow"), (m.group(1), path)
    if (ev.get("tcp_flags") or "") == "S" and not payload:
        return "syn", None
    return "tcp", None


def _auth_info(payload, http):
    low = payload.lower()
    if "ssh_msg_userauth_request" in low:
        return "ssh", _g(r"user=(\S+)", payload)
    if re.search(r"(?m)^PASS\s+\S+", payload):
        return "ftp", _g(r"(?m)^USER\s+(\S+)", payload)
    if "mysql_auth" in low:
        return "mysql", _g(r"user=(\S+)", payload)
    if http and http[0] == "POST" and "password=" in low and re.search(r"/(login|signin|wp-login\.php)", http[1], re.I):
        return "http", _g(r"(?:username|user|email)=([^&\s]+)", payload)
    return None, None


def _det(sid, name, category, severity, reason, evidence="", also=None):
    return {"id": sid, "name": name, "category": category, "severity": severity,
            "reason": reason, "evidence": evidence, "also": also or []}


class Firewall:
    def __init__(self, config=None):
        self.cfg = copy.deepcopy(DEFAULT_CONFIG)
        if config:
            for k, v in config.items():
                if k == "thresholds":
                    self.cfg["thresholds"].update(v)
                else:
                    self.cfg[k] = v
        self.reset_state()

    def reset_state(self):
        self.win = defaultdict(deque)
        self.last_probe_port = {}

    def _window(self, key, ts, window, value=None):
        dq = self.win[key]
        dq.append((ts, value))
        while dq and dq[0][0] < ts - window:
            dq.popleft()
        return dq

    # ---------------------------------------------------------- stateless
    def _stateless(self, ev):
        payload = ev.get("payload") or ""
        if (ev.get("protocol") or "").upper() == "TCP":
            flags = ev.get("tcp_flags") or ""
            if flags in FLAG_SIGNATURES:
                sid, name = FLAG_SIGNATURES[flags]
                return _det(sid, name, "Network Scan", "medium",
                            "Abnormal TCP flag combination (%s) - used by port scanners" % flags, "flags=" + flags)
        if not payload:
            return None
        d1 = unquote_plus(payload)
        text = "\n".join([payload, d1, unquote_plus(d1)])
        hits = []
        for s in SIGNATURES:
            m = s["re"].search(text)
            if m:
                hits.append((s, m.group(0)))
        if not hits:
            return None
        s, ev_txt = hits[0]
        ev_txt = re.sub(r"[\r\n]+", " ", ev_txt)[:90]
        return _det(s["id"], s["name"], s["category"], s["severity"],
                    "Payload matched signature %s" % s["id"], ev_txt, [h[0]["id"] for h in hits[1:]])

    # ----------------------------------------------------------- stateful
    def _stateful(self, ev, kind, http, ts):
        t = self.cfg["thresholds"]
        src = ev["src_ip"]
        port = int(ev.get("dst_port") or 0)
        payload = ev.get("payload") or ""
        found = None

        # port scan: probe-like (empty payload) events hitting many distinct ports
        if not payload:
            dq = self._window((src, "ports"), ts, t["port_scan_window"], port)
            distinct = len({v for _, v in dq})
            prev = self.last_probe_port.get(src)
            self.last_probe_port[src] = port
            if distinct >= t["port_scan_ports"] and port != prev:
                found = _det("SCAN-PORTS-001", "Port scan (many distinct ports)", "Network Scan", "medium",
                             "%d distinct ports probed in %ds" % (distinct, t["port_scan_window"]),
                             "distinct_ports=%d" % distinct)

        # web content discovery
        if http and kind == "http":
            dq = self._window((src, "paths"), ts, t["web_discovery_window"], http[1])
            distinct = len({v for _, v in dq})
            if not found and distinct >= t["web_discovery_paths"]:
                found = _det("SCAN-WEB-001", "Web content discovery (many distinct paths)", "Network Scan", "medium",
                             "%d distinct URL paths requested in %ds" % (distinct, t["web_discovery_window"]),
                             "distinct_paths=%d" % distinct)

        # brute force
        svc, user = _auth_info(payload, http)
        if svc:
            dq = self._window((src, "auth", svc), ts, t["bruteforce_window"], user)
            users = {v for _, v in dq}
            if not found and len(dq) >= t["bruteforce_attempts"]:
                if svc == "http" and len(users) >= t["stuffing_users"]:
                    found = _det("BF-STUFF-001", "Credential stuffing", "Brute Force", "high",
                                 "%d login attempts with %d different usernames in %ds" % (len(dq), len(users), t["bruteforce_window"]),
                                 "attempts=%d users=%d" % (len(dq), len(users)))
                else:
                    sid, name = _BF_NAMES[svc]
                    found = _det(sid, name, "Brute Force", "high",
                                 "%d authentication attempts in %ds" % (len(dq), t["bruteforce_window"]),
                                 "attempts=%d users=%d" % (len(dq), len(users)))

        # slowloris
        if kind == "slow":
            dq = self._window((src, "slow"), ts, t["slowloris_window"])
            if not found and len(dq) >= t["slowloris"]:
                found = _det("DOS-SLOW-001", "Slowloris (incomplete HTTP requests)", "DoS", "high",
                             "%d HTTP requests with unfinished headers in %ds" % (len(dq), t["slowloris_window"]),
                             "incomplete_requests=%d" % len(dq))

        # volumetric floods
        if kind in _FLOOD:
            sid, name, tkey = _FLOOD[kind]
            dq = self._window((src, kind, port), ts, t["flood_window"])
            if not found and len(dq) >= t[tkey]:
                found = _det(sid, name, "DoS", "high",
                             "%d %s packets/requests in %ds (limit %d)" % (len(dq), kind.upper(), t["flood_window"], t[tkey]),
                             "rate=%d/%ds" % (len(dq), t["flood_window"]))
        return found

    # -------------------------------------------------------------- main
    def inspect(self, ev):
        ts = float(ev.get("ts") or time.time())
        payload = ev.get("payload") or ""
        preview = payload[:200].replace("\r", "\\r").replace("\n", "\\n")
        v = {
            "event_id": ev.get("id"), "ts": ts,
            "time": datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
            "src_ip": ev.get("src_ip"), "src_port": ev.get("src_port"),
            "dst_ip": ev.get("dst_ip"), "dst_port": ev.get("dst_port"),
            "protocol": ev.get("protocol"), "tcp_flags": ev.get("tcp_flags", ""),
            "length": ev.get("length", len(payload)), "payload_preview": preview,
            "action": "ALLOWED", "category": "-", "detection": "-", "signature_id": "-",
            "severity": "-", "reason": "No signature or heuristic matched", "evidence": "", "also_matched": "",
        }
        dst = ev.get("dst_ip", "")
        if not valid_ipv4(dst) or not in_range(dst, self.cfg["protected_start"], self.cfg["protected_end"]):
            v["action"] = "IGNORED"
            v["reason"] = "Destination %s is outside the protected range %s - %s" % (
                dst, self.cfg["protected_start"], self.cfg["protected_end"])
            return v
        kind, http = _kind(ev)
        stateful = self._stateful(ev, kind, http, ts)
        det = self._stateless(ev) or stateful
        if det:
            v.update({"action": "BLOCKED", "category": det["category"], "detection": det["name"],
                      "signature_id": det["id"], "severity": det["severity"], "reason": det["reason"],
                      "evidence": det["evidence"], "also_matched": ",".join(det["also"])})
        return v
