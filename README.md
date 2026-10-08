# Simulated Attack & Firewall Lab

A local, browser-based cybersecurity lab. An **Attacker** console launches simulated attacks (DoS, network scans, brute force, injection payloads, malware test strings, …). A **Firewall** receives the raw simulated traffic, works out *what kind of attack it is from the packet content itself*, blocks or allows it, logs it, and shows it on a live dashboard you can filter and export for threat-hunting practice.

> ⚠️ **Educational simulation only.** No real exploits, no real malware, no real network traffic. Every "packet" is a JSON file in a local folder. IP addresses are plain data compared in code — nothing is ever contacted. Both servers bind to `127.0.0.1` only.

## How it works

```
   Terminal 1                      shared/ folder                    Terminal 2
┌─────────────────┐  events/*.json  ┌───────────────┐   ┌──────────────────────────┐
│ run_attacker.py │ ──────────────▶ │ shared/events │ ─▶│ run_firewall.py          │
│ Attacker UI     │                 └───────────────┘   │  1. dst IP in range?     │
│ :5001           │                                     │  2. signatures + flags   │
│ pick attack,    │                 shared/logs/        │  3. rate/scan/auth       │
│ press Start     │                 firewall.log.jsonl◀─│     heuristics           │
└─────────────────┘                                     │  4. BLOCKED/ALLOWED, log │
                                                        │ Dashboard :5002          │
                                                        └──────────────────────────┘
```

- The attacker UI only picks a scenario; the simulator turns it into **packets** (protocol, ports, TCP flags, payload text, timing).
- Packets contain **no attack label**. The firewall classifies them purely from signatures (SQLi, XSS, EICAR, tool user-agents, TCP flag combos, …) and behavior (request rate, distinct ports/paths, repeated auth attempts).
- The attacker also writes its own ground-truth log (`shared/logs/attacker.log.jsonl`) so you can compare "what I selected" with "what the firewall detected".
- No VM, sockets, or network setup: the two "machines" are two terminal windows sharing a folder.

## Run it

Requires Python 3.8+ — no pip packages (standard library only).

Open two terminals in the project folder:

```bash
# Terminal 1 – Firewall
python3 run_firewall.py

# Terminal 2 – Attacker
python3 run_attacker.py
```

(On Windows use `py` or `python`.) Then open:

| What | URL |
|---|---|
| Attacker console | http://127.0.0.1:5001 |
| Firewall dashboard | http://127.0.0.1:5002 |

Put the two tabs side by side, choose an attack category and type, and press **Start attack**. Keep the victim IP inside the firewall's protected range, `196.102.21.0 – 196.102.21.13` (default `196.102.21.5`); traffic to any other address is silently ignored. Alerts appear live on the dashboard.

Tips:
- A victim IP outside the range (e.g. `8.8.8.8`) is dropped silently — nothing appears on the dashboard.
- Run **Benign browsing (control)** to see normal traffic stay **ALLOWED**.
- Press **Reset firewall counters** between demos so earlier traffic doesn't affect rate/scan counts.
- Rate-based detections (floods, scans, brute force) let the first packets through, then block once the threshold is crossed, like a real rate limiter.

### Options
```bash
python3 run_firewall.py --port 5002 --range-start 196.102.21.0 --range-end 196.102.21.13 --keep-events
python3 run_attacker.py --port 5001
# use a different shared folder (both scripts must point at the same one):
python3 run_firewall.py --shared /path/to/shared
python3 run_attacker.py --shared /path/to/shared      # or set LAB_SHARED
```

## Attack catalog

| Category | Types |
|---|---|
| **DoS** | HTTP flood, SYN flood, UDP flood, ICMP flood, Slowloris |
| **Network Scan** | SYN scan, common-ports sweep, XMAS, NULL, FIN, UDP scan, Nmap NSE, Nikto, sqlmap fingerprint, web directory brute-force |
| **Brute Force** | SSH, HTTP login, FTP, MySQL, credential stuffing |
| **Payload** | SQLi (UNION / boolean / time-based), XSS (script / event handler), path traversal, command injection, PHP wrapper LFI, Log4Shell-style JNDI, Shellshock-style header, SSTI, XXE, SSRF, EICAR test file, fabricated malware sample, simulated C2 beacon |
| **Other** | DNS tunneling, HTTP request smuggling, benign control traffic |

Payload strings are well-known textbook test patterns and are sent nowhere. Malware samples are the harmless EICAR test string and fabricated `LABSIM-…` markers.

## How the firewall decides

1. **Scope check** – is `dst_ip` inside the configured range? If not, the event is silently dropped (not logged or shown).
2. **Stateless signatures** – regexes on the URL-decoded payload, plus TCP-flag signatures (XMAS/NULL/FIN).
3. **Stateful heuristics** (per source IP, sliding windows) – distinct ports, distinct URL paths, auth attempts per service, incomplete HTTP requests, packet/request rate.
4. **Verdict** – `BLOCKED` (with category, signature ID, severity, evidence) or `ALLOWED`; written to `shared/logs/firewall.log.jsonl` and shown on the dashboard, which can export the log as JSON or CSV.

All signatures and thresholds are listed on the dashboard under *"What this firewall knows"* and in `lab/detector.py`.

## Project structure

```
simulated-attack-firewall-lab/
├── run_attacker.py        # Attacker server + API (:5001)
├── run_firewall.py        # Firewall watcher + dashboard API (:5002)
├── lab/
│   ├── simulator.py       # attack scenarios -> simulated packets
│   ├── detector.py        # signatures + heuristics engine
│   ├── common.py          # shared folder, IP helpers
│   └── web.py             # tiny HTTP helpers
├── attacker_ui/index.html
├── firewall_ui/index.html
├── shared/                # events/ (queue), logs/ (output)
├── tests/test_lab.py
└── .github/workflows/ci.yml
```

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

The suite replays every scenario through the firewall and checks that the detected category is correct, that packets carry no attack label, that benign traffic is not blocked, and that range boundaries work.

## Author

Sintayehu Desalegn — [github.com/sintayehudesalegn](https://github.com/sintayehudesalegn)

## License

MIT – see `LICENSE`.
