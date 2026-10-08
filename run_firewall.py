#!/usr/bin/env python3
"""Firewall - watches the shared folder, inspects events, serves the dashboard.
Run in terminal 2.  http://127.0.0.1:5002"""
import argparse
import csv
import io
import json
import os
import threading
import time
from collections import Counter

from lab.common import ROOT, shared_paths
from lab.detector import DEFAULT_CONFIG, Firewall, signature_catalog
from lab.web import BaseHandler, run_server

MAX_LOGS = 20000
CSV_FIELDS = ["seq", "time", "action", "category", "detection", "signature_id", "severity", "src_ip",
               "src_port", "dst_ip", "dst_port", "protocol", "tcp_flags", "length", "reason",
               "evidence", "also_matched", "payload_preview"]


class Store:
    def __init__(self, log_path):
        self.lock = threading.Lock()
        self.log_path = log_path
        self.logs, self.seq, self.epoch = [], 0, 1
        self.ignored = 0  # out-of-scope events silently dropped (counter only)
        self._reset_stats()

    def _reset_stats(self):
        self.stats = {"total": 0, "by_action": Counter(), "by_category": Counter(),
                      "by_detection": Counter(), "by_src": Counter()}

    def add(self, v):
        with self.lock:
            self.seq += 1
            v["seq"] = self.seq
            self.logs.append(v)
            if len(self.logs) > MAX_LOGS:
                del self.logs[:len(self.logs) - MAX_LOGS]
            s = self.stats
            s["total"] += 1
            s["by_action"][v["action"]] += 1
            if v["action"] == "BLOCKED":
                s["by_category"][v["category"]] += 1
                s["by_detection"][v["detection"]] += 1
                s["by_src"][v["src_ip"]] += 1
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(v) + "\n")

    def since(self, n, limit=2000):
        with self.lock:
            if not self.logs:
                return []
            start = max(0, n + 1 - self.logs[0]["seq"])
            return self.logs[start:start + limit]

    def snapshot_stats(self):
        with self.lock:
            s = self.stats
            return {"total": s["total"], "by_action": dict(s["by_action"]),
                    "by_category": dict(s["by_category"]),
                    "top_detections": s["by_detection"].most_common(8),
                    "top_sources": s["by_src"].most_common(5)}

    def clear(self):
        with self.lock:
            self.logs = []
            self.epoch += 1
            self._reset_stats()
            open(self.log_path, "w").close()

    def all(self):
        with self.lock:
            return list(self.logs)


def watcher(fw, store, paths, keep, stop):
    while not stop.is_set():
        for f in sorted(paths["events"].glob("*.json")):
            try:
                ev = json.loads(f.read_text(encoding="utf-8"))
                if ev.get("type") == "control":
                    if ev.get("action") == "reset_state":
                        fw.reset_state()
                        print("[firewall] detection state reset")
                else:
                    verdict = fw.inspect(ev)
                    if verdict["action"] == "IGNORED":
                        # Not our asset: drop silently - not logged, not shown on the dashboard.
                        store.ignored += 1
                    else:
                        store.add(verdict)
            except Exception as e:  # malformed event: skip it
                print("[firewall] skipped %s: %s" % (f.name, e))
            finally:
                try:
                    if keep:
                        os.replace(str(f), str(paths["processed"] / f.name))
                    else:
                        f.unlink()
                except OSError:
                    pass
        time.sleep(0.1)


class Handler(BaseHandler):
    index_file = ROOT / "firewall_ui" / "index.html"

    def handle_get(self, path, q):
        app = self.app
        store = app["store"]
        if path == "/api/logs":
            try:
                since = int(q.get("since", ["0"])[0])
            except ValueError:
                since = 0
            logs = store.since(since)
            return self.send_json({"logs": logs, "last_seq": store.seq, "epoch": store.epoch,
                                   "stats": store.snapshot_stats()})
        if path == "/api/config":
            return self.send_json({"protected_start": app["fw"].cfg["protected_start"],
                                   "protected_end": app["fw"].cfg["protected_end"],
                                   "thresholds": app["fw"].cfg["thresholds"],
                                   "signatures": signature_catalog()})
        if path == "/api/download":
            fmt = q.get("format", ["json"])[0]
            only = q.get("action", [""])[0]
            rows = [r for r in store.all() if not only or r["action"] == only]
            if fmt == "csv":
                buf = io.StringIO()
                w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
                return self.send_bytes(200, buf.getvalue().encode("utf-8"), "text/csv; charset=utf-8",
                                       {"Content-Disposition": 'attachment; filename="firewall_log.csv"'})
            return self.send_bytes(200, json.dumps(rows, indent=2).encode("utf-8"), "application/json",
                                   {"Content-Disposition": 'attachment; filename="firewall_log.json"'})
        self.send_json({"error": "not found"}, 404)

    def handle_post(self, path, body):
        if path == "/api/clear":
            self.app["store"].clear()
            return self.send_json({"ok": True})
        self.send_json({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser(description="Firewall + dashboard")
    ap.add_argument("--port", type=int, default=5002)
    ap.add_argument("--shared", help="shared folder (default ./shared or $LAB_SHARED)")
    ap.add_argument("--range-start", default=DEFAULT_CONFIG["protected_start"])
    ap.add_argument("--range-end", default=DEFAULT_CONFIG["protected_end"])
    ap.add_argument("--keep-events", action="store_true", help="move processed events to shared/processed")
    args = ap.parse_args()

    paths = shared_paths(args.shared)
    fw = Firewall({"protected_start": args.range_start, "protected_end": args.range_end})
    store = Store(paths["logs"] / "firewall.log.jsonl")
    print("Shared folder   :", paths["base"])
    print("Protected range : %s - %s" % (args.range_start, args.range_end))
    stop = threading.Event()
    threading.Thread(target=watcher, args=(fw, store, paths, args.keep_events, stop), daemon=True).start()
    Handler.app = {"fw": fw, "store": store}
    try:
        run_server(Handler, "127.0.0.1", args.port, "Firewall")
    finally:
        stop.set()


if __name__ == "__main__":
    main()
