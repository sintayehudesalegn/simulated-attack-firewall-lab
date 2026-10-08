#!/usr/bin/env python3
"""Attacker- attack console server. Run in terminal 1.  http://127.0.0.1:5001"""
import argparse
import json
import threading
import time
from collections import deque

from lab.common import ROOT, shared_paths, valid_ipv4, write_event
from lab.simulator import SCENARIOS, catalog, make_packet
from lab.web import BaseHandler, run_server

import uuid


class Attacker:
    def __init__(self, paths):
        self.paths = paths
        self.lock = threading.Lock()
        self.job = None
        self.log_path = paths["logs"] / "attacker.log.jsonl"

    def start(self, key, victim, src):
        with self.lock:
            if self.job and self.job["state"] == "running":
                raise RuntimeError("An attack is already running - stop it first.")
            scen = SCENARIOS[key]
            steps = scen.build(victim)
            job = {"state": "running", "key": key, "label": scen.label, "sent": 0,
                   "total": len(steps), "recent": deque(maxlen=14), "stop": threading.Event(),
                   "victim": victim, "src": src}
            self.job = job
        threading.Thread(target=self._run, args=(job, steps), daemon=True).start()

    def _run(self, job, steps):
        with open(self.log_path, "a", encoding="utf-8") as log:
            for step in steps:
                if job["stop"].wait(step.delay):
                    break
                ev = make_packet(job["src"], job["victim"], step)
                write_event(self.paths["events"], ev)
                job["sent"] += 1
                preview = ev["payload"][:70].replace("\r", "\\r").replace("\n", "\\n")
                job["recent"].append({"n": job["sent"], "dst_port": ev["dst_port"], "proto": ev["protocol"],
                                      "flags": ev["tcp_flags"], "preview": preview})
                # ground truth for YOU only; the firewall never reads this file
                log.write(json.dumps({"time": ev["ts"], "selected_scenario": job["key"],
                                      "event_id": ev["id"], "dst_ip": ev["dst_ip"],
                                      "dst_port": ev["dst_port"]}) + "\n")
                log.flush()
        job["state"] = "stopped" if job["stop"].is_set() else "done"

    def stop(self):
        if self.job:
            self.job["stop"].set()

    def status(self):
        j = self.job
        if not j:
            return {"state": "idle", "sent": 0, "total": 0, "recent": []}
        return {"state": j["state"], "label": j["label"], "sent": j["sent"], "total": j["total"],
                "recent": list(j["recent"])}


class Handler(BaseHandler):
    index_file = ROOT / "attacker_ui" / "index.html"

    def handle_get(self, path, q):
        if path == "/api/scenarios":
            return self.send_json({"groups": catalog(),
                                   "defaults": {"src_ip": "10.66.6.6", "victim_ip": "196.102.21.5"}})
        if path == "/api/status":
            return self.send_json(self.app.status())
        self.send_json({"error": "not found"}, 404)

    def handle_post(self, path, body):
        a = self.app
        if path == "/api/attack":
            key, victim, src = body.get("scenario"), body.get("victim_ip", ""), body.get("src_ip", "")
            if key not in SCENARIOS:
                return self.send_json({"error": "unknown scenario"}, 400)
            if not valid_ipv4(victim) or not valid_ipv4(src):
                return self.send_json({"error": "Source and victim must be valid IPv4 addresses."}, 400)
            try:
                a.start(key, victim, src)
            except RuntimeError as e:
                return self.send_json({"error": str(e)}, 409)
            return self.send_json({"ok": True})
        if path == "/api/stop":
            a.stop()
            return self.send_json({"ok": True})
        if path == "/api/reset-firewall":
            write_event(a.paths["events"], {"id": uuid.uuid4().hex[:12], "type": "control",
                                            "action": "reset_state", "ts": time.time()})
            return self.send_json({"ok": True})
        self.send_json({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser(description="Attacker B console")
    ap.add_argument("--port", type=int, default=5001)
    ap.add_argument("--shared", help="shared folder (default ./shared or $LAB_SHARED)")
    args = ap.parse_args()
    paths = shared_paths(args.shared)
    print("Shared folder:", paths["base"])
    Handler.app = Attacker(paths)
    run_server(Handler, "127.0.0.1", args.port, "Attacker B")


if __name__ == "__main__":
    main()
