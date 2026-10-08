"""Common helpers: shared-folder paths, IPv4 helpers, event writing."""
import ipaddress
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def shared_paths(shared=None):
    """Return the folder layout used for attacker -> firewall communication."""
    base = Path(shared or os.environ.get("LAB_SHARED") or (ROOT / "shared")).resolve()
    paths = {
        "base": base,
        "events": base / "events",
        "processed": base / "processed",
        "logs": base / "logs",
    }
    for key in ("events", "processed", "logs"):
        paths[key].mkdir(parents=True, exist_ok=True)
    return paths


def valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(str(ip))
        return True
    except ValueError:
        return False


def ip_to_int(ip):
    return int(ipaddress.IPv4Address(str(ip)))


def in_range(ip, start, end):
    """Plain numeric range check. IPs are just data - nothing is ever contacted."""
    return ip_to_int(start) <= ip_to_int(ip) <= ip_to_int(end)


def write_event(events_dir, event):
    """Atomically drop one JSON event into the shared folder."""
    name = "%d_%s" % (time.time_ns(), event["id"])
    tmp = Path(events_dir) / ("." + name + ".tmp")
    final = Path(events_dir) / (name + ".json")
    tmp.write_text(json.dumps(event), encoding="utf-8")
    os.replace(str(tmp), str(final))
    return final
