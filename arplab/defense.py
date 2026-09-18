import argparse
from collections import deque
import ipaddress
import json
from pathlib import Path
import platform
import socket
import subprocess
import sys
import threading
import time

from .config import ARTIFACTS_DIR, IFACE, ROLES, TRUSTED
from .io import EventLog, OUTGOING, atomic_json, raw_socket, set_neighbor
from .packets import mac_bytes, parse_arp


BINDINGS_PATH = Path("/run/arplab/bindings.json")


def validate_bindings(bindings):
    if not isinstance(bindings, dict) or not bindings:
        raise ValueError("A nonempty binding inventory is required")
    result = {}
    for ip, mac in bindings.items():
        address = ipaddress.IPv4Address(ip)
        raw = mac_bytes(mac)
        if address.is_unspecified or address.is_multicast or raw[0] & 1 or not any(raw):
            raise ValueError("Bindings must contain unicast IPv4 and MAC addresses")
        result[str(address)] = mac.lower()
    return result


def read_bindings():
    # Falls back to the configured TRUSTED table (env-var-driven, see config.py)
    # until a stronger inventory (e.g. Linux's docker-inspect-verified enrollment
    # below) has been enrolled, so detection works out of the box everywhere.
    if not BINDINGS_PATH.exists():
        return dict(TRUSTED)
    return validate_bindings(json.loads(BINDINGS_PATH.read_text()))


def ruleset(bindings, iface=IFACE):
    bindings = validate_bindings(bindings)
    if iface != IFACE:
        raise ValueError("ARP inspection is restricted to the lab interface")
    lines = ["add table arp arplab_guard", "flush table arp arplab_guard",
             "add chain arp arplab_guard input { type filter hook input priority -300; policy accept; }"]
    for ip, mac in sorted(bindings.items()):
        lines.append(f'add rule arp arplab_guard input iifname "{iface}" '
                     f'arp saddr ip {ip} arp saddr ether {mac} ether saddr {mac} counter accept')
    lines.append(f'add rule arp arplab_guard input iifname "{iface}" counter drop')
    return "\n".join(lines) + "\n"


def inspection_status():
    result = subprocess.run(["nft", "-j", "list", "tables"],
                            check=True, text=True, capture_output=True)
    tables = json.loads(result.stdout)["nftables"]
    enabled = any(item.get("table", {}).get("family") == "arp" and
                  item.get("table", {}).get("name") == "arplab_guard" for item in tables)
    dropped = 0
    if enabled:
        result = subprocess.run(["nft", "-j", "list", "table", "arp", "arplab_guard"],
                                check=True, text=True, capture_output=True)
        for item in json.loads(result.stdout)["nftables"]:
            expressions = item.get("rule", {}).get("expr", [])
            if any("drop" in expr for expr in expressions):
                dropped += sum(expr.get("counter", {}).get("packets", 0) for expr in expressions)
    return {"enabled": enabled, "dropped_arp": dropped, "bindings": read_bindings(),
            "source": "Docker control-plane inventory"}


def _configure_linux(role, action, bindings, iface):
    if action == "status":
        return inspection_status()
    peer = ROLES["gateway" if role == "victim" else "victim"]
    if action == "enable":
        bindings = validate_bindings(bindings)
        if not set(ROLES.values()).issubset(bindings):
            raise ValueError("Inventory must contain all three lab hosts")
        subprocess.run(["nft", "-f", "-"], input=ruleset(bindings, iface), text=True, check=True)
        atomic_json(BINDINGS_PATH, bindings)
        # Clear any already-poisoned entry so normal ARP resolves fresh, now filtered.
        subprocess.run(["ip", "neigh", "flush", "to", peer, "dev", iface, "nud", "all"], check=True)
    elif action == "disable":
        if inspection_status()["enabled"]:
            subprocess.run(["nft", "delete", "table", "arp", "arplab_guard"], check=True)
        # Seed a genuine reachable entry rather than flushing it away: an
        # unsolicited ARP reply for an IP with *no* existing neighbor entry is
        # ignored by the kernel (arp_accept=0 by default), which would silently
        # break the unprotected poisoning demo this lab exists to show.
        if peer in TRUSTED:
            subprocess.run(["ip", "neigh", "replace", peer, "lladdr", TRUSTED[peer],
                            "nud", "reachable", "dev", iface], check=True)
    else:
        raise ValueError("Unknown defense action")
    return inspection_status()


def _configure_macos(role, action, iface):
    # nftables doesn't exist on Darwin; fall back to pinning the peer's MAC
    # permanently instead of the nftables-filtered dynamic inventory above.
    peer = ROLES["gateway" if role == "victim" else "victim"]
    if action == "status":
        return {"enabled": None, "dropped_arp": None, "bindings": {peer: TRUSTED[peer]},
                "source": "macOS static pinning (nftables unavailable)"}
    if action not in ("enable", "disable"):
        raise ValueError("Unknown defense action")
    set_neighbor(iface, peer, TRUSTED[peer], action == "enable")
    return {"enabled": action == "enable", "peer": peer, "mac": TRUSTED[peer],
            "source": "macOS static pinning (nftables unavailable)"}


def configure(role, action, bindings=None, iface=IFACE):
    if role not in ("victim", "gateway") or iface != IFACE:
        raise ValueError("ARP inspection runs on the victim and gateway lab interfaces")
    if platform.system() == "Linux":
        return _configure_linux(role, action, bindings, iface)
    return _configure_macos(role, action, iface)


class Detector:
    def __init__(self, trusted=None):
        self.trusted = dict({} if trusted is None else trusted)
        self.seen = dict(self.trusted)
        self.requests = {}

    def observe(self, arp, now=None):
        now = time.monotonic() if now is None else now
        self.requests = {key: expiry for key, expiry in self.requests.items() if expiry > now}
        ip, mac = arp["src_ip"], arp["src_mac"]
        reasons = []
        if ip in self.trusted and self.trusted[ip] != mac:
            reasons.append("trusted_mapping_mismatch")
        requested = arp["op"] == 2 and self.requests.pop((arp["dst_ip"], ip), 0) > now
        if ip in self.seen and self.seen[ip] != mac and not requested:
            reasons.append("unsolicited_mapping_change")
        if any(other != ip and known_mac == mac for other, known_mac in self.seen.items()):
            reasons.append("one_mac_claims_multiple_ips")
        if not reasons:
            self.seen[ip] = mac
            if arp["op"] == 1:
                self.requests[(ip, arp["dst_ip"])] = now + 3
        return reasons


class Watcher:
    def __init__(self, role, iface=IFACE):
        self.iface = iface
        self.detector = Detector(read_bindings())
        self.log = EventLog(f"{ARTIFACTS_DIR}/{role}-watch.jsonl", console=False)
        self.alerts = deque(maxlen=200)
        self.count = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.socket = None

    def start(self):
        self.socket = raw_socket(self.iface)
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stop.is_set():
            try:
                frame, addr = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            if addr[2] == OUTGOING:
                continue
            arp = parse_arp(frame)
            if arp:
                bindings = read_bindings()
                if bindings != self.detector.trusted:
                    self.detector = Detector(bindings)
                reasons = self.detector.observe(arp)
                if reasons:
                    alert = self.log.emit("arp_alert", reasons=reasons, **arp)
                    with self.lock:
                        self.count += 1
                        self.alerts.append(alert)

    def snapshot(self):
        with self.lock:
            return {"count": self.count, "recent": list(self.alerts)}

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.socket:
            self.socket.close()
        self.log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("victim", "gateway"))
    parser.add_argument("action", choices=("enable", "disable", "status"))
    parser.add_argument("--bindings-stdin", action="store_true")
    args = parser.parse_args()
    try:
        bindings = json.load(sys.stdin) if args.bindings_stdin else None
        print(json.dumps(configure(args.role, args.action, bindings)))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Defense failed: {exc}\n")
