"""Trusted ARP mapping monitoring and permanent neighbor defense."""
import argparse
from collections import deque
import platform
import socket
import threading
import time

from .config import ARTIFACTS_DIR, IFACE, ROLES, TRUSTED
from .io import EventLog, OUTGOING, raw_socket, set_neighbor
from .packets import parse_arp


class Detector:
    def __init__(self, trusted=None):
        self.trusted = dict(TRUSTED if trusted is None else trusted)
        self.seen = dict(self.trusted)
        self.requests = {}

    def observe(self, arp, now=None):
        now = time.monotonic() if now is None else now
        self.requests = {key: expiry for key, expiry in self.requests.items() if expiry > now}
        if arp["op"] == 1:
            self.requests[(arp["src_ip"], arp["dst_ip"])] = now + 3
            return []
        ip, mac = arp["src_ip"], arp["src_mac"]
        reasons = []
        if ip in self.trusted and self.trusted[ip] != mac:
            reasons.append("trusted_mapping_mismatch")
        requested = self.requests.pop((arp["dst_ip"], ip), 0) > now
        if ip in self.seen and self.seen[ip] != mac and not requested:
            reasons.append("unsolicited_mapping_change")
        if any(other != ip and known_mac == mac for other, known_mac in self.seen.items()):
            reasons.append("one_mac_claims_multiple_ips")
        # Never promote a suspicious reply to the trusted baseline.
        if not reasons:
            self.seen[ip] = mac
        return reasons


class Watcher:
    def __init__(self, role, iface=IFACE):
        self.iface = iface
        self.detector = Detector()
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


def set_static(role, enabled, iface=IFACE):
    if role not in ("victim", "gateway"):
        raise ValueError("Static protection runs on victim or gateway")
    peer = ROLES["gateway" if role == "victim" else "victim"]
    # The pinned neighbor entry is what actually prevents this poisoning attack.
    set_neighbor(iface, peer, TRUSTED[peer], enabled)
    if platform.system() == "Linux":
        # These sysctls control ARP requests/announcements, NOT reply authentication;
        # they have no macOS equivalent and aren't needed for the defense to work.
        for setting, value in (("arp_ignore", 1 if enabled else 0), ("arp_announce", 2 if enabled else 0)):
            # /proc/sys is read-only on some container runtimes; pinning still works.
            try:
                with open(f"/proc/sys/net/ipv4/conf/{iface}/{setting}", "w") as file:
                    file.write(str(value))
            except OSError:
                pass
    return {"enabled": enabled, "peer": peer, "mac": TRUSTED[peer]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("victim", "gateway"))
    parser.add_argument("action", choices=("enable", "disable"))
    args = parser.parse_args()
    print(set_static(args.role, args.action == "enable"))
