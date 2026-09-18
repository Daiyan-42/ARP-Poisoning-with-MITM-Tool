"""Cross-platform raw-networking dispatcher (Linux: AF_PACKET, macOS: BPF).

Every other module imports raw_socket/interface_info/set_neighbor/OUTGOING/
ip_forwarding_enabled from here, never from io_linux/io_macos directly -- that
keeps attack.py, defense.py, and node.py identical on both platforms.
"""
import json
import os
from pathlib import Path
import platform
import socket
import struct
import threading
import time

from .packets import build_arp, parse_arp

_SYSTEM = platform.system()
if _SYSTEM == "Linux":
    from .io_linux import OUTGOING, interface_info, ip_forwarding_enabled, raw_socket, set_neighbor
elif _SYSTEM == "Darwin":
    from .io_macos import OUTGOING, interface_info, ip_forwarding_enabled, raw_socket, set_neighbor
else:
    raise RuntimeError(f"Unsupported platform: {_SYSTEM} (only Linux and macOS are supported)")


def resolve(sock, own_ip, own_mac, target, timeout=3):
    deadline, next_send = time.monotonic() + timeout, 0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_send:
            sock.send(build_arp(own_mac, own_ip, "00:00:00:00:00:00", target, 1, True))
            next_send = time.monotonic() + 0.5
        try:
            frame, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        arp = parse_arp(frame)
        if addr[2] != OUTGOING and arp and arp["op"] == 2 and \
                arp["src_ip"] == target and arp["dst_ip"] == own_ip and arp["dst_mac"] == own_mac:
            return arp["src_mac"]
    raise TimeoutError(f"No ARP reply from {target} within {timeout}s")


class EventLog:
    def __init__(self, path, console=True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("a", buffering=1)
        self.lock = threading.Lock()
        self.console = console

    def emit(self, event, **fields):
        record = dict(time=time.time(), event=event, **fields)
        line = json.dumps(record, sort_keys=True)
        with self.lock:
            self.file.write(line + "\n")
            if self.console:
                print(line, flush=True)
        return record

    def close(self):
        self.file.close()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


class PcapWriter:
    def __init__(self, path):
        self.file = open(path, "wb")
        self.file.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    def write(self, frame):
        now = time.time()
        self.file.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6), len(frame), len(frame)))
        self.file.write(frame)

    def close(self):
        self.file.close()
