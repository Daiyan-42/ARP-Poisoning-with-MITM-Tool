"""Linux raw-networking backend: AF_PACKET sockets and iproute2 neighbor pinning."""
import fcntl
from pathlib import Path
import socket
import struct
import subprocess

OUTGOING = socket.PACKET_OUTGOING


def interface_info(iface):
    if not iface or "/" in iface or len(iface.encode()) > 15:
        raise ValueError("Invalid interface name")
    mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        data = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", iface.encode()))
    return socket.inet_ntoa(data[20:24]), mac


def raw_socket(iface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sock.bind((iface, 0))
    sock.settimeout(0.1)
    return sock


def set_neighbor(iface, ip, mac, permanent):
    nud = "permanent" if permanent else "reachable"
    subprocess.run(["ip", "neigh", "replace", ip, "lladdr", mac, "nud", nud, "dev", iface],
                   check=True)


def ip_forwarding_enabled():
    return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "0"
