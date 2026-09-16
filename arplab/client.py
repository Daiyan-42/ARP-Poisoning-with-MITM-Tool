"""Health checks and repeatable HTTP/DNS traffic for the ARP lab."""
import argparse
import json
import secrets
import socket
import struct
import sys
import time
from urllib.request import ProxyHandler, build_opener

from .config import GATEWAY


def get(url, timeout=3):
    # Container traffic must go directly to the lab, regardless of host proxies.
    with build_opener(ProxyHandler({})).open(url, timeout=timeout) as response:
        return response.read().decode()


def dns_lookup(timeout=3):
    ident = secrets.token_bytes(2)
    query = ident + struct.pack("!5H", 0x0100, 1, 0, 0, 0)
    query += b"\x04demo\x03lab\x00" + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((GATEWAY, 53))
        sock.send(query)
        reply = sock.recv(4096)
    if len(reply) < 12 or reply[:2] != ident or not reply[2] & 0x80:
        raise ValueError("Invalid DNS response")
    if reply[3] & 15 or int.from_bytes(reply[6:8], "big") != 1 or len(reply) < len(query) + 16:
        raise ValueError("DNS answer missing")
    return socket.inet_ntoa(reply[-4:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("health", "alerts", "http", "dns", "traffic"))
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--interval", type=float, default=1)
    args = parser.parse_args()
    import math
    if not 1 <= args.count <= 10000 or not math.isfinite(args.interval) or not 0 <= args.interval <= 60:
        parser.error("count: [1,10000], interval: [0,60]")
    failed = False
    for index in range(args.count):
        actions = ("http", "dns") if args.action == "traffic" else (args.action,)
        for action in actions:
            try:
                if action in ("health", "alerts"):
                    result = json.loads(get(f"http://127.0.0.1:8000/{action}", timeout=1))
                    if action == "health" and not result.get("healthy"):
                        raise RuntimeError("ARP watcher is not running")
                elif action == "http":
                    result = get(f"http://{GATEWAY}:8080/")
                else:
                    result = dns_lookup()
                print(json.dumps({"action": action, "result": result}), flush=True)
            except (OSError, ValueError, RuntimeError) as exc:
                failed = True
                print(json.dumps({"action": action, "error": str(exc)}), flush=True)
        if index + 1 < args.count:
            time.sleep(args.interval)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
