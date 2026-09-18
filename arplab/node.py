import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import signal
import socketserver
import struct
import threading

from .config import GATEWAY, HTTP_ORIGINAL_BODY, IFACE, ROLES, TRUSTED
from .defense import Watcher
from .io import interface_info
from .packets import dns_name


class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = HTTP_ORIGINAL_BODY
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def dns_response(query):
    if len(query) < 12:
        return None
    _, flags, questions, _, _, _ = struct.unpack("!6H", query[:12])
    if flags & 0x8000 or flags & 0x7800 or questions != 1:
        return None
    name = dns_name(query)
    if name is None:
        return None
    pos = 12
    while query[pos]:
        pos += query[pos] + 1
    end = pos + 5
    if end > len(query):
        return None
    kind, cls = struct.unpack("!HH", query[pos + 1:end])
    found = name.lower() == "demo.lab"
    answer = found and (kind, cls) == (1, 1)
    header = query[:2] + struct.pack("!5H", 0x8400 | (flags & 0x0100) |
                                   (0 if found else 3), 1, int(answer), 0, 0)
    payload = header + query[12:end]
    if answer:
        payload += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
        payload += bytes(map(int, GATEWAY.split(".")))
    return payload


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        response = dns_response(query)
        if response is not None:
            sock.sendto(response, self.client_address)


def control_handler(role, watcher):
    class ControlHandler(BaseHTTPRequestHandler):
        def reply(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self.reply(200, {"healthy": watcher.thread.is_alive(), "role": role})
            elif self.path == "/alerts":
                self.reply(200, watcher.snapshot())
            else:
                self.reply(404, {"error": "Unknown endpoint"})

        def log_message(self, *args):
            pass
    return ControlHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=ROLES)
    args = parser.parse_args()
    own_ip, own_mac = interface_info(IFACE)
    if (own_ip, own_mac) != (ROLES[args.role], TRUSTED[ROLES[args.role]]):
        raise RuntimeError("Node must run on the machine matching its configured role "
                          "(check the ARPLAB_* environment variables)")
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    watcher = Watcher(args.role)
    servers, threads = [], []
    try:
        watcher.start()
        if args.role == "gateway":
            servers.append(ThreadingHTTPServer((GATEWAY, 8080), HTTPHandler))
            servers.append(socketserver.UDPServer((GATEWAY, 53), DNSHandler))
        servers.append(ThreadingHTTPServer(("127.0.0.1", 8000),
                                           control_handler(args.role, watcher)))
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        print(f"{args.role} ready at {own_ip}", flush=True)
        stopped.wait()
    finally:
        for server, thread in zip(servers, threads):
            server.shutdown()
            thread.join(timeout=2)
        for server in servers:
            server.server_close()
        watcher.close()


if __name__ == "__main__":
    main()
