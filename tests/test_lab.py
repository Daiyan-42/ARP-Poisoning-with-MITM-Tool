import struct
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from arplab.client import get, main as client_main
from arplab.config import ATTACKER, GATEWAY, TRUSTED, VICTIM
from arplab.defense import Detector
from arplab.node import HTTPHandler, dns_response
from arplab.packets import (build_arp_reply, checksum, complete_transport_checksum, ethernet, parse_arp,
                            parse_ipv4, replace_tcp_payload)


class LabTests(unittest.TestCase):
    def test_http_service(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), HTTPHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            self.assertIn("ORIGINAL", get(f"http://127.0.0.1:{server.server_port}/"))
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_health_failure_is_nonzero(self):
        with patch("sys.argv", ["client", "health"]), patch("builtins.print"), \
                patch("arplab.client.get", return_value='{"healthy": false}'):
            self.assertEqual(client_main(), 1)

    def test_poison_and_restore(self):
        detector = Detector()
        for target, claimed in ((VICTIM, GATEWAY), (GATEWAY, VICTIM)):
            forged = parse_arp(build_arp_reply(TRUSTED[ATTACKER], claimed,
                                               TRUSTED[target], target))
            self.assertEqual(forged["dst_ip"], target)
            self.assertIn("trusted_mapping_mismatch", detector.observe(forged))
            self.assertEqual(detector.seen[claimed], TRUSTED[claimed])
            restored = parse_arp(build_arp_reply(TRUSTED[claimed], claimed,
                                                 TRUSTED[target], target))
            self.assertEqual(detector.observe(restored), [])

    def test_http_modification_preserves_length_and_checksum(self):
        ips = bytes([10, 0, 0, 1, 10, 0, 0, 10])
        payload = b"HTTP/1.0 200 OK\r\n\r\nORIGINAL"
        tcp = struct.pack("!HHIIBBHHH", 8080, 40000, 1, 1, 0x50, 0x18, 4096, 0, 0)
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0) + ips
        frame = ethernet(TRUSTED[ATTACKER], TRUSTED[GATEWAY], 0x0800, ip + tcp + payload)
        updated, changed = replace_tcp_payload(frame)
        self.assertTrue(changed)
        self.assertEqual(len(updated), len(frame))
        self.assertEqual(parse_ipv4(updated)["payload"], payload.replace(b"ORIGINAL", b"MODIFIED"))
        pseudo = ips + struct.pack("!BBH", 0, 6, len(tcp + payload))
        self.assertEqual(checksum(pseudo + updated[34:]), 0)
        self.assertEqual(replace_tcp_payload(updated), (updated, False))

    def test_dns_answer_and_malformed_queries(self):
        query = struct.pack("!6H", 123, 0x100, 1, 0, 0, 0)
        query += b"\x04demo\x03lab\x00\x00\x01\x00\x01"
        response = dns_response(query)
        self.assertEqual(response[:2], query[:2])
        self.assertEqual(response[-4:], bytes([10, 0, 0, 1]))
        self.assertEqual(int.from_bytes(response[6:8], "big"), 1)
        for length in range(len(query)):
            self.assertIsNone(dns_response(query[:length]))
        self.assertIsNone(dns_response(response))
        missing = dns_response(query.replace(b"demo", b"nope"))
        self.assertEqual(missing[3] & 15, 3)

    def test_relay_finishes_offloaded_tcp_and_udp_checksums(self):
        ips = bytes([10, 0, 0, 10, 10, 0, 0, 1])
        for protocol, options, segment in (
            (6, b"", struct.pack("!HHIIBBHHH", 40000, 8080, 1, 0,
                                  0x50, 2, 4096, 0x1420, 0)),
            (17, b"\x01\x01\x01\x00", struct.pack("!HHHH", 40000, 53, 11, 0x1420) + b"dns"),
        ):
            with self.subTest(protocol=protocol):
                ihl = 20 + len(options)
                ip = struct.pack("!BBHHHBBH", 0x40 + ihl // 4, 0,
                                 ihl + len(segment), 1, 0, 64, protocol, 0) + ips + options
                frame = ethernet(TRUSTED[ATTACKER], TRUSTED[VICTIM], 0x0800,
                                 ip + segment) + b"padding"
                pseudo = ips + struct.pack("!BBH", 0, protocol, len(segment))
                self.assertNotEqual(checksum(pseudo + segment), 0)
                updated = complete_transport_checksum(frame)
                self.assertEqual(checksum(pseudo + updated[14 + ihl:-7]), 0)
                self.assertEqual(updated[:14 + ihl], frame[:14 + ihl])
                self.assertEqual(updated[-7:], b"padding")
                self.assertEqual(parse_ipv4(updated)["payload"], parse_ipv4(frame)["payload"])
                self.assertEqual(complete_transport_checksum(updated), updated)
                fragmented = bytearray(frame)
                fragmented[20:22] = b"\x20\x00"
                self.assertEqual(complete_transport_checksum(bytes(fragmented)), bytes(fragmented))


if __name__ == "__main__":
    unittest.main()
