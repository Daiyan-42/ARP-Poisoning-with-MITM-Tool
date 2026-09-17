"""Byte-level packet construction/parsing. No packet-crafting dependencies."""
import socket
import struct

ETH_IP = 0x0800
ETH_ARP = 0x0806


def mac_bytes(value):
    parts = value.split(":")
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        raise ValueError("MAC must have six two-digit hex octets")
    return bytes(int(p, 16) for p in parts)


def mac_text(value):
    return ":".join(f"{b:02x}" for b in value)


def ethernet(dst, src, kind, payload):
    return struct.pack("!6s6sH", mac_bytes(dst), mac_bytes(src), kind) + payload


def build_arp(src_mac, src_ip, dst_mac, dst_ip, opcode=2, broadcast=False):
    if opcode not in (1, 2):
        raise ValueError("Unsupported ARP operation")
    # ! packs all multi-byte fields in network order; no extra htons here.
    payload = struct.pack("!HHBBH6s4s6s4s", 1, ETH_IP, 6, 4, opcode,
                          mac_bytes(src_mac), socket.inet_aton(src_ip),
                          mac_bytes(dst_mac), socket.inet_aton(dst_ip))
    return ethernet("ff:ff:ff:ff:ff:ff" if broadcast else dst_mac,
                    src_mac, ETH_ARP, payload)


def build_arp_reply(src_mac, src_ip, dst_mac, dst_ip):
    return build_arp(src_mac, src_ip, dst_mac, dst_ip)


def parse_arp(frame):
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = struct.unpack(
        "!HHBBH6s4s6s4s", frame[14:42])
    if (htype, ptype, hlen, plen) != (1, ETH_IP, 6, 4) or op not in (1, 2):
        return None
    return dict(op=op, src_mac=mac_text(sha), src_ip=socket.inet_ntoa(spa),
                dst_mac=mac_text(tha), dst_ip=socket.inet_ntoa(tpa))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def parse_ipv4(frame):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    size = int.from_bytes(ip[2:4], "big")
    if ip[0] >> 4 != 4 or ihl < 20 or size < ihl or size > len(ip):
        return None
    frag = int.from_bytes(ip[6:8], "big")
    result = dict(src_ip=socket.inet_ntoa(ip[12:16]), dst_ip=socket.inet_ntoa(ip[16:20]),
                  protocol=ip[9], ttl=ip[8], ihl=ihl, size=size,
                  fragmented=bool(frag & 0x3fff), payload=b"")
    segment = ip[ihl:size]
    if result["fragmented"]:
        return result
    if ip[9] == 6 and len(segment) >= 20:
        offset = (segment[12] >> 4) * 4
        if not 20 <= offset <= len(segment):
            return result
        result.update(src_port=int.from_bytes(segment[:2], "big"),
                      dst_port=int.from_bytes(segment[2:4], "big"),
                      transport_offset=14 + ihl, payload_offset=14 + ihl + offset,
                      payload=segment[offset:])
    elif ip[9] == 17 and len(segment) >= 8:
        length = int.from_bytes(segment[4:6], "big")
        if not 8 <= length <= len(segment):
            return result
        result.update(src_port=int.from_bytes(segment[:2], "big"),
                      dst_port=int.from_bytes(segment[2:4], "big"), payload=segment[8:length])
    return result


def rewrite_ethernet(frame, dst, src):
    return mac_bytes(dst) + mac_bytes(src) + frame[12:]


def complete_transport_checksum(frame):
    """Finish TCP/UDP checksums before raw retransmission in the Docker lab.

    recvfrom returns bytes without the kernel's checksum-offload metadata.
    Even unchanged packets can therefore need a checksum before sock.send.
    Fragmented datagrams need reassembly and are left unchanged.
    """
    info = parse_ipv4(frame)
    if not info or info["fragmented"] or "src_port" not in info:
        return frame
    start = 14 + info["ihl"]
    length = info["size"] - info["ihl"]
    if info["protocol"] == 6:
        offset = start + 16
    elif info["protocol"] == 17:
        length = int.from_bytes(frame[start + 4:start + 6], "big")
        offset = start + 6
    else:
        return frame
    data = bytearray(frame)
    data[offset:offset + 2] = b"\x00\x00"
    pseudo = data[26:34] + struct.pack("!BBH", 0, info["protocol"], length)
    value = checksum(bytes(pseudo + data[start:start + length]))
    if info["protocol"] == 17 and value == 0:
        value = 0xffff  # UDP zero means checksum disabled.
    data[offset:offset + 2] = struct.pack("!H", value)
    return bytes(data)


def replace_tcp_payload(frame, old=b"ORIGINAL", new=b"MODIFIED"):
    if not old or len(old) != len(new):
        raise ValueError("Replacement must be nonempty and have equal byte length")
    info = parse_ipv4(frame)
    if not info or info["protocol"] != 6 or info["fragmented"] or old not in info["payload"]:
        return frame, False
    data = bytearray(frame)
    start = info["payload_offset"]
    end = 14 + info["size"]
    data[start:end] = info["payload"].replace(old, new)
    tcp = info["transport_offset"]
    data[tcp + 16:tcp + 18] = b"\x00\x00"
    pseudo = data[26:34] + struct.pack("!BBH", 0, 6, end - tcp)
    data[tcp + 16:tcp + 18] = struct.pack("!H", checksum(bytes(pseudo + data[tcp:end])))
    return bytes(data), True


def dns_name(payload):
    if len(payload) < 12 or int.from_bytes(payload[4:6], "big") == 0:
        return None
    pos, labels = 12, []
    while pos < len(payload):
        length = payload[pos]
        pos += 1
        if length == 0:
            return ".".join(labels)
        if length > 63 or pos + length > len(payload):
            return None  # This demo uses uncompressed question names.
        labels.append(payload[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return None
