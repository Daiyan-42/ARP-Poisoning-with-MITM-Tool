"""macOS raw-networking backend: BPF devices and BSD arp neighbor pinning.

Standard-library only (fcntl/os/struct/select) -- talks to /dev/bpf* the way
tcpdump/libpcap do internally on Darwin, instead of Linux's AF_PACKET.

NOTE: the BPF ioctl numbers and bpf_hdr layout below are derived from Darwin's
published <net/bpf.h> definitions, not verified against a live Mac in this
environment. If raw_socket() raises OSError/PermissionError or recvfrom()
returns garbage, that is the piece to debug first (see README).
"""
import fcntl
import os
import re
import select
import socket
import struct
import subprocess

# BPF already excludes our own transmitted frames (BIOCSSEESENT below), so
# nothing this backend returns is ever "outgoing" -- OUTGOING is a sentinel
# that never matches, mirroring Linux's socket.PACKET_OUTGOING marker.
OUTGOING = -1

_IOC_IN, _IOC_OUT, _IOC_INOUT = 0x80000000, 0x40000000, 0xC0000000


def _ioc(way, group, num, size):
    return way | ((size & 0x1fff) << 16) | (ord(group) << 8) | num


BIOCSBLEN = _ioc(_IOC_INOUT, "B", 102, 4)      # set/get capture buffer length
BIOCSETIF = _ioc(_IOC_IN, "B", 108, 32)        # bind to an interface (struct ifreq)
BIOCIMMEDIATE = _ioc(_IOC_IN, "B", 112, 4)     # return reads as soon as a packet arrives
BIOCSHDRCMPLT = _ioc(_IOC_IN, "B", 117, 4)     # we fill in the Ethernet source ourselves
BIOCSSEESENT = _ioc(_IOC_IN, "B", 119, 4)      # 0 = do not loop back locally sent frames
_BUFFER_SIZE = 1 << 20


def interface_info(iface):
    if not iface or "/" in iface:
        raise ValueError("Invalid interface name")
    output = subprocess.run(["ifconfig", iface], check=True, capture_output=True,
                            text=True).stdout
    mac = re.search(r"ether ([0-9a-fA-F:]{17})", output)
    ip = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
    if not mac or not ip:
        raise RuntimeError(f"Could not read IP/MAC for {iface} from ifconfig")
    return ip.group(1), mac.group(1).lower()


class _BPFSocket:
    """Wraps /dev/bpf to look like the Linux AF_PACKET socket callers expect:
    send(frame) and recvfrom(n) -> (frame, addr) with addr[2] comparable to OUTGOING."""

    def __init__(self, iface):
        self.fd = None
        for index in range(256):
            try:
                self.fd = os.open(f"/dev/bpf{index}", os.O_RDWR)
                break
            except OSError:
                continue
        if self.fd is None:
            raise OSError("No free /dev/bpf device (run with sudo)")
        fcntl.ioctl(self.fd, BIOCSBLEN, struct.pack("I", _BUFFER_SIZE))
        fcntl.ioctl(self.fd, BIOCSETIF, struct.pack("16s16x", iface.encode()))
        fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("I", 1))
        fcntl.ioctl(self.fd, BIOCSHDRCMPLT, struct.pack("I", 1))
        fcntl.ioctl(self.fd, BIOCSSEESENT, struct.pack("I", 0))
        self._pending = b""
        self._timeout = None

    def settimeout(self, value):
        self._timeout = value

    def send(self, frame):
        os.write(self.fd, frame)

    def recvfrom(self, _bufsize):
        while not self._pending:
            if self._timeout is not None:
                ready, _, _ = select.select([self.fd], [], [], self._timeout)
                if not ready:
                    raise socket.timeout()
            self._pending = os.read(self.fd, _BUFFER_SIZE)
        # struct bpf_hdr { struct BPF_TIMEVAL bh_tstamp; u_int32 bh_caplen;
        #                  u_int32 bh_datalen; u_int16 bh_hdrlen; } -- Darwin
        # keeps bh_tstamp as two 32-bit fields regardless of arch.
        _, _, caplen, _, hdrlen = struct.unpack_from("<iiIIH", self._pending, 0)
        frame = self._pending[hdrlen:hdrlen + caplen]
        record_len = (hdrlen + caplen + 7) & ~7  # BPF_WORDALIGN: 8-byte alignment on 64-bit Darwin
        self._pending = self._pending[record_len:]
        return frame, (None, 0, 0, 0, b"")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)


def raw_socket(iface):
    return _BPFSocket(iface)


def set_neighbor(iface, ip, mac, permanent):
    # BSD's arp -s refuses to overwrite an existing entry ("File exists"),
    # unlike Linux's "ip neigh replace"; delete first (no-op if absent).
    # "ifscope" pins both operations to this interface -- without it, a
    # genuine interface-scoped entry (how macOS normally learns a router's
    # MAC) and our unscoped one can coexist and collide ("can only proxy
    # for <ip>") instead of the second cleanly replacing the first.
    subprocess.run(["arp", "-d", ip, "ifscope", iface], capture_output=True)
    # arp -s entries are permanent by default; "temp" gives an ordinary,
    # ageable entry -- the closest match to Linux's dynamic "nud reachable".
    args = ["arp", "-s", ip, mac] + ([] if permanent else ["temp"]) + ["ifscope", iface]
    subprocess.run(args, check=True)


def ip_forwarding_enabled():
    output = subprocess.run(["sysctl", "-n", "net.inet.ip.forwarding"],
                            check=True, capture_output=True, text=True).stdout
    return output.strip() == "1"
