"""Lab topology. Defaults match the Docker lab; override via environment
variables for native (non-Docker) runs on real machines -- see README."""
import os

IFACE = os.environ.get("ARPLAB_IFACE", "eth0")
VICTIM = os.environ.get("ARPLAB_VICTIM_IP", "10.0.0.10")
GATEWAY = os.environ.get("ARPLAB_GATEWAY_IP", "10.0.0.1")
ATTACKER = os.environ.get("ARPLAB_ATTACKER_IP", "10.0.0.66")
ARTIFACTS_DIR = os.environ.get("ARPLAB_ARTIFACTS_DIR", "/artifacts")
TRUSTED = {
    VICTIM: os.environ.get("ARPLAB_VICTIM_MAC", "02:42:0a:00:00:0a"),
    GATEWAY: os.environ.get("ARPLAB_GATEWAY_MAC", "02:42:0a:00:00:01"),
    ATTACKER: os.environ.get("ARPLAB_ATTACKER_MAC", "02:42:0a:00:00:42"),
}
ROLES = {"victim": VICTIM, "gateway": GATEWAY, "attacker": ATTACKER}

HTTP_BODY_SIZE = 1024
HTTP_ORIGINAL_BODY = b"ORIGINAL: Hello from the lab gateway!".ljust(HTTP_BODY_SIZE - 1) + b"\n"


def replacement_body(text):
    encoded = text.encode("utf-8")
    if len(encoded) > HTTP_BODY_SIZE - 1:
        raise ValueError(f"Text must fit in {HTTP_BODY_SIZE - 1} UTF-8 bytes")
    return encoded.ljust(HTTP_BODY_SIZE - 1) + b"\n"
