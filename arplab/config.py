IFACE = "eth0"
VICTIM = "10.0.0.10"
GATEWAY = "10.0.0.1"
ATTACKER = "10.0.0.66"
TRUSTED = {
    VICTIM: "02:42:0a:00:00:0a",
    GATEWAY: "02:42:0a:00:00:01",
    ATTACKER: "02:42:0a:00:00:42",
}
ROLES = {"victim": VICTIM, "gateway": GATEWAY, "attacker": ATTACKER}
