import argparse
import json
from pathlib import Path
import subprocess

from .config import ROLES
from .defense import validate_bindings


ROOT = Path(__file__).resolve().parents[1]


def bindings_from_containers(containers):
    bindings, found, networks = {}, set(), set()
    for container in containers:
        role = container["Config"]["Labels"].get("com.docker.compose.service")
        if role not in ROLES or role in found or not container["State"]["Running"]:
            raise ValueError("Expected exactly one running container per lab role")
        matches = [network for network in container["NetworkSettings"]["Networks"].values()
                   if network["IPAddress"] == ROLES[role]]
        if len(matches) != 1:
            raise ValueError(f"Cannot identify the lab interface for {role}")
        network = matches[0]
        bindings[network["IPAddress"]] = network["MacAddress"]
        networks.add(network["NetworkID"])
        found.add(role)
    if found != set(ROLES) or len(networks) != 1 or "" in networks:
        raise ValueError("All three running hosts must share one lab network")
    return validate_bindings(bindings)


def discover_bindings():
    result = subprocess.run(["docker", "compose", "ps", "-q", *ROLES], cwd=ROOT,
                            text=True, capture_output=True, check=True)
    identifiers = result.stdout.split()
    if len(identifiers) != len(ROLES):
        raise RuntimeError("Start all three lab containers before enabling defense")
    result = subprocess.run(["docker", "inspect", *identifiers], cwd=ROOT,
                            text=True, capture_output=True, check=True)
    return bindings_from_containers(json.loads(result.stdout))


def apply_defense(action):
    bindings = discover_bindings() if action == "enable" else None
    for role in ("victim", "gateway"):
        command = ["docker", "compose", "exec", "-T", role, "python", "-m",
                   "arplab.defense", role, action]
        if bindings is not None:
            command.append("--bindings-stdin")
        try:
            subprocess.run(command, cwd=ROOT, check=True, text=True,
                           input=json.dumps(bindings) if bindings is not None else None)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"Defense {action} failed on {role}; check status on both peers") from exc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage lab ARP inspection from the Docker host")
    parser.add_argument("action", choices=("enable", "disable", "status"))
    args = parser.parse_args()
    try:
        apply_defense(args.action)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Defense failed: {exc}\n")
