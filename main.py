import json
from pathlib import Path
import shutil
import subprocess
import time
from uuid import uuid4

from arplab.config import ROLES, TRUSTED, replacement_body
from arplab.inventory import apply_defense


ROOT = Path(__file__).resolve().parent


def compose(*args, check=True):
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, check=check)


def node(role, *args, check=True):
    return compose("exec", "-T", role, *args, check=check)


def ready():
    for role in ROLES:
        node(role, "python", "-m", "arplab.client", "health")
    node("victim", "python", "-m", "arplab.client", "http")


def traffic():
    return node("victim", "python", "-m", "arplab.client", "traffic",
                "--count", "3", check=False)


def inspect():
    for role in ("victim", "gateway"):
        print(f"\n{role} neighbor table and alerts:", flush=True)
        node(role, "ip", "neigh", "show")
        node(role, "python", "-m", "arplab.client", "alerts")
        node(role, "python", "-m", "arplab.defense", role, "status")


def defense(action):
    apply_defense(action)
    print(f"Defense {action}d on both peers.")


def wait_ready(output, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = output / "status.json"
        if status.exists():
            if json.loads(status.read_text())["state"] == "running":
                return
        if (output / "exit-code").exists():
            raise RuntimeError("Experiment exited before becoming ready; see console.log.")
        time.sleep(0.1)
    raise RuntimeError("Experiment did not become ready within 10 seconds.")


def experiment(mode):
    text_args = []
    if mode == "modify":
        while True:
            text = input("Replacement text (up to 1023 UTF-8 bytes): ")
            try:
                replacement_body(text)
                break
            except ValueError as exc:
                print(exc)
        text_args = ["--text=" + text]
    ready()
    name = time.strftime("%Y%m%d-%H%M%S") + f"-{mode}-{uuid4().hex[:8]}"
    output = ROOT / "artifacts" / name
    output.mkdir(parents=True)
    print(f"\nLogs: {output}", flush=True)
    print(f"Wireshark capture: {ROOT / 'artifacts' / 'capture.pcap'} "
          "(replaced each run)", flush=True)
    print("With defense enabled, HTTP should remain ORIGINAL. "
          "Otherwise: relay → ORIGINAL, modify → your text, drop → HTTP timeout.", flush=True)
    try:
        compose("exec", "-T", "-d", "attacker", "python", "-m", "arplab.session",
                mode, f"/artifacts/{name}", *text_args)
        wait_ready(output)
        print("Experiment ready; generating victim HTTP and DNS traffic.", flush=True)
        result = traffic()
        if result.returncode:
            print("Some requests failed. HTTP timeouts are expected in unprotected drop mode.")
        inspect()
    finally:
        (output / "stop").touch()
        print("Waiting for experiment cleanup…", flush=True)
        deadline = time.monotonic() + 10
        while not (output / "exit-code").exists() and time.monotonic() < deadline:
            try:
                time.sleep(0.1)
            except KeyboardInterrupt:
                print("Cleanup is still running…", flush=True)
        if (output / "exit-code").exists():
            code = (output / "exit-code").read_text().strip()
            print(f"Experiment exited with code {code}. Logs: {output / 'console.log'}")
            if (output / "stats.json").exists():
                print((output / "stats.json").read_text())
        else:
            print("Cleanup has not been confirmed. Check console.log and container status; "
                  "experiments have a 30-second duration limit.")


def main():
    print("ARP lab — one computer, three Docker containers")
    for role, ip in ROLES.items():
        print(f"  {role:8} {ip:12} {TRUSTED[ip]}")
    print("Gateway is the demo HTTP/DNS server. Run option 1 before your first experiment.")
    if not shutil.which("docker"):
        print("Docker was not found. Install/start Docker Desktop, then run this menu again.")
        return 1
    actions = {
        "1": lambda: compose("up", "--build", "-d", "--wait"),
        "2": traffic,
        "3": lambda: experiment("relay"),
        "4": lambda: experiment("modify"),
        "5": lambda: experiment("drop"),
        "6": lambda: defense("enable"),
        "7": lambda: defense("disable"),
        "8": inspect,
        "9": lambda: compose("ps"),
        "10": lambda: compose("down"),
    }
    while True:
        print("\n1 Start/rebuild lab     2 Generate HTTP/DNS traffic\n"
              "3 Monitor/relay         4 Enter modified HTTP text\n"
              "5 Block HTTP            6 Enable/refresh ARP inspection\n"
              "7 Disable defense       8 Show neighbors, alerts and drops\n"
              "9 Container status     10 Stop lab\n"
              "0 Exit menu (leave containers running)")
        try:
            choice = input("Select: ").strip()
            if choice == "0":
                return 0
            action = actions.get(choice)
            if action is None:
                print("Choose a number from 0 to 10.")
                continue
            action()
        except EOFError:
            return 0
        except KeyboardInterrupt:
            print("\nAction interrupted. Returning to menu.")
        except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
            print(f"Action failed: {exc}\nCheck Docker Desktop and use option 1 to start/rebuild the lab.")


if __name__ == "__main__":
    raise SystemExit(main())
