"""Run from the host: python3 tests/integration.py (requires a running lab)."""
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def docker(*args, check=True):
    result = subprocess.run(["docker", "compose", "exec", "-T", *args],
                            cwd=ROOT, text=True, capture_output=True, timeout=20)
    if check and result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result


def traffic(expected, dropped=False):
    result = docker("victim", "python", "-m", "arplab.client", "traffic", check=False)
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(records) == 2, result.stdout + result.stderr
    http, dns = records
    assert dns.get("result") == "10.0.0.1", records
    if dropped:
        assert result.returncode == 1 and "error" in http, records
    else:
        assert result.returncode == 0 and expected in http.get("result", ""), records


def protection(enabled):
    # Bindings come from the host's Docker control plane (arplab.inventory),
    # not a hardcoded table -- see README "Demonstrate defense".
    subprocess.run(["python3", "-m", "arplab.inventory", "enable" if enabled else "disable"],
                   cwd=ROOT, check=True)


def dropped_arp_total():
    total = 0
    for role in ("victim", "gateway"):
        status = json.loads(docker(role, "python", "-m", "arplab.defense", role, "status").stdout)
        total += status.get("dropped_arp") or 0
    return total


def scenario(name, mode, protected=False, delay=0):
    protection(protected)
    before_dropped = dropped_arp_total() if protected else None
    folder = ROOT / "artifacts" / ("test-" + name + "-" + str(time.time_ns()))
    folder.mkdir(parents=True)
    command = ["docker", "compose", "exec", "-T", "attacker", "python", "-m",
               "arplab.attack", "--mode", mode, "--duration", "9", "--delay-ms",
               str(delay), "--output", "/artifacts/" + folder.name]
    with (folder / "console.log").open("w") as output:
        process = subprocess.Popen(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 6
            while not (folder / "status.json").exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError((folder / "console.log").read_text())
                time.sleep(0.1)
            assert json.loads((folder / "status.json").read_text())["state"] == "running"
            for role, peer in (("victim", "10.0.0.1"), ("gateway", "10.0.0.10")):
                neighbor = docker(role, "ip", "neigh", "show", peer).stdout
                deadline = time.monotonic() + 3
                while not protected and "02:42:0a:00:00:42" not in neighbor and time.monotonic() < deadline:
                    time.sleep(0.2)
                    neighbor = docker(role, "ip", "neigh", "show", peer).stdout
                # Defended peers reject the forged ARP before it ever reaches the
                # neighbor table -- entries stay dynamic, never the attacker's MAC.
                if protected:
                    assert "02:42:0a:00:00:42" not in neighbor, neighbor
                else:
                    assert "02:42:0a:00:00:42" in neighbor, neighbor
            traffic("MODIFIED" if mode == "modify" and not protected else "ORIGINAL",
                    dropped=mode == "drop" and not protected)
            assert process.wait(timeout=15) == 0, (folder / "console.log").read_text()
        finally:
            if process.poll() is None:
                # The bounded attack exits and restores mappings after nine seconds.
                process.wait(timeout=15)
    if protected:
        after_dropped = dropped_arp_total()
        assert after_dropped > before_dropped, (before_dropped, after_dropped)
    stats = json.loads((folder / "stats.json").read_text())
    if protected:
        assert stats["received"] == 0 and stats["modified"] == 0, stats
    else:
        assert stats["victim_to_gateway"] > 0 and stats["gateway_to_victim"] > 0, stats
        assert stats["forwarded"] > 0, stats
        if mode == "modify":
            assert stats["modified"] > 0, stats
        if mode == "drop":
            assert stats["dropped"] > 0, stats
    # Restoration must leave both endpoints with their genuine peer mappings.
    for role, peer, mac in (("victim", "10.0.0.1", "02:42:0a:00:00:01"),
                            ("gateway", "10.0.0.10", "02:42:0a:00:00:0a")):
        assert mac in docker(role, "ip", "neigh", "show", peer).stdout
    traffic("ORIGINAL")
    print(f"PASS {name}: {stats}", flush=True)
    return {"scenario": name, "stats": stats, "artifacts": str(folder.relative_to(ROOT))}


def main():
    results = []
    try:
        protection(False)
        traffic("ORIGINAL")
        print("PASS baseline HTTP and DNS", flush=True)
        for name, mode, protected, delay in (("relay", "relay", False, 0),
                ("modify", "modify", False, 0), ("drop", "drop", False, 0),
                ("delay", "relay", False, 100), ("defense", "modify", True, 0)):
            results.append(scenario(name, mode, protected, delay))
        alerts = json.loads(docker("victim", "python", "-m", "arplab.client", "alerts").stdout)
        assert alerts["result"]["count"] > 0, alerts
        (ROOT / "artifacts" / "integration-results.json").write_text(json.dumps(results, indent=2) + "\n")
        print("PASS detection; all live integration checks passed", flush=True)
    finally:
        protection(False)


if __name__ == "__main__":
    main()
