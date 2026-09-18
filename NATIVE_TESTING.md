# Native (non-Docker) verification checklist

Two physical devices, one running each role, plus your real router as the
passive gateway (no code runs on the router). Run every command from the repo
root, with the same `ARPLAB_*` environment variables exported on **both**
devices first (see [README.md](README.md#running-natively-on-real-machines-macos--linux)).

Legend: **A** = victim device, **B** = attacker device. Either can be the Mac
or the Linux box — the code doesn't care.

## Phase 0 — one-time env setup (A and B)

```bash
export ARPLAB_IFACE=en0            # wlan0 / your real interface on Linux
export ARPLAB_VICTIM_IP=192.168.10.43
export ARPLAB_VICTIM_MAC=<A's real MAC>
export ARPLAB_GATEWAY_IP=192.168.10.1
export ARPLAB_GATEWAY_MAC=<router's real MAC, from `arp -n <gw-ip>` / `ip neigh show <gw-ip>`>
export ARPLAB_ATTACKER_IP=192.168.10.77
export ARPLAB_ATTACKER_MAC=<B's real MAC>
export ARPLAB_ARTIFACTS_DIR=./artifacts
```
**Confirms:** nothing yet — this just wires reality into the code. Every phase
below silently fails its identity checks if any of these are wrong.

## Phase 1 — unit tests (A or B, no sudo)

```bash
python3 -m unittest discover -s tests -v
```
**Expected:** `Ran 6 tests in ~Xs` / `OK`.
**Confirms:** packet parsing, checksum math, the ARP `Detector`'s poison/restore
logic, and the demo HTTP/DNS handlers are all correct in isolation, before any
live network is involved.

## Phase 2 — raw-socket backend smoke test (A and B, needs sudo)

```bash
env ARPLAB_IFACE=$ARPLAB_IFACE sudo -E python3 -c "
from arplab.config import GATEWAY, IFACE
from arplab.io import interface_info, raw_socket, resolve
ip, mac = interface_info(IFACE)
print('own', ip, mac)
sock = raw_socket(IFACE)
print('resolved gateway MAC:', resolve(sock, ip, mac, GATEWAY))"
```
**Expected:** `own <your real IP> <your real MAC>` then
`resolved gateway MAC: <router's real MAC>`.
**Confirms:** the platform's raw-socket backend (BPF on macOS, AF_PACKET on
Linux) can actually open a raw device, broadcast a real ARP request, and
receive/parse a real reply — the lowest-level, most platform-specific code
path. Verified live on macOS: `own 192.168.10.43 0e:76:1f:19:f9:8a` /
`resolved gateway MAC: 80:af:ca:1c:5c:cc`, matching `arp -n` independently.
**If this fails, stop here** — nothing downstream can work without it.

## Phase 3 — victim watcher up (A only)

```bash
sudo -E python3 -m arplab.node victim
```
**Expected:** prints `victim ready at <A's IP>` and keeps running (leave it
in its own terminal tab).
**Confirms:** the ARP watcher thread and the local health/alerts API
(`127.0.0.1:8000`) started — this is what will report poisoning attempts
later, attack or no attack.

## Phase 4 — baseline, before any attack (A, second terminal)

```bash
arp -a | grep <gateway-ip>          # macOS
ip neigh show <gateway-ip>          # Linux
curl -s -m 3 http://<gateway-ip>/ -o /dev/null -w '%{http_code}\n'
```
**Expected:** ARP entry shows the router's genuine MAC; curl returns a normal
HTTP status (whatever your router serves, e.g. `200`/`401`).
**Confirms:** the network is clean before the experiment, so any change you
see next is caused by the attack, not something pre-existing.

## Phase 5 — run the attack (B)

```bash
sudo -E python3 -m arplab.attack --mode relay --duration 60
```
**Expected console output (JSON lines):** a `discovery` event whose `peers`
values match the real victim/gateway MACs from Phase 0, then a `ready` event.
**Confirms:** the attacker resolved both real peers correctly and started the
poisoning loop.

## Phase 6 — poisoning confirmed (A, during the 60s window)

```bash
arp -a | grep <gateway-ip>          # macOS
ip neigh show <gateway-ip>          # Linux
```
**Expected:** the entry now shows **B's MAC**, not the router's.
**Confirms:** the ARP cache poisoning worked — A now sends gateway-bound
traffic to B instead of the real router.

## Phase 7 — interception confirmed (B, during/after the run)

```bash
tail -f artifacts/manual/events.jsonl      # live
# or open artifacts/manual/capture.pcap in Wireshark afterward
```
**Expected:** `intercept` events with `direction: victim_to_gateway` /
`gateway_to_victim` for A's real traffic (pings, curl, DNS lookups you
trigger from A during the window).
**Confirms:** traffic is genuinely flowing *through* B — this is the MITM
position itself, not just a poisoned cache with no effect.

## Phase 8 — restoration confirmed (A, after the attack ends or Ctrl+C on B)

```bash
arp -a | grep <gateway-ip>          # macOS
ip neigh show <gateway-ip>          # Linux
```
**Expected:** back to the router's genuine MAC.
**Confirms:** the attacker's cleanup path correctly undid the poisoning,
leaving the network in its original state.

## Phase 9 — defense confirmed (A, then B)

```bash
# on A
sudo -E python3 -m arplab.defense victim enable
```
Repeat Phase 5 on B, then re-check Phase 6 on A.
**Expected:** the ARP entry stays on the router's genuine MAC throughout
(`PERMANENT` on Linux) even while B is actively trying to poison it; A's
`python3 -m arplab.client alerts` still reports the attempted forgery.
**Confirms:** the pinned static entry actually blocks the redirection, and
the watcher still detects the attempt even though it failed.

```bash
# cleanup, on A
sudo -E python3 -m arplab.defense victim disable
```

## Known limitation

`--mode modify` looks for a literal `ORIGINAL` string from an HTTP server you
control — your real router won't serve that, so it isn't part of this native
checklist. `relay`/`drop`/`delay-ms` fully demonstrate the MITM position
against real traffic as-is; see the README's "Native" section for what `modify`
would need on a real network.
