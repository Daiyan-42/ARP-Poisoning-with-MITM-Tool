# ARP cache poisoning and man-in-the-middle lab

A Python standard-library semester project using three Linux containers on an
internal Docker network. No ports are published to the host. The attacker is
restricted to the configured victim and gateway addresses.

| Role | IP | Purpose |
| --- | --- | --- |
| Victim | 10.0.0.10 | Generates HTTP and DNS requests |
| Gateway | 10.0.0.1 | Serves HTTP on 8080 and DNS on 53 |
| Attacker | 10.0.0.66 | Poisons ARP mappings and relays Ethernet frames |

The gateway is the demonstration server, not an Internet router. The experiment
intercepts traffic between these two peers. Kernel forwarding stays disabled;
the attack implements its own Ethernet relay. HTTP is plaintext; this project
does not decrypt HTTPS.

## Start and test

For the interactive workflow, start Docker Desktop and run on your host:

```sh
python3 main.py
```

Choose **1** to build/start the lab, then **2** for baseline traffic or **3–5**
for monitoring, HTTP modification, or HTTP blocking. Demonstrations automatically
generate victim HTTP/DNS traffic, display neighbor tables and alerts, and request
graceful attack cleanup. Each run saves logs in a unique `artifacts/` directory
and replaces the single `artifacts/capture.pcap` file. Ctrl+C during a demonstration requests cleanup before returning to the
menu; experiments also have a 30-second duration limit.

Choose **6** to enable or refresh ARP inspection on both peers and repeat a
demonstration to observe the defense. **7** removes the inspection rules. **10** stops
the lab; **0** exits the menu while leaving containers running. The menu uses the
three configured lab devices and requires only one computer and one terminal.
It does not require host-side Python dependencies or `sudo`.

Install Docker with Compose (Docker Desktop on macOS), then run:

```sh
docker compose up --build -d --wait
docker compose exec attacker python -m unittest discover -s tests -v
docker compose exec victim python -m arplab.client traffic
```

The baseline HTTP response contains `ORIGINAL`; DNS resolves `demo.lab` to
`10.0.0.1`. Normal traffic resolves peer addresses through ARP; neighbor entries
remain dynamic, including while the defense is enabled.

## Demonstrate interception and modification

In one terminal, start a 60-second attack:

```sh
docker compose exec attacker python -m arplab.attack --mode modify --duration 60 --output /artifacts/modify
```

After the `ready` event, run in a second terminal:

```sh
docker compose exec victim python -m arplab.client traffic --count 5
docker compose exec victim ip neigh show
docker compose exec gateway ip neigh show
docker compose exec victim python -m arplab.client alerts
```

HTTP should contain `MODIFIED`. Both peers' neighbor entries should associate
the opposite peer with the attacker MAC `02:42:0a:00:00:42`. Alerts report the
forged mappings. The attack writes `events.jsonl`, `stats.json`, and `status.json`
under `artifacts/modify/` on the host. There is only one capture:
`artifacts/capture.pcap`. Every experiment overwrites it. Open this file in
Wireshark to inspect ARP replies and intercepted frames; reopen it after a new run.

Other experiments: use `--mode relay` to observe unchanged traffic, `--mode drop`
to cause HTTP timeouts while DNS continues, or `--delay-ms 100` to delay forwarded
frames. Output directories hold each experiment's logs; the capture is always replaced.
The modification replaces an equal-length token within individual TCP packets;
it does not reassemble TCP streams.

The relay completes TCP and UDP checksums on every unfragmented packet before
forwarding. Docker's virtual interfaces can deliver packets with unfinished
offloaded checksums; raw retransmission loses the metadata needed to finish them.
Without this step, HTTP connection attempts and DNS queries can both time out.
After changing the Python code, rebuild the containers with
`docker compose up --build -d --wait` because the code is copied into the image.

## Demonstrate defense

Run the following on the **host**, or choose menu option **6**:

```sh
python3 -m arplab.inventory enable
```

The host reads the running containers' IP and MAC assignments from Docker's
control plane. It sends that inventory through `docker compose exec` to each
endpoint, which stores it in `/run/arplab/bindings.json`. The attacker has no
Docker socket mount and cannot edit either endpoint's private binding file.
No defense MAC addresses are taken from `config.py`, an ARP response, or an
already-poisoned neighbor cache.

Each endpoint installs an nftables ARP input filter. A packet is accepted only
when its ARP sender IP, ARP sender MAC, and Ethernet source MAC match an enrolled
binding. Unenrolled senders and mismatches are counted and dropped before Linux
updates its neighbor cache. Both requests and replies are checked. Enabling or
refreshing the rules also flushes the peer's old neighbor entry so normal ARP can
resolve it again. No permanent entries or ARP sysctl tweaks are used.

Repeat option **4**: HTTP should remain `ORIGINAL`, DNS should work, and option
**8** should show dynamic neighbor entries plus an increasing `dropped_arp`
counter. The passive watcher can still see rejected attempts and report alerts.
To inspect the filter directly:

```sh
python3 -m arplab.inventory status
docker compose exec victim nft list table arp arplab_guard
```

Option **6** re-reads the inventory and atomically replaces each endpoint's rules;
it also resets that endpoint's drop counters. Refresh after an authorized address
change. Updates across both endpoints are sequential, not one shared transaction.
Containers recreated by option **1** need defense enabled again. To remove the
filters and repeat an unprotected experiment, choose **7** or run on the host:

```sh
python3 -m arplab.inventory disable
```

The detector starts without a hardcoded trusted table. Before enrollment, it can
observe changes but cannot establish whether the first claim is genuine. Once
option **6** supplies the authoritative inventory, it compares claims against
that inventory. Disabling filtering retains the inventory for alerts. Its
`seen` dictionary is observation history, not proof of identity; alerts alone
never block packets.

This is a managed-inventory ARP inspection demonstration. Real switches commonly
use a DHCP-snooping binding database for [Dynamic ARP Inspection](https://www.cisco.com/c/en/us/support/docs/switches/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html).
This static Docker network has no DHCP server, so Docker's control plane supplies
the bindings instead. [nftables](https://netfilter.org/projects/nftables/manpage.html)
provides the endpoint ARP filtering. The lab does not implement DHCP snooping,
switch-port identity checks, or automatic lease updates. An attacker cloning a
valid IP and both source MAC fields can pass this endpoint check; switch-port
controls are needed for that threat. Legitimate new hosts must be enrolled before
the default-deny ARP filter will accept them. ARP probes using sender IP 0.0.0.0
are also rejected in this fixed-address lab.

The attacker attempts to restore genuine ARP mappings on normal completion or
SIGINT/SIGTERM. Forced termination cannot guarantee restoration; recreate the lab
if necessary. Stop the experiment before shutting down the containers:

```sh
docker compose down
```

Health checks use a container-local HTTP endpoint on port 8000. For startup
problems, inspect `docker compose ps` and `docker compose logs`. Unit tests cover
ARP poisoning detection/restoration, TCP payload checksums, and DNS responses;
Run `python3 tests/integration.py` on the host for the live relay, modify, drop,
delay, and protected-modify checks, including rejected ARP counters and dynamic
neighbor entries. This test replaces the single capture with its last scenario.

### Enter your own replacement text

Run `python3 main.py`, use option **1** to rebuild/start the lab, then option **4**.
Type the text the victim should receive and press Enter. The menu starts the
attacker and generates victim traffic automatically. Disable defense with option
**7** first if you want to observe successful modification.

To type directly in the attacker terminal:

```sh
docker compose exec attacker python -m arplab.attack --mode modify --prompt
```

While it runs, generate traffic in another terminal:

```sh
docker compose exec victim python -m arplab.client traffic
```

You can also supply `--text "Your message here"` instead of `--prompt`.
Custom text supports UTF-8, including spaces and emoji, up to **1023 bytes**.
The demo gateway reserves a 1024-byte body; the attacker pads your text with
spaces and a final newline to preserve TCP sequence numbers and HTTP content
length, and recalculates the TCP checksum. The victim CLI hides trailing padding.
This modifier targets the demo response when its body is present in one TCP
packet; it does not reassemble bodies split across packets. Without custom text,
the command-line modify mode retains the original `ORIGINAL` → `MODIFIED` demo.

## Running natively on real machines (macOS / Linux)

The `arplab` package also runs outside Docker, directly on Linux or macOS, using
`arplab/io_linux.py` (AF_PACKET) or `arplab/io_macos.py` (BPF) depending on
`platform.system()` -- `arplab/io.py` picks the right one automatically, so
`attack.py`/`node.py`/`client.py` are identical on both platforms. `defense.py`
also branches on platform: Linux (Docker or a native box) uses the nftables
inventory-based inspection described above; macOS has no `nftables`, so it
falls back to permanently pinning the peer's MAC instead (the same mechanism
the lab used before nftables support was added).

All lab addresses are environment-variable overrides on top of the Docker
defaults (`arplab/config.py`): `ARPLAB_IFACE`, `ARPLAB_VICTIM_IP`,
`ARPLAB_VICTIM_MAC`, `ARPLAB_GATEWAY_IP`, `ARPLAB_GATEWAY_MAC`,
`ARPLAB_ATTACKER_IP`, `ARPLAB_ATTACKER_MAC`, `ARPLAB_ARTIFACTS_DIR`. Export the
same values on every participating machine before running any `arplab` command,
then run `arplab.node`/`arplab.client`/`arplab.attack`/`arplab.defense` with
`sudo` exactly as in the Docker walkthrough above (raw sockets need root on
both platforms). Both machines must be on the same Wi-Fi/LAN broadcast segment,
and the router's client/AP isolation (if any) must be disabled. See
[NATIVE_TESTING.md](NATIVE_TESTING.md) for a step-by-step verification checklist.

macOS's BPF backend needs no extra dependencies beyond the standard library and
system `ifconfig`/`arp`/`sysctl`; its raw-socket path (`interface_info` +
`raw_socket` + ARP resolution) has been live-verified against a real router.
The full attack/defense loop on macOS has not been exercised end-to-end yet.
