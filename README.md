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

Install Docker with Compose (Docker Desktop on macOS), then run:

```sh
docker compose up --build -d --wait
docker compose exec attacker python -m unittest discover -s tests -v
docker compose exec victim python -m arplab.client traffic
```

The baseline HTTP response contains `ORIGINAL`; DNS resolves `demo.lab` to
`10.0.0.1`. Startup seeds genuine dynamic neighbor entries on both peers.

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
forged mappings. The attack writes `events.jsonl`, `capture.pcap`, `stats.json`,
and `status.json` under `artifacts/modify/` on the host. Open the PCAP in Wireshark
to inspect ARP replies and intercepted frames.

Other experiments: use `--mode relay` to observe unchanged traffic, `--mode drop`
to cause HTTP timeouts while DNS continues, or `--delay-ms 100` to delay forwarded
frames. Use distinct output directories to keep each experiment's results.
The modification replaces an equal-length token within individual TCP packets;
it does not reassemble TCP streams.

The relay completes TCP and UDP checksums on every unfragmented packet before
forwarding. Docker's virtual interfaces can deliver packets with unfinished
offloaded checksums; raw retransmission loses the metadata needed to finish them.
Without this step, HTTP connection attempts and DNS queries can both time out.
After changing the Python code, rebuild the containers with
`docker compose up --build -d --wait` because the code is copied into the image.

## Demonstrate defense

Enable permanent mappings on both endpoints, then repeat the attack and requests:

```sh
docker compose exec victim python -m arplab.defense victim enable
docker compose exec gateway python -m arplab.defense gateway enable
```

HTTP should remain `ORIGINAL`, and neighbor entries should remain genuine and
`PERMANENT`. The watcher may still report attempted poisoning.

Restore dynamic mappings before another unprotected experiment:

```sh
docker compose exec victim python -m arplab.defense victim disable
docker compose exec gateway python -m arplab.defense gateway disable
```

The attacker attempts to restore genuine ARP mappings on normal completion or
SIGINT/SIGTERM. Forced termination cannot guarantee restoration; recreate the lab
if necessary. Stop the experiment before shutting down the containers:

```sh
docker compose down
```

Health checks use a container-local HTTP endpoint on port 8000. For startup
problems, inspect `docker compose ps` and `docker compose logs`. Unit tests cover
ARP poisoning detection/restoration, TCP payload checksums, and DNS responses;
the commands above exercise the live network behavior.
