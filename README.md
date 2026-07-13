# Net-Link

Net-Link is a network segmentation assessment tool for validating which hosts,
ports, and services are reachable from one or more network vantage points. It
runs as a single static binary and is designed for authorized assessments on
laptops, Raspberry Pis, and constrained devices such as the WiFi Pineapple Pager.

## Install

```bash
go install github.com/Zetascrub/net-link/cmd/net-link@latest
```

Or build from source:

```bash
git clone https://github.com/Zetascrub/net-link
cd net-link
make build
```

## Usage

```bash
# Test a single host
net-link test 10.20.30.40 --ports 22,80,443

# Import an Nmap XML file and validate open ports
net-link test --nmap scan.xml --out run.nljson

# Run Nmap and validate results in one step
net-link scan 10.20.30.0/24 --scanner nmap --out run.nljson

# Sweep the local network for reachable services
net-link discover --scope 10.20.30.0/24 --ports 22,80,443

# Automatically discover directly connected private networks
net-link discover --auto --dry-run

# Also include private non-default routes visible to the host
net-link discover --auto --include-routes --ports 22,80,443

# Generate a Markdown report from saved results
net-link report run.nljson --format markdown --out report.md
```

Use `--dry-run` on any scanning command to preview targets without sending probes.

Automatic discovery supports `--interface` and `--exclude-interface` filters,
`--max-hosts` per subnet, and `--max-total-hosts` across the complete automatic
scope. Route discovery is opt-in because routed networks may substantially widen
the authorized assessment scope. Default routes, public routes, and common
container/VPN interfaces are excluded unless an interface is explicitly selected.
RFC1918, loopback, link-local, and `100.64.0.0/10` shared-address networks are
treated as internal; the shared range supports environments such as ChromeOS
Crostini while ordinary public ranges remain blocked.

Public IP targets are blocked by default. Pass `--allow-public` only when the
assessment scope explicitly permits it.

Human summaries are printed to stderr by default. Use `--out run.nljson` to save
full JSON evidence, or `--json` to print it to stdout. Evidence files are replaced
atomically and written with owner-only permissions (`0600`).

## Link Mode

> **Experimental:** Link mode is currently unauthenticated. Remote service
> checks are disabled by default. Use it only on networks you control.

Link mode lets two or more Net-Link instances discover each other on internal
networks and verify bidirectional connectivity.

```bash
# On a device placed on VLAN 20
net-link link listen --name field-node --bind-address 10.20.0.15

# On the operator laptop
net-link link discover
net-link link matrix --ports 22,80,443,47889 --out matrix.nljson
```

Each discovered peer is verified with a bidirectional TCP handshake. The matrix
command tests TCP reachability from the local node to each peer and requests the
peer to test back, producing a cross-VLAN reachability table. To enable the
reverse service-check portion during this experimental phase, the listening peer
and the matrix command must explicitly opt in and provide a local policy:

```bash
net-link link listen --name field-node --allow-remote-checks \
  --remote-scope 10.20.0.0/24 --remote-ports 22,80,443,47889
```

Remote requests can contain only literal internal IP addresses inside the listed
CIDRs and only the listed ports. Requests are also bounded by message size,
target count, duration, worker count, and concurrent-client count. This remains
unsafe on untrusted networks and is not a substitute for authentication.

## Build Targets

```bash
make build               # local platform
make build-linux-amd64   # Linux x86-64
make build-pi-arm64      # Raspberry Pi (arm64)
make build-pi-armv7      # Raspberry Pi (armv7)
make build-pager         # WiFi Pineapple Pager (MIPS LE soft-float)
make test                # run tests
make vet                 # run go vet
make check               # formatting, vet, tests, and race detector
make dist                # cross-build release artifacts and checksums
```

See [AUTOMATION.md](AUTOMATION.md) for CI, reproducible builds, security checks,
artifact generation, and tag-driven releases.

## WiFi Pineapple Pager

The Pager payload lives in `payloads/pager/net_link`. Install layout on the
device:

```text
/mmc/root/payloads/user/general/net_link/
  payload
  payload.sh
  net-link          ← built with make build-pager
```

The payload menu provides:

| Button | Action |
| --- | --- |
| GREEN / A | Listen for peers |
| UP | Find peers (saves evidence to `runs/`) |
| DOWN | Peer service matrix (choose port profile) |
| LEFT | Status — count and summary of saved runs |
| RIGHT | LAN service discovery (with confirmation) |
| RED / B | Exit |

LED and D-pad LEDs reflect the current state: magenta at idle, cyan while
listening, yellow while scanning, green on success, red on no results.
Timestamped evidence files are saved to `runs/` on the MMC for later retrieval.

## Safety

- Public IP targets are blocked by default (`--allow-public` to override).
- Use `--dry-run` to preview scope and target counts before any broad scan.
- The link protocol is currently unauthenticated. Use on networks you control.
  Peer pairing and mutual authentication are planned for a future release.
- Remote link service checks are disabled by default. The explicit
  `--allow-remote-checks` opt-in also requires `--remote-scope` and
  `--remote-ports`; it still permits unauthenticated requests and should only be
  used in an isolated, controlled assessment network.

## Design

See [DESIGN.md](DESIGN.md) for the full product design and
[IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md) for the tracked hardening roadmap.

## License

[MIT](LICENSE)
