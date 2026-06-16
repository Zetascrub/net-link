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

# Generate a Markdown report from saved results
net-link report run.nljson --format markdown --out report.md
```

Use `--dry-run` on any scanning command to preview targets without sending probes.

Public IP targets are blocked by default. Pass `--allow-public` only when the
assessment scope explicitly permits it.

Human summaries are printed to stderr by default. Use `--out run.nljson` to save
full JSON evidence, or `--json` to print it to stdout.

## Link Mode

Link mode lets two or more Net-Link instances discover each other on internal
networks and run bidirectional connectivity tests.

```bash
# On a device placed on VLAN 20
net-link link listen --name field-node

# On the operator laptop
net-link link discover
net-link link matrix --ports 22,80,443,47889 --out matrix.nljson
```

Each discovered peer is verified with a bidirectional TCP handshake. The matrix
command tests TCP reachability from the local node to each peer and requests the
peer to test back, producing a cross-VLAN reachability table.

## Build Targets

```bash
make build               # local platform
make build-linux-amd64   # Linux x86-64
make build-pi-arm64      # Raspberry Pi (arm64)
make build-pi-armv7      # Raspberry Pi (armv7)
make build-pager         # WiFi Pineapple Pager (MIPS LE soft-float)
make test                # run tests
make vet                 # run go vet
```

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

## Design

See [DESIGN.md](DESIGN.md) for the full product design, data model, protocol
sketch, and roadmap.

## License

[MIT](LICENSE)
