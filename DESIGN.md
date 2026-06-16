# Net-Link Design Document

## Overview

Net-Link is a network segmentation assessment tool for validating whether two network positions can communicate with each other, and by which paths. It is intended first for authorized client assessments, with a long-term goal of being suitable for public release as a professional open-source tool.

The first version is CLI based, but should still feel rich: interactive progress, structured results, evidence capture, and useful summaries rather than a stream of raw socket errors. Reporting should be polished enough for assessment evidence, but should not bloat the tool into a heavy report-writing platform.

The working name is `net-link`. Other possible names:

- `segment-link`
- `pathcheck`
- `netprobe`
- `linkscope`
- `segtest`

## Goals

- Test connectivity from the local host to a target IP across many protocols and port states.
- Parse Nmap XML and test the discovered open ports directly.
- Run in a linked mode where multiple Net-Link instances discover each other on internal networks and exchange controlled connectivity tests.
- Help operators understand segmentation from multiple vantage points, including laptops, Raspberry Pis, WiFi Pineapple-style devices, jump boxes, and small appliances.
- Produce human-friendly CLI output and machine-readable reports.
- Keep testing explicit, rate-limited, auditable, and suitable for authorized environments.
- Prioritize human inspection during live use while preserving enough structured evidence for assessment reports.
- Ship as a single easy-to-deploy binary when possible.

## Non-Goals

- Exploitation, credential attacks, payload delivery, or persistence.
- Internet-wide scanning.
- Stealth or evasion.
- Bypassing segmentation through unauthorized pivoting.
- Exploit-style VLAN hopping or switch abuse techniques.
- Replacing full-featured scanners such as Nmap, Masscan, or vulnerability scanners.

Net-Link can consume scanner output, run scanner-assisted prototype workflows, and eventually include its own focused scanner. It should not try to become a general-purpose offensive framework.

## Primary Use Cases

### Standalone Target Test

An operator provides a target IP or hostname. Net-Link attempts a suite of connectivity checks and records which methods succeed.

Example:

```bash
net-link test 10.20.30.40
net-link test 10.20.30.40 --ports 22,80,443,445
net-link test 10.20.30.40 --profile common
```

### Nmap XML Validation

An operator imports an Nmap XML scan. Net-Link extracts hosts and open ports, then performs connection validation against those endpoints from the current network position.

Example:

```bash
net-link test --nmap scan.xml
net-link test --nmap scan.xml --host 10.20.30.40
```

### Nmap-Assisted Prototype Scan

During prototype versions, Net-Link can execute Nmap directly and consume the resulting XML internally. This gives the project a useful scanner quickly while the in-house scanner matures.

Example:

```bash
net-link scan 10.20.30.0/24 --scanner nmap
net-link scan 10.20.30.0/24 --scanner nmap --profile common
```

The long-term direction is to move common scanning into Net-Link itself so deployment does not depend on Nmap being present on every assessment device.

### Linked Segmentation Test

An operator runs Net-Link on two or more machines in different network locations. Instances discover each other where possible, establish an authenticated link, and coordinate tests from each vantage point.

Example:

```bash
# On a small device placed on VLAN 20
net-link link listen --name pi-vlan20

# On the operator laptop
net-link link scan
net-link link connect pi-vlan20
net-link matrix --targets 10.10.0.0/24,10.20.0.0/24
```

### Report Generation

An operator exports results for audit evidence, change validation, or client reporting.

Example:

```bash
net-link report results.nljson --format html
net-link report results.nljson --format markdown
net-link report results.nljson --format json
```

## Operating Modes

### 1. Standalone Mode

Standalone mode runs all checks from the local machine.

Inputs:

- Target IP, hostname, CIDR, or imported Nmap XML.
- Optional port list.
- Optional probe profile.
- Optional timeout, concurrency, retries, and output path.

Outputs:

- Terminal summary.
- Detailed evidence log.
- Optional structured report file.

### 2. Link Mode

Link mode coordinates multiple trusted Net-Link peers. Each instance should be capable of performing tests, advertising its local view, and accepting authorized test requests from paired peers.

The user experience can still present a temporary controller role for the machine the operator is actively using:

- `controller`: operator-facing instance that coordinates tests.
- `peer`: any trusted Net-Link instance that can run local checks and return results.

This gives the implementation a clear command flow without permanently limiting the system to a strict controller/worker model.

### 3. Passive Import Mode

Passive import mode parses previous outputs and generates reports without performing new network actions.

Example:

```bash
net-link import --nmap scan.xml --out baseline.nljson
net-link report baseline.nljson
```

## Connectivity Checks

The tool should separate probe types from target definitions. A target is an address plus optional service metadata. A probe is a method used to test reachability.

Initial probe types:

- ICMP echo request where permitted.
- TCP connect.
- TCP SYN where raw sockets are available and privileges permit.
- TLS handshake.
- HTTP and HTTPS request.
- DNS query.
- SMB connection check.
- SSH banner check.
- RDP connection check.
- Custom raw TCP payload with optional expected response.
- UDP send and response detection for selected protocols, available but disabled by default.

Each probe should record:

- Source node.
- Destination address.
- Destination port and protocol.
- Probe type.
- Start time and duration.
- Result state.
- Error category.
- Evidence, such as banner, TLS metadata, HTTP status, or response bytes.

Suggested result states:

- `reachable`
- `unreachable`
- `filtered`
- `refused`
- `timed_out`
- `dns_failed`
- `unsupported`
- `permission_denied`
- `error`

Default probe profile:

- ICMP echo where supported.
- TCP connect.
- TLS handshake for likely TLS services.
- HTTP or HTTPS request for likely web services.
- DNS query for DNS services.
- SSH, SMB, and RDP lightweight connection/banner checks when those ports are in scope.

UDP should be opt-in because UDP results are often ambiguous and can produce misleading assessment evidence without protocol-specific handling.

## Scanning Strategy

Prototype builds can use Nmap directly for host and port discovery, then feed the discovered endpoints into Net-Link's validation engine.

Supported scanner modes:

- `--scanner nmap`: execute Nmap locally and parse XML output.
- `--nmap <file>`: parse an existing Nmap XML file.
- `--scanner builtin`: use Net-Link's in-house scanner once implemented.

The built-in scanner should focus on deployability and segmentation validation rather than replacing Nmap outright.

Initial built-in scanner features:

- TCP connect scan.
- Configurable port list.
- Conservative CIDR expansion.
- Private-address guardrails.
- Rate limiting and concurrency control.
- Basic service inference from port number and probe response.

Later built-in scanner features:

- SYN scan when raw sockets and privileges are available.
- UDP protocol checks for selected services.
- Service fingerprinting sufficient to select validation probes.
- Resume and checkpoint support for larger internal ranges.

Nmap remains useful for advanced discovery and service detection, but Net-Link should not require it for common assessment workflows once the built-in scanner exists.

## Nmap XML Support

The Nmap parser should extract:

- Host address.
- Hostname if present.
- Port number.
- Transport protocol.
- Port state.
- Service name.
- Product/version metadata where present.

Default behavior should test only open ports. Optional flags can include filtered, closed, or all discovered ports.

Example:

```bash
net-link test --nmap internal.xml --states open
net-link test --nmap internal.xml --states open,filtered
```

Nmap import should preserve source metadata:

- Nmap command line if present.
- Scan start and end timestamps.
- Imported file hash.
- Parser warnings.

## Link Mode Discovery

Discovery must be careful and scoped to internal networks only. By default, Net-Link should avoid public IP ranges and require explicit confirmation or configuration before probing anything outside private, loopback, link-local, or operator-approved ranges.

Discovery should be automatic when link mode starts, with an explicit `discover` command available for manual refreshes and debugging.

Discovery methods:

- mDNS service advertisement on local broadcast domains.
- UDP broadcast on configured internal interfaces.
- Optional explicit seed list.
- Optional QR/token pairing for devices without easy keyboard access.

Initial automatic discovery should prefer:

1. Explicit peer address.
2. mDNS on local subnets.
3. UDP broadcast on RFC1918 and ULA IPv6 interfaces.
4. Configured CIDR scan with conservative rate limits.

Discovery record fields:

- Node ID.
- Node name.
- Advertised addresses.
- Version.
- Capabilities.
- Pairing status.
- Last seen time.

## Link Mode Trust And Pairing

Linked instances should never accept arbitrary remote commands simply because they are discoverable.

Recommended first implementation:

- Each node generates a persistent Ed25519 identity on first run.
- Pairing requires an explicit shared token or confirmation code.
- Paired nodes remember trusted peer identities between runs.
- A shared pairing key or invite token can bootstrap trust, but long-term trust should bind to each peer's persistent identity key.
- Session transport uses mutually authenticated TLS or Noise protocol.
- Any paired peer can request tests from another peer, subject to the receiving peer's local policy.
- Peers maintain their own local allowlist and denylist.
- The active operator node can behave as the run coordinator for a specific test without gaining special permanent authority.

Pairing example:

```bash
# Peer
net-link link listen --pair
# Shows: Pairing code: river-4f2c-91ad

# Controller
net-link link pair 10.20.0.15 --code river-4f2c-91ad
```

Peer policy example:

```yaml
peer:
  name: pi-vlan20
  allowed_targets:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - fd00::/8
  denied_targets:
    - 10.20.99.0/24
  max_concurrency: 64
  max_rate_per_second: 100
  allow_raw_sockets: false
```

## Hopping Subnets

The phrase "hop subnets" needs a careful product definition. For Net-Link, the primary behavior should be coordinated multi-vantage testing and segmentation validation, not exploit-style VLAN hopping or unauthorized traffic forwarding.

Supported behavior:

- Discover Net-Link nodes reachable from the current node.
- Ask each paired node what networks and routes it can see locally.
- Run tests from each paired node to approved targets.
- Build a reachability graph showing which vantage points can reach which services.
- Detect cases where node A cannot reach node C directly but can communicate with node B, and node B can test C.
- Highlight unexpected cross-VLAN or cross-subnet reachability.
- Validate whether segmentation boundaries behave differently by protocol.

VLAN validation behavior:

- Inspect local interfaces and VLAN-tagged subinterfaces where the OS exposes them.
- Report observed VLAN-related interface metadata.
- Test approved targets from each reachable network position.
- Detect accidental bridging, permissive firewall paths, routing leaks, or misconfigured inter-VLAN ACLs.

Avoid in the initial design:

- SOCKS proxying through peers.
- Packet forwarding.
- Tunneling arbitrary traffic.
- Transparent pivoting.
- Exploit-driven VLAN hopping techniques.

Possible future feature, if needed and explicitly authorized:

- Controlled relay tests where a coordinator asks a peer to perform a specific single connection and return only metadata, not arbitrary traffic streams.

## CLI Experience

The CLI should use an interactive terminal UI by default for live work, with plain non-interactive output available for scripting and CI-style use.

Recommended commands:

```bash
net-link test <target>
net-link test --nmap <file>
net-link scan <target-or-cidr>
net-link discover
net-link link listen
net-link link pair <peer>
net-link link peers
net-link matrix
net-link report <result-file>
net-link config init
net-link config show
```

Suggested global flags:

```bash
--profile <name>
--ports <list>
--timeout <duration>
--retries <n>
--concurrency <n>
--rate <n/sec>
--interface <name>
--scope <cidr>
--out <path>
--format table|json|yaml|markdown|html
--interactive
--no-interactive
--allow-public
--verbose
--quiet
```

CLI output should include:

- Live panes, progress bars, or spinners.
- Grouped result sections by host, service, and source node.
- Color-coded states where supported.
- Compact summary tables.
- Detailed mode for evidence.
- Final "what changed" comparison when a baseline is supplied.

The interactive UI should optimize for fast human inspection:

- Current run status.
- Discovered peers.
- Active source nodes.
- In-flight probes.
- Reachability matrix.
- Notable findings.
- Error and warning panel.

The same run should still produce structured result files suitable for Markdown or HTML reporting.

Example summary:

```text
Net-Link run nl-20260616-191455

Sources
  local-laptop     192.168.1.42
  pi-vlan20        10.20.0.15

Results
  10.20.30.40:22/tcp     reachable from pi-vlan20, filtered from local-laptop
  10.20.30.40:443/tcp    reachable from both
  10.20.30.40:445/tcp    refused from pi-vlan20, timed out from local-laptop

Summary
  Tested endpoints: 3
  Reachable: 3
  Filtered/timeouts: 2
  Refused: 1
  Duration: 8.4s
```

## Data Model

### Node

```json
{
  "id": "node_01J...",
  "name": "pi-vlan20",
  "version": "0.1.0",
  "addresses": ["10.20.0.15"],
  "capabilities": ["tcp_connect", "icmp", "http", "tls"],
  "policy_hash": "sha256:..."
}
```

### Target

```json
{
  "id": "target_01J...",
  "host": "10.20.30.40",
  "port": 443,
  "protocol": "tcp",
  "service": "https",
  "source": {
    "type": "nmap",
    "file": "scan.xml"
  }
}
```

### Probe Result

```json
{
  "id": "probe_01J...",
  "run_id": "run_01J...",
  "source_node_id": "node_local",
  "target_id": "target_01J...",
  "probe": "tls_handshake",
  "state": "reachable",
  "started_at": "2026-06-16T18:14:55Z",
  "duration_ms": 142,
  "evidence": {
    "tls_version": "TLSv1.3",
    "certificate_subject": "CN=internal.example"
  }
}
```

## Configuration

Default config path:

- Linux: `~/.config/net-link/config.yaml`
- macOS: `~/Library/Application Support/net-link/config.yaml`
- Windows: `%APPDATA%\net-link\config.yaml`

Project-local config can be supported with `net-link.yaml`.

Example:

```yaml
defaults:
  timeout: 2s
  retries: 1
  concurrency: 128
  rate_per_second: 200

scope:
  allow_private_only: true
  allow_public: false
  allowed_targets:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - fd00::/8
  denied_targets: []

profiles:
  common:
    probes:
      - icmp_echo
      - tcp_connect
      - tls_handshake
      - http_request
  quiet:
    probes:
      - tcp_connect
    concurrency: 16
    rate_per_second: 20
```

## Build Targets And Device Profiles

Net-Link should have a generic build for normal laptops, desktops, and servers, plus specific device profiles for assessment appliances.

Recommended release artifacts:

- `net-link-linux-amd64`: generic Linux desktop/server build.
- `net-link-linux-arm64`: modern Raspberry Pi and ARM64 Linux devices.
- `net-link-linux-armv7`: older Raspberry Pi 32-bit installs.
- `net-link-linux-mipsle-softfloat`: WiFi Pineapple Pager build.
- `net-link-darwin-arm64`: Apple Silicon operator laptops.
- `net-link-darwin-amd64`: Intel macOS operator laptops.
- `net-link-windows-amd64.exe`: Windows operator laptops.

The core behavior should stay the same across builds:

- Target parsing.
- Probe execution.
- Nmap XML import.
- Built-in scanning.
- Result storage.
- Markdown/JSON reporting.
- Peer protocol.

Device-specific behavior should live behind capability detection and build tags where needed.

### Generic Build

The generic build is the default operator experience.

Expected behavior:

- Full interactive terminal UI.
- All unprivileged probes.
- Nmap execution when `nmap` is installed.
- Markdown, JSON, and eventually HTML reporting.
- Peer coordination and discovery.

### WiFi Pineapple Pager Build

The Pager build targets constrained MIPS hardware:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o net-link-linux-mipsle-softfloat ./cmd/net-link
```

Pager profile expectations:

- Prefer compact/plain output by default.
- Support peer mode and local probes.
- Avoid heavy terminal UI features unless explicitly enabled.
- Avoid runtime dependencies.
- Keep memory usage conservative.
- Treat Nmap as optional because it may not be installed.

### Raspberry Pi Build

The Raspberry Pi build can support richer appliance behavior, especially when attached to an e-ink display.

Raspberry Pi profile expectations:

- Run as a normal CLI peer.
- Optionally run as a long-lived field node.
- Support a lightweight local status display for e-ink hardware.
- Show pairing state, node name, IP addresses, current run status, and last result summary on the e-ink display.
- Avoid requiring the display for normal operation.

Potential Pi artifacts:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o net-link-linux-arm64 ./cmd/net-link
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o net-link-linux-armv7 ./cmd/net-link
```

The e-ink integration should be optional and isolated from the core scanner/link logic. A Pi without a display should behave like a normal Linux peer.

## Architecture

Suggested modules:

- `cli`: command parsing, terminal rendering, output formatting.
- `config`: config loading, validation, and policy resolution.
- `targets`: target parsing, CIDR expansion, Nmap XML import.
- `scanner`: Nmap execution wrapper and eventual built-in scanner.
- `probes`: probe implementations and common result schema.
- `runner`: scheduling, concurrency, retries, timeouts, rate limiting.
- `link`: discovery, pairing, peer sessions, peer RPC.
- `policy`: local authorization checks for target scopes and probe types.
- `store`: result persistence and import/export.
- `report`: Markdown, HTML, JSON, and comparison reports.
- `device`: optional device integrations such as Pager profile defaults and Raspberry Pi e-ink status output.

Core flow:

1. Resolve config and policy.
2. Parse targets from CLI, Nmap XML, or linked peers.
3. Select probes from profile and service metadata.
4. Schedule local or remote probe jobs.
5. Normalize results.
6. Render live terminal output.
7. Persist the run.
8. Optionally generate reports.

## Protocol Sketch

The link protocol can begin as a small peer RPC API over authenticated TLS.

Initial RPC methods:

- `hello`: exchange version, node ID, capabilities, and policy summary.
- `pair_begin`: start pairing.
- `pair_confirm`: complete pairing.
- `list_interfaces`: return local interface and route summary.
- `list_capabilities`: return supported probe types.
- `list_observed_networks`: return locally observed networks, routes, and interface metadata.
- `run_probes`: request a bounded set of probe jobs.
- `stream_results`: stream probe results back to controller.
- `cancel_run`: stop an active run.
- `health`: check peer availability.

All remote requests should include:

- Request ID.
- Controller node ID.
- Run ID.
- Target list.
- Probe list.
- Timeout and rate limits.
- Reason or label for audit logs.

Peers should validate every request against local policy before execution.

## Safety And Authorization

Net-Link should make safe defaults easy:

- Refuse public targets by default.
- Require explicit `--allow-public` for public IP space.
- Require explicit pairing before remote control.
- Remember paired peer identities between runs.
- Log all remote test requests on both the coordinating node and the peer executing the test.
- Enforce local peer policy even for trusted peers.
- Rate-limit discovery and probing.
- Display a scope summary before broad tests.
- Provide a dry-run mode.

Broad scan example:

```bash
net-link matrix --targets 10.0.0.0/8 --dry-run
```

Dry-run output should show:

- Target count estimate.
- Probe count estimate.
- Source nodes.
- Rate limits.
- Excluded ranges.
- Expected maximum duration.

## Reporting

Reports should answer practical questions:

- Which hosts and services are reachable?
- From which source nodes?
- Which expected boundaries held?
- Which unexpected paths exist?
- What changed since the last run?
- What evidence supports each conclusion?

Report views:

- Source-to-target matrix.
- Target detail page.
- Source node detail page.
- Service summary.
- Change summary.
- Raw evidence appendix.
- Optional network map for HTML reports once link mode can build a useful graph.

Initial report priority:

1. Markdown for assessment notes and easy sharing.
2. JSON for machine-readable evidence and future imports.
3. HTML once network mapping and richer visual summaries exist.

## MVP

### Phase 1: Standalone Probing

- CLI skeleton.
- Config loading.
- Target parser for single IP, hostname, port list, and CIDR.
- TCP connect probe.
- ICMP probe where permitted.
- TLS, HTTP, DNS, SSH, SMB, and RDP lightweight checks where applicable.
- Interactive terminal output.
- JSON result output.
- Public target blocking with explicit `--allow-public` override.

### Phase 2: Nmap-Assisted Scanning

- Nmap execution wrapper for prototype scans.
- Nmap XML parser.
- Open-port extraction.
- Service-aware probe selection.
- Import warnings.
- Markdown report.

### Phase 3: Built-In Scanner

- TCP connect scanner.
- Configurable port lists.
- CIDR target expansion.
- Rate limiting and concurrency control.
- Scanner result normalization into the same data model as Nmap imports.

### Phase 4: Link Mode Alpha

- Peer listener.
- Automatic local discovery.
- Explicit peer pairing token.
- Remembered trusted peers.
- Authenticated RPC.
- Remote TCP connect probes.
- Source-to-target matrix output.

### Phase 5: Discovery And Multi-Node Runs

- mDNS discovery.
- UDP broadcast discovery.
- Multiple linked peers.
- Capability and policy summaries.
- VLAN/subnet reachability graph.
- HTML report.

## Open Questions

- Should constrained devices use the same interactive UI, or default to compact/plain output?
- Should release builds include a dedicated Pager artifact name such as `net-link-linux-mipsle-softfloat`?
- How much peer-side policy should be exposed in v1 versus handled through safe defaults?
- Is raw socket support important enough for early built-in scanning, or should privileged scanning stay in Nmap until later?
- Do we need a web UI later, or is a rich terminal UI plus reports enough?
- Which HTML network map style is most useful: peer graph, subnet graph, or source-to-target matrix?

## Recommended Implementation Direction

The preferred implementation language is Go.

The WiFi Pineapple Pager target has been confirmed over SSH as:

```text
Linux kernel: 6.6.86
Machine: Hak5 WiFi Pineapple Pager
SoC: MediaTek MT7628AN
CPU: MIPS 24KEc, MIPS32r2
libc: musl 1.2.5
ABI hint: mipsel-sf
```

This makes Go the strongest fit for the real tool because Net-Link should be easy to deploy as a single binary across Linux desktops, Raspberry Pi-class devices, and MIPS-based assessment devices.

Recommended Pager build target:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -o net-link-pager ./cmd/net-link
```

Python is still the fastest path for early experimentation, especially if the first prototypes execute Nmap directly and focus on parsing, probe orchestration, and interactive UI behavior.

Python benefits:

- Faster to write if the maintainer is already comfortable with it.
- Excellent XML parsing and scripting ergonomics.
- Strong libraries for CLI work, including `typer`, `rich`, `textual`, and `asyncio`.
- Easy to experiment with probe behavior before freezing architecture.

Python drawbacks:

- Single-binary distribution is possible but less clean than Go.
- Cross-platform packaging can be fiddly.
- Running reliably on small devices may require managing Python versions and virtual environments.
- High-concurrency networking is possible with `asyncio`, but operational simplicity depends on careful implementation.

Go benefits:

- Easy static binaries for Raspberry Pi and laptops.
- Good networking standard library.
- Good concurrency model for many probes.
- Straightforward cross-compilation.
- Mature CLI and terminal UI libraries.
- Better fit for the preferred "single binary" deployment model.
- Better fit for constrained MIPS/OpenWrt-style targets where Python dependency packaging would be painful.

Go drawbacks:

- Slower early development if the maintainer is less familiar with it.
- More upfront type and project structure decisions.
- Interactive terminal UIs are good, but Python's Rich/Textual ecosystem may feel quicker for prototyping.

Rust is also a good fit if memory safety and long-term rigor are the priority, but it will likely slow early iteration.

Recommended path:

1. Start in Go to avoid a rewrite and to prove cross-device deployment early.
2. Keep the first build small: CLI, scanner wrapper, built-in TCP checks, Markdown/JSON output.
3. Use a simpler non-interactive output mode on constrained devices if the full TUI is too heavy.
4. Keep the data model and protocol schema clean enough that Python helper scripts can still be used during development.

Suggested Go libraries:

- CLI: `spf13/cobra`
- Config: `spf13/viper` or a small typed YAML loader
- Terminal UI: `charmbracelet/bubbletea`, `bubbles`, `lipgloss`
- mDNS: `grandcat/zeroconf`
- IDs: ULID library
- Serialization: standard JSON plus YAML support

Suggested Python libraries:

- CLI: `typer`
- Terminal UI: `rich` initially, `textual` if a full TUI is needed
- Async networking: `asyncio`
- Config: `pydantic` plus YAML support
- Reports: `jinja2` for HTML and Markdown templates
- Packaging: `pyinstaller` or `shiv` for early binaries

## First Build Slice

The first useful version should be:

```bash
net-link test 10.20.30.40 --ports 22,80,443 --out run.nljson
net-link scan 10.20.30.0/24 --scanner nmap --out run.nljson
net-link test --nmap scan.xml --out run.nljson
net-link report run.nljson --format markdown
```

That slice validates the core data model, result format, probe runner, CLI tone, and report shape before the more complex linked protocol is introduced.
