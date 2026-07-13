# Net-Link Improvement Plan

This document tracks the work needed to move Net-Link from an early prototype
toward a safe, dependable assessment tool. Checkboxes describe implementation
status; completing a checkbox should include relevant tests and documentation.

## Phase 0: Make current risk explicit

- [x] Mark link mode as experimental in CLI help and user documentation.
- [x] Print a prominent warning when `link listen` starts.
- [x] Disable remote service-check requests by default and require explicit
  `--allow-remote-checks` opt-in on listeners and matrix responders.
- [x] Add `--bind-address` so the persistent link listener does not have to bind
  to every IPv4 interface.
- [x] Add and execute an automated protocol-handler test for the safe default.
- [ ] Add an integration test for the explicit opt-in path once authenticated
  transport and bounded request handling are designed.

Phase 0 is a containment measure, not a security boundary. Opted-in link traffic
remains unauthenticated and must only be used on networks the operator controls.

### Phase 0 verification

Verified with Go 1.26.5 on Linux/amd64:

- `go test ./... -cover`
- `go vet ./...`
- `go test -race ./...`
- `make build`
- `make build-linux-amd64`

The safe-default link tests pass. Overall coverage is still intentionally tracked
as Phase 3 work; several packages currently report no test coverage.

## Phase 1: Close security and safety gaps

- [x] Apply a local CIDR and port allowlist to every remote service-check request.
- [x] Reject public, unspecified, multicast, and otherwise disallowed remote targets.
- [x] Cap targets per request, message size, concurrent clients, and duration.
- [x] Resolve standalone hostnames and validate every resolved address before
  creating connection targets.
- [ ] Add persistent Ed25519 node identities and explicit pairing. Persistent
  identities are complete; pairing remains outstanding.
- [ ] Add mutually authenticated transport and peer authorization.
- [ ] Record authenticated peer identity and authorization decisions in evidence.
  Local authorization denials are returned and logged; authenticated identity is
  blocked on pairing and authenticated transport.
- [x] Replace unbounded line reads and per-target goroutines with bounded decoding
  and a fixed worker pool.
- [ ] Validate all CLI ports, timeouts, concurrency values, and operational limits.
  Ports, timeouts, and concurrency are complete; total run limits remain.

## Phase 2: Improve correctness and evidence integrity

- [x] Use a signal-aware root context for every active command.
- [ ] Stop dispatching work when a run is cancelled and distinguish cancellation
  from a network timeout. Both dispatch cancellation and result classification
  are complete; explicit run-level cancellation metadata remains.
- [x] Write evidence atomically with restrictive permissions (`0600`).
- [ ] Introduce an evidence schema version and build metadata.
- [ ] Validate required fields, states, ports, IDs, and relationships when reading
  saved evidence.
- [ ] Preserve Nmap command, timestamps, source hash, hostnames, and warnings.
- [ ] Escape generated Markdown and safely include useful error/evidence details.

## Phase 3: Establish a meaningful test and CI baseline

- [ ] Add policy tests for DNS, IPv4, IPv6, mixed answers, and public targets.
- [ ] Add hostile-input and authorization tests for link handlers.
- [ ] Add runner cancellation, concurrency, and summary tests with fake probes.
  Cancellation coverage is complete.
- [ ] Add store permission, atomicity, schema, and round-trip tests. Permission and
  atomic replacement coverage is complete.
- [ ] Add CLI parsing, validation, help, output, and exit-code tests.
- [ ] Add Markdown golden tests and broader Nmap XML fixtures.
- [x] Run formatting, vet, unit tests, race tests, `staticcheck`, and
  `govulncheck` in CI.

## Phase 4: Product completeness

- [x] Add bounded automatic private-interface discovery with optional private
  route discovery and interface filters.
- [ ] Keep README examples and the design roadmap aligned with implemented code.
- [ ] Add built-in TCP scanning after policy, limits, cancellation, and evidence
  integrity are established.
- [ ] Add protocol-aware probes incrementally.
- [ ] Add safe, tested HTML reporting.
- [ ] Produce tagged cross-platform releases with checksums, SBOMs, and injected
  version metadata. Tag releases, checksums, and metadata injection are complete;
  SBOM generation and artifact signing remain.

## Proposed milestones

- **0.1.1-dev (implemented):** Phase 0, signal handling, initial strict limits,
  cancellation-aware dispatch, and secure evidence files. Verified on Linux with
  unit tests, race detection, vet, and all documented cross-build targets.
- **0.2.0-dev (in progress):** Persistent identities, authorization, fixed worker
  pools, target-policy enforcement, and network/request limits are implemented.
  Pairing and authenticated encrypted transport remain release blockers.
- **0.3.0:** Evidence schema/versioning, richer imports and reports, comprehensive CI.
- **0.4.0:** Built-in scanning and additional protocol-aware probes.
