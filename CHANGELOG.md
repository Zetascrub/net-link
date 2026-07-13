# Changelog

## 0.2.1-dev

- Add explicit `discover --auto` interface-based private scope discovery.
- Add opt-in private routing-table discovery with `--include-routes`.
- Add interface inclusion and exclusion filters with safe virtual-interface defaults.
- Deduplicate overlapping automatic targets and enforce `--max-total-hosts` in
  addition to the existing per-CIDR `--max-hosts` limit.
- Expand dry-run output to show how automatic scope was selected.
- Recognize `100.64.0.0/10` shared address space used by ChromeOS Crostini and
  similar NAT environments as internal scope.
- Add local and CI automation for formatting, coverage, race testing, vet,
  Staticcheck, vulnerability analysis, cross-builds, and checksum verification.
- Add tag-triggered GitHub releases and manual development-artifact workflows.
- Inject version, commit, and deterministic build date into binaries and evidence.
- Validate GitHub Actions workflows with a pinned Actionlint release in CI.

## 0.2.0-dev

- Resolve hostname targets before runs and validate every resolved address.
- Reject unspecified and multicast destinations even with public targeting enabled.
- Require explicit internal CIDR and port policy for remote service checks.
- Limit concurrent link clients and total service-request duration.
- Return and log local-policy denial reasons for remote requests.
- Generate persistent Ed25519 node identities and advertise public keys. Transport
  authentication and pairing are not yet implemented.
- Distinguish canceled probes from timed-out probes in evidence and reports.

## 0.1.1-dev

- Mark link mode experimental and disable remote service checks by default.
- Add explicit remote-check opt-in and configurable listener bind address.
- Use one signal-aware context across active CLI commands.
- Stop dispatching new runner work after cancellation.
- Bound link messages, service targets, and service-check workers.
- Validate CLI network ports, timeouts, and concurrency.
- Write evidence atomically with owner-only permissions.
- Add tests for safe link defaults, message limits, cancellation, bind validation,
  and secure evidence output.
