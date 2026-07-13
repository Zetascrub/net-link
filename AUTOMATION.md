# Build and Release Automation

Net-Link uses the same Make targets locally and in GitHub Actions. Builds embed
the version, commit, and commit timestamp into peer and run metadata.

## Local verification

```bash
make check       # formatting, vet, unit tests, race detector
make coverage    # coverage/coverage.out plus a function summary
make staticcheck # requires staticcheck on PATH
make vulncheck   # requires govulncheck on PATH
make workflow-lint # requires actionlint on PATH
```

## Artifacts

```bash
make build       # local development binary
make build-all   # all supported Linux targets
make dist        # clean cross-build plus dist/SHA256SUMS
```

Build metadata can be overridden explicitly:

```bash
make dist VERSION=v0.2.1 COMMIT=$(git rev-parse HEAD)
```

`BUILD_DATE` defaults to the commit timestamp rather than the current clock,
which avoids changing otherwise identical artifacts simply because they were
built at different times.

## Continuous integration

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`. It performs
formatting, vet, coverage, race, Staticcheck, vulnerability analysis, cross-builds,
checksum verification, and artifact upload. Concurrent runs for an outdated commit
on the same branch are cancelled automatically.

Dependabot checks GitHub Actions versions weekly.

## Releases

Pushing a version tag triggers the release workflow:

```bash
git tag -a v0.2.1 -m "Net-Link v0.2.1"
git push origin v0.2.1
```

The workflow reruns all required checks, builds artifacts with the tag as the
embedded version, verifies their checksums, and publishes a GitHub release with
generated notes. Manual workflow runs upload development artifacts but never
publish a release.
