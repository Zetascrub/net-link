GO ?= go
VERSION ?= 0.2.1-dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/Zetascrub/net-link/internal/model.Version=$(VERSION) -X github.com/Zetascrub/net-link/internal/model.BuildCommit=$(COMMIT) -X github.com/Zetascrub/net-link/internal/model.BuildDate=$(BUILD_DATE)

.PHONY: build build-all build-linux-amd64 build-pager build-pi-arm64 build-pi-armv7 \
	test coverage race vet fmt fmt-check staticcheck vulncheck workflow-lint check clean dist checksums

test:
	$(GO) test ./...

coverage:
	mkdir -p coverage
	$(GO) test ./... -coverprofile=coverage/coverage.out
	$(GO) tool cover -func=coverage/coverage.out

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@files="$$(gofmt -l $$(git ls-files '*.go'))"; test -z "$$files" || { echo "Unformatted Go files:"; echo "$$files"; exit 1; }

staticcheck:
	staticcheck ./...

vulncheck:
	govulncheck ./...

workflow-lint:
	actionlint

check: fmt-check vet test race

build:
	mkdir -p bin
	$(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/net-link ./cmd/net-link

build-linux-amd64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/net-link-linux-amd64 ./cmd/net-link

build-pager:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/net-link-linux-mipsle-softfloat ./cmd/net-link

build-pi-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/net-link-linux-arm64 ./cmd/net-link

build-pi-armv7:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/net-link-linux-armv7 ./cmd/net-link

build-all: build-linux-amd64 build-pi-arm64 build-pi-armv7 build-pager

checksums:
	cd bin && sha256sum net-link-linux-* > SHA256SUMS

dist: clean build-all checksums
	mkdir -p dist
	cp bin/net-link-linux-* bin/SHA256SUMS dist/

clean:
	rm -rf bin coverage dist
