.PHONY: build build-linux-amd64 build-pager build-pi-arm64 build-pi-armv7 test vet

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -buildvcs=false -o bin/net-link ./cmd/net-link

build-linux-amd64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -o bin/net-link-linux-amd64 ./cmd/net-link

build-pager:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -buildvcs=false -o bin/net-link-linux-mipsle-softfloat ./cmd/net-link

build-pi-arm64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -o bin/net-link-linux-arm64 ./cmd/net-link

build-pi-armv7:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -buildvcs=false -o bin/net-link-linux-armv7 ./cmd/net-link
