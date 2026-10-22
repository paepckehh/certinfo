PROJECT=$(shell basename $(CURDIR))
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')

all:
	make -C cmd/$(PROJECT) all

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(PROJECT) ./cmd/$(PROJECT)

deps: 
	rm go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v	

check: 
	gofmt -w -s .
	go vet ./...
	go fix ./...
	go test ./...
	# expect some legacy crypto DSA support complains, need for analysis of bad and old legacy certs
	# staticcheck
	# golangci-lint run
	make -C cmd/$(PROJECT) check
