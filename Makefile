PROJECT=$(shell basename $(CURDIR))

all:
	make -C cmd/$(PROJECT) all

deps: 
	rm go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v	

check: 
	gofmt -w -s .
	# expect some legacy crypto DSA support complains, need for analysis of bad and old legacy certs
	# staticcheck
	# golangci-lint run
	make -C cmd/$(PROJECT) check
