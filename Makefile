PROJECT=$(shell basename $(CURDIR))

all:
	make -C cmd/$(PROJECT) all

clean:
	make -C cmd/$(PROJECT) clean

examples:
	make -C cmd/$(PROJECT) examples

deps: 
	rm go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v	

check: 
	echo "expect some legacy crypto DSA support complains, need for analysis of bad certs/actors"
	gofmt -w -s .
	staticcheck
	make -C cmd/$(PROJECT) check
