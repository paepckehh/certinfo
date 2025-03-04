all:
	go run main.go example.txt

check: 
	gofmt -w -s .
	go vet .
	staticcheck
	golangci-lint run

examples:
	go run main.go example.txt
