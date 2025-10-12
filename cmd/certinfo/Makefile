all:
	go run main.go example.txt

check: 
	gofmt -w -s .
	CGO_ENABLED=0 go vet .
	CGO_ENABLED=0 staticcheck

examples:
	go run main.go example.txt
