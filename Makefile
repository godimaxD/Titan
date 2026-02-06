.PHONY: fmt test build run

fmt:
	gofmt -w ./...

test:
	go test -v -timeout 10m ./... -count=1

build:
	go build ./...

run:
	go run .
