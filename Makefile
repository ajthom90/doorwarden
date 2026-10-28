.PHONY: build test vet

build:
	CGO_ENABLED=0 go build -o bin/doorwarden ./cmd/doorwarden

test:
	go test ./... -race

vet:
	go vet ./...
