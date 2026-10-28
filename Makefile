.PHONY: build test vet

build:
	CGO_ENABLED=0 go build -o bin/proxypilot ./cmd/proxypilot

test:
	go test ./... -race

vet:
	go vet ./...
