.PHONY: build test vet notices check-notices docs-check

build:
	CGO_ENABLED=0 go build -o bin/doorwarden ./cmd/doorwarden

test:
	go test ./... -race

vet:
	go vet ./...

notices:
	go run ./scripts/notices

check-notices:
	go run ./scripts/notices -check

docs-check:
	./scripts/check-docs.sh
