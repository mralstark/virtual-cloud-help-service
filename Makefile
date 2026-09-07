.PHONY: help init run check build integration

help:
	@printf '%s\n' 'make init        Initialize development keys (Linux/WSL)' 'make run         Start the local control plane' 'make check       Format, race tests, vet, module verification' 'make build       Build all command binaries into bin/' 'make integration Test a disposable PostgreSQL vchs_test database'

init:
	bash scripts/dev.sh init

run:
	bash scripts/dev.sh run

check:
	test -z "$$(gofmt -l cmd internal)"
	go test -race ./...
	go vet ./...
	go mod verify

build:
	mkdir -p bin
	go build -trimpath -o bin/ ./cmd/...

integration:
	bash scripts/test-database.sh
