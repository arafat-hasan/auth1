VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build test lint vuln generate migrate

build:
	go build -ldflags "$(LDFLAGS)" -o bin/auth1 ./cmd/auth1

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

vuln:
	govulncheck ./...

generate:
	go generate ./...

# The migrate command arrives with WP-05; until then this target fails.
migrate:
	go run ./cmd/auth1 migrate $(ARGS)
