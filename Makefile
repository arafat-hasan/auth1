VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: build test lint vuln generate spec-lint spec-diff migrate

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

# Lints the contracts: vacuum for OpenAPI, the AsyncAPI CLI for AsyncAPI.
spec-lint:
	go -C tools tool vacuum lint -b -d -r ../api/vacuum.yaml ../api/openapi.yaml
	npx --yes @asyncapi/cli@6.2.2 config analytics --disable >/dev/null
	SUPPRESS_NO_CONFIG_WARNING=1 npx --yes @asyncapi/cli@6.2.2 validate api/asyncapi.yaml

# Breaking changes in the OpenAPI contract against the last v* tag.
spec-diff:
	./scripts/oasdiff.sh

# make migrate ARGS="status --config config.yaml --dsn-file <migrator dsn>"
migrate:
	go run ./cmd/auth1 migrate $(ARGS)
