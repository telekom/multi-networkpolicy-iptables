# Multi-NetworkPolicy nftables - Makefile
BINARY_NAME ?= multi-networkpolicy-nftables
CMD_DIR ?= ./cmd/multi-networkpolicy-nftables/
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
GO_LDFLAGS ?= -s -w
IMAGE_REPO ?= ghcr.io/telekom/multi-networkpolicy-nftables
IMAGE_TAG ?= dev

.PHONY: all build test lint vet fmt fmt-fix clean e2e image help

all: build

## build: Build the binary
build:
	CGO_ENABLED=0 GOARCH=$(GOARCH) GOOS=$(GOOS) go build -ldflags "$(GO_LDFLAGS)" -o $(BINARY_NAME)_$(GOOS)_$(GOARCH) $(CMD_DIR)

## test: Run unit tests (requires root for nftables tests)
test:
	@if [ "$(GOOS)" != "linux" ]; then \
		echo "make test requires Linux for nftables tests"; \
		exit 1; \
	elif [ "$$(id -u)" -eq 0 ]; then \
		modprobe nft_ct 2>/dev/null || true; \
		uid=$$(id -u); gid=$$(id -g); \
		go test -v -coverprofile=profile.cov ./...; \
	elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then \
		sudo -n modprobe nft_ct 2>/dev/null || true; \
		uid=$$(id -u); gid=$$(id -g); \
		sudo go test -v -coverprofile=profile.cov ./...; \
		if [ -f profile.cov ]; then sudo chown "$$uid:$$gid" profile.cov; fi; \
	else \
		echo "make test requires root or passwordless sudo; refusing to prompt interactively"; \
		exit 1; \
	fi

## lint: Run golangci-lint
lint:
	golangci-lint run

## vet: Run go vet
vet:
	go vet ./...

## fmt: Check formatting
fmt:
	@diff=$$(gofmt -d -s ./cmd/ ./pkg/); \
	if [ -n "$$diff" ]; then \
		echo "$$diff"; \
		exit 1; \
	fi

## fmt-fix: Fix formatting
fmt-fix:
	gofmt -w -s ./cmd/ ./pkg/

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)_* profile.cov

## image: Build container image
image:
	docker build -t $(IMAGE_REPO):$(IMAGE_TAG) -f Dockerfile .

## e2e: Run e2e tests (requires kind cluster)
e2e:
	cd e2e && ./run_all_tests.sh

## help: Show this help
help:
	@echo "Available targets:"
	@awk '/^## / { line = substr($$0, 4); split(line, parts, ": "); printf "  %s\t%s\n", parts[1], parts[2] }' Makefile
