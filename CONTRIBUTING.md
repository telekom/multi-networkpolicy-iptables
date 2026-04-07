# Contributing to multi-networkpolicy-nftables

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Getting Started

1. Fork the repository
2. Create a feature branch from `nftables` (the default branch)
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.24+ (see go.mod for exact version requirements)
- Linux with nftables support
- Docker
- [kind](https://kind.sigs.k8s.io/) (for e2e tests)

### Building

```bash
go build ./cmd/multi-networkpolicy-nftables/
```

### Running Tests

Unit tests require root privileges for nftables operations:

```bash
sudo modprobe nft_ct
sudo go test -v ./...
```

### Linting

```bash
golangci-lint run
```

### E2E Tests

```bash
cd e2e
./get_tools.sh
./setup_cluster.sh
./run_all_tests.sh
```

## Pull Request Guidelines

- Base your PR on the `nftables` branch
- Keep changes focused and atomic — one concern per PR
- Include tests for new functionality
- Ensure all existing tests pass
- Run `golangci-lint run` before submitting
- Update documentation if behavior changes

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `fmt.Errorf("context: %w", err)` for error wrapping
- Do not edit vendored code in `vendor/` directly — use `go mod vendor`
- Do not edit generated files under `config/`

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce for bugs
- Include Kubernetes and Go version information

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
