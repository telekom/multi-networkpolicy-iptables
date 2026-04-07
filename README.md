# multi-networkpolicy-nftables

[![build](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/build.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/build.yml)
[![test](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/test.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/test.yml)
[![lint](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/golangci-lint.yml)
[![e2e](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/kind-e2e.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/kind-e2e.yml)
[![CodeQL](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/codeql.yml/badge.svg)](https://github.com/telekom/multi-networkpolicy-nftables/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/telekom/multi-networkpolicy-nftables)](https://goreportcard.com/report/github.com/telekom/multi-networkpolicy-nftables)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

[multi-networkpolicy](https://github.com/telekom/multi-networkpolicy) implementation with nftables

## Current Status of the Repository

It is now being actively developed and is not stable yet. Bug reports and feature requests are welcome.

## Description

Kubernetes provides [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) for network security. Currently net-attach-def does not support Network Policies because net-attach-def is a CRD (user-defined resource) outside of Kubernetes.
multi-networkpolicy implements Network Policy functionality for net-attach-def, by nftables and provides network security for net-attach-def networks.

## Architecture

multi-networkpolicy-nftables runs as a DaemonSet on each Kubernetes node. It watches for MultiNetworkPolicy custom resources and translates them into nftables rules applied directly in pod network namespaces.

### Components

- **Controllers** (`pkg/controllers/`): Watch Kubernetes resources (Pods, Namespaces, MultiNetworkPolicies, NetworkAttachmentDefinitions) using client-go informers.
- **Server** (`pkg/server/`): Core orchestration and sync loop that coordinates controllers and triggers rule generation.
- **Rule Generator** (`pkg/server/netfilterrules.go`): Translates MultiNetworkPolicy specs into nftables rule sets using the google/nftables library.

### How It Works

1. The daemon watches for changes to MultiNetworkPolicy resources and related objects (Pods, Namespaces, NetworkAttachmentDefinitions).
2. On each sync cycle, it determines which pods are affected by which policies.
3. For each affected pod, it enters the pod's network namespace and applies nftables rules that enforce the specified ingress/egress policies.
4. When policies are removed, the corresponding nftables rules are cleaned up automatically.

![Multi NetworkPolicy Overview](docs/images/multi-networkpolicy-overview.png)

## Quickstart

Install MultiNetworkPolicy CRD into Kubernetes.

```
$ git clone https://github.com/k8snetworkplumbingwg/multi-networkpolicy
$ cd multi-networkpolicy
$ kubectl create -f scheme.yml
customresourcedefinition.apiextensions.k8s.io/multi-networkpolicies.k8s.cni.cncf.io created
```

Deploy multi-networkpolicy-nftables into Kubernetes.

```
$ git clone https://github.com/telekom/multi-networkpolicy-nftables
$ cd multi-networkpolicy-nftables
$ kubectl create -f deploy.yml
clusterrole.rbac.authorization.k8s.io/multi-networkpolicy created
clusterrolebinding.rbac.authorization.k8s.io/multi-networkpolicy created
serviceaccount/multi-networkpolicy created
daemonset.apps/multi-networkpolicy-ds-amd64 created
```

## Requirements

This project leverages `nftables` hence the netfilter module needs to be loaded on the container host:

```
# modprobe nf_ct
# modprobe nf_tables
```

## Configurations

See [Configurations](docs/configurations.md).

## Development

### Prerequisites

- Go 1.24+ (see go.mod for exact version requirements)
- Linux with nftables support (for tests)
- Docker (for container image builds)
- [kind](https://kind.sigs.k8s.io/) (for e2e tests)
- [Bats](https://bats-core.readthedocs.io/) (for e2e tests; install via `brew install bats-core` or your package manager)

### Build

```bash
go build ./cmd/multi-networkpolicy-nftables/
```

### Test

Unit tests require root privileges for nftables operations:

```bash
sudo modprobe nft_ct
sudo go test -v ./...
```

### Lint

```bash
golangci-lint run
```

### E2E Tests

End-to-end tests use kind to create a cluster with Calico, Multus, and bond-cni:

```bash
cd e2e
./get_tools.sh
./setup_cluster.sh
./run_all_tests.sh
```

## Roadmap

- Improved e2e test coverage and reliability
- Enhanced CI/CD pipeline with caching and security scanning
- Performance benchmarks for rule generation

## Contact Us

For any questions about Multus CNI, feel free to ask a question in #general in the [NPWG Slack](https://npwg-team.slack.com/), or open up a GitHub issue. Request an invite to NPWG slack [here](https://intel-corp.herokuapp.com/).
