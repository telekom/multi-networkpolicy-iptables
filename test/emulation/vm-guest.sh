#!/usr/bin/env bash
#
# Copyright 2026 Deutsche Telekom AG.
# Licensed under the Apache License, Version 2.0.
#
# vm-guest.sh — the in-VM half of vm-run.sh. Runs as root inside a virtme-ng VM
# with a real kernel and the host rootfs (Go toolchain + repo checkout) shared
# in. Do not run this directly; use test/emulation/vm-run.sh.
set -uo pipefail

echo "== inside VM: kernel $(uname -r) =="

# Self-locate the repo root from this script's own path. The VM shares the host
# rootfs, so this file lives at the same path inside the guest — no need to pass
# REPO_ROOT across the host->guest boundary (virtme-ng versions differ on --env
# support). Falls back to $1 or an inherited REPO_ROOT if BASH_SOURCE is unset.
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
elif [[ -n "${1:-}" ]]; then
  REPO_ROOT="$1"
fi
: "${REPO_ROOT:?could not determine REPO_ROOT}"
export PATH="/usr/local/go/bin:/usr/lib/go/bin:${PATH}"
cd "${REPO_ROOT}" || { echo "cannot cd ${REPO_ROOT}"; exit 1; }

modprobe netdevsim 2>/dev/null || true
modprobe nft_ct 2>/dev/null || true

rc=0

echo "== emulation scripts (netdevsim discovery + veth flower enforcement) =="
bash test/emulation/run.sh || rc=1

echo "== Go real-kernel tests (netdevsim round-trip + software-enforcement e2e) =="
# The VM has no network, so we do NOT run `go test` here (it would try to fetch
# the toolchain/modules). vm-run.sh pre-compiles a test binary on the host
# (TCFLOWER_TESTBIN); we just execute it. If it's missing, fall back to `go test`
# only when a go cache is usable offline.
TESTBIN="${TCFLOWER_TESTBIN:-${REPO_ROOT}/tcflower.test}"
if [[ -x "${TESTBIN}" ]]; then
  # -test.run selects the real-kernel tests; they self-skip on missing features.
  "${TESTBIN}" -test.run 'Netdevsim|TCFlower|E2E' -test.v || rc=1
elif command -v go >/dev/null 2>&1; then
  GOFLAGS=-mod=vendor GOPROXY=off go test -count=1 -run 'Netdevsim|TCFlower|E2E' ./pkg/tcflower/... -v || rc=1
else
  echo "SKIP: no prebuilt test binary and no usable go toolchain"
fi

echo "== vm-guest exit: ${rc} =="
exit "${rc}"
