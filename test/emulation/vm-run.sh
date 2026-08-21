#!/usr/bin/env bash
#
# Copyright 2026 Deutsche Telekom AG.
# Licensed under the Apache License, Version 2.0.
#
# vm-run.sh — run the tc-flower e2e / emulation suite inside a real VM kernel
# via KVM, so netdevsim (a kernel module), switchdev representors, and the
# software-datapath flower enforcement run against a full, real kernel instead
# of a shared container kernel.
#
# This is the "closest to reality without a ConnectX card" tier: a VM lets us
#   (a) modprobe netdevsim and exercise switchdev eswitch + VF representors, and
#   (b) later boot a *patched* kernel (netdevsim tc.c that actually enforces
#       offloaded flower rules — "Layer D") to close the offloaded-drop gap.
#
# It uses virtme-ng (https://github.com/arighi/virtme-ng), the standard tool for
# booting a kernel in a throwaway VM that reuses the host root filesystem, so the
# Go toolchain and repo checkout are available inside with no image building.
#
# Requirements: /dev/kvm (nested virtualization), virtme-ng (`vng`) + qemu, and
# a kernel to boot (the host kernel by default; set VNG_KERNEL to a built kernel
# tree / bzImage for Layer D). Exits 0 (skip) when KVM or vng are unavailable,
# so it is safe to run where nested virtualization is not offered.
#
# Usage:  bash test/emulation/vm-run.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

skip() { echo "SKIP: $*"; exit 0; }

if [[ ! -e /dev/kvm ]]; then
  skip "no /dev/kvm (KVM/nested virtualization unavailable); cannot boot a VM"
fi
if ! command -v vng >/dev/null 2>&1; then
  skip "virtme-ng (vng) not installed; install with 'pip install virtme-ng' on a KVM runner"
fi

# The in-VM steps live in a sibling script so there is no fragile shell quoting
# across the host->guest boundary; vng runs it with the repo path in the env.
GUEST_SCRIPT="${HERE}/vm-guest.sh"
if [[ ! -x "${GUEST_SCRIPT}" ]]; then
  skip "guest script ${GUEST_SCRIPT} missing/not executable"
fi

# Pre-compile the tcflower test binary ON THE HOST (which has network) so the
# network-less VM never needs to fetch the Go toolchain or modules. The guest
# executes this binary instead of running `go test`.
TESTBIN="${REPO_ROOT}/tcflower.test"
if command -v go >/dev/null 2>&1; then
  echo "== pre-building tcflower test binary on host =="
  if ( cd "${REPO_ROOT}" && go test -c -o "${TESTBIN}" ./pkg/tcflower/ ); then
    export TCFLOWER_TESTBIN="${TESTBIN}"
  else
    echo "WARN: could not pre-build test binary; guest will fall back to offline go test"
  fi
else
  echo "WARN: no go toolchain on host to pre-build the test binary"
fi

KERNEL_ARG=()
if [[ -n "${VNG_KERNEL:-}" ]]; then
  KERNEL_ARG=(--kimg "${VNG_KERNEL}")
  echo "== booting custom kernel: ${VNG_KERNEL} =="
else
  echo "== booting host kernel in a VM =="
  # virtme-ng reuses the host kernel image + modules; on some CI runners these
  # are root-only. Best-effort make them readable so vng (even non-root) can
  # boot them. Ignored if we lack sudo or the files are already readable.
  krel="$(uname -r)"
  if [[ ! -r "/boot/vmlinuz-${krel}" ]]; then
    sudo chmod -R +rX "/boot" "/lib/modules/${krel}" 2>/dev/null \
      || skip "host kernel /boot/vmlinuz-${krel} not readable and cannot chmod; boot a kernel via VNG_KERNEL or run as root"
  fi
fi

# --user root: run privileged in the guest (modprobe, tc, netns all need it).
# The host rootfs (incl. the repo checkout and the Go toolchain) is shared, so
# the guest script resolves REPO_ROOT from its own path; we also pass it as a
# positional arg as a fallback. We deliberately avoid `vng --env`, which older
# virtme-ng releases do not support.
exec vng --run "${KERNEL_ARG[@]}" --user root --cpus 2 --memory 2G -- \
  bash "${GUEST_SCRIPT}" "${REPO_ROOT}"
