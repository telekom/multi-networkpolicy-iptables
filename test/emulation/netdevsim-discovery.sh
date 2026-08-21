#!/usr/bin/env bash
#
# Copyright 2026 Deutsche Telekom AG.
# Licensed under the Apache License, Version 2.0.
#
# Layer A — discovery emulation.
#
# Proves that netdevsim can present a switchdev topology (phys_switch_id +
# phys_port_name on the resulting netdevs) that pkg/tcflower.ResolveRepresentor
# can be pointed at. It is BEST-EFFORT: if the running kernel's netdevsim lacks
# switchdev/devlink support it prints a clear message and exits 0 (skip) rather
# than failing CI.
#
# It does NOT itself run the Go resolver; it materializes the sysfs topology and
# prints the phys_switch_id / phys_port_name so a human (or the Go integration
# test) can confirm the discovery inputs exist.

set -euo pipefail

# A high, unlikely-to-collide netdevsim instance id and a small port count.
readonly NSIM_ID="${NSIM_ID:-2025}"
readonly NSIM_PORTS="${NSIM_PORTS:-2}"
readonly NSIM_BUS=/sys/bus/netdevsim
readonly NSIM_DEV="netdevsim/netdevsim${NSIM_ID}"

skip() { echo "SKIP: $*"; exit 0; }

cleanup() {
  # Best-effort teardown; never let cleanup failures mask the real exit code.
  if [[ -w "${NSIM_BUS}/del_device" ]]; then
    echo "${NSIM_ID}" > "${NSIM_BUS}/del_device" 2>/dev/null || true
  fi
}

[[ "$(id -u)" -eq 0 ]] || skip "must run as root (netdevsim/devlink need CAP_NET_ADMIN)"

if ! modprobe netdevsim 2>/dev/null && [[ ! -d "${NSIM_BUS}" ]]; then
  skip "netdevsim module unavailable (modprobe netdevsim failed and ${NSIM_BUS} absent)"
fi
[[ -w "${NSIM_BUS}/new_device" ]] || skip "${NSIM_BUS}/new_device not writable"

trap cleanup EXIT

# In case a previous run left the instance behind.
cleanup

echo "== Creating netdevsim instance ${NSIM_ID} with ${NSIM_PORTS} port(s) =="
echo "${NSIM_ID} ${NSIM_PORTS}" > "${NSIM_BUS}/new_device"

# Give udev/netdev a moment to materialize the netdevs.
sleep 1

echo "== Attempting to switch eswitch to switchdev mode via devlink =="
if command -v devlink >/dev/null 2>&1; then
  # netdevsim's devlink support for eswitch mode varies by kernel; tolerate
  # failure and just log it (Layer A still demonstrates the sysfs topology).
  if devlink dev eswitch set "${NSIM_DEV}" mode switchdev 2>/tmp/nsim_devlink.err; then
    echo "  switchdev mode set on ${NSIM_DEV}"
  else
    echo "  NOTE: could not set switchdev mode on ${NSIM_DEV}: $(cat /tmp/nsim_devlink.err)"
    echo "        (this kernel's netdevsim may not expose eswitch mode; continuing best-effort)"
  fi
  echo "== devlink dev show =="
  devlink dev show "${NSIM_DEV}" 2>/dev/null || true
  echo "== devlink port show =="
  devlink port show 2>/dev/null | grep -i "netdevsim${NSIM_ID}" || echo "  (no devlink ports listed for this instance)"
else
  echo "  NOTE: devlink not found; skipping eswitch mode switch (sysfs topology still shown)."
fi

echo "== Resulting netdevs and their switchdev attributes =="
found_any=0
for dev in /sys/class/net/*; do
  name="$(basename "$dev")"
  psid_file="$dev/phys_switch_id"
  ppn_file="$dev/phys_port_name"
  psid=""; ppn=""
  [[ -r "$psid_file" ]] && psid="$(cat "$psid_file" 2>/dev/null || true)"
  [[ -r "$ppn_file" ]] && ppn="$(cat "$ppn_file" 2>/dev/null || true)"
  if [[ -n "$psid" || -n "$ppn" ]]; then
    found_any=1
    printf "  %-16s phys_switch_id=%-20s phys_port_name=%s\n" "$name" "${psid:-<none>}" "${ppn:-<none>}"
  fi
done

if [[ "$found_any" -eq 0 ]]; then
  echo "  No netdev exposed phys_switch_id/phys_port_name."
  skip "this kernel's netdevsim does not expose switchdev representor attributes"
fi

echo "PASS: netdevsim switchdev topology materialized; ResolveRepresentor inputs present."
echo "      Point pkg/tcflower.ResolveRepresentor at these netdevs (phys_switch_id + phys_port_name)."
