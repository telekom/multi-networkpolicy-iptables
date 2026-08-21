#!/usr/bin/env bash
#
# Copyright 2026 Deutsche Telekom AG.
# Licensed under the Apache License, Version 2.0.
#
# Layer C — software flower enforcement (the REAL dataplane, no hardware).
#
# Proves that a tc flower `... action drop` filter installed on a real clsact
# qdisc ACTUALLY drops matching traffic and PASSES non-matching traffic. This is
# the T2 enforcement-correctness proof for the rule translation.
#
# IMPORTANT: the filter is installed in SOFTWARE (skip_hw) because veth and
# netdevsim have no hardware offload. The production backend defaults to skip_sw
# (hardware-only), but the tc flower engine now supports a configurable SOFTWARE
# offload mode (--tc-offload-mode=software / OffloadSoftware), which emits the
# identical flower match with skip_hw for in-kernel enforcement. This script
# hand-writes that same skip_hw match; its Go-driven twin,
# TestSoftwareEnforcementE2E (pkg/tcflower/e2e_linux_test.go), proves the engine
# produces and enforces it end to end. Hardware offload (skip_sw in the eSwitch)
# remains gated to real ConnectX (CX5+) hardware.
#
# Topology (two network namespaces joined by a veth pair):
#
#   ns-a (10.10.0.1/24)  veth-a <====> veth-b  ns-b (10.10.0.2/24)
#
# We attach a clsact qdisc to veth-b (inside ns-b) and add a flower filter on its
# ingress that drops IP traffic destined to 10.10.0.2 on TCP dport 9999. We then
# assert:
#   - a matching TCP connection to 10.10.0.2:9999 is BLOCKED, and
#   - ICMP (ping) to 10.10.0.2 still PASSES (non-matching -> not dropped).
#
# Skips (exit 0) if ip/tc are unavailable. Cleans up both namespaces via trap.

set -euo pipefail

readonly NS_A="mnp-emul-a"
readonly NS_B="mnp-emul-b"
readonly VETH_A="veth-a"
readonly VETH_B="veth-b"
readonly IP_A="10.10.0.1"
readonly IP_B="10.10.0.2"
readonly PREFIX=24
readonly DROP_PORT=9999

skip() { echo "SKIP: $*"; exit 0; }
fail() { echo "FAIL: $*"; exit 1; }

cleanup() {
  ip netns del "${NS_A}" 2>/dev/null || true
  ip netns del "${NS_B}" 2>/dev/null || true
}

[[ "$(id -u)" -eq 0 ]] || skip "must run as root (netns/tc need CAP_NET_ADMIN)"
command -v ip >/dev/null 2>&1 || skip "iproute2 'ip' not found"
command -v tc >/dev/null 2>&1 || skip "iproute2 'tc' not found"

trap cleanup EXIT
cleanup # in case of a stale prior run

echo "== Building veth topology across two netns =="
ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${VETH_A}" netns "${NS_A}" type veth peer name "${VETH_B}" netns "${NS_B}"

ip -n "${NS_A}" addr add "${IP_A}/${PREFIX}" dev "${VETH_A}"
ip -n "${NS_B}" addr add "${IP_B}/${PREFIX}" dev "${VETH_B}"
ip -n "${NS_A}" link set "${VETH_A}" up
ip -n "${NS_B}" link set "${VETH_B}" up
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up

echo "== Baseline connectivity (no filter yet) =="
if ! ip netns exec "${NS_A}" ping -c1 -W2 "${IP_B}" >/dev/null 2>&1; then
  skip "baseline ping failed; veth/netns not functional on this runner"
fi
echo "  baseline ping ${IP_A} -> ${IP_B} OK"

echo "== Installing SOFTWARE flower drop filter on ${VETH_B} ingress =="
# clsact gives us an ingress hook on veth-b (traffic entering ns-b from ns-a).
ip netns exec "${NS_B}" tc qdisc add dev "${VETH_B}" clsact
# NOTE: no skip_sw -> software datapath. flip=off is implicit for veth.
# skip_hw is added explicitly to make the software intent unambiguous and to
# avoid any driver trying (and failing) to offload on a veth.
ip netns exec "${NS_B}" tc filter add dev "${VETH_B}" ingress \
  protocol ip prio 1 flower skip_hw \
  ip_proto tcp dst_ip "${IP_B}" dst_port "${DROP_PORT}" \
  action drop

echo "== tc filter installed: =="
ip netns exec "${NS_B}" tc -s filter show dev "${VETH_B}" ingress

# 1) Non-matching traffic (ICMP) must STILL pass.
echo "== Assert: non-matching ICMP still passes =="
if ip netns exec "${NS_A}" ping -c1 -W2 "${IP_B}" >/dev/null 2>&1; then
  echo "  PASS: ICMP to ${IP_B} still allowed (does not match tcp/${DROP_PORT})"
else
  fail "ICMP to ${IP_B} was dropped but should NOT match the tcp/${DROP_PORT} filter"
fi

# 2) Matching traffic (TCP dport 9999) must be BLOCKED.
echo "== Assert: matching TCP dport ${DROP_PORT} is blocked =="
matched_drop=""
if command -v nc >/dev/null 2>&1; then
  # Start a listener in ns-b; a matching SYN should be dropped before delivery,
  # so the connect must time out / fail.
  ip netns exec "${NS_B}" sh -c "nc -l -p ${DROP_PORT} >/dev/null 2>&1 &" || true
  sleep 1
  if ip netns exec "${NS_A}" nc -w2 -z "${IP_B}" "${DROP_PORT}" >/dev/null 2>&1; then
    fail "TCP connect to ${IP_B}:${DROP_PORT} SUCCEEDED but the flower drop filter should block it"
  else
    matched_drop=1
    echo "  PASS: TCP connect to ${IP_B}:${DROP_PORT} blocked by flower drop filter"
  fi
else
  # Fallback: no nc. Assert via the flower filter's packet counter instead.
  # Generate a matching packet with /dev/tcp and confirm the filter's drop
  # counter incremented.
  before="$(ip netns exec "${NS_B}" tc -s filter show dev "${VETH_B}" ingress | grep -oE 'Sent [0-9]+ bytes [0-9]+ pkt' | grep -oE '[0-9]+ pkt' | grep -oE '[0-9]+' | head -1 || echo 0)"
  ip netns exec "${NS_A}" timeout 2 bash -c "exec 3<>/dev/tcp/${IP_B}/${DROP_PORT}" >/dev/null 2>&1 || true
  after="$(ip netns exec "${NS_B}" tc -s filter show dev "${VETH_B}" ingress | grep -oE 'Sent [0-9]+ bytes [0-9]+ pkt' | grep -oE '[0-9]+ pkt' | grep -oE '[0-9]+' | head -1 || echo 0)"
  if [[ "${after:-0}" -gt "${before:-0}" ]]; then
    matched_drop=1
    echo "  PASS: flower drop counter incremented (${before} -> ${after}); matching packet dropped"
  fi
fi

[[ -n "${matched_drop}" ]] || fail "could not confirm the matching packet was dropped"

echo "PASS: software flower enforcement verified (matching dropped, non-matching passed)."
