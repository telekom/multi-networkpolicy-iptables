#!/usr/bin/env bash
#
# Copyright 2026 Deutsche Telekom AG.
# Licensed under the Apache License, Version 2.0.
#
# Runs every emulation layer and prints a pass/skip/fail summary. Each layer
# self-skips (exit 0) when its kernel features are missing, so this runner treats
# exit 0 as "ran or skipped" and only a non-zero exit as a hard failure.
#
# Usage:  sudo bash test/emulation/run.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare -a SCRIPTS=(
  "netdevsim-discovery.sh"
  "veth-flower-enforcement.sh"
  "netdevsim-layerd-offload-drop.sh"
)

pass=0
skipped=0
failed=0
declare -a results=()

for s in "${SCRIPTS[@]}"; do
  echo
  echo "############################################################"
  echo "# Running ${s}"
  echo "############################################################"
  out="$(bash "${HERE}/${s}" 2>&1)"
  rc=$?
  echo "${out}"
  if [[ ${rc} -ne 0 ]]; then
    failed=$((failed + 1))
    results+=("FAIL  ${s} (exit ${rc})")
  elif echo "${out}" | grep -q '^SKIP:'; then
    skipped=$((skipped + 1))
    results+=("SKIP  ${s}")
  else
    pass=$((pass + 1))
    results+=("PASS  ${s}")
  fi
done

echo
echo "############################################################"
echo "# Emulation harness summary"
echo "############################################################"
for r in "${results[@]}"; do
  echo "  ${r}"
done
echo "  ----------------------------------------"
echo "  pass=${pass} skip=${skipped} fail=${failed}"
echo
echo "  NOTE: Layer D (offloaded skip_sw drop actually blocks) is ATTEMPTED but"
echo "        SELF-SKIPS on a stock kernel: netdevsim's TC_SETUP_CLSFLOWER is a"
echo "        no-op, so an offloaded drop does not fire. It ASSERTS only on a"
echo "        kernel carrying test/emulation/kernel/netdevsim-flower-enforce.patch."
echo "        Real mlx5 offload remains gated to CX5+ hardware. See README.md."

# Only a hard failure fails the harness; skips are expected on limited runners.
[[ ${failed} -eq 0 ]]
