# tc-flower dataplane emulation harness

This harness exercises the real control-plane and software-dataplane paths of the
SR-IOV tc-flower backend **without Mellanox (CX5+) hardware**, so as much of the
backend as possible is covered in CI. Hardware offload semantics that cannot be
emulated remain gated to real switchdev NICs (see "What is NOT emulated" below).

It is deliberately layered so each layer proves a distinct property, and every
layer **skips (exit 0) rather than failing** when a kernel feature is missing —
CI runners have varying `netdevsim`/`devlink`/`tc` support.

## The layers

| Layer | Artifact | What it proves | Emulation |
|-------|----------|----------------|-----------|
| **A — discovery** | `netdevsim-discovery.sh` + `pkg/tcflower/netdevsim_linux_test.go` (`ResolveRepresentor` path is Go-tested against fake sysfs elsewhere) | `netdevsim` can present a switchdev topology (`phys_switch_id` / `phys_port_name`) that the sysfs representor-resolution algorithm can be pointed at. | `netdevsim` + `devlink … mode switchdev` |
| **B — control plane** | `pkg/tcflower/netdevsim_linux_test.go` | The real `netlinkDriver` (go-tc) round-trips a flower filter built from `FlowerRule.toObject`: EnsureClsact → AddFilter → ListFilters (assert keys present) → DelFilter (assert gone). Exercises the actual netlink marshaling end-to-end. | `netdevsim` netdev |
| **C — software enforcement** | `veth-flower-enforcement.sh` | A flower `... action drop` filter installed on a real qdisc **actually drops** matching traffic and passes non-matching traffic. This is the T2 enforcement-correctness proof for the *translation* (`BuildFlowerRules`/`toObject`) — run in **software** (no `skip_sw`) because veth/netdevsim have no HW offload. | veth pair + netns + clsact |
| **D — offloaded drop actually blocks** | *(optional — patched-kernel VM via `vm-run.sh` + `VNG_KERNEL`; draft patch in [`kernel/`](kernel/))* | That a `skip_sw` (hardware-only) filter, once accepted by the NIC, blocks packets in the eSwitch. | Needs a patched `netdevsim` kernel booted in the VM tier; **not** possible on stock `netdevsim`. See [`kernel/README.md`](kernel/README.md) — optional/non-blocking; the CX5/CX6 hardware tier remains authoritative. |

## Running

```sh
# everything, with a pass/skip/fail summary (needs root for netns/netdevsim):
sudo bash test/emulation/run.sh

# individual layers:
sudo bash test/emulation/netdevsim-discovery.sh
sudo bash test/emulation/veth-flower-enforcement.sh

# the Go control-plane integration test (self-skips without root/netdevsim/-short):
sudo -E go test -run Netdevsim ./pkg/tcflower/... -v

# the software-enforcement e2e (drives the REAL engine: BuildFlowerRules ->
# real netlink driver on a veth -> asserts packets are actually dropped/allowed):
sudo -E go test -run E2E ./pkg/tcflower/... -v
```

All scripts use `set -euo pipefail` and clean up their netns / netdevsim devices
via `trap`.

## VM tier — closest to reality without hardware

`vm-run.sh` boots the whole suite inside a **real VM kernel** via KVM
([virtme-ng](https://github.com/arighi/virtme-ng)), reusing the host rootfs so
the Go toolchain and repo checkout are available with no image build:

```sh
# needs /dev/kvm (nested virtualization) + `vng`; skips (exit 0) otherwise:
bash test/emulation/vm-run.sh
```

A shared-kernel container (e.g. the default GitHub-runner environment) often
lacks the `netdevsim` module and `devlink` switchdev support, so Layers A/B
*skip* there. A VM has a full kernel with modules, so it actually runs them.
This is wired in GitLab CI as the `tc-flower-vm-e2e` job (GitLab runners support
KVM); set `VM_E2E_RUNNER_TAG` to a KVM-capable runner tag to enable it.

**Layer D via a patched kernel:** point `VNG_KERNEL` at a built kernel tree /
`bzImage` whose `netdevsim` `TC_SETUP_CLSFLOWER` handler enforces offloaded
flower rules, and `vm-run.sh` boots that instead of the host kernel — the path
to closing the Layer-D gap in CI (still short of real CX5 silicon).

## What is NOT emulated (remains CX5-gated)

Layer D above. On stock upstream `netdevsim`, the TC flower offload entry point
(`nsim_setup_tc_block_cb` handling `TC_SETUP_CLSFLOWER`) is effectively a
**no-op**: it accepts the filter for offload bookkeeping but does not build a
dataplane rule, so an *offloaded* (`skip_sw`) drop does **not** block packets.
Therefore:

- Layers A/B assert the filter is **installed and carries the expected keys**,
  not that an offloaded filter drops packets.
- Layer C proves drop-correctness in **software** (default/`skip_hw`), which
  validates the *rule translation* but not the offload path.

To close Layer D in CI would require a **`netdevsim` kernel patch** that makes
`TC_SETUP_CLSFLOWER` build a minimal matching/drop dataplane (or a
kernel-selftest-style shim). Writing that kernel patch is **out of scope** here
and is documented as the future step. Until then, "an offloaded `skip_sw` drop
truly blocks in the eSwitch" is validated only on real CX5+ hardware.

## Attribution

The `netdevsim` switchdev-topology setup mirrors the approach used by the Linux
kernel `tools/testing/selftests/drivers/net/netdevsim` selftests and the
conventions in `Mellanox/sriovnet` (Apache-2.0). No code is copied; see the
repository `NOTICE` for third-party attribution.
