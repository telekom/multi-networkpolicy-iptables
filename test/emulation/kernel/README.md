# Layer-D netdevsim kernel patch (optional, GPL-2.0)

This directory holds a **draft Linux kernel patch** that makes `netdevsim`
actually enforce an offloaded (`skip_sw`) tc-flower **drop** rule, so CI can
prove the one property the software tiers cannot: *"an offloaded drop truly
blocks a packet in the simulated eSwitch."*

- [`netdevsim-flower-enforce.patch`](netdevsim-flower-enforce.patch) — the patch.

## Why this exists

Stock upstream `netdevsim`'s `TC_SETUP_CLSFLOWER` handler is a no-op: it accepts
the offload (the filter shows `in_hw`) but never builds a dataplane rule, so a
`skip_sw` drop does **not** block packets. That is why the emulation README's
Layer D is "not emulated" on a stock kernel. This patch stores a minimal flower
key/mask + verdict per port and evaluates it in `nsim_start_xmit`.

## Licensing boundary

The patch is **GPL-2.0 Linux kernel code** and is intentionally kept **out of the
Go module** — it lives only as a `.patch` applied to a CI kernel build, never
compiled into or linked with the Apache-2.0 daemon (which talks to the kernel
over netlink, across the syscall boundary). Do not move it into the Go source
tree.

## Status & honest verdict

**Draft, best-effort against mainline (~`58717b2a1365`); it MUST be rebased to
the exact CI kernel** — line numbers, the `flow_rule` dissector API, and
`nsim_start_xmit` drift between releases. The `nsim_create`/`nsim_destroy` hunks
are marked `@@ -XXXX` and must be located at rebase time. It implements IPv4
5-tuple + eth_type + drop/pass only — enough to prove enforcement, not full
flower semantics.

**It is optional / nice-to-have, not recommended as the primary Layer-D signal.**
The real Layer-D guarantee — actual mlx5 offload, DMFS/SMFS behaviour, switchdev
insertion rejection — is only meaningful on the **CX5/CX6 hardware tier (T4)**.
This simulated matcher tests code *we* wrote, not mlx5, so it can drift from real
hardware and give false confidence. Recommended posture:

1. Keep Layer D authoritative on the **CX5/CX6 hardware tier**.
2. If a hardware-free signal is wanted, land a patched-kernel job that is
   **capability-probed and non-blocking**: it asserts the drop only on a patched
   kernel and **self-SKIPs** on stock kernels (install a `skip_sw` drop, send a
   matching packet; if it is not dropped → SKIP "stock netdevsim no-op flower").
3. If maintaining the rebase becomes a burden, drop the job and rely on **Layer C
   (software translation proof) + the CX5 hardware tier**, which already cover
   the meaningful risk surface.

## How to use

```sh
# 1. Rebase + apply against the target kernel:
git -C <kernel-tree> apply /path/to/netdevsim-flower-enforce.patch   # after rebase
# 2. Build with CONFIG_NETDEVSIM + CONFIG_NET_CLS_FLOWER:
make -C <kernel-tree> -j                                              # -> arch/x86/boot/bzImage
# 3. Boot it under the existing harness:
VNG_KERNEL=<kernel-tree>/arch/x86/boot/bzImage bash test/emulation/vm-run.sh
```

The Layer-D test then installs `flower skip_sw ... action drop`, confirms
`in_hw`, and asserts a matching packet is dropped while a non-matching packet
passes.
