# SR-IOV tc-flower dataplane backend

The controller ships two dataplane backends in one binary, selected **per pod
interface**:

- **nftables-in-netns** (default, unchanged): enters the pod network namespace
  and programs nftables. Correct for veth-style CNIs (macvlan, ipvlan, bond)
  whose traffic traverses the kernel netfilter path.
- **tc-flower-on-representor** (this document): programs `tc flower` filters on
  the host-side **VF representor** of an SR-IOV VF, offloaded to the NIC's
  embedded eSwitch. Required for SR-IOV VFs in **switchdev** mode, whose
  VF-to-VF traffic is switched inside the NIC and never reaches a kernel
  netfilter hook — so in-pod nftables cannot see it.

Both run side by side in the same reconcile pass. A single pod with both a
macvlan secondary and an SR-IOV VF secondary gets nftables on the veth and tc
flower on the representor; neither backend touches the other's interfaces.

## Backend selection (zero-config, per interface)

Selection is data-driven off the Multus `k8s.v1.cni.cncf.io/network-status`
annotation. If an interface carries a `DeviceInfo.Pci` block (VF PCI address /
representor), it is routed to the tc backend; otherwise to the nftables backend.

Operators must add the SR-IOV plugin name(s) to `--network-plugins` so SR-IOV
net-attach-defs pass the plugin-type filter (the default list is unchanged):

```
--network-plugins=macvlan,sriov,accelerated-bridge
```

## Prerequisites (out-of-band, not this daemon's job)

The tc backend requires the NIC to already be in switchdev mode with hardware
tc offload enabled. This is a node-provisioning concern; the daemon **detects**
its absence and errors loudly rather than silently leaving traffic unenforced.

- NIC: NVIDIA/Mellanox ConnectX-5 or newer (mlx5).
- eSwitch in switchdev mode: `devlink dev eswitch set pci/<pf> mode switchdev`.
- Hardware tc offload on the uplink: `ethtool -K <pf> hw-tc-offload on`.
- The DaemonSet mounts host `/sys` and `/proc` (already privileged, per node)
  and honours `--host-prefix` for all sysfs reads.

If the representor cannot be resolved or offload is off, the interface is
treated as **fail-closed** and reported via metrics/logs — never silently
allowed.

## Flags

| Flag | Default | Effect |
|------|---------|--------|
| `--enable-tc-backend` | `true` | Master switch for the whole SR-IOV tc backend. When `false`, every interface that would route to the tc backend is skipped — SR-IOV VFs are **not enforced** by this daemon and only the nftables backend runs. Use to opt out entirely on nodes/clusters where SR-IOV enforcement is not wanted. |
| `--tc-offload-mode` | `hardware` | `hardware` = `skip_sw` (hardware-only, fail-closed on insertion; production default). `software` = `skip_hw` (in-kernel software enforcement; for debugging/emulation without offload-capable HW). Ignored by the nftables backend. |
| `--tc-ct-mode` | `auto` | Stateful conntrack (CT) offload policy. `auto`: emit the CT pipeline where the NIC can hardware-offload it (SMFS steering), otherwise **degrade to the stateless pipeline** and log the lost stateful tracking (DMFS cannot offload CT). `require`: always emit CT; if the NIC cannot offload it the filters are rejected and the interface is left unenforced (fail-closed, stateful-or-nothing). `off`: never use CT (always stateless). Ignored by the nftables backend. |

### Graceful degradation — always enforce the maximum the hardware allows

The backend never silently does nothing. On each representor it enforces the
largest offloadable subset of the policy for the current NIC/steering config and
**logs, once, what was lost and how to recover it**:

- **Stateless allow/deny** (5-tuple, CIDR, ports, both IPv4 and IPv6) offloads on
  any switchdev NIC with `hw-tc-offload on`, regardless of steering mode.
- **Stateful CT** (established/related auto-accept) needs SMFS; under
  `--tc-ct-mode=auto` a DMFS/HMFS/unknown NIC degrades to stateless and logs an
  info-level "improvement available: switch to SMFS" line.
- If even the stateless filters cannot be offloaded (e.g. `hw-tc-offload off` in
  hardware mode) insertion fails **fail-closed** and the error is surfaced (log +
  `multinetworkpolicy_tc_filter_apply_errors_total{reason="skip_sw"}`), never
  silently allowed.

See [SR-IOV tc backend operations & debugging](sriov-tc-operations.md) for the
per-mode capability matrix, the exact log lines, metrics, and a debugging
runbook.

Disabling the backend cluster-wide:

```
--enable-tc-backend=false
```

## Stateful (CT) offload

To match the nftables backend's established/related accept, the tc backend can
emit mlx5 CT action chains (`ct` action + `ct_state` matching). Hardware CT
offload historically requires the mlx5 **SMFS** steering mode
(`devlink dev param set <pci> name flow_steering_mode value smfs`) and consumes
at least two eSwitch flow-table entries per tracked connection. The daemon runs
a preflight check and exposes CT-offload readiness and `ct_max_offloaded_conns`
as metrics.

## Deployment note: T-CaaS bm4x

The bm4x bare-metal profile **is** switchdev with VF representors, so the tc
backend applies directly. eSwitch mode is set out-of-band during imaging
(netplan `embedded-switch-mode: switchdev` + the `sriov-setup.sh` ansible step
running `devlink dev eswitch set ... mode switchdev` and
`ethtool -K <nic> hw-tc-offload on`); CNI is accelerated-bridge-cni on
ConnectX-5 (MCX512F) / ConnectX-6 Lx.

**Caveat — CT offload on bm4x as imaged:** bm4x hosts run the mlx5 default
**DMFS** steering mode, not SMFS. Hardware CT offload is associated with SMFS,
so on bm4x as currently imaged the CT chains are unlikely to hardware-offload.
Stateless policy (allow/deny by 5-tuple, CIDR, ports) offloads normally; only
the stateful established/related path is affected. See the steering-mode
section below for the recommendation to move bm4x to SMFS.

## Flow-steering modes (DMFS / SMFS / HMFS)

mlx5 selects how eSwitch steering rules are built via one runtime devlink
parameter, `flow_steering_mode` (values `dmfs` / `smfs` / `hmfs`):

- **DMFS** (Device-Managed Flow Steering) — the **default**. Steering entities
  are created and managed by **firmware**.
- **SMFS** (Software-Managed Flow Steering) — the **driver** builds the HW
  steering entities without firmware round-trips. The upstream kernel doc
  states plainly: *"SMFS mode is faster and provides better rule insertion rate
  compared to default DMFS mode."* It is the mode associated with OVS/ASAP²
  hardware offload and conntrack offload at scale.
- **HMFS** (Hardware-Managed Flow Steering) — newest, WQE-based, "millions of
  rules per second"; hardware floor is **ConnectX-6 Dx**.

Set (runtime):

```
devlink dev param set pci/<pf> name flow_steering_mode value smfs cmode runtime
```

Per-card support across our fleet (from the upstream mlx5 steering-format enum
and DR capability gate):

| Card | DMFS | SMFS | HMFS |
|------|------|------|------|
| ConnectX-4 / CX4-Lx | ✓ (only) | ✗ (no SW-steering format) | ✗ |
| ConnectX-5 | ✓ | ✓ | ✗ |
| ConnectX-6 Lx | ✓ | ✓ | not confirmed |
| ConnectX-6 Dx | ✓ | ✓ | ✓ |
| ConnectX-7 | ✓ | ✓ | ✓ |

### Should bm4x switch to SMFS?

**Recommendation: yes, move bm4x (CX5 + CX6 Lx + CX6 Dx) to SMFS** — all three
support it, it is faster for rule insertion, and it is the mode aligned with
CT/OVS hardware offload. Caveats to respect:

1. **Set SMFS before switchdev.** The mlx5 driver rejects `smfs` once the
   eSwitch is already in offloads mode ("Software managed steering is not
   supported when eswitch offloads enabled"). Provisioning must set
   `flow_steering_mode=smfs` **first**, then `devlink dev eswitch set … mode
   switchdev`. Wrong ordering is the main footgun.
2. **DMFS-only feature lost:** E-Switch *aggregated-affinity* matching is
   DMFS-only. Only relevant if bm4x uses multi-port/bond affinity matching in
   the FDB — verify it does not.
3. **CX5 feature/version floor:** CX5 uses the oldest SW-steering format and
   lacks some DR optimizations that CX6 Dx+ have; SMFS still works, but confirm
   the shipped MLNX_OFED/DOCA + kernel is recent enough for the CT ruleset.
4. **Host cost:** "software-managed" shifts steering-table construction to the
   host CPU/RAM. NVIDIA publishes no quantified overhead; do a canary rollout
   and watch driver CPU/RAM.

HMFS is **not** recommended fleet-wide: CX5 cannot do it, so SMFS is the common
denominator across bm4x.

> **Sourcing note:** the mode definitions, the "SMFS is faster" statement, and
> the per-card steering-format support are from the upstream kernel docs and
> mlx5 driver source (primary). "CT offload *requires* SMFS" is widely
> documented by NVIDIA (ASAP²) but the upstream tc CT path is not gated on
> steering mode — treat it as strong guidance, verify on the target
> OFED/firmware. `ct_max_offloaded_conns` and its `-ENOSPC` at
> `offloaded_flows >= ct_max_offloaded_conns * 2` behaviour are MLNX_OFED
> (out-of-tree) specifics; the BlueField default is 1,000,000 (adapter default
> not separately published — read `devlink dev param show`).

## Testing without hardware

The `test/emulation/` harness exercises discovery, control-plane netlink
round-trips, and software enforcement in CI without a Mellanox card. See
[`test/emulation/README.md`](../test/emulation/README.md) for the layered model
and what remains gated to real CX5+ silicon.

---

# Architecture & internals (extended)

> This section records everything currently known about how the backend works
> and the environment it runs in, including material that is **not verifiable
> from a primary source right now**. Confidence markers: **[impl]** = true of
> this codebase (read the source to confirm); **[primary]** = upstream
> kernel/man/source; **[secondary]** = NVIDIA/OFED docs; **[unconfirmed]** =
> engineering knowledge/inference, verify on your driver/firmware before relying
> on it. Anything marked **[unconfirmed]** may be wrong on a given
> kernel/OFED/firmware combination.

## A. Data path & the direction inversion

On a switchdev NIC every VF has a **representor** netdev on the host. The
representor is a *mirror* of the VF: a packet the VF **sends** arrives at the
representor as an **ingress** packet, and a packet **sent to** the representor is
delivered to the VF. Consequences for policy mapping **[primary: kernel
representors.rst; validate empirically]**:

| MultiNetworkPolicy direction | Meaning | Representor qdisc parent it is installed on |
|---|---|---|
| **ingress** (traffic *to* the pod) | packets delivered to the VF | representor **egress** (`clsact` egress / `HandleMinEgress`) |
| **egress** (traffic *from* the pod) | packets the VF sends | representor **ingress** (`clsact` ingress / `HandleMinIngress`) |

This inversion is the **single highest-risk correctness area** and is only fully
verified on real switchdev silicon. **[impl]** The mapping lives in
`Direction.parentHandle()` in `pkg/tcflower/engine.go`. If allow/deny appears
mirrored in production, suspect this first — see the validation procedure in the
operations guide.

VF-to-VF traffic is switched **inside** the NIC eSwitch and never reaches a host
kernel netfilter hook, which is exactly why in-pod nftables cannot police it and
why enforcement must happen on the representor via tc-flower offloaded to the
eSwitch **[primary: switchdev model]**.

## B. Translation model (MultiNetworkPolicy → tc flower)

**[impl]** The engine (`pkg/tcflower/engine.go`, `BuildFlowerRules`) mirrors the
nft engine's policy *selection* but re-expresses enforcement for a flow-based,
first-match flower pipeline:

- Each ingress/egress rule expands to the **(ports × peers)** cross-product;
  every emitted accept filter carries the **full** match (proto + dst port +
  peer address) because tc flower cannot AND separate filters like nft chains.
- `ipBlock` → one accept filter per CIDR; each `Except` CIDR → a higher-priority
  drop ahead of the allow.
- `podSelector`/`namespaceSelector` → resolve peer pod IPs (restricted to the
  policy networks), one `/32` (v4) or `/128` (v6) filter per peer address.
- Empty peers = match-any address; empty ports = match-any L4.
- A lowest-priority catch-all **drop** per direction implements default-deny.

**Dual-stack:** a flower filter matches exactly **one** ethertype, so every rule
is single-family. Match-any / default-deny / CT-entry rules carry no L3 address
but still carry an ethertype, so they are expanded into **both** a v4 and a v6
filter — otherwise IPv6 would fall off the end of the chain and be implicitly
accepted **[impl]**.

### Priority allocation (one-mask-per-priority)

**[primary: tc-flower(8)]** tc flower allows only **one mask per priority** — all
filters at a given priority must share the same key mask (only values differ).
**[impl]** `assignPriorities` groups candidates into classes keyed by
`(direction, chain, tier, mask-shape, policy)` and numbers them from 1 within
each `(direction, chain)` priority space. Tiers guarantee ordering:
`except (0) < allow (1) < default-deny (2)`. Rules whose prefix lengths differ
have different mask shapes and therefore land on different priorities. The map is
a pure function of the candidate set → **stable across reconciles** (no churn).

### Stable handles & idempotent reconcile

**[impl]** Each filter gets a deterministic 32-bit handle hashed from its full
identity (`FlowerRule.handle()`), so `AddFilter` (tc *replace*) is idempotent and
the reconcile diff keys on `(parent, chain, priority, handle)` without relying on
kernel-assigned handles. Reconcile lists installed managed filters, installs the
desired set (replace = self-healing), then deletes managed filters not in the
desired set. "Managed" = a flower filter carrying `skip_sw` **or** `skip_hw`
(so foreign filters are never touched). Runs every `--sync-period`.

## C. CT (stateful) pipeline internals

**[impl]** When CT is enabled the filters split across two tc chains per
representor parent:

- **chain 0** (entry): `+trk+inv → drop` (defensive); `+trk+est → accept` and
  `+trk+rel → accept` (stateful return traffic, mirroring nft
  `allowConntracked`); `-trk → ct(zone) pipe, goto chain 1` (send new packets
  through conntrack then evaluate policy).
- **chain 1** (policy): the same first-match allow/except/default-deny set as
  stateless, except each **accept commits** the NEW connection
  (`ct commit zone <z>`) so its reply is tracked and auto-accepted by chain 0.

**Conntrack zones [impl]:** `ctZoneFor(rep, dir)` derives a stable non-zero
uint16 zone per `(representor, direction)` (low bit = direction) so flows on
different reps/directions do not collide in the shared eSwitch conntrack table.

**Action encodings [primary: include/uapi/linux/pkt_cls.h, tc_act/tc_ct.h;
impl]:** `TC_ACT_GOTO_CHAIN = 0x40000000`; ct_state bits `new/est/rel/trk/inv/rpl`;
ct action `commit=1`. IPv6 flower L3 keys are provided by upstream go-tc
(florianl/go-tc#330, merged); the module is pinned to the merge-commit
pseudo-version until florianl cuts a tagged release, then bump to the tag. The
personal fork is no longer referenced **[impl]**.

## D. Discovery internals (VF → representor)

**[impl]** `ResolveRepresentor` (`pkg/tcflower/discover.go`):

1. **Annotation-first** — trust `DeviceInfo.Pci.RepresentorDevice` from Multus
   `network-status` if present, but verify the netdev exists.
2. **sysfs fallback** — from the VF PCI: read `physfn` → PF; find the `virtfnN`
   index matching the VF; read the PF uplink's `phys_switch_id`; scan
   `/sys/class/net` for the netdev whose `phys_switch_id` matches **and** whose
   `phys_port_name` parses to that VF index. **Representors are never identified
   by parsing the netdev name** — always by `phys_switch_id` + `phys_port_name`
   **[primary: switchdev model]**.

All reads honour `--host-prefix`. The algorithm re-implements `Mellanox/sriovnet`
(Apache-2.0, credited) in a prefix-aware, unit-testable form; we deliberately do
**not** depend on sriovnet because it hardcodes `/sys` **[impl]**.

### Representor / port naming variants **[primary/unconfirmed]**

The `phys_port_name` sysfs attribute distinguishes port types. Known forms:

| Form | Meaning | Confidence |
|------|---------|-----------|
| `p0`, `p1` | physical uplink port | [primary] |
| `pf0vf3` | VF 3 of PF 0 (VF representor) | [primary] |
| `vf3` | bare VF representor (older naming) | [unconfirmed] |
| `pf0sf<N>` | **subfunction (SF)** representor | [unconfirmed] |
| `c<ctrl>pf<port>vf<vf>` | multi-host / SmartNIC-controller form | [unconfirmed] |

**[impl]** `parseVFIndexFromPortName` currently recognizes the `pfXvfY` and bare
`vfY` forms via a `LastIndex("vf")` scan. **It does NOT recognize subfunction
`pfXsfN` representors** — SR-IOV VFs are supported; **subfunctions are not yet
handled** by discovery. If your fleet uses SFs instead of VFs, discovery will not
find the representor. This is a known limitation, not covered by the annotation
path either unless the CNI populates `RepresentorDevice` directly.

### Subfunctions (SF) vs VFs **[secondary/unconfirmed]**

Subfunctions are a lighter-weight alternative to SR-IOV VFs on mlx5: they share a
PF's PCI function but get their own representor and switchdev port, created via
`devlink port add ... flavour pcisf`. They are **out of scope** for this backend
today (see the naming limitation above). Noted for future work.

## E. Offload flags & fail-closed semantics

**[primary: tc-flower(8)]** `skip_sw` = hardware-only: if the NIC cannot offload
the filter (unsupported match, table full, offload disabled) the kernel
**rejects the insertion** rather than silently enforcing in software — this is
the fail-closed guarantee. `skip_hw` = software datapath only.

**[impl]** `--tc-offload-mode=hardware` stamps `skip_sw` (production); `software`
stamps `skip_hw` (CI/emulation on veth/netdevsim, and non-offload NICs). A
rejected `skip_sw` insertion surfaces as `EOPNOTSUPP`/`ENOTSUPP` and is counted
as `filter_apply_errors_total{reason="skip_sw"}`.

**[unconfirmed]** On a real switchdev NIC, software mode (`skip_hw`) does **not**
see eSwitch-switched VF-to-VF traffic (it never reaches the host datapath), so
software mode is for emulation/veth and non-offload NICs — not a production
fallback for inter-VF policy on switchdev hardware.

## F. Lifecycle & cleanup

**[impl]** On pod delete / daemon shutdown (`Flush` via `cleanupAllPods`) the
backend deletes only its **managed** filters on the representor's clsact parents.
It is tolerant of a representor that has already gone away (VF returned, node
reboot): an unresolvable representor or missing clsact qdisc is "nothing to
clean", not an error. The **clsact qdisc itself is left in place** because it may
be shared with other tenants of the same representor.

**[unconfirmed] Orphan filters:** if the daemon is killed hard (SIGKILL, node
crash) before Flush, managed filters persist on the host representor. On restart
the declarative reconcile converges them back to desired state, but a
representor for a pod that no longer exists could retain stale filters until the
next full resync touches it. Worth watching `filters_installed` vs live pods.

## G. eSwitch tuning params (adjacent, out-of-band) **[primary/unconfirmed]**

Set at provisioning, not by this daemon; listed so operators know the full knob
surface:

- `flow_steering_mode` (dmfs/smfs/hmfs) — see the steering-mode section. **Must
  be set before switchdev** **[secondary]**.
- `inline-mode` — `devlink dev eswitch set pci/<bdf> inline-mode
  {none|link|network|transport}`; controls how much header the driver must
  inline for the eSwitch to match. Transport-level is often needed for L4
  matching. **[unconfirmed]** exact requirement per match.
- `encap` / `encap-mode` — tunnel encap offload (`basic`/`none`); relevant for
  VXLAN/GENEVE offload, **not** used by this backend's L3/L4 policy.
- **VF-LAG / bonding**: two PFs bonded under one eSwitch; representors live under
  the bond. **[unconfirmed]** interaction with per-PF representor discovery —
  verify representor `phys_switch_id` is shared across the bonded PFs.
- `total_vfs` / `sriov_numvfs` — VF count; the max is device-specific
  (`sriov_totalvfs`), **[unconfirmed]** for a given card (read the sysfs value).

## H. Scale & hardware limits **[secondary/unconfirmed]**

- **Max offloaded flower rules / steering-table size:** NVIDIA publishes **no**
  hard per-device number **[primary: absence confirmed]**. Treat as measured;
  watch `filters_installed` and `filters_not_in_hw`.
- **CT capacity:** `ct_max_offloaded_conns` (mlx5 devlink, **MLNX_OFED
  out-of-tree** **[secondary]**). Effective flow ceiling is `2 ×` this value
  (two entries per bidirectional connection); insertion refused with `-ENOSPC`
  at `num_offloaded_flows >= ct_max_offloaded_conns * 2` **[secondary: OFED
  tc_ct.c]**. BlueField default 1,000,000; **adapter default unpublished
  [unconfirmed]** — read `devlink dev param show`.
- **Host conntrack interplay [unconfirmed]:** whether the host
  `net.netfilter.nf_conntrack_max` sysctl bounds *offloaded* connections is not
  confirmed from a primary source; offloaded flows live in the NIC, but the
  kernel ct entry may still be created. Verify before assuming independence.
- **Priorities:** DPDK mlx5 guide cites "up to 21844 priorities in non-root
  tables" **[secondary]** — a priority-count figure, not a rule-count cap.

## I. Security / deployment surface **[impl]**

- Runs as a **privileged**, host-networked DaemonSet with host `/sys` and
  `/proc` mounted (honouring `--host-prefix`) and `CAP_NET_ADMIN` for netlink tc
  programming.
- Shells out **best-effort** to `devlink` (steering mode, `ct_max_offloaded_conns`)
  and `ethtool` (hw-tc-offload); absence degrades observability only, never
  enforcement.
- Talks to the kernel over **netlink** (go-tc on `mdlayher/netlink`, cgo-free) —
  no `tc` binary required for the fast path; the `tc -j` cmdline path is used
  only for verification/fallback **[impl]**.

## J. DPU / BlueField **[unconfirmed]**

On DPU/BlueField SmartNICs the VF representors live on the **DPU Arm cores**, not
the x86 host, so a host-side daemon cannot see or program them. This backend
targets **host-side** switchdev (adapter mode); DPU/embedded-CPU mode is **out of
scope** and would need the daemon to run on the DPU. Noted for future work.
