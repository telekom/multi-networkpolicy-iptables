# Mellanox/NVIDIA mlx5 eSwitch — hardware internals, edge cases & limits

Exhaustive reference for the mlx5 (ConnectX) switchdev/eSwitch/tc-flower hardware
behaviour this backend depends on. **This is a knowledge dump, not a warranty.**
It deliberately includes material that cannot be verified against a primary
source right now, because it is still useful to an operator debugging real
hardware — every such item is marked.

> **Confidence markers.** **[primary]** = upstream kernel docs / Linux source /
> man pages. **[secondary]** = NVIDIA/OFED/DOCA docs, DPDK guide, conference
> talks, mailing lists. **[unconfirmed]** = engineering knowledge or inference,
> NOT verified against a primary source for this doc — **may be wrong on a given
> ASIC/firmware/OFED/kernel combination; verify before relying on it.**
>
> Cards in scope: **ConnectX-5, ConnectX-6 Lx, ConnectX-6 Dx, ConnectX-7**
> (ConnectX-4/Lx noted where behaviour differs). This doc is being cross-checked
> by source-hunting passes; markers will tighten over time.

---

## 1. Flow-steering engines (DMFS / SMFS / HMFS)

Selected by the runtime devlink param `flow_steering_mode` **[primary:
devlink/mlx5.rst]**.

- **DMFS** — Device-Managed Flow Steering. Steering entities created/managed by
  **firmware**. The **default**. **[primary]**
- **SMFS** — Software-Managed Flow Steering (a.k.a. "SWS" / Direct Rules / DR in
  DPDK). The **driver** builds the HW steering entities directly, no firmware
  round-trip → higher insertion rate. Kernel doc: *"SMFS mode is faster and
  provides better rule insertion rate compared to default DMFS mode."*
  **[primary]**
- **HMFS / HWS** — Hardware-Managed (WQE-based) steering; "millions of rules per
  second"; hardware floor **ConnectX-6 Dx** **[secondary: DPDK mlx5]**.

**Steering-format version per ASIC** (gates which DR features exist)
**[primary: include/linux/mlx5/mlx5_ifc.h]**: `CONNECTX_5 = 0`,
`CONNECTX_6DX = 1`, `CONNECTX_7 = 2`, `CONNECTX_8 = 3`. CX4/CX4-Lx have no
SW-steering format → **no SMFS** **[primary/unconfirmed]**.

**STE layout is versioned by the format [primary: `steering/sws/dr_ste.c`]:**
CX5 (format 0) uses match-STE **v0** (`if (version ==
MLX5_STEERING_FORMAT_CONNECTX_5) return mlx5dr_ste_get_ctx_v0();`); newer formats
use v1+. Non-root tables support up to **21844 priorities** **[secondary:
DPDK]**. Byte-level STE bit layouts per version were not read this pass
**[unconfirmed]**. The steering table for SMFS is stored in host-allocated ICM
(driver-mapped device memory) — the host-RAM cost of software-managed steering
**[unconfirmed]**.

**CX5 STEv0 HW bug [primary: `dr_domain.c`]:** a per-vport cached FW FT is kept
for checksum recalculation "due to a HW bug in STEv0" — a CX5-specific quirk.

**Directory layout [primary]:** `mlx5/core/steering/` now splits into `sws/`
(SMFS / `mlx5dr` direct-rules) and `hws/` (HMFS / WQE-based hardware steering).
The `flow_steering_mode` string param is validated by `fs_core.c`
`mlx5_fs_mode_validate()` (rejects unknown values: supported are
`["dmfs","smfs","hmfs"]`).

**HWS gating [primary: `hws/mlx5hws.h`]:** HMFS needs
`wqe_based_flow_table_update_cap` && `ignore_flow_level_rtc_valid`; object model
context→table→matcher→rule, using RTCs and `INSERT_BY_HASH`/`INSERT_BY_INDEX`.

**Ordering rule — CONFIRMED IN UPSTREAM CODE [primary: `fs_core.c`
`mlx5_fs_mode_validate()`]:** the driver **rejects a steering-mode change while
the eSwitch is in offloads mode** with "Changing fs mode is not supported when
eswitch offloads enabled." Set SMFS **before** switchdev. (Earlier this was only
attributed to OFED; it is confirmed in mainline.)

## 2. Why a flower rule fails to offload (`not_in_hw` / `-EOPNOTSUPP`)

The kernel accepts a `skip_sw` filter only if the driver can program it; else it
rejects insertion (fail-closed). mlx5 emits specific extack strings — verbatim
rejection messages verified in `en_tc.c`/`act/*.c`/`eswitch_offloads.c`
**[primary-extracted: exact strings confirmed, line numbers not captured]**:

- **Unsupported match keys** — "Unsupported key"; "Matching on CVLAN is not
  supported"; "Matching on TTL is not supported"; "Only UDP and TCP transports
  are supported for L4 matching"; "Matching on MPLS is supported only for MPLS
  over UDP"; "Match on tunnel is not supported"; "Flow is not offloaded due to
  min inline setting".
- **One-mask-per-priority** — two different masks at the same tc `prio` is
  invalid **[primary: tc-flower(8)]**; the backend already avoids this via its
  priority allocator.
- **Action-list ordering/count/composition** — "Rule must have at least one
  forward/drop action"; "Rule cannot support forward+drop action"; "Drop with
  modify header action is not supported"; "Cannot offload flows with nested
  jumps"; pedit: "too many pedit actions, can't offload", "can't set and add to
  the same HW field", "can't offload re-write of non TCP/UDP"; police ordering:
  "Offload not supported when conform action is not continue"/"…exceed action is
  not drop"/"…action is not last".
- **Chain / goto limits** — FDB tc limits **without** the `ignore_flow_level`
  cap: `FDB_TC_MAX_CHAIN 3`, `FDB_TC_MAX_PRIO 16`, `FDB_TC_LEVELS_PER_PRIO 2`
  **[primary: `fs_core.h`]**; out-of-range → "Requested destination chain is out
  of supported range". "Goto lower numbered chain isn't supported"; "Goto chain
  is not allowed if action has reformat or decap"; "Decap with goto isn't
  supported". Multi-table/CT/meter/goto needs the `ignore_flow_level` cap — else
  `post_act` init fails with "firmware flow level support is missing" and
  `-EOPNOTSUPP` **[primary: `post_act.c`]**.
- **Chains/prios unsupported by FW entirely** — falls back to chain 0 only,
  logging "Tc chains and priorities offload aren't supported, update firmware if
  needed" **[primary-extracted: `eswitch_offloads.c`]**.
- **mirred fan-out** — "devices are not on same switch HW, can't offload
  forwarding"; "can't forward from a VF to itself"; ceiling
  `MLX5_MAX_FLOW_FWD_VPORTS 32` **[primary: `eswitch.h`]**.
- **Offload globally off** — `hw-tc-offload off` on the uplink → every `skip_sw`
  filter rejected. (`hw-tc-offload` is **not** documented in mlx5's own kernel
  docs — only in other drivers' rst and as the `NETIF_F_HW_TC` feature; treat
  the mlx5-specific requirement as **[secondary/unconfirmed]** even though it is
  the de-facto enablement.)

When rejected, the daemon surfaces `EOPNOTSUPP`/`ENOTSUPP` and counts
`filter_apply_errors_total{reason="skip_sw"}` (fail-closed) **[impl]**.

## 3. Conntrack (CT) offload internals & limits

> **Major correction (verified this pass):** the `ct_max_offloaded_conns`
> parameter, the `× 2`, `num_offloaded_flows`, and the `-ENOSPC` check
> **DO NOT EXIST in upstream torvalds/linux** — grepping mainline `en/tc_ct.c`
> for these returns zero matches **[primary, negative finding]**. They are
> **MLNX-OFED out-of-tree only**. A stock upstream/inbox-driver kernel has no
> such connection cap. This materially changes bm4x expectations depending on
> whether it runs inbox or MLNX-OFED/DOCA drivers.

- **Mechanism [primary: mainline `en/tc_ct.c`]:** CT is a two-table hardware
  pipeline — a **CT/CT-NAT** table (`struct mlx5_flow_table *ct` and `*ct_nat`;
  `attr->ft = nat ? ct_nat : ct`) matches tuple+zone, then forwards to the
  **post-action (`post_act`) table** (`attr->dest_ft =
  mlx5e_tc_post_act_get_ft(...)`) which resumes chain/prio processing. First
  packet of a flow misses to software, which programs the tuple; subsequent
  packets offload. Matches the daemon's chain-0/chain-1 model.
- **Steering mode [primary: `mlx5_tc_ct_fs_init`]:** the code default is
  `mlx5_ct_fs_dmfs_ops_get()`; SMFS/HMFS CT providers are selected only if the
  device steering mode is set to them (else `-EOPNOTSUPP`, "Requested flow
  steering mode is not enabled"). **So CT is supported in DMFS, SMFS AND HMFS in
  the code.** "CT requires SMFS" is a **vendor/operational recommendation**
  **[secondary/unconfirmed]** (NVIDIA ASAP² pages 404'd), not a code gate — but
  the daemon still probes for SMFS and degrades on non-SMFS because that is the
  documented-working configuration; verify DMFS CT offload empirically on your
  firmware before relying on it.
- **`post_ct` = the post_act table [primary]**, not a separately-named object.
- **ct_state bits [primary]:** written to metadata register **C2** (state upper
  16 bits, zone lower 16 bits); `EST BIT(1)`, `TRK BIT(2)`, `NAT BIT(3)`,
  `REPLY BIT(4)`, `RELATED BIT(5)`, `INVALID BIT(6)`, `NEW BIT(7)`.
- **Protocols [primary]:** ports parsed only for TCP/UDP (match level
  `MLX5_MATCH_L4`); GRE is L3-only; any other proto → `-EOPNOTSUPP`. TCP
  RST/FIN (`MLX5_CT_TCP_FLAGS_MASK`) stop offloading torn-down flows.
- **Capacity (MLNX-OFED ONLY) [secondary: OFED `tc_ct.c` mirror]:**
  `ct_max_offloaded_conns` (devlink U32, runtime). Default
  `MLX5_CT_DEFAULT_MAX_OFFLOADED_CONNS = UINT_MAX` (effectively unlimited unless
  set). The guard is `if (atomic_read(&num_offloaded_flows) >=
  max_offloaded_conns * 2) return -ENOSPC;` with the in-source comment "Two
  rules inserted per connection". **Crucially `-ENOSPC` is a pure SOFTWARE
  admission check in the driver, returned BEFORE any HW rule is programmed — not
  a firmware table-full error.** BlueField provisioning default is 1,000,000
  (`mlnx_bf_configure`); **adapter default unpublished [unconfirmed]**.
- **NAT on CT (MLNX-OFED) [secondary]:** `ct_action_on_nat_conns` devlink param;
  not used by this backend (no NAT in NetworkPolicy).
- **Aging [primary]:** netfilter-driven — `struct nf_flowtable *nf_ft`; HW entry
  add/del is triggered by `FLOW_CLS_*` offload callbacks; timeouts live in
  netfilter sysctls, not an mlx5 timer. UDP/TCP use different conntrack timeouts.
- **CT zones [primary + impl]:** `u16 zone` in reg C2 low 16 bits; tuple
  rhashtables sized `min_size = 16 * 1024`. The backend assigns a distinct zone
  per (rep, direction) so flows don't collide **[impl]**. Max zones / per-zone
  cap **[unconfirmed]** (`ESW_ZONE_ID_BITS` value not obtained).

## 4. Counters, stats & aging

- **Per-rule stats [primary: tc]:** `tc -s filter show dev <rep>` reports packet
  and byte counters per flower filter, plus `in_hw` / `not_in_hw` and
  `in_hw_count`. Offloaded-rule stats come from HW flow counters synced by the
  driver.
- **`used` time / aging [unconfirmed]:** the driver polls HW counters to update a
  rule's last-used time; idle offloaded flows can be aged/removed. Poll interval
  is driver-internal.
- **HW counter exhaustion [unconfirmed]:** the ASIC has a finite number of flow
  counters; at scale, rules may share counters or counter allocation can fail —
  a possible (undocumented) scale limit distinct from the steering-table limit.
- **Encap/neigh update path [unconfirmed]:** for tunnel rules the driver watches
  neighbour updates to refresh encap headers; not relevant to this backend's
  L3/L4 policy.

## 5. Hard limits & per-gen differences

| Limit | Value / behaviour | Confidence |
|-------|-------------------|-----------|
| Max VFs per PF | device-specific; read `sriov_totalvfs`. Commonly quoted ~127/port but **unverified** | [unconfirmed] |
| Max offloaded flower rules | **no published hard number** for any CX gen | [primary: absence] |
| Max priorities (non-root) | up to **21844** | [secondary: DPDK] |
| FDB tc chains / prios (without `ignore_flow_level` cap) | `FDB_TC_MAX_CHAIN 3`, `FDB_TC_MAX_PRIO 16`, `FDB_TC_LEVELS_PER_PRIO 2`; out-of-range → `-EOPNOTSUPP`. With the cap: effectively `UINT_MAX` | [primary: `fs_core.h`] |
| Max forward vports (mirred fan-out) | `MLX5_MAX_FLOW_FWD_VPORTS 32` | [primary: `eswitch.h`] |
| Flow-counter bulk / pool | bulk `BIT(15)`=32768; pool max `BIT(18)`=262144; also capped by `log_max_flow_counter_bulk` | [primary: `fs_counters.c`] |
| Stats refresh | polled, **1 s** default (`MLX5_FC_STATS_PERIOD`), `HW_STATS_DELAYED` — not real-time | [primary] |
| Insertion rate | SMFS > DMFS (qualitative); HWS "millions/sec" | [primary/secondary] |
| CT connections | **MLNX-OFED only**: `ct_max_offloaded_conns × 2`; NOT in upstream | [secondary] |
| Modify-header / reformat | per-ASIC; SMFS modify-header pattern/arg needs format `≥ CONNECTX_6DX` | [primary: `dr_domain.c`] |
| VLAN-push-on-RX (SMFS) | needs steering format **> CX5** (`fs_dr.c`) | [primary] |
| Meters / policers offload (`tc police`) | uses the **ASO flow-meter** → **CX6-class** (CX6 Lx/Dx/CX7, BF-2+), **NOT CX5** | [primary mechanism; unconfirmed exact gen] |
| Sample offload (`tc sample`/psample) | gated on FW cap bits (`SAMPLER` obj + `ignore_flow_level`), **CX5+**, NOT CX6-only | [primary mechanism; secondary CX5 baseline] |
| Mirror offload (`tc mirred mirror`) | multi-dest FDB rule; CX5+ | [primary + secondary] |
| HMFS/HWS | needs `wqe_based_flow_table_update_cap`; DPDK floor CX6 Dx; sole mode on CX9+; CX6 Lx status unknown | [primary caps; secondary gen] |
| STEv0 (CX5) checksum-recalc | per-vport cached FW FT workaround for "a HW bug in STEv0" | [primary: `dr_domain.c`] |

## 6. switchdev-mode transition edge cases

- **SMFS-before-switchdev — CONFIRMED IN CODE [primary: `fs_core.c`
  `mlx5_fs_mode_validate()`]:** if `mlx5_eswitch_mode(dev) ==
  MLX5_ESWITCH_OFFLOADS` the steering-mode change returns `-EOPNOTSUPP` with
  "Changing fs mode is not supported when eswitch offloads enabled." So SMFS
  **must** be set before switchdev. This is the main provisioning footgun for
  bm4x.
- **Mode-set is blocked in several states [primary-extracted:
  `eswitch_offloads.c`]:** "Can't change eswitch mode during firmware reset"
  (`-EBUSY`); "Can't change mode, E-Switch is busy"; "Can't change eswitch mode
  when IPsec SA and/or policies are configured"; "Can't change mode while
  devlink traps are active"; "Can't change E-Switch mode to switchdev when
  netdev net namespace has diverged from the devlink's."
- **Mode switch fully tears down + rebuilds [primary]:** the transition sets
  `eswitch_operation_in_progress`, blocks representors (`mlx5_esw_reps_block`),
  disables the eSwitch, runs `esw_offloads_start/stop`, then unblocks; LAG
  changes are disabled around it. Existing offloaded rules are dropped — do it
  before pods land.
- **devlink reload supported [primary: devlink/mlx5.rst]:** "supports reloading
  via `DEVLINK_CMD_RELOAD`."
- **Representor lifecycle [primary: representors.rst + impl]:** representors are
  created/destroyed dynamically as VFs/ports appear and disappear; the daemon's
  Flush tolerates a vanished rep.
- **PCI FLR / firmware reset / link down [unconfirmed]:** a function-level reset
  or FW reset can flush offloaded rules and re-create representors; the daemon's
  next reconcile should reconverge, but in-flight connections lose CT state.
  (Exact FLR/link-down representor-teardown behaviour not verified from source
  this pass.)

## 7. Multi-port / VF-LAG / bonding

- **Shared (single) FDB across bonded PFs — CONFIRMED [primary: `lag/lag.c`,
  `lag/shared_fdb.c`]:** `mlx5_lag_shared_fdb_supported()` →
  `mlx5_lag_create_single_fdb()`, logging "Operation mode is single FDB". This is
  the upstream name for what NVIDIA calls VF-LAG. Preconditions
  (`mlx5_lag_shared_fdb_supported_filter`): **both** PFs must be
  `is_mdev_switchdev_mode` AND `mlx5_eswitch_vport_match_metadata_enabled` AND
  have `lag_native_fdb_selection` + `root_ft_on_other_esw` caps; the master also
  needs `esw_shared_ingress_acl`. Reps from both ports are merged into one FDB
  via `mlx5_eswitch_offloads_single_fdb_add_one()`.
- **Multipath LAG limits [primary: `lag/mp.c`]:** max **2 ports**
  (`MLX5_LAG_MULTIPATH_OFFLOADS_SUPPORTED_PORTS 2`), **IPv4-only** (`if
  (info->family != AF_INET) return NOTIFY_DONE;`), no duplicate-nexthop routes,
  disabled in Socket-Direct mode.
- **Shared switch id [primary: switchdev.rst]:** "returning the same physical ID
  for each port of a switch"; a port moved into a bond sees its upper master
  change. The backend keys discovery on `phys_switch_id` + `phys_port_name`, so a
  shared switch id across bonded PFs should resolve — but the "same
  `phys_switch_id` across bonded PF representors" specific claim is
  **[secondary/inferred]** from the shared-FDB peer logic, not a verbatim mlx5
  statement; **verify on real bonded hardware**.

## 8. Subfunctions (SF) vs VFs **[secondary/unconfirmed]**

Subfunctions share a PF's PCI function but get their own switchdev port and
representor, created via `devlink port add ... flavour pcisf`. Representor
`phys_port_name` form is `pfXsfN`. **The backend does not currently handle SF
representors** (discovery only parses `pfXvfY`/`vfY`), so SF-based deployments
are unsupported today — a known gap.

## 9. Firmware & driver version dependencies **[secondary/unconfirmed]**

- CT offload, HWS, and some modify-header/reformat features have **minimum
  firmware** floors per ConnectX gen — NVIDIA documents these in ASAP²/DOCA/OFED
  release notes; **not verified here**, read your release notes.
- **MLNX_OFED vs inbox driver:** several params (`ct_max_offloaded_conns`,
  `ct_action_on_nat_conns`) are **out-of-tree (OFED-only)** and absent from a
  stock upstream kernel; feature parity differs by OFED/DOCA version.

## 10. Visibility / packet inspection (incl. the BGP-over-SR-IOV case)

What you can see/log/filter for traffic on a VF (e.g. an app running BGP on
tcp/179 over an SR-IOV VF). Summary of what's possible **today on CX5+** vs a
**stretch**:

| Capability | Verdict | HW | Confidence |
|------------|---------|----|-----------|
| Count bytes/packets of a flow (flower filter + `tc -s filter show`, `in_hw_count`) | ✅ today | CX5+ | [primary] |
| Allow/deny a flow by 5-tuple (tcp/179 + peer IPs), offloaded | ✅ today | CX5+ | [primary] |
| Rate-limit a flow (`tc police`, bps/pps) | ✅ but ASO flow-meter → **CX6-class**, not CX5 | CX6 Lx/Dx/CX7 | [primary mechanism] |
| Copy matched packets to a monitor via `tc action mirred mirror` (tcpdump there) | ✅ today | CX5+ | [primary+secondary] |
| Sample matched packets via `tc action sample` → psample/sFlow collector | ✅ today (FW-cap gated, **CX5+** not CX6-only) | CX5+ | [primary mechanism] |
| See offloaded packets with `tcpdump -i <rep>` | ⚠️ **only miss/slow-path**; offloaded fast-path is invisible | all | [primary] |
| Inspect BGP message contents (OPEN/UPDATE, AS_PATH, prefixes) in the eSwitch | ❌ **impossible** — flower is L2/L3/L4 only | any adapter | [primary] |
| Host-side ConnectX DPI/L7 as a steering match | ❌ no evidence; a DPU job | — | [unconfirmed] |

Details:

- **Counters [primary]:** flower dumps `TCA_FLOWER_IN_HW_COUNT` and sets
  `TCA_CLS_FLAGS_IN_HW`; `mlx5e_stats_flower()` reads HW via
  `mlx5_fc_query_cached()` and pushes `flow_stats_update(...,
  FLOW_ACTION_HW_STATS_DELAYED)`. Delayed/cached (1 s poll), not real-time. The
  `in_hw`/`in_hw_count` keywords are iproute2 print artifacts, **absent from the
  man pages**.
- **Representor only carries the slow path [primary]:** `en_rep.c` creates the
  representor root FT empty (`max_fte = 0`, miss→next table); a fully-offloaded
  flow switches inside the eSwitch and **never traverses the representor's RX**,
  so `tcpdump -i <rep>` sees only miss/first-packet/control/non-offloaded
  traffic. `switchdev.rst`: the port netdev is "a conduit for control traffic".
  To capture offloaded traffic: `mirred mirror` it, capture in-guest on the VF,
  or force software with `ethtool -K <uplink> hw-tc-offload off`.
- **sample [primary]:** `en/tc/sample.c` builds a FW **Flow Sampler Object** +
  slow-path termination table forwarding a fraction to the eSwitch management
  vport; `mlx5e_tc_sample_skb → psample_sample_packet()`. Gated on
  `MLX5_HCA_CAP_GENERAL_OBJECT_TYPES_SAMPLER` **and**
  `MLX5_CAP_ESW_FLOWTABLE_FDB(mdev, ignore_flow_level)` — FW capability bits,
  **CX5+**, not a CX6 generation floor (correction to a common assumption).
- **mirror [primary+secondary]:** `tc action mirred mirror` to a spare VF/dummy
  netdev; NVIDIA ASAP²: "The mirrored VF can be used to run traffic analyzer
  (tcpdump, wireshark, etc)."
- **No L7 [primary]:** flower keys top out at L4 (`TCF_LAYER_TRANSPORT`); there
  is no payload/byte-offset/L7 key. BGP message contents live in the TCP payload
  → not matchable in the eSwitch. `action ct` adds flow *state* only, not payload
  inspection.
- **DPU path [secondary]:** true L7/DPI is a BlueField (DPU) design, not a host
  ConnectX-adapter feature. Confirmed via a browser against the NVIDIA DOCA docs
  (v3.4.0, `networking-docs.nvidia.com/doca`): **DOCA Flow Inspector** is
  described as "the DOCA Flow Inspector service container **on top of NVIDIA
  BlueField**", and **DOCA Pipeline Language (DPL)** is "a software development
  solution based on a domain-specific programming language … for NVIDIA
  BlueField" — i.e. programmable packet processing lives on the DPU Arm cores.
  The standalone DOCA **DPI/RegEx (RXP)** library that older docs described is
  no longer a top-level DOCA 3.x component (renamed/folded), so the specific
  "RXP RegEx engine" claim stays **[unconfirmed]** — but the architectural point
  (L7 inspection = a DPU job, steer VF traffic to Arm cores) is now
  **[secondary]**. Out of scope for this host-side backend.

**BGP-over-SR-IOV recommendation:** count BGP and allow/deny it by 5-tuple entirely in HW on
CX5+; rate-limit needs CX6+; get a packet *copy* via mirror/sample; but plain
tcpdump on the rep won't show the offloaded fast path, and BGP-message-level
inspection is not possible in the eSwitch at all.

---

## Appendix: quick reference commands **[primary]**

```sh
# steering mode / CT capacity
devlink dev param show pci/<bdf> name flow_steering_mode
devlink dev param show pci/<bdf> name ct_max_offloaded_conns
# eswitch mode + inline
devlink dev eswitch show pci/<bdf>
# offload feature
ethtool -k <uplink> | grep hw-tc-offload
# per-rule stats + offload state
tc -s filter show dev <rep> ingress
tc -j -s filter show dev <rep> ingress | jq '.[] | {pref,in_hw,not_in_hw,in_hw_count}'
# live filter events
tc monitor
# SMFS software-steering rule dump (FDB domain only; SMFS mode only) [primary: dr_dbg.c]
ls /sys/kernel/debug/mlx5/<pci-bdf>/steering/fdb/
# copy a flow for inspection (offloaded fast path is invisible to tcpdump on the rep)
tc filter add dev <rep> ingress protocol ip flower skip_sw ip_proto tcp dst_port 179 \
   action mirred egress mirror dev <monitor-netdev>
```

The mlx5 debugfs steering dump path `/sys/kernel/debug/mlx5/<bdf>/steering/fdb/`
is created by `mlx5dr_dbg_init_dump()` **[primary: `steering/sws/dr_dbg.c`]** and
exists **only in SMFS mode** and **only for the FDB domain** (the source warns
"Steering dump is not supported for NIC RX/TX domains").
