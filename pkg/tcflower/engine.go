/*
Copyright 2026 Deutsche Telekom AG.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tcflower

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// ipProto is an IANA IP protocol number. The zero value means "match any L4
// protocol" (no ip_proto key emitted).
type ipProto uint8

// ipFamily selects the L3 address family (and thus the ethertype and IP key
// set) of a single flower filter. A flower filter matches exactly ONE
// ethertype, so every emitted FlowerRule is single-family. familyV4 is the zero
// value, so a stateless IPv4 rule literal without an explicit Family is
// byte-for-byte identical to before.
//
// familyAny is NOT a value a FlowerRule ever carries: a "match any address"
// policy rule (empty peers) must cover BOTH families on a first-match stateless
// pipeline, so it is expanded at build time into one familyV4 filter and one
// familyV6 filter (see expandRule / defaultDeny / ctEntryRules).
type ipFamily uint8

const (
	familyV4 ipFamily = iota // 0 — IPv4 (ethertype 0x0800, KeyIPv4*)
	familyV6                 // 1 — IPv6 (ethertype 0x86dd, KeyIPv6*)
)

// bothFamilies is the ordered set a match-any / default-deny / CT-entry rule is
// expanded across so that both ethertypes are enforced.
var bothFamilies = [...]ipFamily{familyV4, familyV6}

// L2/L3/L4 protocol constants (IANA / EtherType). Hardcoded rather than taken
// from golang.org/x/sys/unix so the pure translation layer stays
// cross-platform (ETH_P_IP / ETH_P_IPV6 are Linux-only and the golden tests
// run on darwin).
const (
	ethTypeIPv4 uint16 = 0x0800 // ETH_P_IP
	ethTypeIPv6 uint16 = 0x86dd // ETH_P_IPV6

	ipProtoAny  ipProto = 0
	ipProtoTCP  ipProto = 6
	ipProtoUDP  ipProto = 17
	ipProtoSCTP ipProto = 132
)

// familyOfAddr classifies a netip.Addr into its L3 family. IPv4-mapped v6
// addresses (Is4()==false) are treated as v6.
func familyOfAddr(a netip.Addr) ipFamily {
	if a.Is4() {
		return familyV4
	}
	return familyV6
}

// ethTypeFor returns the ethertype for a family.
func ethTypeFor(f ipFamily) uint16 {
	if f == familyV6 {
		return ethTypeIPv6
	}
	return ethTypeIPv4
}

// Direction is the MultiNetworkPolicy rule direction that a FlowerRule
// enforces. It is mapped to a VF-representor tc qdisc parent in toObject.
//
// DIRECTION MAPPING (IMPORTANT — needs empirical hardware validation):
// From the host's point of view the VF representor is a mirror of the pod's
// VF, so traffic directions are INVERTED relative to the pod:
//
//	representor INGRESS qdisc (packets the representor receives) == traffic
//	    leaving the pod           == MultiNetworkPolicy EGRESS  (DirEgress)
//	representor EGRESS qdisc  (packets the representor transmits) == traffic
//	    entering the pod          == MultiNetworkPolicy INGRESS (DirIngress)
//
// This inversion is the crux of the tc flower backend and MUST be validated on
// real switchdev hardware before this backend is trusted in production.
type Direction int

const (
	// DirIngress enforces MultiNetworkPolicy ingress (traffic TO the pod). It
	// is installed on the representor's EGRESS parent.
	DirIngress Direction = iota
	// DirEgress enforces MultiNetworkPolicy egress (traffic FROM the pod). It
	// is installed on the representor's INGRESS parent.
	DirEgress
)

func (d Direction) String() string {
	if d == DirIngress {
		return "ingress"
	}
	return "egress"
}

// Verdict is the terminal action of a FlowerRule.
type Verdict int

const (
	// VerdictAccept passes the packet (tc gact TC_ACT_OK).
	VerdictAccept Verdict = iota
	// VerdictDrop drops the packet (tc gact TC_ACT_SHOT).
	VerdictDrop
)

func (v Verdict) String() string {
	if v == VerdictDrop {
		return "drop"
	}
	return "accept"
}

// OffloadMode selects how a flower filter's hardware-offload flags are stamped
// (see toObject). It is derived once from CommonRuleConfig.TCOffloadMode and
// threaded onto every FlowerRule so the mode is captured in the comparable rule
// identity (and thus in the reconcile diff key). OffloadHardware is the zero
// value, so a rule literal without an explicit Offload is byte-for-byte the
// production hardware-only rule it always was.
type OffloadMode uint8

const (
	// OffloadHardware (zero value / "hardware") stamps skip_sw: the filter is
	// hardware-only and fail-closed — the kernel rejects it if the NIC cannot
	// offload it, rather than silently enforcing it in software. Production
	// default on ConnectX switchdev NICs.
	OffloadHardware OffloadMode = iota
	// OffloadSoftware ("software") stamps skip_hw: the filter is enforced in the
	// kernel software datapath. Enables real enforcement on veth/netdevsim (no
	// hardware offload) for CI and graceful use on non-offload NICs.
	OffloadSoftware
	// OffloadAuto ("auto") would stamp neither flag (kernel offloads if it can,
	// else software). It is NOT supported yet: managed-filter detection keys on
	// an explicit skip_sw/skip_hw flag, so a flag-less filter cannot be
	// distinguished from a foreign one. parseOffloadMode rejects it.
	OffloadAuto
)

func (m OffloadMode) String() string {
	switch m {
	case OffloadSoftware:
		return "software"
	case OffloadAuto:
		return "auto"
	default:
		return "hardware"
	}
}

// parseOffloadMode normalizes the CommonRuleConfig.TCOffloadMode string into a
// typed OffloadMode. The empty string and "hardware" both map to the
// fail-closed hardware-only default. "auto" is rejected as not-yet-supported
// (see OffloadAuto); any other value is an error.
func parseOffloadMode(s string) (OffloadMode, error) {
	switch s {
	case "", "hardware":
		return OffloadHardware, nil
	case "software":
		return OffloadSoftware, nil
	case "auto":
		return OffloadAuto, fmt.Errorf("tc offload mode %q is not yet supported: "+
			"managed-filter detection requires an explicit skip_sw/skip_hw flag", s)
	default:
		return OffloadHardware, fmt.Errorf("invalid tc offload mode %q: want \"hardware\", \"software\" (or \"auto\")", s)
	}
}

// offloadFlags maps an OffloadMode to the go-tc flower Flags value stamped in
// toObject: skip_sw (hardware-only) for the default, skip_hw (software) for
// software mode. OffloadAuto is unreachable here (rejected by parseOffloadMode)
// and falls through to the fail-closed hardware default.
func offloadFlags(m OffloadMode) uint32 {
	if m == OffloadSoftware {
		return tc.SkipHw
	}
	return tc.SkipSw
}

// CTMode governs whether the stateful conntrack-offload (CT) pipeline is used,
// and how the backend reacts when the NIC/eSwitch cannot hardware-offload it
// (which requires SMFS steering; the default DMFS mode cannot offload CT).
//
// It is resolved once from CommonRuleConfig.CTMode. The zero value is CTModeAuto
// so an unset config degrades gracefully rather than failing closed on DMFS.
type CTMode uint8

const (
	// CTModeAuto (zero / "auto"): emit the CT pipeline only when hardware CT
	// offload is available (SMFS confirmed). When it is not — DMFS, or the
	// steering mode cannot be determined — fall back to the STATELESS pipeline
	// (which offloads on any switchdev NIC) and log the loss of stateful
	// established/related tracking. Maximizes successfully-offloaded enforcement.
	CTModeAuto CTMode = iota
	// CTModeRequire ("require"): always emit the CT pipeline. If the NIC cannot
	// offload it the skip_sw filters are rejected (fail-closed) and the interface
	// is left unenforced rather than silently degraded. For SMFS fleets that want
	// stateful-or-error.
	CTModeRequire
	// CTModeOff ("off"): never emit the CT pipeline; always use the stateless
	// first-match pipeline. Stateful return traffic is not tracked.
	CTModeOff
)

func (m CTMode) String() string {
	switch m {
	case CTModeRequire:
		return "require"
	case CTModeOff:
		return "off"
	default:
		return "auto"
	}
}

// parseCTMode normalizes the CommonRuleConfig.CTMode string into a typed CTMode.
// The empty string and "auto" both map to CTModeAuto. Any other value is an
// error (fail-closed: an unrecognized mode aborts rather than guessing).
func parseCTMode(s string) (CTMode, error) {
	switch s {
	case "", "auto":
		return CTModeAuto, nil
	case "require":
		return CTModeRequire, nil
	case "off":
		return CTModeOff, nil
	default:
		return CTModeAuto, fmt.Errorf("invalid tc CT mode %q: want \"auto\", \"require\" or \"off\"", s)
	}
}

// tc gact control actions (from include/uapi/linux/pkt_cls.h).
const (
	tcActOK        uint32 = 0          // TC_ACT_OK   — accept/pass
	tcActPipe      uint32 = 3          // TC_ACT_PIPE — continue to the next action in the list
	tcActShot      uint32 = 2          // TC_ACT_SHOT — drop
	tcActGotoChain uint32 = 0x40000000 // TC_ACT_GOTO_CHAIN — jump to (control & TC_ACT_EXT_VAL_MASK) chain
)

// conntrack ct_state flag bits (from include/uapi/linux/pkt_cls.h,
// TCA_FLOWER_KEY_CT_FLAGS_*). These are matched via the flower KeyCtState /
// KeyCtStateMask key pair. A match encodes (value, mask): a bit set in the mask
// is examined; the corresponding value bit is the required setting.
const (
	ctStateNew         uint16 = 1 << 0 // +new  — first packet of a new connection
	ctStateEstablished uint16 = 1 << 1 // +est  — part of an established connection
	ctStateRelated     uint16 = 1 << 2 // +rel  — related to an established connection
	ctStateTracked     uint16 = 1 << 3 // +trk  — the packet has been through conntrack
	ctStateInvalid     uint16 = 1 << 4 // +inv  — conntrack could not classify the packet
	ctStateReply       uint16 = 1 << 5 // +rpl  — reply direction of a tracked connection
)

// conntrack ct action bitfield (struct tc_ct / TCA_CT_ACT_* from
// include/uapi/linux/tc_act/tc_ct.h). Carried in go-tc's Ct.Action.
const (
	ctActCommit uint16 = 1 // TCA_CT_ACT_COMMIT — commit the (new) connection to conntrack
	ctActForce  uint16 = 2 // TCA_CT_ACT_FORCE
	ctActClear  uint16 = 4 // TCA_CT_ACT_CLEAR
	ctActNAT    uint16 = 8 // TCA_CT_ACT_NAT
)

// The full ct_state and ct-action bit sets are declared above to document the
// UAPI as a unit; only a subset is currently emitted. Reference the remainder
// so the enum stays complete without tripping the unused-symbol linter.
var _ = [...]uint16{ctStateNew, ctStateReply, ctActForce, ctActClear, ctActNAT}

// CT pipeline chain numbers. In stateful (CT offload) mode traffic is split
// across two tc filter chains per representor parent:
//   - chain 0 (ctEntryChain) is the entry chain: it dispatches untracked
//     packets through conntrack and statefully accepts established/related
//     return traffic (mirroring the nft backend's allowConntracked).
//   - chain 1 (ctPolicyChain) holds the per-policy allow/except/default-deny
//     rules — the same first-match set as the stateless pipeline, except each
//     accept also commits the NEW connection so its reply is tracked.
//
// In stateless mode everything lives in chain 0 (ctEntryChain), exactly as in
// Phase 2, so the stateless golden output is unchanged.
const (
	ctEntryChain  uint32 = 0
	ctPolicyChain uint32 = 1
)

// FlowerRule is an abstract, comparable description of one desired tc flower
// filter. It is intentionally independent of go-tc marshaling so it can be
// unit-tested as golden data. toObject converts it to a go-tc Object.
//
// Both IPv4 and IPv6 are supported: each FlowerRule is single-family (see
// Family), and rules that must cover both families (match-any allow,
// default-deny, CT-entry) are expanded into one v4 and one v6 FlowerRule at
// build time.
type FlowerRule struct {
	// Rep is the host VF representor netdev name (the enforcement point).
	Rep string
	// Offload selects how toObject stamps the filter's hardware-offload flags
	// (skip_sw for OffloadHardware, skip_hw for OffloadSoftware). It is a
	// comparable scalar so FlowerRule stays a valid map key, and it is part of
	// the rule identity so hardware- and software-mode filters never alias in
	// the reconcile diff. OffloadHardware is the zero value, so a rule literal
	// without an explicit Offload is the production hardware-only rule.
	Offload OffloadMode
	// Direction selects the policy direction (and thus representor parent).
	Direction Direction
	// Priority is the tc filter priority. Lower = evaluated first. Assigned
	// deterministically by BuildFlowerRules (see assignPriorities).
	Priority uint16

	// Proto is the IP protocol to match (ipProtoTCP/UDP/SCTP). 0 = match any
	// L4 protocol (no ip_proto key).
	Proto ipProto

	// Family is the L3 address family (and thus ethertype + IP key set) this
	// filter matches. A flower filter matches exactly one ethertype, so every
	// FlowerRule is single-family. When Src/Dst is a valid prefix the family
	// necessarily agrees with the prefix's family; Family is authoritative for
	// match-any/default-deny/CT rules that carry no address prefix. familyV4 is
	// the zero value so a stateless IPv4 literal is unchanged.
	Family ipFamily

	// Src / Dst carry the address match as an IP prefix. For policy ingress
	// the peer is the SOURCE (Src); for policy egress the peer is the
	// DESTINATION (Dst). A zero netip.Prefix{} (i.e. !IsValid()) means no
	// address match (match-any).
	Src netip.Prefix
	Dst netip.Prefix

	// HasPort reports whether an L4 destination-port match is present. When
	// true PortMin..PortMax (inclusive) is the matched range; PortMin==PortMax
	// denotes a single port.
	HasPort bool
	PortMin uint16
	PortMax uint16

	// Verdict is the terminal action.
	Verdict Verdict

	// --- CT (stateful) offload fields (Phase 4) ---
	//
	// These are all zero-valued for stateless (Phase 2) rules, so a stateless
	// FlowerRule is byte-for-byte identical to before and the existing golden
	// output is unchanged. They are only populated when CT is enabled.

	// Chain is the tc filter chain this rule lives in (ctEntryChain /
	// ctPolicyChain). Zero == chain 0 (the default), which is also the only
	// chain used in stateless mode.
	Chain uint32

	// HasCTState reports whether a ct_state match (CTState/CTStateMask) is
	// present on this filter. Used by the chain-0 dispatch/accept rules.
	HasCTState  bool
	CTState     uint16 // ct_state value bits (see ctState* consts)
	CTStateMask uint16 // ct_state mask bits: which flags are examined

	// CTCommit, when set on an accept rule, prepends a `ct commit` action
	// (zone CTZone) before the terminal gact pass, so the NEW connection is
	// committed to conntrack and its reply direction is tracked.
	CTCommit bool

	// CTDispatch, when set, marks the chain-0 untracked-packet rule whose
	// action list is [ct (zone CTZone) pipe, gact goto_chain GotoChain]: send
	// the packet through conntrack, then continue policy evaluation in
	// GotoChain.
	CTDispatch bool
	GotoChain  uint32 // goto-chain target for a CTDispatch rule

	// CTZone is the conntrack zone used by the ct/ct-commit actions. It is
	// per-representor+direction so connections on different reps/directions do
	// not collide in a shared conntrack table.
	CTZone uint16
}

// priority tiers. Lower tier => numerically lower priority => evaluated first.
// Ordering guarantees that a more-specific "except" drop precedes the broader
// "allow" it carves out, and that the catch-all default-deny is evaluated last.
const (
	tierExcept  = 0 // ipBlock.Except drops
	tierAllow   = 1 // allow (accept) rules
	tierDefault = 2 // default-deny catch-all
)

// priority tiers WITHIN the CT entry chain (chain 0). Priorities are numbered
// independently per (direction, chain), so these reuse the same numeric space
// as the policy-chain tiers above without colliding. The ct_state matches are
// mutually exclusive (they differ in the +trk / +est / +rel / +inv bits), so
// ordering only needs to be deterministic, not semantically layered; the tiers
// give a stable, readable order.
const (
	tierCTInvalid  = 0 // +trk+inv  -> drop (defensive)
	tierCTEstRel   = 1 // +trk+est / +trk+rel -> accept (stateful return traffic)
	tierCTDispatch = 2 // -trk      -> ct + goto policy chain
)

// candidate is an in-progress FlowerRule plus the metadata used to allocate a
// deterministic priority.
type candidate struct {
	rule     FlowerRule
	tier     int
	policyID string // "" for the default-deny catch-all
}

// BuildFlowerRules performs the pure translation of the MultiNetworkPolicies
// that apply to pod/iface into an ordered set of abstract FlowerRules. It does
// not touch netlink; toObject / the Driver handle installation.
//
// Semantics mirror pkg/server/netfilterrules.go, re-expressed for a stateless,
// first-match tc flower pipeline:
//   - policy selection: identical to pkg/server (see select.go).
//   - each ingress/egress rule is expanded to the (ports × peers) cross
//     product; every emitted accept filter carries the FULL match (proto +
//     dst port + peer address) because tc flower cannot AND separate filters.
//   - ipBlock: CIDR => accept; each Except CIDR => higher-priority drop.
//   - podSelector/namespaceSelector: resolved to peer pod /32 (v4) and /128
//     (v6) addresses (restricted to the policy networks), one rule per address.
//   - empty peers => match-any address; empty ports => match-any L4.
//   - a lowest-priority catch-all drop is emitted per direction that has at
//     least one selected policy (default-deny).
//
// DUAL-STACK: a flower filter matches exactly ONE ethertype, so each emitted
// FlowerRule is single-family. A rule with an IPv4 peer emits an IPv4 filter
// (ethertype 0x0800, KeyIPv4*); a rule with an IPv6 peer emits an IPv6 filter
// (ethertype 0x86dd, KeyIPv6*). "Match any address" rules (empty peers), the
// per-direction default-deny catch-all, and the CT-entry (chain-0) rules carry
// no L3 address key but still carry an ethertype, so they are expanded into
// BOTH a v4 and a v6 filter to enforce both families on the first-match
// stateless/stateful pipeline.
func BuildFlowerRules(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig,
	policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo, iface controllers.InterfaceInfo) ([]FlowerRule, error) {
	// cfg.CTEnabled selects the stateful CT-offload pipeline; the remaining
	// cfg fields (common-prefix / ICMP rules) are Phase 3+ and kept in the
	// signature for parity with the nft engine.
	ctEnabled := cfg.CTEnabled

	// The offload mode is uniform across every filter this call emits, so it is
	// parsed once and stamped onto each candidate before priority assignment
	// (below). Parsing here fails closed: an invalid/unsupported mode aborts the
	// build rather than emitting filters with the wrong (or missing) flags.
	mode, err := parseOffloadMode(cfg.TCOffloadMode)
	if err != nil {
		return nil, err
	}

	rep := iface.RepresentorDevice
	if rep == "" {
		return nil, fmt.Errorf("interface %q has no resolved representor device", iface.InterfaceName)
	}

	ingressPolicies, egressPolicies := selectPolicies(policyMap, pod, podInfo)

	var cands []candidate

	for _, sp := range ingressPolicies {
		for idx, rule := range sp.policy.Spec.Ingress {
			c, err := expandRule(ctx, deps, rep, DirIngress, sp, idx, rule.Ports, rule.From, podInfo, ctEnabled)
			if err != nil {
				return nil, err
			}
			cands = append(cands, c...)
		}
	}
	for _, sp := range egressPolicies {
		for idx, rule := range sp.policy.Spec.Egress {
			c, err := expandRule(ctx, deps, rep, DirEgress, sp, idx, rule.Ports, rule.To, podInfo, ctEnabled)
			if err != nil {
				return nil, err
			}
			cands = append(cands, c...)
		}
	}

	// default-deny catch-all per direction that carries any policy, plus (when
	// CT is enabled) the chain-0 conntrack dispatch/stateful-accept rules that
	// sit in front of the per-policy chain.
	if len(ingressPolicies) > 0 {
		cands = append(cands, defaultDeny(rep, DirIngress, ctEnabled)...)
		if ctEnabled {
			cands = append(cands, ctEntryRules(rep, DirIngress)...)
		}
	}
	if len(egressPolicies) > 0 {
		cands = append(cands, defaultDeny(rep, DirEgress, ctEnabled)...)
		if ctEnabled {
			cands = append(cands, ctEntryRules(rep, DirEgress)...)
		}
	}

	// Stamp the (uniform) offload mode onto every candidate. Doing it here keeps
	// buildRule/defaultDeny/ctEntryRules mode-agnostic and guarantees the mode
	// is part of the comparable rule identity used for the reconcile diff.
	for i := range cands {
		cands[i].rule.Offload = mode
	}

	return assignPriorities(cands), nil
}

// ctZoneFor derives a stable, non-zero conntrack zone for a representor and
// direction so connections tracked on different reps/directions do not collide
// in the shared eSwitch conntrack table. The two directions of the same rep get
// distinct zones (the low bit encodes the direction) so pod-ingress and
// pod-egress flows are tracked independently.
func ctZoneFor(rep string, dir Direction) uint16 {
	h := fnv.New32a()
	_, _ = fmt.Fprint(h, rep)
	// Fold the 32-bit hash into 15 bits and use the low bit for direction,
	// keeping the zone within uint16 and non-zero. The 0x7fff mask makes the
	// uint16 conversion provably lossless.
	base := uint16(h.Sum32()&0x7fff) << 1 //nolint:gosec // masked to 15 bits, fits uint16
	zone := base | uint16(dir)            //nolint:gosec // dir is a 0/1 enum
	if zone == 0 {
		zone = 1
	}
	return zone
}

// ctEntryRules builds the chain-0 (ctEntryChain) conntrack pipeline for a
// direction. Ordered by tier (lower prio evaluated first):
//   - +trk+inv               -> drop (defensive: reject packets conntrack
//     could not classify, mirroring nft's implicit invalid handling).
//   - +trk+est / +trk+rel    -> accept (stateful return traffic; mirrors the
//     nft backend's allowConntracked "ct state related,established accept").
//   - -trk (untracked)       -> ct(zone) pipe + goto ctPolicyChain: run the
//     packet through conntrack, then evaluate the per-policy rules.
//
// NEW packets fall through conntrack as untracked on first sight, get dispatched
// by the -trk rule, and are then matched (and committed) by the policy chain.
//
// PER-FAMILY: the ct_state match itself is L3-agnostic, but a flower filter
// still carries an ethertype (KeyEthType). An ethertype-less flower filter is
// not what we emit — toObject always stamps KeyEthType — so the ct-entry rules
// are emitted for BOTH families (v4 + v6). That guarantees established/related
// v6 return traffic is accepted and untracked v6 packets are dispatched through
// conntrack, exactly as for v4. The zone is per (rep, direction) and shared by
// both families (a connection's family does not change), matching the policy
// chain's commit zone.
func ctEntryRules(rep string, dir Direction) []candidate {
	zone := ctZoneFor(rep, dir)
	var out []candidate
	for _, fam := range bothFamilies {
		base := FlowerRule{Rep: rep, Direction: dir, Family: fam, Chain: ctEntryChain, HasCTState: true, CTZone: zone}

		invalid := base
		invalid.CTState = ctStateTracked | ctStateInvalid
		invalid.CTStateMask = ctStateTracked | ctStateInvalid
		invalid.Verdict = VerdictDrop

		established := base
		established.CTState = ctStateTracked | ctStateEstablished
		established.CTStateMask = ctStateTracked | ctStateEstablished
		established.Verdict = VerdictAccept

		related := base
		related.CTState = ctStateTracked | ctStateRelated
		related.CTStateMask = ctStateTracked | ctStateRelated
		related.Verdict = VerdictAccept

		dispatch := base
		dispatch.CTState = 0
		dispatch.CTStateMask = ctStateTracked // match -trk (tracked bit examined, value 0)
		dispatch.CTDispatch = true
		dispatch.GotoChain = ctPolicyChain
		dispatch.Verdict = VerdictAccept // unused for a dispatch rule; goto-chain is the control action

		out = append(out,
			candidate{rule: invalid, tier: tierCTInvalid},
			candidate{rule: established, tier: tierCTEstRel},
			candidate{rule: related, tier: tierCTEstRel},
			candidate{rule: dispatch, tier: tierCTDispatch},
		)
	}
	return out
}

// defaultDeny builds the lowest-precedence catch-all drop for a direction. When
// CT is enabled it lives in the post-conntrack policy chain (ctPolicyChain).
//
// The catch-all carries no L3 address key but still carries an ethertype, so it
// is emitted for BOTH families: a v4 catch-all drop AND a v6 catch-all drop.
// Without the v6 drop, IPv6 traffic would fall off the end of the chain and be
// implicitly accepted, defeating the default-deny.
func defaultDeny(rep string, dir Direction, ctEnabled bool) []candidate {
	out := make([]candidate, 0, len(bothFamilies))
	for _, fam := range bothFamilies {
		out = append(out, candidate{
			rule: FlowerRule{Rep: rep, Direction: dir, Family: fam, Chain: policyChain(ctEnabled), Verdict: VerdictDrop},
			tier: tierDefault,
		})
	}
	return out
}

// policyChain returns the chain the per-policy allow/except/default-deny rules
// live in: the post-conntrack chain when CT is enabled, else chain 0.
func policyChain(ctEnabled bool) uint32 {
	if ctEnabled {
		return ctPolicyChain
	}
	return ctEntryChain
}

// expandRule expands a single ingress/egress rule (ports × peers) into
// candidates for the given direction.
func expandRule(ctx context.Context, deps controllers.PolicyDeps, rep string, dir Direction,
	sp selectedPolicy, ruleIdx int, ports []multiv1beta1.MultiNetworkPolicyPort,
	peers []multiv1beta1.MultiNetworkPolicyPeer, podInfo *controllers.PodInfo, ctEnabled bool) ([]candidate, error) {
	_ = ruleIdx // ruleIdx is not needed for priority (mask-shape keyed); kept for readability/parity.

	policyID := sp.policy.GetNamespace() + "/" + sp.policy.GetName()

	portMatches, err := expandPorts(ports)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", policyID, err)
	}

	// Expand peers into allow prefixes and (higher-priority) except prefixes.
	// An empty peers list means "match any address".
	type peerAddrs struct {
		allow  []netip.Prefix // prefixes to accept (zero Prefix = any)
		except []netip.Prefix // prefixes to drop (higher priority)
		// matchAnyFamily is only meaningful when a prefix is the zero
		// (invalid) Prefix — i.e. a match-any rule that carries no L3 key. It
		// selects the ethertype (family) of the emitted single-family filter.
		// For valid prefixes the family is derived from the prefix itself.
		matchAnyFamily ipFamily
	}
	var expanded []peerAddrs
	if len(peers) == 0 {
		// "match any address" — no L3 key. On a first-match pipeline this must
		// cover BOTH families, so emit a zero (invalid) prefix per family; the
		// candidate loop below expands each into a concrete single-family rule.
		for _, fam := range bothFamilies {
			expanded = append(expanded, peerAddrs{matchAnyFamily: fam, allow: []netip.Prefix{{}}})
		}
	} else {
		for _, peer := range peers {
			switch {
			case peer.IPBlock != nil:
				allow := parseCIDRs([]string{peer.IPBlock.CIDR})
				except := parseCIDRs(peer.IPBlock.Except)
				expanded = append(expanded, peerAddrs{allow: allow, except: except})
			case peer.PodSelector != nil || peer.NamespaceSelector != nil:
				ips, err := resolvePeerIPs(ctx, deps, peer, podInfo, sp.policyNetworks)
				if err != nil {
					return nil, fmt.Errorf("policy %q: resolve selector peer: %w", policyID, err)
				}
				var cidrs []netip.Prefix
				for _, ip := range ips {
					// /32 for v4, /128 for v6 (host route to the peer address).
					cidrs = append(cidrs, netip.PrefixFrom(ip, ip.BitLen()))
				}
				expanded = append(expanded, peerAddrs{allow: cidrs})
			default:
				return nil, fmt.Errorf("policy %q: peer has neither ipBlock nor selector", policyID)
			}
		}
	}

	var out []candidate
	for _, pm := range portMatches {
		for _, pa := range expanded {
			for _, ex := range pa.except {
				out = append(out, candidate{
					rule:     buildRule(rep, dir, pm, ex, pa.matchAnyFamily, VerdictDrop, ctEnabled),
					tier:     tierExcept,
					policyID: policyID,
				})
			}
			for _, cidr := range pa.allow {
				out = append(out, candidate{
					rule:     buildRule(rep, dir, pm, cidr, pa.matchAnyFamily, VerdictAccept, ctEnabled),
					tier:     tierAllow,
					policyID: policyID,
				})
			}
		}
	}
	return out, nil
}

// buildRule assembles a per-policy FlowerRule, placing the peer CIDR in the src
// slot for policy ingress and the dst slot for policy egress.
//
// When CT is enabled the rule lives in the post-conntrack policy chain, and an
// accept additionally commits the NEW connection (CTCommit) so its reply
// direction is tracked and statefully accepted by the chain-0 est/rel rules.
// Drops (except-carve-outs, default-deny) never commit.
func buildRule(rep string, dir Direction, pm portMatch, cidr netip.Prefix, matchAnyFamily ipFamily, verdict Verdict, ctEnabled bool) FlowerRule {
	r := FlowerRule{
		Rep:       rep,
		Direction: dir,
		Chain:     policyChain(ctEnabled),
		Proto:     pm.proto,
		HasPort:   pm.hasPort,
		PortMin:   pm.portMin,
		PortMax:   pm.portMax,
		Verdict:   verdict,
	}
	if ctEnabled && verdict == VerdictAccept {
		r.CTCommit = true
		r.CTZone = ctZoneFor(rep, dir)
	}
	if cidr.IsValid() {
		// The filter's ethertype is dictated by the address family of its L3
		// match; a single flower filter matches exactly one ethertype.
		r.Family = familyOfAddr(cidr.Addr())
		if dir == DirIngress {
			r.Src = cidr
		} else {
			r.Dst = cidr
		}
	} else {
		// Match-any (no L3 key): the caller chooses the ethertype explicitly.
		r.Family = matchAnyFamily
	}
	return r
}

// portMatch is one expanded L4 match: a protocol plus an optional destination
// port (single or inclusive range).
type portMatch struct {
	proto   ipProto // 0 = any L4
	hasPort bool
	portMin uint16
	portMax uint16
}

// expandPorts turns a policy port list into portMatches. An empty list yields a
// single match-any-L4 entry. A port entry with a protocol but no port number
// yields a protocol-only match (all ports of that protocol).
func expandPorts(ports []multiv1beta1.MultiNetworkPolicyPort) ([]portMatch, error) {
	if len(ports) == 0 {
		return []portMatch{{}}, nil
	}
	var out []portMatch
	for _, p := range ports {
		proto := protoToNumber(p.Protocol)
		if p.Port == nil {
			// protocol-only match (all ports).
			out = append(out, portMatch{proto: proto})
			continue
		}
		min, err := portNumber(p.Port)
		if err != nil {
			return nil, err
		}
		max := min
		if p.EndPort != nil && *p.EndPort > int32(min) {
			if *p.EndPort < 1 || *p.EndPort > 65535 {
				return nil, fmt.Errorf("endPort %d out of range [1,65535]", *p.EndPort)
			}
			max = uint16(*p.EndPort)
		}
		out = append(out, portMatch{proto: proto, hasPort: true, portMin: min, portMax: max})
	}
	return out, nil
}

// protoToNumber maps a k8s protocol to its IP protocol number, defaulting to
// TCP (mirrors pkg/server.getProtocolInfo).
func protoToNumber(p *corev1.Protocol) ipProto {
	if p == nil {
		return ipProtoTCP
	}
	switch *p {
	case corev1.ProtocolUDP:
		return ipProtoUDP
	case corev1.ProtocolSCTP:
		return ipProtoSCTP
	default:
		return ipProtoTCP
	}
}

// portNumber extracts a numeric port from an IntOrString, accepting numeric
// string ports and rejecting non-numeric named ports (mirrors
// pkg/server.validatePortSpec).
func portNumber(p *intstr.IntOrString) (uint16, error) {
	var num int
	if p.Type == intstr.String {
		n, err := strconv.Atoi(p.StrVal)
		if err != nil {
			return 0, fmt.Errorf("named port %q is not supported; numeric ports are required", p.StrVal)
		}
		num = n
	} else {
		num = p.IntValue()
	}
	if num < 1 || num > 65535 {
		return 0, fmt.Errorf("port %d out of range [1,65535]", num)
	}
	return uint16(num), nil
}

// parseCIDRs returns the cidrs as valid netip.Prefixes of EITHER family (v4 or
// v6), canonicalized to their masked network form. Unparseable entries are
// dropped. The input strings come from the CRD IPBlock (CIDR / Except). Each
// prefix's family later dictates the ethertype of the filter it becomes.
func parseCIDRs(cidrs []string) []netip.Prefix {
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}

// resolvePeerIPs resolves a podSelector/namespaceSelector peer to the set of
// peer pod addresses on the policy networks. It mirrors
// pkg/server.applyPolicyPeersRulesSelector but collects only the PEER pod
// interface IPs (the addresses we must match), of BOTH families. The result is
// deduped and sorted with a stable cross-family comparator (v4 before v6, then
// by address bytes) so BuildFlowerRules stays deterministic.
func resolvePeerIPs(ctx context.Context, deps controllers.PolicyDeps, peer multiv1beta1.MultiNetworkPolicyPeer,
	podInfo *controllers.PodInfo, policyNetworks []string) ([]netip.Addr, error) {
	podSelector := labels.Everything()
	if peer.PodSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("pod selector: %w", err)
		}
		podSelector = s
	}

	var nsSelector labels.Selector
	if peer.NamespaceSelector != nil {
		s, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("namespace selector: %w", err)
		}
		nsSelector = s
	}

	pods, err := deps.ListPods(ctx, podSelector)
	if err != nil {
		return nil, fmt.Errorf("pod list failed: %w", err)
	}

	// The target pod must itself be attached to one of the policy networks,
	// mirroring the nft engine's gate.
	targetOnNet := false
	for _, intf := range podInfo.Interfaces {
		if intf.CheckPolicyNetwork(policyNetworks) {
			targetOnNet = true
			break
		}
	}
	if !targetOnNet {
		return nil, nil
	}

	seen := make(map[netip.Addr]struct{})
	var ips []netip.Addr
	for _, sPod := range pods {
		nsInfo, err := deps.GetNamespaceInfo(ctx, sPod.Namespace)
		if err != nil {
			continue
		}
		if nsSelector != nil && !nsSelector.Matches(labels.Set(nsInfo.Labels)) {
			continue
		}
		sPodInfo, err := deps.GetPodInfo(ctx, sPod)
		if err != nil {
			continue
		}
		for _, sIntf := range sPodInfo.Interfaces {
			if !sIntf.CheckPolicyNetwork(policyNetworks) {
				continue
			}
			for _, ip := range sIntf.IPs {
				if _, ok := seen[ip]; ok {
					continue
				}
				seen[ip] = struct{}{}
				ips = append(ips, ip)
			}
		}
	}
	// Stable cross-family order: v4 before v6, then by address. netip.Addr's
	// own Compare already orders v4 ahead of v6 and sorts within a family, so
	// it is a total, deterministic comparator across both families.
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	return ips, nil
}

// assignPriorities deterministically allocates tc filter priorities.
//
// Scheme: within each (direction, chain) — an independent tc priority space,
// since ingress/egress are different qdisc parents and each chain numbers its
// preferences independently — rules are grouped into priority CLASSES keyed by
// (tier, mask-shape, policy identity). The classes are sorted by that key and
// numbered from 1. Consequences:
//   - tc flower's "one mask per priority" rule is honored: a class shares a
//     single mask shape, so all filters at a priority use the same mask (only
//     their VALUES differ, e.g. several /32 peer addresses).
//   - two rules whose address prefix lengths differ have different mask shapes
//     and therefore always land on different priorities.
//   - tier ordering (except < allow < default-deny) guarantees except drops
//     precede the allows they carve out, and default-deny is evaluated last.
//   - the mapping is a pure function of the candidate set, so repeated calls
//     yield identical priorities (stability).
//
// The mask-shape signature includes the chain and ct_state shape, so chain-0
// CT rules and chain-N policy rules occupy separate priority classes even
// though both directions share a parent.
func assignPriorities(cands []candidate) []FlowerRule {
	type spaceKey struct {
		dir   Direction
		chain uint32
	}
	type classKey struct {
		space    spaceKey
		tier     int
		sig      string
		policyID string
	}

	// Collect distinct classes per (direction, chain) priority space.
	classesBySpace := make(map[spaceKey]map[classKey]struct{})
	keyOf := func(c candidate) classKey {
		return classKey{
			space:    spaceKey{dir: c.rule.Direction, chain: c.rule.Chain},
			tier:     c.tier,
			sig:      maskSignature(c.rule),
			policyID: c.policyID,
		}
	}
	for _, c := range cands {
		k := keyOf(c)
		if classesBySpace[k.space] == nil {
			classesBySpace[k.space] = make(map[classKey]struct{})
		}
		classesBySpace[k.space][k] = struct{}{}
	}

	// Sort each space's classes and assign priorities.
	prio := make(map[classKey]uint16)
	for space := range classesBySpace {
		keys := make([]classKey, 0, len(classesBySpace[space]))
		for k := range classesBySpace[space] {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b classKey) int {
			if a.tier != b.tier {
				return a.tier - b.tier
			}
			if c := strings.Compare(a.sig, b.sig); c != 0 {
				return c
			}
			return strings.Compare(a.policyID, b.policyID)
		})
		for i, k := range keys {
			// tc filter priorities are a uint16 space. In practice the number of
			// distinct (tier, mask-shape, policy) classes per direction is tiny;
			// guard against a pathological overflow rather than wrapping.
			if i+1 > 0xffff {
				prio[k] = 0xffff
				continue
			}
			prio[k] = uint16(i + 1) //nolint:gosec // bounded above to <= 0xffff
		}
	}

	// Materialize rules with priorities, dedupe, and sort deterministically.
	seen := make(map[FlowerRule]struct{})
	var out []FlowerRule
	for _, c := range cands {
		r := c.rule
		r.Priority = prio[keyOf(c)]
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	slices.SortFunc(out, compareFlowerRule)
	return out
}

// maskSignature captures every aspect of a rule that determines the tc flower
// key MASK: chain, direction, src/dst prefix lengths (-1 when absent), the L4
// protocol, whether/what kind of destination-port match is present, and the
// ct_state mask. Including chain + ct_state mask keeps chain-0 CT rules and
// chain-N policy rules in separate priority classes and honors flower's
// one-mask-per-priority constraint for the ct_state key too.
func maskSignature(r FlowerRule) string {
	portKind := 0
	if r.HasPort {
		if r.PortMin == r.PortMax {
			portKind = 1 // single
		} else {
			portKind = 2 // range
		}
	}
	// Family is part of the mask shape: a v4 filter and a v6 filter have
	// different key sets (KeyIPv4* vs KeyIPv6*) and different ethertypes, so
	// they must never share a priority class.
	return fmt.Sprintf("c%d|d%d|f%d|s%d|D%d|p%d|k%d|m%d", r.Chain, r.Direction, r.Family,
		prefixLen(r.Src), prefixLen(r.Dst), r.Proto, portKind, r.CTStateMask)
}

// prefixLen returns the prefix length, or -1 when the prefix is invalid/absent.
func prefixLen(p netip.Prefix) int {
	if !p.IsValid() {
		return -1
	}
	return p.Bits()
}

// prefixString renders a prefix for hashing/comparison, returning the empty
// string for an invalid/absent prefix (match-any) so the derived handle stays
// stable and unique.
func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

// compareFlowerRule provides a total, deterministic ordering for output.
func compareFlowerRule(a, b FlowerRule) int {
	if a.Direction != b.Direction {
		return int(a.Direction) - int(b.Direction)
	}
	if a.Chain != b.Chain {
		return int(a.Chain) - int(b.Chain)
	}
	if a.Priority != b.Priority {
		return int(a.Priority) - int(b.Priority)
	}
	if a.Family != b.Family {
		return int(a.Family) - int(b.Family)
	}
	if a.CTStateMask != b.CTStateMask {
		return int(a.CTStateMask) - int(b.CTStateMask)
	}
	if a.CTState != b.CTState {
		return int(a.CTState) - int(b.CTState)
	}
	if a.Verdict != b.Verdict {
		return int(a.Verdict) - int(b.Verdict)
	}
	if c := strings.Compare(a.Src.String(), b.Src.String()); c != 0 {
		return c
	}
	if c := strings.Compare(a.Dst.String(), b.Dst.String()); c != 0 {
		return c
	}
	if a.Proto != b.Proto {
		return int(a.Proto) - int(b.Proto)
	}
	if a.PortMin != b.PortMin {
		return int(a.PortMin) - int(b.PortMin)
	}
	return int(a.PortMax) - int(b.PortMax)
}

// parentHandle returns the clsact qdisc parent for the rule's direction on the
// VF representor. See the Direction doc for the inversion rationale.
func (d Direction) parentHandle() uint32 {
	if d == DirIngress {
		// policy ingress (to pod) => representor EGRESS parent.
		return core.BuildHandle(0xffff, tc.HandleMinEgress)
	}
	// policy egress (from pod) => representor INGRESS parent.
	return core.BuildHandle(0xffff, tc.HandleMinIngress)
}

// handle derives a stable, non-zero 32-bit tc filter handle from the rule's
// identity so that AddFilter is idempotent and reconcile can key filters by
// (parent, chain, priority, handle) without relying on kernel-assigned handles.
//
// The chain and ct_state / CT-action fields are folded into the hash so that
// two filters that share a numeric priority but live in different chains (e.g.
// a chain-0 CT rule and a chain-N policy rule) — or two chain-0 CT rules whose
// only difference is their ct_state combo — get distinct handles and never
// collide in the reconcile diff key.
func (r FlowerRule) handle() uint32 {
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%d|%d|%d|%d|%d|%d|%s|%s|%t|%d|%d|%d|%t|%d|%d|%t|%d|%d",
		r.Offload, r.Chain, r.Direction, r.Priority, r.Family, r.Proto, prefixString(r.Src), prefixString(r.Dst),
		r.HasPort, r.PortMin, r.PortMax, r.Verdict,
		r.HasCTState, r.CTState, r.CTStateMask, r.CTDispatch, r.GotoChain, r.CTZone)
	sum := h.Sum32()
	if sum == 0 {
		sum = 1
	}
	return sum
}

// toObject converts the abstract FlowerRule into a go-tc Object ready to be
// installed on the given representor ifindex. The hardware-offload flag is
// stamped from r.Offload:
//   - OffloadHardware (default): SkipSw — HARDWARE-ONLY, fail closed: if the NIC
//     cannot offload it, the kernel rejects the insertion rather than silently
//     enforcing in software. This is the production behavior on switchdev NICs.
//   - OffloadSoftware: SkipHw — in-kernel (software) enforcement, so the same
//     match/verdict is enforced on veth/netdevsim (no hardware offload) and on
//     non-offload NICs.
//
// OffloadAuto (no flag) is rejected at build time (see parseOffloadMode), so
// every emitted filter always carries exactly one of SkipSw/SkipHw — which
// isManagedFilter relies on to recognize filters this backend owns.
func (r FlowerRule) toObject(ifindex int) tc.Object {
	flags := offloadFlags(r.Offload)
	ethType := ethTypeFor(r.Family)

	flower := &tc.Flower{
		KeyEthType: &ethType,
		Flags:      &flags,
	}

	if r.Proto != ipProtoAny {
		proto := uint8(r.Proto)
		flower.KeyIPProto = &proto
	}

	// L3 address keys, selected by family. A v4 filter uses KeyIPv4*; a v6
	// filter uses KeyIPv6* (16-byte address + /128 mask). The two never mix on
	// a single filter (one ethertype per flower filter).
	if r.Family == familyV6 {
		if r.Src.IsValid() {
			if ip, mask, ok := cidrToIPv6Mask(r.Src); ok {
				flower.KeyIPv6Src = &ip
				flower.KeyIPv6SrcMask = &mask
			}
		}
		if r.Dst.IsValid() {
			if ip, mask, ok := cidrToIPv6Mask(r.Dst); ok {
				flower.KeyIPv6Dst = &ip
				flower.KeyIPv6DstMask = &mask
			}
		}
	} else {
		if r.Src.IsValid() {
			if ip, mask, ok := cidrToIPMask(r.Src); ok {
				flower.KeyIPv4Src = &ip
				flower.KeyIPv4SrcMask = &mask
			}
		}
		if r.Dst.IsValid() {
			if ip, mask, ok := cidrToIPMask(r.Dst); ok {
				flower.KeyIPv4Dst = &ip
				flower.KeyIPv4DstMask = &mask
			}
		}
	}

	if r.HasPort {
		if r.PortMin == r.PortMax {
			port := r.PortMin
			switch r.Proto {
			case ipProtoUDP:
				flower.KeyUDPDst = &port
			case ipProtoSCTP:
				flower.KeySctpDst = &port
			default:
				flower.KeyTCPDst = &port
			}
		} else {
			min := r.PortMin
			max := r.PortMax
			flower.KeyPortDstMin = &min
			flower.KeyPortDstMax = &max
		}
	}

	// ct_state match (stateful pipeline only): match on (value, mask) so the
	// chain-0 rules can select untracked / established / related / invalid
	// packets. A zero mask (stateless rules) emits no ct_state key.
	if r.HasCTState {
		state := r.CTState
		mask := r.CTStateMask
		flower.KeyCtState = &state
		flower.KeyCtStateMask = &mask
	}

	flower.Actions = r.buildActions()

	// Chain is only stamped when non-zero: chain 0 filters (stateless rules and
	// the CT entry chain) omit the attribute exactly as Phase 2 did.
	attr := tc.Attribute{
		Kind:   "flower",
		Flower: flower,
	}
	if r.Chain != 0 {
		chain := r.Chain
		attr.Chain = &chain
	}

	return tc.Object{
		Msg: tc.Msg{
			Ifindex: uint32(ifindex), //nolint:gosec // ifindex is a small positive netdev index
			Handle:  r.handle(),
			Parent:  r.Direction.parentHandle(),
			Info:    core.FilterInfo(r.Priority, ethType),
		},
		Attribute: attr,
	}
}

// buildActions assembles the ordered tc action list for the filter:
//   - CTDispatch (chain-0 untracked rule): [ct(zone) pipe, gact goto_chain N] —
//     send the packet through conntrack, then jump to the policy chain.
//   - CTCommit accept (chain-N NEW-connection allow): [ct commit(zone), gact
//     pass] — commit the connection so its reply is statefully tracked, then
//     pass.
//   - everything else: a single gact (pass for accept, shot for drop),
//     identical to the stateless Phase 2 output.
func (r FlowerRule) buildActions() *[]*tc.Action {
	switch {
	case r.CTDispatch:
		zone := r.CTZone
		goto_ := r.GotoChain
		actions := []*tc.Action{
			{
				Kind: "ct",
				Ct:   &tc.Ct{Zone: &zone},
				// TC_ACT_PIPE: continue to the next action after conntrack.
				Gact: nil,
			},
			{
				Kind: "gact",
				Gact: &tc.Gact{
					Parms: &tc.GactParms{Action: tcActGotoChain | goto_},
				},
			},
		}
		// The ct action's own control disposition is PIPE (fall through to the
		// next action). go-tc carries the ct action's control in CtParms.Action.
		(actions)[0].Ct.Parms = &tc.CtParms{Action: tcActPipe}
		return &actions

	case r.CTCommit && r.Verdict == VerdictAccept:
		zone := r.CTZone
		commit := ctActCommit
		actions := []*tc.Action{
			{
				Kind: "ct",
				Ct: &tc.Ct{
					Action: &commit,
					Zone:   &zone,
					Parms:  &tc.CtParms{Action: tcActPipe},
				},
			},
			{
				Kind: "gact",
				Gact: &tc.Gact{Parms: &tc.GactParms{Action: tcActOK}},
			},
		}
		return &actions

	default:
		control := tcActOK
		if r.Verdict == VerdictDrop {
			control = tcActShot
		}
		actions := []*tc.Action{
			{
				Kind: "gact",
				Gact: &tc.Gact{
					Parms: &tc.GactParms{Action: control},
				},
			},
		}
		return &actions
	}
}

// cidrToIPMask converts an IPv4 netip.Prefix into its 4-byte network address
// and mask for go-tc. A non-IPv4 prefix is skipped (ok == false).
func cidrToIPMask(prefix netip.Prefix) (ip net.IP, mask net.IP, ok bool) {
	if !prefix.Addr().Is4() {
		return nil, nil, false
	}
	network := prefix.Masked()
	b := network.Addr().As4()
	return net.IP(b[:]), net.IP(net.CIDRMask(prefix.Bits(), 32)), true
}

// cidrToIPv6Mask converts an IPv6 netip.Prefix into its 16-byte network address
// and mask for go-tc. A prefix whose address is IPv4 (Is4) is skipped
// (ok == false); an IPv4-mapped v6 address (Is4()==false, Is6()==true) is
// treated as v6 and rendered as its 16-byte form.
func cidrToIPv6Mask(prefix netip.Prefix) (ip net.IP, mask net.IP, ok bool) {
	if prefix.Addr().Is4() {
		return nil, nil, false
	}
	network := prefix.Masked()
	b := network.Addr().As16()
	return net.IP(b[:]), net.IP(net.CIDRMask(prefix.Bits(), 128)), true
}
