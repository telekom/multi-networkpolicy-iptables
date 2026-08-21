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
	"net/netip"
	"testing"

	tc "github.com/florianl/go-tc"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

// buildCTRules is the CT-enabled twin of buildRules (engine_test.go): it flips
// CommonRuleConfig.CTEnabled so the stateful two-chain pipeline is produced.
func buildCTRules(t *testing.T, deps controllers.PolicyDeps, policyMap controllers.PolicyMap) []FlowerRule {
	t.Helper()
	rules, err := BuildFlowerRules(context.Background(), deps, controllers.CommonRuleConfig{CTEnabled: true},
		policyMap, targetPod(nil), targetPodInfo(), targetIface())
	if err != nil {
		t.Fatalf("BuildFlowerRules(CTEnabled) returned error: %v", err)
	}
	return rules
}

// ctEntrySummary collects the chain-0 CT entry rules for a direction so tests
// can assert the dispatch / established / related / invalid shape.
type ctEntrySummary struct {
	dispatch    *FlowerRule
	established *FlowerRule
	related     *FlowerRule
	invalid     *FlowerRule
	zone        uint16
}

func summarizeCTEntry(t *testing.T, rules []FlowerRule, dir Direction) ctEntrySummary {
	t.Helper()
	var s ctEntrySummary
	for i := range rules {
		r := &rules[i]
		if r.Direction != dir || r.Chain != ctEntryChain || !r.HasCTState {
			continue
		}
		s.zone = r.CTZone
		switch {
		case r.CTDispatch:
			s.dispatch = r
		case r.CTStateMask == ctStateTracked|ctStateEstablished && r.Verdict == VerdictAccept:
			s.established = r
		case r.CTStateMask == ctStateTracked|ctStateRelated && r.Verdict == VerdictAccept:
			s.related = r
		case r.CTStateMask == ctStateTracked|ctStateInvalid && r.Verdict == VerdictDrop:
			s.invalid = r
		}
	}
	return s
}

func TestCTIngressPipeline(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	rules := buildCTRules(t, deps, policyMapOf(policy))

	// --- chain 0: conntrack entry pipeline ---
	entry := summarizeCTEntry(t, rules, DirIngress)
	if entry.dispatch == nil || entry.established == nil || entry.related == nil || entry.invalid == nil {
		t.Fatalf("missing chain-0 CT rules: %+v", entry)
	}
	if entry.zone == 0 {
		t.Errorf("CT zone must be non-zero")
	}

	// Dispatch rule: match -trk (tracked bit in mask, value 0), action ct + goto policy chain.
	if entry.dispatch.CTState != 0 || entry.dispatch.CTStateMask != ctStateTracked {
		t.Errorf("dispatch rule must match -trk (state=0 mask=trk), got state=%#x mask=%#x",
			entry.dispatch.CTState, entry.dispatch.CTStateMask)
	}
	if entry.dispatch.GotoChain != ctPolicyChain {
		t.Errorf("dispatch rule must goto policy chain %d, got %d", ctPolicyChain, entry.dispatch.GotoChain)
	}

	// Established / related bits.
	if entry.established.CTState != ctStateTracked|ctStateEstablished {
		t.Errorf("established rule state = %#x, want +trk+est", entry.established.CTState)
	}
	if entry.related.CTState != ctStateTracked|ctStateRelated {
		t.Errorf("related rule state = %#x, want +trk+rel", entry.related.CTState)
	}

	// --- chain N: post-conntrack policy rules ---
	var allow, deny *FlowerRule
	for i := range rules {
		r := &rules[i]
		if r.Chain != ctPolicyChain {
			continue
		}
		if r.Verdict == VerdictAccept && r.Src.String() == "192.168.1.0/24" {
			allow = r
		}
		if r.Verdict == VerdictDrop && !r.Src.IsValid() {
			deny = r
		}
	}
	if allow == nil {
		t.Fatalf("missing policy-chain allow for 192.168.1.0/24; rules=%+v", rules)
	}
	if deny == nil {
		t.Fatalf("missing policy-chain default-deny; rules=%+v", rules)
	}
	// The NEW-direction allow must commit the connection so its reply is tracked.
	if !allow.CTCommit {
		t.Errorf("policy-chain accept must set CTCommit so the reply is tracked")
	}
	if allow.CTZone != entry.zone {
		t.Errorf("policy-chain commit zone %d must match entry zone %d", allow.CTZone, entry.zone)
	}
	// Default-deny must NOT commit.
	if deny.CTCommit {
		t.Errorf("default-deny must not commit to conntrack")
	}

	// --- toObject: skip_sw + chain + ct_state + action lists ---
	do := entry.dispatch.toObject(11)
	if do.Flower.Flags == nil || *do.Flower.Flags != tc.SkipSw {
		t.Errorf("dispatch filter must carry skip_sw")
	}
	if do.Chain == nil || *do.Chain != ctEntryChain {
		// chain 0 is emitted with a nil Chain attribute (kernel default).
		if do.Chain != nil {
			t.Errorf("chain-0 filter should omit Chain attribute, got %v", *do.Chain)
		}
	}
	if do.Flower.KeyCtState == nil || do.Flower.KeyCtStateMask == nil {
		t.Fatalf("dispatch filter must set ct_state key + mask")
	}
	if *do.Flower.KeyCtStateMask != ctStateTracked {
		t.Errorf("dispatch mask = %#x, want trk", *do.Flower.KeyCtStateMask)
	}
	acts := *do.Flower.Actions
	if len(acts) != 2 || acts[0].Kind != "ct" || acts[1].Kind != "gact" {
		t.Fatalf("dispatch action list must be [ct, gact], got %+v", acts)
	}
	if acts[0].Ct == nil || acts[0].Ct.Zone == nil || *acts[0].Ct.Zone != entry.zone {
		t.Errorf("dispatch ct action must carry the zone")
	}
	if acts[1].Gact.Parms.Action != (tcActGotoChain | ctPolicyChain) {
		t.Errorf("dispatch gact must be goto_chain %d, got %#x", ctPolicyChain, acts[1].Gact.Parms.Action)
	}

	// Policy-chain allow: chain attribute set, action list [ct commit, gact pass].
	ao := allow.toObject(11)
	if ao.Chain == nil || *ao.Chain != ctPolicyChain {
		t.Errorf("policy-chain filter must set Chain=%d", ctPolicyChain)
	}
	if ao.Flower.Flags == nil || *ao.Flower.Flags != tc.SkipSw {
		t.Errorf("policy-chain filter must carry skip_sw")
	}
	aacts := *ao.Flower.Actions
	if len(aacts) != 2 || aacts[0].Kind != "ct" || aacts[1].Kind != "gact" {
		t.Fatalf("policy-chain accept action list must be [ct commit, gact], got %+v", aacts)
	}
	if aacts[0].Ct == nil || aacts[0].Ct.Action == nil || *aacts[0].Ct.Action != ctActCommit {
		t.Errorf("policy-chain ct action must commit")
	}
	if aacts[1].Gact.Parms.Action != tcActOK {
		t.Errorf("policy-chain terminal must be TC_ACT_OK")
	}

	// established accept toObject: ct_state key set, single gact pass (no commit).
	eo := entry.established.toObject(11)
	if eo.Flower.KeyCtState == nil || *eo.Flower.KeyCtState != ctStateTracked|ctStateEstablished {
		t.Errorf("established ct_state key not set correctly")
	}
	eacts := *eo.Flower.Actions
	if len(eacts) != 1 || eacts[0].Kind != "gact" || eacts[0].Gact.Parms.Action != tcActOK {
		t.Errorf("established accept must be a single gact pass, got %+v", eacts)
	}
}

func TestCTEgressPipeline(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
		nil,
		[]multiv1beta1.MultiNetworkPolicyEgressRule{
			{To: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.10.0.0/16"}}}},
		})

	rules := buildCTRules(t, deps, policyMapOf(policy))

	entry := summarizeCTEntry(t, rules, DirEgress)
	if entry.dispatch == nil || entry.established == nil || entry.related == nil || entry.invalid == nil {
		t.Fatalf("missing chain-0 CT egress rules: %+v", entry)
	}
	if entry.dispatch.GotoChain != ctPolicyChain {
		t.Errorf("egress dispatch must goto policy chain")
	}

	var allow *FlowerRule
	for i := range rules {
		r := &rules[i]
		if r.Chain == ctPolicyChain && r.Verdict == VerdictAccept && r.Dst.String() == "10.10.0.0/16" {
			allow = r
		}
	}
	if allow == nil {
		t.Fatalf("missing egress policy-chain allow for 10.10.0.0/16; rules=%+v", rules)
	}
	if !allow.CTCommit {
		t.Errorf("egress NEW-direction allow must commit")
	}

	// Every CT filter must carry skip_sw and the egress parent.
	for _, r := range rules {
		if r.Direction != DirEgress {
			continue
		}
		obj := r.toObject(5)
		if obj.Flower.Flags == nil || *obj.Flower.Flags != tc.SkipSw {
			t.Errorf("egress CT filter %+v must carry skip_sw", r)
		}
		if obj.Parent != DirEgress.parentHandle() {
			t.Errorf("egress CT filter %+v wrong parent %#x", r, obj.Parent)
		}
	}

	// Ingress-direction CT zone differs from egress (independent tracking).
	if zi := ctZoneFor(testRep, DirIngress); zi == entry.zone {
		t.Errorf("ingress and egress CT zones must differ: both %d", zi)
	}
}

// TestCTReturnTrafficWithoutEgressPolicy proves that an ingress-only allow
// policy, under CT, covers its own return traffic: the chain-0 established and
// related accepts exist for the same direction as the NEW-direction allow, so
// no explicit egress policy is needed for replies.
func TestCTReturnTrafficWithoutEgressPolicy(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "172.16.0.0/12"}}}},
		}, nil)

	rules := buildCTRules(t, deps, policyMapOf(policy))

	// NEW-direction allow in the policy chain (ingress).
	var newAllow *FlowerRule
	for i := range rules {
		if rules[i].Chain == ctPolicyChain && rules[i].Verdict == VerdictAccept && rules[i].Src.String() == "172.16.0.0/12" {
			newAllow = &rules[i]
		}
	}
	if newAllow == nil {
		t.Fatalf("missing NEW-direction ingress allow; rules=%+v", rules)
	}
	if !newAllow.CTCommit {
		t.Fatalf("NEW-direction allow must commit so the reply is tracked")
	}

	// Return traffic acceptance: established + related on the SAME direction.
	entry := summarizeCTEntry(t, rules, DirIngress)
	if entry.established == nil || entry.related == nil {
		t.Fatalf("return-traffic acceptance (est/rel) missing on ingress; rules=%+v", rules)
	}

	// No egress policy was defined, so there must be NO egress filters at all
	// (return traffic is handled statefully on the ingress direction chains).
	for _, r := range rules {
		if r.Direction == DirEgress {
			t.Errorf("unexpected egress filter for an ingress-only CT policy: %+v", r)
		}
	}
}

// TestCTHandleUniquenessAcrossChains verifies that chain-0 CT filters and
// chain-N policy filters do not collide in the reconcile diff key even when
// they share a numeric priority.
func TestCTHandleUniquenessAcrossChains(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	rules := buildCTRules(t, deps, policyMapOf(policy))

	// Confirm at least one chain-0 and one chain-N filter share a priority.
	// The reconcile diff key mirrors apply.go's filterKey (parent, chain, prio,
	// handle); it is redeclared locally because filterKey lives in the
	// linux-only apply.go and this test is cross-platform.
	type diffKey struct {
		parent uint32
		chain  uint32
		prio   uint16
		handle uint32
	}
	seenPrio := map[uint16][]uint32{}
	keys := map[diffKey]FlowerRule{}
	sharedPrio := false
	for _, r := range rules {
		obj := r.toObject(3)
		k := diffKey{parent: obj.Parent, chain: r.Chain, prio: r.Priority, handle: obj.Handle}
		if prev, ok := keys[k]; ok {
			t.Fatalf("reconcile key collision between %+v and %+v: key=%+v", prev, r, k)
		}
		keys[k] = r
		seenPrio[r.Priority] = append(seenPrio[r.Priority], r.Chain)
	}
	for _, chains := range seenPrio {
		has0, hasN := false, false
		for _, c := range chains {
			if c == ctEntryChain {
				has0 = true
			}
			if c == ctPolicyChain {
				hasN = true
			}
		}
		if has0 && hasN {
			sharedPrio = true
		}
	}
	if !sharedPrio {
		t.Logf("note: no shared priority across chains in this fixture (still valid); keys unique")
	}

	// Also assert handles differ for two rules at the same prio in different chains.
	// Build two synthetic rules that share a priority but differ only in chain.
	a := FlowerRule{Rep: testRep, Direction: DirIngress, Chain: ctEntryChain, Priority: 1, HasCTState: true, CTStateMask: ctStateTracked, CTDispatch: true, GotoChain: ctPolicyChain, CTZone: 7, Verdict: VerdictAccept}
	b := FlowerRule{Rep: testRep, Direction: DirIngress, Chain: ctPolicyChain, Priority: 1, Src: netip.MustParsePrefix("192.168.1.0/24"), CTCommit: true, CTZone: 7, Verdict: VerdictAccept}
	if a.handle() == b.handle() {
		t.Errorf("filters differing only in chain must get distinct handles")
	}
}

// TestCTEntryRulesPerFamily proves the chain-0 conntrack entry pipeline is
// emitted for BOTH families: a flower filter always carries an ethertype, so
// there must be a v4 AND a v6 established/related/invalid/dispatch set. Without
// the v6 set, established/related v6 return traffic would not be statefully
// accepted and untracked v6 packets would not be dispatched through conntrack.
func TestCTEntryRulesPerFamily(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	rules := buildCTRules(t, deps, policyMapOf(policy))

	// Count chain-0 established / related accepts per family.
	type fam struct{ est, rel, inv, disp bool }
	byFamily := map[ipFamily]*fam{familyV4: {}, familyV6: {}}
	for i := range rules {
		r := &rules[i]
		if r.Direction != DirIngress || r.Chain != ctEntryChain || !r.HasCTState {
			continue
		}
		f := byFamily[r.Family]
		switch {
		case r.CTDispatch:
			f.disp = true
		case r.CTStateMask == ctStateTracked|ctStateEstablished && r.Verdict == VerdictAccept:
			f.est = true
		case r.CTStateMask == ctStateTracked|ctStateRelated && r.Verdict == VerdictAccept:
			f.rel = true
		case r.CTStateMask == ctStateTracked|ctStateInvalid && r.Verdict == VerdictDrop:
			f.inv = true
		}
	}
	for _, family := range []ipFamily{familyV4, familyV6} {
		f := byFamily[family]
		if !f.est || !f.rel || !f.inv || !f.disp {
			t.Errorf("family %d: missing chain-0 CT rules (est=%v rel=%v inv=%v disp=%v)",
				family, f.est, f.rel, f.inv, f.disp)
		}
	}

	// The v6 established accept must emit ethertype 0x86dd and a ct_state key.
	for i := range rules {
		r := &rules[i]
		if r.Chain == ctEntryChain && r.Family == familyV6 &&
			r.CTStateMask == ctStateTracked|ctStateEstablished && r.Verdict == VerdictAccept {
			obj := r.toObject(1)
			if obj.Flower.KeyEthType == nil || *obj.Flower.KeyEthType != ethTypeIPv6 {
				t.Errorf("v6 established filter ethertype = %v, want 0x86dd", obj.Flower.KeyEthType)
			}
			if obj.Flower.KeyCtState == nil {
				t.Errorf("v6 established filter must set ct_state key")
			}
		}
	}
}

// TestCTDisabledIsStateless confirms the stateless (default) pipeline is
// unchanged: no chains, no ct_state, no CT actions.
func TestCTDisabledIsStateless(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy)) // CTEnabled=false

	for _, r := range rules {
		if r.Chain != 0 || r.HasCTState || r.CTCommit || r.CTDispatch {
			t.Errorf("stateless rule must have no CT fields set: %+v", r)
		}
		obj := r.toObject(1)
		if obj.Chain != nil {
			t.Errorf("stateless filter must omit Chain attribute")
		}
		if obj.Flower.KeyCtState != nil {
			t.Errorf("stateless filter must have no ct_state key")
		}
		if acts := *obj.Flower.Actions; len(acts) != 1 || acts[0].Kind != "gact" {
			t.Errorf("stateless filter must have a single gact action, got %+v", acts)
		}
	}
}
