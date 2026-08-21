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

// Exhaustive edge-case coverage for the pure translation layer
// (BuildFlowerRules and its helpers). Everything here is netlink-free and runs
// cross-platform (darwin/linux, no root): it exercises only the abstract
// FlowerRule surface and its go-tc Object projection.
//
// Fixtures and fake PolicyDeps are reused from engine_test.go / ct_test.go
// (both untagged, so available on every platform): newFakeDeps, makePolicy,
// policyMapOf, targetPod, targetPodInfo, targetIface, buildRules, buildCTRules,
// intPort, protoPtr, int32Ptr, assertRules, testNS, testNet, testRep.

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// addPeerPodCustom registers a peer pod with an explicit interface list so a
// test can model multiple interfaces (e.g. overlapping IPs to exercise the
// resolvePeerIPs dedup) or an interface on a non-policy network.
func (s *fakeDeps) addPeerPodCustom(namespace, name string, lbls map[string]string, ifaces []controllers.InterfaceInfo) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: lbls},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	nn := types.NamespacedName{Namespace: namespace, Name: name}
	s.pods[nn] = pod
	s.podMap[nn] = controllers.PodInfo{Name: name, Namespace: namespace, Interfaces: ifaces}
}

// ifaceOn builds an InterfaceInfo attached to the given policy network with the
// given IP strings.
func ifaceOn(netattach, ifname string, ips ...string) controllers.InterfaceInfo {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	return controllers.InterfaceInfo{NetattachName: netattach, InterfaceName: ifname, IPs: addrs}
}

// mapKey is the reconcile diff identity (mirrors apply.go's filterKey, which is
// linux-only, so it is redeclared here for these cross-platform tests).
type mapKey struct {
	parent uint32
	chain  uint32
	prio   uint16
	handle uint32
}

// assertNoKeyCollision builds the (parent,chain,prio,handle) set from a rule
// slice and fails if any two DISTINCT rules share a key — the critical
// reconcile-correctness property (a collision would make one desired filter
// silently overwrite another or dodge stale-deletion).
func assertNoKeyCollision(t *testing.T, rules []FlowerRule) {
	t.Helper()
	seen := make(map[mapKey]FlowerRule, len(rules))
	for _, r := range rules {
		obj := r.toObject(3)
		k := mapKey{parent: obj.Parent, chain: r.Chain, prio: r.Priority, handle: obj.Handle}
		if prev, ok := seen[k]; ok && !reflect.DeepEqual(prev, r) {
			t.Fatalf("reconcile key collision: key=%+v\n  a=%+v\n  b=%+v", k, prev, r)
		}
		seen[k] = r
	}
}

// --- 1. Empty policy map / pod not selected => no rules (no default-deny) ---

func TestEmptyPolicyMapEmitsNoRules(t *testing.T) {
	deps := newFakeDeps()
	rules := buildRules(t, deps, policyMapOf())
	if len(rules) != 0 {
		t.Fatalf("empty policy map must emit no rules (not even a default-deny); got %+v", rules)
	}
}

func TestPodNotSelectedEmitsNoRules(t *testing.T) {
	deps := newFakeDeps()
	// A policy whose podSelector does not match the (label-less) target pod.
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)
	policy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "does-not-match"}}

	rules := buildRules(t, deps, policyMapOf(policy))
	if len(rules) != 0 {
		t.Fatalf("a pod not selected by any policy must get no rules; got %+v", rules)
	}
}

func TestTargetOffPolicyNetworkEmitsNoRules(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	// Target pod attached only to a DIFFERENT network than the policy targets.
	pod := targetPod(nil)
	podInfo := &controllers.PodInfo{
		Name: "target", Namespace: testNS,
		Interfaces: []controllers.InterfaceInfo{
			{NetattachName: "testns/other-net", InterfaceName: "net1", RepresentorDevice: testRep,
				IPs: []netip.Addr{netip.MustParseAddr("10.0.0.5")}},
		},
	}
	rules, err := BuildFlowerRules(context.Background(), deps, controllers.CommonRuleConfig{},
		policyMapOf(policy), pod, podInfo, podInfo.Interfaces[0])
	if err != nil {
		t.Fatalf("BuildFlowerRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("target off the policy network must get no rules; got %+v", rules)
	}
}

// --- 2. Idempotency on a rich mixed input (extends TestPriorityStability) ---

func TestBuildFlowerRulesIdempotentMixed(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{{Protocol: protoPtr(corev1.ProtocolTCP), Port: intPort(443)}},
				From: []multiv1beta1.MultiNetworkPolicyPeer{
					{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24", Except: []string{"192.168.1.128/25"}}},
					{IPBlock: &multiv1beta1.IPBlock{CIDR: "2001:db8::/32"}},
				},
			},
		},
		[]multiv1beta1.MultiNetworkPolicyEgressRule{
			{To: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.0/8"}}}},
		})
	pm := policyMapOf(policy)

	// Stateless and stateful pipelines must both be byte-for-byte stable.
	for _, ct := range []bool{false, true} {
		first, err := BuildFlowerRules(context.Background(), deps, controllers.CommonRuleConfig{CTEnabled: ct},
			pm, targetPod(nil), targetPodInfo(), targetIface())
		if err != nil {
			t.Fatalf("first build (ct=%v): %v", ct, err)
		}
		second, err := BuildFlowerRules(context.Background(), deps, controllers.CommonRuleConfig{CTEnabled: ct},
			pm, targetPod(nil), targetPodInfo(), targetIface())
		if err != nil {
			t.Fatalf("second build (ct=%v): %v", ct, err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("BuildFlowerRules not idempotent (ct=%v):\nfirst:  %+v\nsecond: %+v", ct, first, second)
		}
	}
}

// --- 3. Port edge cases (expandPorts / portNumber, exercised directly) ---

func TestPortNumberBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		port    *intstr.IntOrString
		want    uint16
		wantErr bool
	}{
		{"low boundary 1", intPort(1), 1, false},
		{"high boundary 65535", intPort(65535), 65535, false},
		{"zero rejected", intPort(0), 0, true},
		{"65536 rejected", intPort(65536), 0, true},
		{"numeric string accepted", strPort("8080"), 8080, false},
		{"named port rejected", strPort("http"), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := portNumber(tt.port)
			if (err != nil) != tt.wantErr {
				t.Fatalf("portNumber(%v) err=%v, wantErr=%v", tt.port, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("portNumber(%v) = %d, want %d", tt.port, got, tt.want)
			}
		})
	}
}

func TestExpandPortsEdgeCases(t *testing.T) {
	udp := protoPtr(corev1.ProtocolUDP)

	tests := []struct {
		name    string
		ports   []multiv1beta1.MultiNetworkPolicyPort
		want    []portMatch
		wantErr bool
	}{
		{
			name:  "empty list => single match-any-L4",
			ports: nil,
			want:  []portMatch{{}},
		},
		{
			name:  "protocol only, no port => all ports of that proto",
			ports: []multiv1beta1.MultiNetworkPolicyPort{{Protocol: udp}},
			want:  []portMatch{{proto: ipProtoUDP}},
		},
		{
			name:  "EndPort == Port => single (not a range)",
			ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: intPort(80), EndPort: int32Ptr(80)}},
			want:  []portMatch{{proto: ipProtoTCP, hasPort: true, portMin: 80, portMax: 80}},
		},
		{
			name:  "EndPort < Port => treated as single (current behavior)",
			ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: intPort(100), EndPort: int32Ptr(50)}},
			want:  []portMatch{{proto: ipProtoTCP, hasPort: true, portMin: 100, portMax: 100}},
		},
		{
			name:  "EndPort > Port => inclusive range",
			ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: intPort(1000), EndPort: int32Ptr(2000)}},
			want:  []portMatch{{proto: ipProtoTCP, hasPort: true, portMin: 1000, portMax: 2000}},
		},
		{
			name: "multiple ports in one rule",
			ports: []multiv1beta1.MultiNetworkPolicyPort{
				{Protocol: protoPtr(corev1.ProtocolTCP), Port: intPort(80)},
				{Protocol: udp, Port: intPort(53)},
			},
			want: []portMatch{
				{proto: ipProtoTCP, hasPort: true, portMin: 80, portMax: 80},
				{proto: ipProtoUDP, hasPort: true, portMin: 53, portMax: 53},
			},
		},
		{
			name:    "endPort out of range rejected",
			ports:   []multiv1beta1.MultiNetworkPolicyPort{{Port: intPort(100), EndPort: int32Ptr(70000)}},
			wantErr: true,
		},
		{
			name:    "port 0 rejected",
			ports:   []multiv1beta1.MultiNetworkPolicyPort{{Port: intPort(0)}},
			wantErr: true,
		},
		{
			name:    "named port rejected",
			ports:   []multiv1beta1.MultiNetworkPolicyPort{{Port: strPort("http")}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandPorts(tt.ports)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expandPorts err=%v, wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expandPorts = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// --- 4. ipBlock: parseCIDRs and multi-except ordering ---

func TestParseCIDRs(t *testing.T) {
	in := []string{
		"192.168.1.0/24",
		"10.0.0.5/32",     // host /32
		"2001:db8::/32",   // v6
		"2001:db8::1/128", // host /128
		"not-a-cidr",      // dropped, no crash
		"192.168.1.42/24", // non-canonical -> masked to 192.168.1.0/24
	}
	got := parseCIDRs(in)
	want := []string{"192.168.1.0/24", "10.0.0.5/32", "2001:db8::/32", "2001:db8::1/128", "192.168.1.0/24"}
	if len(got) != len(want) {
		t.Fatalf("parseCIDRs len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("parseCIDRs[%d] = %s, want %s", i, got[i].String(), want[i])
		}
	}
}

func TestIPBlockInvalidCIDRSkippedNotCrashing(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "garbage/33"}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	// The unparseable CIDR contributes no allow rule, but the direction still
	// carries a policy so the default-deny catch-all (v4 + v6) must remain.
	for _, r := range rules {
		if r.Verdict == VerdictAccept {
			t.Errorf("invalid CIDR must yield no accept rule; got %+v", r)
		}
	}
	want := []FlowerRule{
		{Rep: testRep, Direction: DirIngress, Priority: 1, Verdict: VerdictDrop},
		{Rep: testRep, Direction: DirIngress, Priority: 2, Family: familyV6, Verdict: VerdictDrop},
	}
	assertRules(t, rules, want)
}

func TestIPBlockMultipleExceptOrderedBeforeAllow(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{
				CIDR:   "10.0.0.0/8",
				Except: []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.3.0/24"}, // last is more specific
			}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	var allowPrio uint16
	excepts := map[string]uint16{}
	for _, r := range rules {
		switch {
		case r.Verdict == VerdictAccept && r.Src.String() == "10.0.0.0/8":
			allowPrio = r.Priority
		case r.Verdict == VerdictDrop && r.Src.IsValid():
			excepts[r.Src.String()] = r.Priority
		}
	}
	if allowPrio == 0 {
		t.Fatalf("missing allow rule for 10.0.0.0/8; got %+v", rules)
	}
	for _, cidr := range []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.3.0/24"} {
		p, ok := excepts[cidr]
		if !ok {
			t.Fatalf("missing except-drop for %s; got %+v", cidr, rules)
		}
		if p >= allowPrio {
			t.Errorf("except %s prio %d must be < allow prio %d", cidr, p, allowPrio)
		}
	}
}

// --- 5. Selector peers ---

func TestNamespaceSelectorOnlyPeer(t *testing.T) {
	deps := newFakeDeps()
	deps.addNamespace(testNS, map[string]string{"kubernetes.io/metadata.name": testNS})
	deps.addNamespace("otherns", map[string]string{"kubernetes.io/metadata.name": "otherns"})
	deps.addPeerPod(testNS, "in-ns", map[string]string{"app": "x"}, testNet, []string{"10.0.0.20"})
	deps.addPeerPod("otherns", "out-ns", map[string]string{"app": "x"}, testNet, []string{"10.0.0.30"})

	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": testNS}},
			}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	got := allowSrcSet(rules)
	if !got["10.0.0.20/32"] {
		t.Errorf("expected peer in selected namespace; got %v", got)
	}
	if got["10.0.0.30/32"] {
		t.Errorf("peer in non-selected namespace must be excluded; got %v", got)
	}
}

func TestPodAndNamespaceSelectorPeer(t *testing.T) {
	deps := newFakeDeps()
	deps.addNamespace(testNS, map[string]string{"kubernetes.io/metadata.name": testNS})
	deps.addPeerPod(testNS, "db", map[string]string{"app": "db"}, testNet, []string{"10.0.0.20"})
	deps.addPeerPod(testNS, "web", map[string]string{"app": "web"}, testNet, []string{"10.0.0.21"})

	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": testNS}},
			}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))
	got := allowSrcSet(rules)
	if !got["10.0.0.20/32"] {
		t.Errorf("expected db pod matched by pod+namespace selector; got %v", got)
	}
	if got["10.0.0.21/32"] {
		t.Errorf("web pod must not match app=db selector; got %v", got)
	}
}

func TestSelectorPeerOnDifferentNetworkExcluded(t *testing.T) {
	deps := newFakeDeps()
	deps.addNamespace(testNS, map[string]string{"kubernetes.io/metadata.name": testNS})
	// Peer pod exists but its only interface is on a network the policy does
	// not target => it must not contribute any address.
	deps.addPeerPodCustom(testNS, "offnet", map[string]string{"app": "db"},
		[]controllers.InterfaceInfo{ifaceOn("testns/other-net", "net1", "10.0.0.40")})

	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))
	if allowSrcSet(rules)["10.0.0.40/32"] {
		t.Errorf("peer on a non-policy network must be excluded; got %+v", rules)
	}
}

func TestSelectorPeerDedupAcrossInterfaces(t *testing.T) {
	deps := newFakeDeps()
	deps.addNamespace(testNS, map[string]string{"kubernetes.io/metadata.name": testNS})
	// One peer pod with two interfaces on the policy network sharing an IP; the
	// duplicate must collapse and the extra IP must appear once.
	deps.addPeerPodCustom(testNS, "multi", map[string]string{"app": "db"},
		[]controllers.InterfaceInfo{
			ifaceOn(testNet, "net1", "10.0.0.20"),
			ifaceOn(testNet, "net2", "10.0.0.20", "10.0.0.21"),
		})

	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	count20 := 0
	for _, r := range rules {
		if r.Verdict == VerdictAccept && r.Src.String() == "10.0.0.20/32" {
			count20++
		}
	}
	if count20 != 1 {
		t.Errorf("dup peer IP 10.0.0.20 must appear exactly once, got %d (%+v)", count20, rules)
	}
	if !allowSrcSet(rules)["10.0.0.21/32"] {
		t.Errorf("expected the distinct second IP 10.0.0.21/32; got %+v", rules)
	}
}

// --- 6. Multiple policies selecting the same pod ---

func TestMultiplePoliciesNoKeyCollisionAndDedup(t *testing.T) {
	deps := newFakeDeps()
	// Two distinct policies, one with a duplicated identical peer (must dedup
	// within the policy), plus a second policy allowing the SAME CIDR (distinct
	// policy identity => distinct priority class, no reconcile-key collision).
	p1 := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}},
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}, // exact dup
			}},
		}, nil)
	p2 := makePolicy("p2",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(p1, p2))

	// No two distinct rules may share the reconcile key.
	assertNoKeyCollision(t, rules)

	// The exact-dup peer inside p1 collapses; across p1/p2 the same CIDR yields
	// distinct rules (different priorities), so we expect exactly two allow
	// rules for 192.168.1.0/24 at DISTINCT priorities.
	var prios []uint16
	for _, r := range rules {
		if r.Verdict == VerdictAccept && r.Src.String() == "192.168.1.0/24" {
			prios = append(prios, r.Priority)
		}
	}
	if len(prios) != 2 {
		t.Fatalf("expected 2 allow rules (one per policy, intra-policy dup collapsed), got %d: %+v", len(prios), rules)
	}
	if prios[0] == prios[1] {
		t.Errorf("allow rules from distinct policies must occupy distinct priority classes, both = %d", prios[0])
	}
}

// --- 7. PolicyTypes semantics ---

func TestPolicyTypesSemantics(t *testing.T) {
	ingressRule := []multiv1beta1.MultiNetworkPolicyIngressRule{
		{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
	}
	egressRule := []multiv1beta1.MultiNetworkPolicyEgressRule{
		{To: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.0/8"}}}},
	}

	tests := []struct {
		name        string
		ptypes      []multiv1beta1.MultiPolicyType
		ingress     []multiv1beta1.MultiNetworkPolicyIngressRule
		egress      []multiv1beta1.MultiNetworkPolicyEgressRule
		wantIngress bool
		wantEgress  bool
	}{
		{"ingress only", []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress}, ingressRule, nil, true, false},
		{"egress only", []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress}, nil, egressRule, false, true},
		{"both", []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress}, ingressRule, egressRule, true, true},
		// Ingress rules present but PolicyTypes=[Egress]: types OVERRIDE presence,
		// so the ingress rule is NOT enforced; the egress direction is enabled
		// (default-deny only, since it has no egress rules).
		{"types override presence", []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress}, ingressRule, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := newFakeDeps()
			policy := makePolicy("p1", tt.ptypes, tt.ingress, tt.egress)

			// Cross-check the selection primitive directly.
			gotIn, gotEg := enabledPolicyTypes(policy)
			if gotIn != tt.wantIngress || gotEg != tt.wantEgress {
				t.Errorf("enabledPolicyTypes = (in=%v,eg=%v), want (in=%v,eg=%v)", gotIn, gotEg, tt.wantIngress, tt.wantEgress)
			}

			rules := buildRules(t, deps, policyMapOf(policy))
			hasIngress, hasEgress := false, false
			for _, r := range rules {
				if r.Direction == DirIngress {
					hasIngress = true
				}
				if r.Direction == DirEgress {
					hasEgress = true
				}
			}
			if hasIngress != tt.wantIngress {
				t.Errorf("ingress filters present = %v, want %v (rules=%+v)", hasIngress, tt.wantIngress, rules)
			}
			if hasEgress != tt.wantEgress {
				t.Errorf("egress filters present = %v, want %v (rules=%+v)", hasEgress, tt.wantEgress, rules)
			}
		})
	}
}

// --- 8. Direction/parent inversion ---

func TestDirectionParentInversion(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		},
		[]multiv1beta1.MultiNetworkPolicyEgressRule{
			{To: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.0/8"}}}},
		})

	// The documented inversion: policy ingress => representor EGRESS parent,
	// policy egress => representor INGRESS parent.
	repEgressParent := core.BuildHandle(0xffff, tc.HandleMinEgress)
	repIngressParent := core.BuildHandle(0xffff, tc.HandleMinIngress)

	rules := buildRules(t, deps, policyMapOf(policy))
	sawIngress, sawEgress := false, false
	for _, r := range rules {
		obj := r.toObject(1)
		switch r.Direction {
		case DirIngress:
			sawIngress = true
			if obj.Parent != repEgressParent {
				t.Errorf("ingress rule must land on representor egress parent %#x; got %#x", repEgressParent, obj.Parent)
			}
		case DirEgress:
			sawEgress = true
			if obj.Parent != repIngressParent {
				t.Errorf("egress rule must land on representor ingress parent %#x; got %#x", repIngressParent, obj.Parent)
			}
		}
	}
	if !sawIngress || !sawEgress {
		t.Fatalf("expected both ingress and egress rules; got %+v", rules)
	}
	if repIngressParent == repEgressParent {
		t.Fatal("ingress and egress parents must differ")
	}
}

// --- 9. handle uniqueness across a realistic mixed rule set ---

func TestHandleUniquenessMixedRuleSet(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{
					{Protocol: protoPtr(corev1.ProtocolTCP), Port: intPort(80)},
					{Protocol: protoPtr(corev1.ProtocolUDP), Port: intPort(1000), EndPort: int32Ptr(2000)},
				},
				From: []multiv1beta1.MultiNetworkPolicyPeer{
					{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24", Except: []string{"192.168.1.128/25"}}},
					{IPBlock: &multiv1beta1.IPBlock{CIDR: "2001:db8::/32"}},
				},
			},
		},
		[]multiv1beta1.MultiNetworkPolicyEgressRule{
			{To: []multiv1beta1.MultiNetworkPolicyPeer{
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.0/8"}},
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "fd00::/8"}},
			}},
		})
	pm := policyMapOf(policy)

	// Both stateless and CT-enabled (chain 0 + chain 1) mixes must be collision-free.
	rules := buildRules(t, deps, pm)
	if len(rules) == 0 {
		t.Fatal("expected a non-trivial rule set")
	}
	assertNoKeyCollision(t, rules)

	ctRules := buildCTRules(t, deps, pm)
	assertNoKeyCollision(t, ctRules)
}

// --- 10. maskSignature ---

func TestMaskSignatureDistinguishesPrefixLen(t *testing.T) {
	base24 := FlowerRule{Direction: DirIngress, Src: netip.MustParsePrefix("10.0.0.0/24")}
	other24 := FlowerRule{Direction: DirIngress, Src: netip.MustParsePrefix("10.1.1.0/24")} // same shape, different value
	base16 := FlowerRule{Direction: DirIngress, Src: netip.MustParsePrefix("10.0.0.0/16")}  // different prefix length

	if maskSignature(base24) != maskSignature(other24) {
		t.Errorf("rules with identical mask shape must share a signature: %q vs %q",
			maskSignature(base24), maskSignature(other24))
	}
	if maskSignature(base24) == maskSignature(base16) {
		t.Errorf("rules differing only in prefix length must get different signatures (both %q)", maskSignature(base24))
	}
}

// --- 11. Offload modes on toObject / offloadFlags ---

func TestOffloadFlagsMapping(t *testing.T) {
	if offloadFlags(OffloadHardware) != tc.SkipSw {
		t.Errorf("hardware mode must map to SkipSw")
	}
	if offloadFlags(OffloadSoftware) != tc.SkipHw {
		t.Errorf("software mode must map to SkipHw")
	}
	// OffloadAuto is rejected at parse time, and offloadFlags falls back to the
	// fail-closed hardware default rather than emitting a flag-less filter.
	if offloadFlags(OffloadAuto) != tc.SkipSw {
		t.Errorf("auto (unreachable) must fall back to SkipSw, not a flag-less filter")
	}
	if _, err := parseOffloadMode("auto"); err == nil {
		t.Errorf("parseOffloadMode(auto) must error (not-yet-supported)")
	}
	if m, err := parseOffloadMode(""); err != nil || m != OffloadHardware {
		t.Errorf("empty mode must default to hardware, got %v err=%v", m, err)
	}
}

// --- helpers ---

func strPort(s string) *intstr.IntOrString {
	p := intstr.FromString(s)
	return &p
}

func allowSrcSet(rules []FlowerRule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		if r.Verdict == VerdictAccept && r.Src.IsValid() {
			out[r.Src.String()] = true
		}
	}
	return out
}
