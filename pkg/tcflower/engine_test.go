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
	"net/netip"
	"reflect"
	"testing"

	tc "github.com/florianl/go-tc"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// --- fake PolicyDeps (mirrors the testPolicyDeps pattern from
// pkg/server/netfilterrules_test.go, without the CRI/nftables machinery) ---

type fakeDeps struct {
	podMap       map[types.NamespacedName]controllers.PodInfo
	namespaceMap map[string]controllers.NamespaceInfo
	pods         map[types.NamespacedName]*corev1.Pod
}

var _ controllers.PolicyDeps = (*fakeDeps)(nil)

func newFakeDeps() *fakeDeps {
	return &fakeDeps{
		podMap:       make(map[types.NamespacedName]controllers.PodInfo),
		namespaceMap: make(map[string]controllers.NamespaceInfo),
		pods:         make(map[types.NamespacedName]*corev1.Pod),
	}
}

func (s *fakeDeps) ListPods(_ context.Context, selector labels.Selector) ([]*corev1.Pod, error) {
	if selector == nil {
		selector = labels.Everything()
	}
	pods := make([]*corev1.Pod, 0, len(s.pods))
	for _, pod := range s.pods {
		if selector.Matches(labels.Set(pod.Labels)) {
			pods = append(pods, pod)
		}
	}
	return pods, nil
}

func (s *fakeDeps) GetNamespaceInfo(_ context.Context, namespace string) (*controllers.NamespaceInfo, error) {
	ns, ok := s.namespaceMap[namespace]
	if !ok {
		return nil, fmt.Errorf("namespace %q not found", namespace)
	}
	return &ns, nil
}

func (s *fakeDeps) GetPodInfo(_ context.Context, pod *corev1.Pod) (*controllers.PodInfo, error) {
	if pod == nil {
		return nil, fmt.Errorf("nil pod")
	}
	pi, ok := s.podMap[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]
	if !ok {
		return nil, fmt.Errorf("podInfo not found")
	}
	return &pi, nil
}

func (s *fakeDeps) addNamespace(name string, lbls map[string]string) {
	s.namespaceMap[name] = controllers.NamespaceInfo{Name: name, Labels: lbls}
}

func (s *fakeDeps) addPeerPod(namespace, name string, lbls map[string]string, netattach string, ips []string) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: lbls},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	nn := types.NamespacedName{Namespace: namespace, Name: name}
	s.pods[nn] = pod
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	s.podMap[nn] = controllers.PodInfo{
		Name:      name,
		Namespace: namespace,
		Interfaces: []controllers.InterfaceInfo{
			{NetattachName: netattach, InterfaceName: "net1", IPs: addrs},
		},
	}
}

// --- test fixtures ---

const (
	testNS      = "testns"
	testNet     = "testns/policy-net-1"
	testRep     = "enp3s0f0_1"
	testNetName = "policy-net-1"
)

// targetPod / targetPodInfo describe the pod being enforced.
func targetPod(lbls map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: "target", Labels: lbls},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func targetPodInfo() *controllers.PodInfo {
	return &controllers.PodInfo{
		Name:      "target",
		Namespace: testNS,
		Interfaces: []controllers.InterfaceInfo{
			{
				NetattachName:     testNet,
				InterfaceName:     "net1",
				IPs:               []netip.Addr{netip.MustParseAddr("10.0.0.5")},
				PCIAddress:        "0000:03:00.1",
				RepresentorDevice: testRep,
			},
		},
	}
}

func targetIface() controllers.InterfaceInfo {
	return targetPodInfo().Interfaces[0]
}

func protoPtr(p corev1.Protocol) *corev1.Protocol { return &p }
func int32Ptr(v int32) *int32                     { return &v }

// makePolicy builds a MultiNetworkPolicy on the test network selecting all pods.
func makePolicy(name string, ptypes []multiv1beta1.MultiPolicyType, ingress []multiv1beta1.MultiNetworkPolicyIngressRule, egress []multiv1beta1.MultiNetworkPolicyEgressRule) *multiv1beta1.MultiNetworkPolicy {
	return &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   testNS,
			Name:        name,
			Annotations: map[string]string{policyNetworkAnnotation: testNetName},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PolicyTypes: ptypes,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

func policyMapOf(policies ...*multiv1beta1.MultiNetworkPolicy) controllers.PolicyMap {
	m := controllers.PolicyMap{}
	for _, p := range policies {
		m[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = p
	}
	return m
}

func buildRules(t *testing.T, deps controllers.PolicyDeps, policyMap controllers.PolicyMap) []FlowerRule {
	t.Helper()
	rules, err := BuildFlowerRules(context.Background(), deps, controllers.CommonRuleConfig{},
		policyMap, targetPod(nil), targetPodInfo(), targetIface())
	if err != nil {
		t.Fatalf("BuildFlowerRules returned error: %v", err)
	}
	return rules
}

// --- tests ---

func TestIngressAllowFromCIDRAndDefaultDeny(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	want := []FlowerRule{
		{Rep: testRep, Direction: DirIngress, Priority: 1, Src: netip.MustParsePrefix("192.168.1.0/24"), Verdict: VerdictAccept},
		{Rep: testRep, Direction: DirIngress, Priority: 2, Verdict: VerdictDrop},                   // v4 default-deny
		{Rep: testRep, Direction: DirIngress, Priority: 3, Family: familyV6, Verdict: VerdictDrop}, // v6 default-deny
	}
	assertRules(t, rules, want)

	// Every converted rule must carry skip_sw and the correct parent.
	for _, r := range rules {
		obj := r.toObject(42)
		if obj.Flower == nil || obj.Flower.Flags == nil || *obj.Flower.Flags != tc.SkipSw {
			t.Errorf("rule %+v: expected skip_sw flag", r)
		}
		if obj.Parent != DirIngress.parentHandle() {
			t.Errorf("rule %+v: wrong parent %#x, want ingress parent %#x", r, obj.Parent, DirIngress.parentHandle())
		}
	}
}

func TestEgressAllowToCIDR(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
		nil,
		[]multiv1beta1.MultiNetworkPolicyEgressRule{
			{To: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.10.0.0/16"}}}},
		})

	rules := buildRules(t, deps, policyMapOf(policy))

	want := []FlowerRule{
		{Rep: testRep, Direction: DirEgress, Priority: 1, Dst: netip.MustParsePrefix("10.10.0.0/16"), Verdict: VerdictAccept},
		{Rep: testRep, Direction: DirEgress, Priority: 2, Verdict: VerdictDrop},                   // v4 default-deny
		{Rep: testRep, Direction: DirEgress, Priority: 3, Family: familyV6, Verdict: VerdictDrop}, // v6 default-deny
	}
	assertRules(t, rules, want)

	for _, r := range rules {
		if r.Direction != DirEgress {
			continue
		}
		obj := r.toObject(7)
		if obj.Parent != DirEgress.parentHandle() {
			t.Errorf("egress rule %+v got parent %#x, want %#x", r, obj.Parent, DirEgress.parentHandle())
		}
	}
}

func TestIPBlockWithExcept(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{
				CIDR:   "10.0.0.0/8",
				Except: []string{"10.1.0.0/16"},
			}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	// Except drop must have a numerically lower priority than the allow.
	var exceptPrio, allowPrio uint16
	var foundExcept, foundAllow bool
	for _, r := range rules {
		if r.Verdict == VerdictDrop && r.Src.String() == "10.1.0.0/16" {
			exceptPrio = r.Priority
			foundExcept = true
		}
		if r.Verdict == VerdictAccept && r.Src.String() == "10.0.0.0/8" {
			allowPrio = r.Priority
			foundAllow = true
		}
	}
	if !foundExcept || !foundAllow {
		t.Fatalf("expected both except-drop and allow rules; got %+v", rules)
	}
	if exceptPrio >= allowPrio {
		t.Errorf("except drop priority %d must be < allow priority %d", exceptPrio, allowPrio)
	}
}

func TestPodSelectorPeerExpandsToIPv4(t *testing.T) {
	deps := newFakeDeps()
	deps.addNamespace(testNS, map[string]string{"kubernetes.io/metadata.name": testNS})
	deps.addPeerPod(testNS, "peer1", map[string]string{"app": "db"}, testNet, []string{"10.0.0.20"})
	deps.addPeerPod(testNS, "peer2", map[string]string{"app": "db"}, testNet, []string{"10.0.0.21"})
	deps.addPeerPod(testNS, "other", map[string]string{"app": "web"}, testNet, []string{"10.0.0.99"})

	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	got := map[string]bool{}
	for _, r := range rules {
		if r.Verdict == VerdictAccept && r.Src.IsValid() {
			got[r.Src.String()] = true
		}
	}
	if !got["10.0.0.20/32"] || !got["10.0.0.21/32"] {
		t.Errorf("expected /32 rules for peer1 and peer2, got %v", got)
	}
	if got["10.0.0.99/32"] {
		t.Errorf("did not expect a rule for the non-matching pod, got %v", got)
	}
}

func TestSinglePortAndPortRange(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{
					{Protocol: protoPtr(corev1.ProtocolTCP), Port: intPort(80)},
					{Protocol: protoPtr(corev1.ProtocolUDP), Port: intPort(1000), EndPort: int32Ptr(2000)},
				},
				From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.0.0/24"}}},
			},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	var single, rangeR *FlowerRule
	for i := range rules {
		r := &rules[i]
		if r.Verdict != VerdictAccept {
			continue
		}
		if r.Proto == ipProtoTCP && r.HasPort && r.PortMin == 80 && r.PortMax == 80 {
			single = r
		}
		if r.Proto == ipProtoUDP && r.HasPort && r.PortMin == 1000 && r.PortMax == 2000 {
			rangeR = r
		}
	}
	if single == nil {
		t.Fatalf("expected single TCP/80 rule; got %+v", rules)
	}
	if rangeR == nil {
		t.Fatalf("expected UDP 1000-2000 range rule; got %+v", rules)
	}

	// toObject: single port sets KeyTCPDst; range sets KeyPortDstMin/Max.
	so := single.toObject(1)
	if so.Flower.KeyTCPDst == nil || *so.Flower.KeyTCPDst != 80 {
		t.Errorf("single port: expected KeyTCPDst=80, got %+v", so.Flower.KeyTCPDst)
	}
	if so.Flower.KeyIPProto == nil || *so.Flower.KeyIPProto != uint8(ipProtoTCP) {
		t.Errorf("single port: expected ip_proto TCP")
	}
	ro := rangeR.toObject(1)
	if ro.Flower.KeyPortDstMin == nil || *ro.Flower.KeyPortDstMin != 1000 ||
		ro.Flower.KeyPortDstMax == nil || *ro.Flower.KeyPortDstMax != 2000 {
		t.Errorf("range port: expected 1000-2000, got min=%v max=%v", ro.Flower.KeyPortDstMin, ro.Flower.KeyPortDstMax)
	}
	if ro.Flower.KeyUDPDst == nil || *ro.Flower.KeyUDPDst != 1000 {
		// go-tc range still keys off protocol port fields? No: for ranges we
		// only set PortDstMin/Max, not KeyUDPDst. Assert it's absent.
		if ro.Flower.KeyUDPDst != nil {
			t.Errorf("range port should not set KeyUDPDst, got %v", *ro.Flower.KeyUDPDst)
		}
	}
}

func TestEmptyPeersAndEmptyPorts(t *testing.T) {
	deps := newFakeDeps()
	// Ingress rule with neither ports nor peers => match-any accept.
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{{}}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	// Match-any (empty peers) covers BOTH families, and so does the
	// default-deny catch-all: a v4 and a v6 filter for each.
	want := []FlowerRule{
		{Rep: testRep, Direction: DirIngress, Priority: 1, Verdict: VerdictAccept},                   // v4 match-any
		{Rep: testRep, Direction: DirIngress, Priority: 2, Family: familyV6, Verdict: VerdictAccept}, // v6 match-any
		{Rep: testRep, Direction: DirIngress, Priority: 3, Verdict: VerdictDrop},                     // v4 default-deny
		{Rep: testRep, Direction: DirIngress, Priority: 4, Family: familyV6, Verdict: VerdictDrop},   // v6 default-deny
	}
	assertRules(t, rules, want)
}

// TestMixedIPBlockEmitsBothFamilies proves a single ipBlock peer carrying both
// a v4 and a v6 CIDR yields one v4 filter and one v6 filter, each with the
// correct family and address key. (This inverts the former Phase-2
// "IPv6 peers skipped" test, which asserted v6 was dropped.)
func TestMixedIPBlockEmitsBothFamilies(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "2001:db8::/32"}},  // v6 => v6 filter
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.5.0/24"}}, // v4 => v4 filter
			}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	var v4, v6 *FlowerRule
	for i := range rules {
		r := &rules[i]
		if r.Verdict != VerdictAccept {
			continue
		}
		if r.Src.String() == "192.168.5.0/24" {
			v4 = r
		}
		if r.Src.String() == "2001:db8::/32" {
			v6 = r
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("expected both a v4 and a v6 allow rule; got %+v", rules)
	}
	if v4.Family != familyV4 {
		t.Errorf("v4 CIDR rule must carry familyV4, got %d", v4.Family)
	}
	if v6.Family != familyV6 {
		t.Errorf("v6 CIDR rule must carry familyV6, got %d", v6.Family)
	}

	// v4 filter: ethertype 0x0800, KeyIPv4Src; no v6 keys.
	o4 := v4.toObject(1)
	if o4.Flower.KeyEthType == nil || *o4.Flower.KeyEthType != ethTypeIPv4 {
		t.Errorf("v4 filter ethertype = %v, want 0x0800", o4.Flower.KeyEthType)
	}
	if o4.Flower.KeyIPv4Src == nil || o4.Flower.KeyIPv6Src != nil {
		t.Errorf("v4 filter must set KeyIPv4Src and not KeyIPv6Src")
	}

	// v6 filter: ethertype 0x86dd, 16-byte KeyIPv6Src + mask; no v4 keys.
	o6 := v6.toObject(1)
	if o6.Flower.KeyEthType == nil || *o6.Flower.KeyEthType != ethTypeIPv6 {
		t.Errorf("v6 filter ethertype = %v, want 0x86dd", o6.Flower.KeyEthType)
	}
	if o6.Flower.KeyIPv6Src == nil || o6.Flower.KeyIPv6SrcMask == nil {
		t.Fatalf("v6 filter must set KeyIPv6Src + mask")
	}
	if len(*o6.Flower.KeyIPv6Src) != 16 {
		t.Errorf("v6 src key must be 16 bytes, got %d", len(*o6.Flower.KeyIPv6Src))
	}
	if o6.Flower.KeyIPv4Src != nil {
		t.Errorf("v6 filter must not set KeyIPv4Src")
	}
	if o6.Flower.Flags == nil || *o6.Flower.Flags != tc.SkipSw {
		t.Errorf("v6 filter must carry skip_sw")
	}
}

func TestPriorityStability(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}, // /24 mask shape
				{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.5/32"}},    // /32 mask shape
			}},
		}, nil)
	pm := policyMapOf(policy)

	first := buildRules(t, deps, pm)
	second := buildRules(t, deps, pm)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("BuildFlowerRules not stable:\nfirst:  %+v\nsecond: %+v", first, second)
	}

	// Two different mask shapes must land on different priorities.
	var p24, p32 uint16
	for _, r := range first {
		switch r.Src.String() {
		case "192.168.1.0/24":
			p24 = r.Priority
		case "10.0.0.5/32":
			p32 = r.Priority
		}
	}
	if p24 == 0 || p32 == 0 {
		t.Fatalf("expected both /24 and /32 rules; got %+v", first)
	}
	if p24 == p32 {
		t.Errorf("different mask shapes must get different priorities: /24=%d /32=%d", p24, p32)
	}
}

func TestToObjectSkipSwAndKeys(t *testing.T) {
	r := FlowerRule{
		Rep:       testRep,
		Direction: DirIngress,
		Priority:  3,
		Proto:     ipProtoTCP,
		Src:       netip.MustParsePrefix("192.168.1.0/24"),
		HasPort:   true,
		PortMin:   443,
		PortMax:   443,
		Verdict:   VerdictAccept,
	}
	obj := r.toObject(99)

	if obj.Kind != "flower" || obj.Flower == nil {
		t.Fatalf("expected flower object, got kind %q", obj.Kind)
	}
	if obj.Flower.Flags == nil || *obj.Flower.Flags != tc.SkipSw {
		t.Errorf("expected skip_sw flag set")
	}
	if obj.Flower.KeyIPProto == nil || *obj.Flower.KeyIPProto != uint8(ipProtoTCP) {
		t.Errorf("expected ip_proto TCP")
	}
	if obj.Flower.KeyTCPDst == nil || *obj.Flower.KeyTCPDst != 443 {
		t.Errorf("expected KeyTCPDst=443")
	}
	if obj.Flower.KeyIPv4Src == nil || obj.Flower.KeyIPv4SrcMask == nil {
		t.Errorf("expected src ipv4 addr + mask set")
	}
	if obj.Flower.Actions == nil || len(*obj.Flower.Actions) != 1 {
		t.Fatalf("expected exactly one gact action")
	}
	act := (*obj.Flower.Actions)[0]
	if act.Kind != "gact" || act.Gact == nil || act.Gact.Parms == nil {
		t.Fatalf("expected gact action with parms")
	}
	if act.Gact.Parms.Action != tcActOK {
		t.Errorf("accept verdict should map to TC_ACT_OK (%d), got %d", tcActOK, act.Gact.Parms.Action)
	}

	// drop verdict maps to TC_ACT_SHOT
	rd := r
	rd.Verdict = VerdictDrop
	od := rd.toObject(99)
	if (*od.Flower.Actions)[0].Gact.Parms.Action != tcActShot {
		t.Errorf("drop verdict should map to TC_ACT_SHOT (%d)", tcActShot)
	}
}

// TestIPv6IngressAllowFromCIDR: an ingress ipBlock with a v6 CIDR produces a
// familyV6 accept whose toObject carries ethertype 0x86dd and a 16-byte
// KeyIPv6Src + /64 mask, plus a v6 default-deny.
func TestIPv6IngressAllowFromCIDR(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "2001:db8::/64"}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	var allow *FlowerRule
	for i := range rules {
		if rules[i].Verdict == VerdictAccept && rules[i].Src.String() == "2001:db8::/64" {
			allow = &rules[i]
		}
	}
	if allow == nil {
		t.Fatalf("missing v6 allow for 2001:db8::/64; rules=%+v", rules)
	}
	if allow.Family != familyV6 {
		t.Errorf("allow rule family = %d, want familyV6", allow.Family)
	}

	obj := allow.toObject(1)
	if obj.Flower.KeyEthType == nil || *obj.Flower.KeyEthType != ethTypeIPv6 {
		t.Errorf("expected ethertype 0x86dd, got %v", obj.Flower.KeyEthType)
	}
	if obj.Flower.KeyIPv6Src == nil || len(*obj.Flower.KeyIPv6Src) != 16 {
		t.Fatalf("expected 16-byte KeyIPv6Src, got %v", obj.Flower.KeyIPv6Src)
	}
	if obj.Flower.KeyIPv6SrcMask == nil || len(*obj.Flower.KeyIPv6SrcMask) != 16 {
		t.Fatalf("expected 16-byte KeyIPv6SrcMask, got %v", obj.Flower.KeyIPv6SrcMask)
	}
	// /64 mask: first 8 bytes 0xff, last 8 bytes 0x00.
	m := *obj.Flower.KeyIPv6SrcMask
	for i := 0; i < 8; i++ {
		if m[i] != 0xff {
			t.Errorf("mask byte %d = %#x, want 0xff", i, m[i])
		}
	}
	for i := 8; i < 16; i++ {
		if m[i] != 0x00 {
			t.Errorf("mask byte %d = %#x, want 0x00", i, m[i])
		}
	}
	if obj.Flower.Flags == nil || *obj.Flower.Flags != tc.SkipSw {
		t.Errorf("v6 filter must carry skip_sw")
	}
	// A v6 default-deny must exist too.
	var v6deny bool
	for _, r := range rules {
		if r.Verdict == VerdictDrop && r.Family == familyV6 && !r.Src.IsValid() {
			v6deny = true
		}
	}
	if !v6deny {
		t.Errorf("expected a v6 default-deny catch-all; got %+v", rules)
	}
}

// TestIPv6EgressAllowToCIDR: an egress ipBlock with a v6 CIDR puts the prefix
// in the Dst slot with familyV6.
func TestIPv6EgressAllowToCIDR(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
		nil,
		[]multiv1beta1.MultiNetworkPolicyEgressRule{
			{To: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "fd00::/8"}}}},
		})

	rules := buildRules(t, deps, policyMapOf(policy))

	var allow *FlowerRule
	for i := range rules {
		if rules[i].Verdict == VerdictAccept && rules[i].Dst.String() == "fd00::/8" {
			allow = &rules[i]
		}
	}
	if allow == nil {
		t.Fatalf("missing v6 egress allow for fd00::/8; rules=%+v", rules)
	}
	if allow.Family != familyV6 {
		t.Errorf("egress v6 allow family = %d, want familyV6", allow.Family)
	}
	obj := allow.toObject(1)
	if obj.Flower.KeyEthType == nil || *obj.Flower.KeyEthType != ethTypeIPv6 {
		t.Errorf("expected ethertype 0x86dd")
	}
	if obj.Flower.KeyIPv6Dst == nil || len(*obj.Flower.KeyIPv6Dst) != 16 {
		t.Errorf("expected 16-byte KeyIPv6Dst")
	}
	if obj.Flower.KeyIPv4Dst != nil {
		t.Errorf("v6 filter must not set KeyIPv4Dst")
	}
}

// TestIPBlockWithV6Except: a v6 ipBlock with a v6 Except emits the except-drop
// at a lower priority than the allow, both familyV6.
func TestIPBlockWithV6Except(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{
				CIDR:   "2001:db8::/32",
				Except: []string{"2001:db8:1::/48"},
			}}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	var exceptPrio, allowPrio uint16
	var foundExcept, foundAllow bool
	for _, r := range rules {
		if r.Verdict == VerdictDrop && r.Src.String() == "2001:db8:1::/48" {
			if r.Family != familyV6 {
				t.Errorf("except drop must be familyV6, got %d", r.Family)
			}
			exceptPrio = r.Priority
			foundExcept = true
		}
		if r.Verdict == VerdictAccept && r.Src.String() == "2001:db8::/32" {
			if r.Family != familyV6 {
				t.Errorf("allow must be familyV6, got %d", r.Family)
			}
			allowPrio = r.Priority
			foundAllow = true
		}
	}
	if !foundExcept || !foundAllow {
		t.Fatalf("expected both v6 except-drop and v6 allow; got %+v", rules)
	}
	if exceptPrio >= allowPrio {
		t.Errorf("v6 except drop priority %d must be < allow priority %d", exceptPrio, allowPrio)
	}
}

// TestPodSelectorPeerDualStack: a peer pod carrying both a v4 and a v6 address
// yields one v4 filter (/32) and one v6 filter (/128).
func TestPodSelectorPeerDualStack(t *testing.T) {
	deps := newFakeDeps()
	deps.addNamespace(testNS, map[string]string{"kubernetes.io/metadata.name": testNS})
	deps.addPeerPod(testNS, "peer1", map[string]string{"app": "db"}, testNet, []string{"10.0.0.20", "2001:db8::20"})

	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			}}},
		}, nil)

	rules := buildRules(t, deps, policyMapOf(policy))

	var v4, v6 *FlowerRule
	for i := range rules {
		r := &rules[i]
		if r.Verdict != VerdictAccept {
			continue
		}
		if r.Src.String() == "10.0.0.20/32" {
			v4 = r
		}
		if r.Src.String() == "2001:db8::20/128" {
			v6 = r
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("expected both /32 (v4) and /128 (v6) allow rules; got %+v", rules)
	}
	if v4.Family != familyV4 {
		t.Errorf("v4 /32 rule family = %d, want familyV4", v4.Family)
	}
	if v6.Family != familyV6 {
		t.Errorf("v6 /128 rule family = %d, want familyV6", v6.Family)
	}
	if o := v4.toObject(1); o.Flower.KeyIPv4Src == nil {
		t.Errorf("v4 /32 filter must set KeyIPv4Src")
	}
	if o := v6.toObject(1); o.Flower.KeyIPv6Src == nil || len(*o.Flower.KeyIPv6Src) != 16 {
		t.Errorf("v6 /128 filter must set 16-byte KeyIPv6Src")
	}
}

// TestParseOffloadMode covers every accepted value, the unsupported "auto"
// case, and an invalid value.
func TestParseOffloadMode(t *testing.T) {
	tests := []struct {
		in      string
		want    OffloadMode
		wantErr bool
	}{
		{"", OffloadHardware, false},
		{"hardware", OffloadHardware, false},
		{"software", OffloadSoftware, false},
		{"auto", OffloadAuto, true},      // recognized but not-yet-supported
		{"bogus", OffloadHardware, true}, // invalid -> error, fail-closed default
	}
	for _, tt := range tests {
		got, err := parseOffloadMode(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseOffloadMode(%q) err=%v, wantErr=%v", tt.in, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parseOffloadMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// TestToObjectOffloadFlags asserts hardware mode emits SkipSw and software mode
// emits SkipHw. (isManagedFilter recognition for both modes is asserted in the
// linux-tagged apply_test.go, since isManagedFilter lives in the linux build.)
func TestToObjectOffloadFlags(t *testing.T) {
	base := FlowerRule{
		Rep:       testRep,
		Direction: DirIngress,
		Priority:  1,
		Src:       netip.MustParsePrefix("192.168.1.0/24"),
		Verdict:   VerdictAccept,
	}

	hw := base // OffloadHardware is the zero value
	hwObj := hw.toObject(1)
	if hwObj.Flower.Flags == nil || *hwObj.Flower.Flags != tc.SkipSw {
		t.Errorf("hardware mode: expected Flags==SkipSw, got %v", hwObj.Flower.Flags)
	}

	sw := base
	sw.Offload = OffloadSoftware
	swObj := sw.toObject(1)
	if swObj.Flower.Flags == nil || *swObj.Flower.Flags != tc.SkipHw {
		t.Errorf("software mode: expected Flags==SkipHw, got %v", swObj.Flower.Flags)
	}

	// Different offload modes must produce distinct handles/identities so the
	// two never alias in the reconcile diff.
	if hwObj.Handle == swObj.Handle {
		t.Errorf("hardware and software filters must have distinct handles; both = %#x", hwObj.Handle)
	}
}

// TestBuildFlowerRulesSoftwareMode threads TCOffloadMode="software" through the
// engine and asserts every emitted rule carries OffloadSoftware and stamps
// SkipHw, while the default (empty) stays hardware/SkipSw.
func TestBuildFlowerRulesSoftwareMode(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)
	pm := policyMapOf(policy)

	swRules, err := BuildFlowerRules(context.Background(), deps,
		controllers.CommonRuleConfig{TCOffloadMode: "software"},
		pm, targetPod(nil), targetPodInfo(), targetIface())
	if err != nil {
		t.Fatalf("BuildFlowerRules(software): %v", err)
	}
	if len(swRules) == 0 {
		t.Fatal("expected rules in software mode")
	}
	for _, r := range swRules {
		if r.Offload != OffloadSoftware {
			t.Errorf("software mode: rule %+v has Offload=%v", r, r.Offload)
		}
		if o := r.toObject(1); o.Flower.Flags == nil || *o.Flower.Flags != tc.SkipHw {
			t.Errorf("software mode: rule %+v must stamp SkipHw", r)
		}
	}

	// Default (empty mode) stays hardware/SkipSw.
	hwRules := buildRules(t, deps, pm)
	for _, r := range hwRules {
		if r.Offload != OffloadHardware {
			t.Errorf("default mode: rule %+v has Offload=%v, want hardware", r, r.Offload)
		}
		if o := r.toObject(1); o.Flower.Flags == nil || *o.Flower.Flags != tc.SkipSw {
			t.Errorf("default mode: rule %+v must stamp SkipSw", r)
		}
	}
}

// TestBuildFlowerRulesAutoRejected asserts the engine fails closed on the
// not-yet-supported "auto" mode rather than emitting flag-less filters.
func TestBuildFlowerRulesAutoRejected(t *testing.T) {
	deps := newFakeDeps()
	policy := makePolicy("p1",
		[]multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		[]multiv1beta1.MultiNetworkPolicyIngressRule{
			{From: []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"}}}},
		}, nil)

	_, err := BuildFlowerRules(context.Background(), deps,
		controllers.CommonRuleConfig{TCOffloadMode: "auto"},
		policyMapOf(policy), targetPod(nil), targetPodInfo(), targetIface())
	if err == nil {
		t.Fatal("expected BuildFlowerRules to reject auto mode, got nil error")
	}
}

// --- helpers ---

func intPort(v int) *intstr.IntOrString {
	p := intstr.FromInt(v)
	return &p
}

func assertRules(t *testing.T, got, want []FlowerRule) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("rule count mismatch: got %d, want %d\ngot:  %+v\nwant: %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("rule[%d] mismatch:\n got: %+v\nwant: %+v", i, got[i], want[i])
		}
	}
}
