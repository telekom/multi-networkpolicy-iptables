/*
Copyright 2025 Deutsche Telekom AG.

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

package server

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"

	nftables "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/nftest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const DEBUG = false

type testPolicyDeps struct {
	podMap       map[types.NamespacedName]controllers.PodInfo
	namespaceMap map[string]controllers.NamespaceInfo
	netdefMap    map[types.NamespacedName]string
	cfg          controllers.CommonRuleConfig
	pods         map[types.NamespacedName]*corev1.Pod
}

var _ controllers.PolicyDeps = (*testPolicyDeps)(nil)
var _ controllers.NetDefResolver = (*testPolicyDeps)(nil)

func (s *testPolicyDeps) ListPods(_ context.Context, selector labels.Selector) ([]*corev1.Pod, error) {
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

func (s *testPolicyDeps) GetNamespaceInfo(_ context.Context, namespace string) (*controllers.NamespaceInfo, error) {
	if s == nil || s.namespaceMap == nil {
		return nil, fmt.Errorf("not found")
	}

	nsInfo, ok := s.namespaceMap[namespace]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	return &nsInfo, nil
}

func (s *testPolicyDeps) GetPodInfo(_ context.Context, pod *corev1.Pod) (*controllers.PodInfo, error) {
	if s == nil || s.podMap == nil || pod == nil {
		return nil, fmt.Errorf("not found")
	}

	podInfo, ok := s.podMap[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	return &podInfo, nil
}

func (s *testPolicyDeps) GetPluginType(_ context.Context, namespacedName types.NamespacedName) (string, error) {
	if s == nil || s.netdefMap == nil {
		return "", nil
	}

	pluginType, ok := s.netdefMap[namespacedName]
	if !ok {
		return "", nil
	}

	return pluginType, nil
}

func TestBootstrap(t *testing.T) {
	// Open a system connection in a separate network namespace it requires root
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.FlushRuleset()
	defer c.CloseLasting()
	c.FlushRuleset()

	podMockInfo := &controllers.PodInfo{
		Interfaces: []controllers.InterfaceInfo{
			{NetattachName: "one", InterfaceName: "eth0", IPs: []string{"10.0.0.0", "fd00::"}},
			{NetattachName: "two", InterfaceName: "eth1", IPs: []string{"fd01::"}},
			{NetattachName: "three", InterfaceName: "eth2", IPs: []string{"10.0.0.0"}},
		},
	}

	_, err := bootstrapNetfilterRules(c, podMockInfo)
	if err != nil {
		t.Fatalf("bootstrapNetfilterRules() failed: %v", err)
	}
	err = c.Flush()
	if err != nil {
		t.Fatalf("Cannot flush %v", err)
	}

	checkForBootstrap := func() bool {

		filterTable, err := c.ListTableOfFamily(FilterTableName, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(%q) failed: %v", FilterTableName, err)
		}
		natTable, err := c.ListTableOfFamily(NatTableName, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(%q) failed: %v", NatTableName, err)
		}
		if filterTable == nil || natTable == nil {
			t.Errorf("filterTable or natTable is nil %v, %v", filterTable, natTable)
			return false
		}
		chains, err := c.ListChains()
		if err != nil {
			t.Fatalf("c.ListChains() failed: %v", err)
		}
		var foundInput, foundOutput, foundIngress, foundEgress, foundCommonIngress, foundCommonEgress, foundPreRouting bool
		for _, ch := range chains {
			if ch.Table.Name == FilterTableName {
				switch ch.Name {
				case ingressChain:
					foundIngress = true
				case egressChain:
					foundEgress = true
				case fmt.Sprintf("%s-%s", ingressChain, common):
					foundCommonIngress = true
				case fmt.Sprintf("%s-%s", egressChain, common):
					foundCommonEgress = true
				case "input":
					foundInput = true
				case "output":
					foundOutput = true
				}
			}
			if ch.Table.Name == NatTableName {
				if ch.Name == "prerouting" {
					foundPreRouting = true
				}
			}
		}
		if !foundIngress || !foundEgress || !foundCommonIngress || !foundCommonEgress || !foundPreRouting || !foundInput || !foundOutput {
			t.Errorf("chains not found: ingress %v, egress %v, commonIngress %v, commonEgress %v, prerouting %v, input %v, output %v",
				foundIngress, foundEgress, foundCommonIngress, foundCommonEgress, foundPreRouting, foundInput, foundOutput)
			return false
		}
		inputRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: "input",
		})
		if err != nil {
			t.Fatalf("c.GetRules(filterTable, \"input\") failed: %v", err)
		}
		outputRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: "output",
		})
		if err != nil {
			t.Fatalf("c.GetRules(filterTable, \"output\") failed: %v", err)
		}
		natRules, err := c.GetRules(natTable, &nftables.Chain{
			Name: "prerouting",
		})
		if err != nil {
			t.Fatalf("c.GetRules(natTable, \"prerouting\") failed: %v", err)
		}
		if len(inputRules) != 1 || len(outputRules) != 1 || len(natRules) != 1 {
			t.Errorf("inputRules, outputRules or natRules does not have the expected rules: 1!=%d, 1!=%d, 1!=%d", len(inputRules), len(outputRules), len(natRules))
			return false
		}
		return true
	}
	if !checkForBootstrap() {
		t.Fatal("Something in Bootstrap did not complete as expected")
	}
}

func TestApplyPolicyRulesForPodAndFamilyReturnsPolicyRuleError(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.FlushRuleset()
	defer c.CloseLasting()
	c.FlushRuleset()

	namespace := "testns1"
	pod := NewFakePodWithNetAnnotation(
		namespace,
		"testpod1",
		"policy-net-1",
		NewFakeNetworkStatus(namespace, "policy-net-1", "192.168.1.1", "10.1.1.1"),
		map[string]string{"app": "selected"},
	)
	podInfo := &controllers.PodInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Interfaces: []controllers.InterfaceInfo{{
			NetattachName: fmt.Sprintf("%s/%s", namespace, "policy-net-1"),
			InterfaceName: "net1",
			IPs:           []string{"10.1.1.1"},
		}},
	}
	badPort := intstr.IntOrString{Type: intstr.Int, IntVal: 70000}
	policy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "bad-port",
			Annotations: map[string]string{
				PolicyNetworkAnnotation: "policy-net-1",
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "selected"}},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeIngress,
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &badPort}},
			}},
		},
	}

	err := ApplyPolicyRulesForPodAndFamily(
		context.Background(),
		newTestPolicyDeps(),
		controllers.CommonRuleConfig{},
		controllers.PolicyMap{
			types.NamespacedName{Namespace: namespace, Name: policy.Name}: policy,
		},
		pod,
		podInfo,
		c,
	)
	if err == nil {
		t.Fatal("ApplyPolicyRulesForPodAndFamily() error = nil, want invalid policy rule error")
	}
	if !strings.Contains(err.Error(), "failed to apply pod ingress rules") || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("ApplyPolicyRulesForPodAndFamily() error = %v, want invalid port context", err)
	}
}

func TestApplyCommonChainRules(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()
	podMockInfo := &controllers.PodInfo{
		Interfaces: []controllers.InterfaceInfo{
			{InterfaceName: "eth0", IPs: []string{"10.0.0.0", "fd00::"}},
			{InterfaceName: "eth1", IPs: []string{"fd01::"}},
			{InterfaceName: "eth2", IPs: []string{"10.0.0.0"}},
		},
	}
	nftState, err := bootstrapNetfilterRules(c, podMockInfo)
	if err != nil {
		t.Fatalf("bootstrapNetfilterRules() failed: %v", err)
	}
	if nftState == nil {
		t.Fatalf("bootstrapNetfilterRules() returned nil state")
	}

	err = nftState.applyCommonChainRules(controllers.CommonRuleConfig{
		AcceptICMPv6:   true,
		AcceptICMP:     true,
		AllowSrcPrefix: []string{"fc00::/8", "fd00::/8", "10.0.0.1/32", "10.0.1.0/24"},
		AllowDstPrefix: []string{"fe00::/8", "ff00::/8", "10.0.0.2/32", "10.0.2.0/24"},
	})
	if err != nil {
		t.Fatalf("applyCommonChainRules() failed: %v", err)
	}
	err = nftState.nft.Flush()

	if err != nil {
		t.Fatalf("nft flush failed after applying common chain rules: %v", err)
	}

	checkCommon := func() bool {
		filterTable, err := c.ListTableOfFamily(FilterTableName, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(%q) failed: %v", FilterTableName, err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", ingressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", egressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}
		if len(ingressRules) != 5 {
			t.Errorf("ingressRules does not have the expected number of rules: 5 != %d", len(ingressRules))
			return false
		}
		if len(egressRules) != 5 {
			t.Errorf("egressRules does not have the expected number of rules: 5 != %d", len(egressRules))
			return false
		}
		sets, err := c.GetSets(filterTable)
		if err != nil {
			t.Fatalf("c.GetSets(%q) failed: %v", filterTable.Name, err)
		}
		for _, set := range sets {
			if set.Name == fmt.Sprintf("%s_%s_%s", common, protoIPv4, sourceAddressSuffix) || set.Name == fmt.Sprintf("%s_%s_%s", common, protoIPv4, destinationAddressSuffix) ||
				set.Name == fmt.Sprintf("%s_%s_%s", common, protoIPv6, sourceAddressSuffix) || set.Name == fmt.Sprintf("%s_%s_%s", common, protoIPv6, destinationAddressSuffix) {
				if set.Table.Name != filterTable.Name {
					t.Errorf("set %q is not in table %q", set.Name, filterTable.Name)
				}
				elements, err := c.GetSetElements(set)
				if err != nil {
					t.Fatalf("c.GetSetElements(%q) failed: %v", set.Name, err)
				}
				if len(elements) == 0 {
					t.Errorf("set %q does not have any elements", set.Name)
				}
				for _, elem := range elements {
					if len(elem.Key) == 0 {
						t.Errorf("set %q has an element with no data", set.Name)
					}
					ip, ok := netip.AddrFromSlice(elem.Key)
					if !ok {
						t.Errorf("set %q has an element with invalid IP data: %v", set.Name, err)
					}
					t.Logf("set %q has element %q", set.Name, ip.String())
				}
			}
		}
		return true
	}
	if !checkCommon() {
		t.Fatal("Something in applyCommonChainRules did not complete as expected")
	}
}

func TestApplyPodRules(t *testing.T) {
	// TODO(enhancement): Currently validates rule and set counts only. Full validation
	// of rule content against the MultiNetworkPolicy CR spec (e.g. verifying port ranges,
	// IP blocks, and protocol values in the nftables binary encoding) is tracked separately.
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, testNs, mockServer, podMockInfo, err := prepareEnv(c, true)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Add an interface matching the selector pods' network attachment name so
	// applyPolicyPeersRulesSelector can match both the local pod and the
	// selector target pod (testpod2) against the same policyNetworks list.
	policyNetAttach := fmt.Sprintf("%s/policy-net-1", testNs)
	podMockInfo.Interfaces = append(podMockInfo.Interfaces, controllers.InterfaceInfo{
		NetattachName: policyNetAttach,
		InterfaceType: "macvlan",
		InterfaceName: "net1",
		IPs:           []string{"10.1.1.1"},
	})
	policyNetworks := []string{"net1", "net2", policyNetAttach}

	// Define protocol variables to take their addresses
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	eighty, ninety, fiftythree, oneTwoThreeFour, twoFourSixEight :=
		intstr.FromInt(80), intstr.FromInt(90).IntVal, intstr.FromInt(53),
		intstr.FromInt(1234), intstr.FromInt(2468).IntVal

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: testNs,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": fmt.Sprintf("%s/policy-net-1", testNs),
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"test"},
					},
				},
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
							Port:     &eighty,
							EndPort:  &ninety,
						},
						{
							Protocol: &protocolUDP,
							Port:     &fiftythree,
						},
						{
							Protocol: &protocolSCTP,
							Port:     &oneTwoThreeFour,
							EndPort:  &twoFourSixEight,
						},
					},
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "face::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
							Port:     &eighty,

							EndPort: &ninety,
						},
						{
							Protocol: &protocolUDP,
							Port:     &fiftythree,
						},
						{
							Protocol: &protocolSCTP,
							Port:     &oneTwoThreeFour,
							EndPort:  &twoFourSixEight,
						},
					},
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "badc::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeEgress,
				multiv1beta1.PolicyTypeIngress,
			},
		},
	}
	_, err = nftState.applyPodRules(context.Background(), mockServer, mockServer.cfg, nftState.ingressChain, podMockInfo, mockPolicy, policyNetworks)
	if err != nil {
		t.Fatalf("applyPodRules() for ingress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying ingress rules: %v", err)
	}

	_, err = nftState.applyPodRules(context.Background(), mockServer, mockServer.cfg, nftState.egressChain, podMockInfo, mockPolicy, policyNetworks)
	if err != nil {
		t.Fatalf("applyPodRules() for egress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying egress rules: %v", err)
	}

	check := func() bool {
		filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", ingressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", egressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}
		if len(ingressRules) != 2 {
			t.Errorf("ingressRules does not have the expected number of rules: 2 != %d", len(ingressRules))
			return false
		}
		if len(egressRules) != 2 {
			t.Errorf("egressRules does not have the expected number of rules: 2 != %d", len(egressRules))
			return false
		}

		set, err := c.GetSetByName(filterTable, "pod_interfaces")
		if err != nil {
			t.Fatalf("c.GetSetByName(%q, 'pod_interfaces') failed: %v", filterTable.Name, err)
		}
		elements, err := c.GetSetElements(set)
		if err != nil {
			t.Fatalf("unable to get elements for set 'pod_interfaces': %v", err)
		}

		if len(elements) != 3 {
			t.Fatalf("pod_interfaces set does not have the expected number of elements: 3 != %d", len(elements))
		}

		ingressChain0 := fmt.Sprintf("%s-%s", ingressChain, policyRuleNamespacedName(mockPolicy))
		ingressPortChain := fmt.Sprintf("%s-%s-0", ingressChain0, portsChainSuffix)
		ingressPeerChain := fmt.Sprintf("%s-%s-0", ingressChain0, peersChainSuffix)
		if err := verifyVerdicts(c, filterTable, ingressChain0, ingressPortChain, ingressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		egressChain0 := fmt.Sprintf("%s-%s", egressChain, policyRuleNamespacedName(mockPolicy))
		egressPortChain := fmt.Sprintf("%s-%s-0", egressChain0, portsChainSuffix)
		egressPeerChain := fmt.Sprintf("%s-%s-0", egressChain0, peersChainSuffix)
		if err := verifyVerdicts(c, filterTable, egressChain0, egressPortChain, egressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		checkPortChainRules := func(portChainLogicalName string) {
			portChainActualName, err := getChainByNameInComment(c, filterTable, portChainLogicalName)
			if err != nil {
				t.Fatalf("failed to get port chain %q: %s", portChainLogicalName, err.Error())
			}
			portChainRules, err := c.GetRules(filterTable, &nftables.Chain{Name: portChainActualName})
			if err != nil {
				t.Fatalf("c.GetRules(%q, %q) failed: %s", filterTable.Name, portChainActualName, err.Error())
			}
			foundProtocols := make(map[string]bool)
			for _, r := range portChainRules {
				for _, e := range r.Exprs {
					if el, ok := e.(*expr.Lookup); ok {
						portSet, err := c.GetSetByName(filterTable, el.SetName)
						if err != nil {
							t.Fatalf("failed to get set %q: %s", el.SetName, err.Error())
						}
						port, err := getSetPorts(c, portSet)
						if err != nil {
							t.Fatalf("failed to get port data for set %q: %s", el.SetName, err.Error())
						}
						foundProtocols[port.protocol] = true
						var start, end uint16
						switch port.protocol {
						case "tcp":
							start = uint16(eighty.IntVal)
							end = uint16(ninety)
						case "udp":
							start = uint16(fiftythree.IntVal)
							end = uint16(fiftythree.IntVal)
						case "sctp":
							start = uint16(oneTwoThreeFour.IntVal)
							end = uint16(twoFourSixEight)
						}
						if err := checkPort(port, start, end); err != nil {
							t.Fatalf("invalid %s port configuration: %s", portChainLogicalName, err.Error())
						}
					}
				}
			}
			for _, proto := range []string{"tcp", "udp", "sctp"} {
				if !foundProtocols[proto] {
					t.Errorf("port chain %q missing expected protocol %s", portChainLogicalName, proto)
				}
			}
		}

		checkPortChainRules(ingressPortChain)
		checkPortChainRules(egressPortChain)

		checkPeerChainContainsCIDR := func(peerChainLogicalName, cidrStr string) {
			peerChainActualName, err := getChainByNameInComment(c, filterTable, peerChainLogicalName)
			if err != nil {
				t.Fatalf("failed to get peer chain %q: %s", peerChainLogicalName, err.Error())
			}
			peerChainRules, err := c.GetRules(filterTable, &nftables.Chain{Name: peerChainActualName})
			if err != nil {
				t.Fatalf("c.GetRules(%q, %q) failed: %s", filterTable.Name, peerChainActualName, err.Error())
			}

			// Collect rules from the peer chain and any sub-chains it jumps to,
			// since ipBlock peers are now placed in a dedicated ipblock sub-chain.
			allRules := peerChainRules
			for _, r := range peerChainRules {
				for _, e := range r.Exprs {
					if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump {
						subRules, subErr := c.GetRules(filterTable, &nftables.Chain{Name: v.Chain})
						if subErr == nil {
							allRules = append(allRules, subRules...)
						}
					}
				}
			}

			prefix, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				t.Fatalf("failed to parse expected CIDR %q: %v", cidrStr, err)
			}
			startKey := prefix.Addr().As16()
			endBytes := startKey
			bits := prefix.Bits()
			for i := bits; i < 128; i++ {
				endBytes[i/8] |= 1 << uint(7-i%8)
			}
			for i := 15; i >= 0; i-- {
				endBytes[i]++
				if endBytes[i] != 0 {
					break
				}
			}
			expectedStartKey := startKey[:]
			expectedEndKey := endBytes[:]

			foundStart := false
			foundEnd := false
			for _, r := range allRules {
				for _, e := range r.Exprs {
					if el, ok := e.(*expr.Lookup); ok {
						peerSet, err := c.GetSetByName(filterTable, el.SetName)
						if err != nil {
							t.Fatalf("failed to get peer set %q: %s", el.SetName, err.Error())
						}
						setElems, err := c.GetSetElements(peerSet)
						if err != nil {
							t.Fatalf("failed to get elements for set %q: %s", el.SetName, err.Error())
						}
						for _, elem := range setElems {
							if !elem.IntervalEnd && strings.EqualFold(
								fmt.Sprintf("%x", elem.Key),
								fmt.Sprintf("%x", expectedStartKey),
							) {
								foundStart = true
							}
							if elem.IntervalEnd && strings.EqualFold(
								fmt.Sprintf("%x", elem.Key),
								fmt.Sprintf("%x", expectedEndKey),
							) {
								foundEnd = true
							}
						}
					}
				}
			}
			if !foundStart {
				t.Errorf("peer chain %q does not contain expected CIDR start address for %q", peerChainLogicalName, cidrStr)
			}
			if !foundEnd {
				t.Errorf("peer chain %q does not contain expected CIDR end address for %q", peerChainLogicalName, cidrStr)
			}
		}

		checkPeerChainContainsCIDR(ingressPeerChain, "face::/16")
		checkPeerChainContainsCIDR(egressPeerChain, "badc::/16")

		checkPeerChainContainsIP := func(peerChainLogicalName, expectedIPStr string) {
			peerChainActualName, err := getChainByNameInComment(c, filterTable, peerChainLogicalName)
			if err != nil {
				t.Fatalf("failed to get peer chain %q: %s", peerChainLogicalName, err.Error())
			}
			peerChainRules, err := c.GetRules(filterTable, &nftables.Chain{Name: peerChainActualName})
			if err != nil {
				t.Fatalf("c.GetRules(%q, %q) failed: %s", filterTable.Name, peerChainActualName, err.Error())
			}
			expectedIP := net.ParseIP(expectedIPStr).To4()
			if expectedIP == nil {
				expectedIP = net.ParseIP(expectedIPStr).To16()
			}
			if expectedIP == nil {
				t.Fatalf("failed to parse expected IP %q", expectedIPStr)
			}

			found := false
			for _, r := range peerChainRules {
				for _, e := range r.Exprs {
					if el, ok := e.(*expr.Lookup); ok {
						peerSet, err := c.GetSetByName(filterTable, el.SetName)
						if err != nil {
							t.Fatalf("failed to get peer set %q: %s", el.SetName, err.Error())
						}
						setElems, err := c.GetSetElements(peerSet)
						if err != nil {
							t.Fatalf("failed to get elements for set %q: %s", el.SetName, err.Error())
						}
						for _, elem := range setElems {
							if !elem.IntervalEnd && strings.EqualFold(
								fmt.Sprintf("%x", elem.Key),
								fmt.Sprintf("%x", []byte(expectedIP)),
							) {
								found = true
							}
						}
					}
				}
			}
			if !found {
				t.Errorf("peer chain %q does not contain expected pod selector IP %q (testpod2 app=test2)", peerChainLogicalName, expectedIPStr)
			}
		}

		checkPeerChainContainsIP(ingressPeerChain, "10.1.1.2")
		checkPeerChainContainsIP(egressPeerChain, "10.1.1.2")

		return true
	}

	if !check() {
		t.Fatal("Something in applyPodRules did not complete as expected")
	}
}

func TestApplyPodRulesNoPorts(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, testNs, mockServer, podMockInfo, err := prepareEnv(c, true)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Define protocol variables to take their addresses
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: testNs,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": fmt.Sprintf("%s/policy-net-1", testNs),
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"test"},
					},
				},
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
						},
						{
							Protocol: &protocolUDP,
						},
						{
							Protocol: &protocolSCTP,
						},
					},
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "face::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
						},
						{
							Protocol: &protocolUDP,
						},
						{
							Protocol: &protocolSCTP,
						},
					},
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "badc::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeEgress,
				multiv1beta1.PolicyTypeIngress,
			},
		},
	}
	_, err = nftState.applyPodRules(context.Background(), mockServer, mockServer.cfg, nftState.ingressChain, podMockInfo, mockPolicy, []string{"net1", "net2"})
	if err != nil {
		t.Fatalf("applyPodRules() for ingress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying ingress rules: %v", err)
	}

	_, err = nftState.applyPodRules(context.Background(), mockServer, mockServer.cfg, nftState.egressChain, podMockInfo, mockPolicy, []string{"net1", "net2"})
	if err != nil {
		t.Fatalf("applyPodRules() for egress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying egress rules: %v", err)
	}

	check := func() bool {
		filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", ingressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: fmt.Sprintf("%s-%s", egressChain, common),
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}
		if len(ingressRules) != 2 {
			t.Errorf("ingressRules does not have the expected number of rules: 2 != %d", len(ingressRules))
			return false
		}
		if len(egressRules) != 2 {
			t.Errorf("egressRules does not have the expected number of rules: 2 != %d", len(egressRules))
			return false
		}

		set, err := c.GetSetByName(filterTable, "pod_interfaces")
		if err != nil {
			t.Fatalf("c.GetSetByName(%q, 'pod_interfaces') failed: %v", filterTable.Name, err)
		}
		elements, err := c.GetSetElements(set)
		if err != nil {
			t.Fatalf("unable to get elements for set 'pod_interfaces': %v", err)
		}

		if len(elements) != 3 {
			t.Fatalf("pod_interfaces set does not have the expected number of elements: 3 != %d", len(elements))
		}

		ingressChain0 := fmt.Sprintf("%s-%s", ingressChain, policyRuleNamespacedName(mockPolicy))
		ingressPortChain := fmt.Sprintf("%s-%s-0", ingressChain0, portsChainSuffix)
		ingressPeerChain := fmt.Sprintf("%s-%s-0", ingressChain0, peersChainSuffix)
		if err := verifyVerdicts(c, filterTable, ingressChain0, ingressPortChain, ingressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		egressChain0 := fmt.Sprintf("%s-%s", egressChain, policyRuleNamespacedName(mockPolicy))
		egressPortChain := fmt.Sprintf("%s-%s-0", egressChain0, portsChainSuffix)
		egressPeerChain := fmt.Sprintf("%s-%s-0", egressChain0, peersChainSuffix)
		if err := verifyVerdicts(c, filterTable, egressChain0, egressPortChain, egressPeerChain); err != nil {
			t.Fatal(err.Error())
		}

		ingressPortChainRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: ingressPortChain,
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %s", filterTable.Name, ingressPortChain, err.Error())
		}

		for _, r := range ingressPortChainRules {
			for _, e := range r.Exprs {
				if el, ok := e.(*expr.Lookup); ok {
					set, err := c.GetSetByName(filterTable, el.SetName)
					if err != nil {
						t.Fatalf("failed to get set %q: %s", el.SetName, err.Error())
					}
					port, err := getSetPorts(c, set)
					if err != nil {
						t.Fatalf("failed to get port data for set %q: %s", el.SetName, err.Error())
					}

					if err := checkPort(port, 1, math.MaxUint16); err != nil {
						t.Fatalf("invalid configuration: %s", err.Error())
					}
				}
			}

		}
		return true
	}

	if !check() {
		t.Fatal("Something in applyPodRules did not complete as expected")
	}
}

// TestApplyPodRulesNamespaceSelectorOnlyPeer is a regression test for ingress
// peers that specify only a NamespaceSelector (PodSelector == nil, not an
// empty &metav1.LabelSelector{}). Per Kubernetes NetworkPolicy semantics, such
// a peer must match ALL pods in the namespace(s) selected by NamespaceSelector.
// This relies on applyPolicyPeersRulesSelector() treating a nil PodSelector as
// labels.Everything() instead of panicking (guarded in PR #51).
//
// The negative ("blocked") pod is deliberately attached to the SAME policy
// network as the allowed pod (via a networks annotation/network-status name
// prefixed with testNs, same as other pods in this file), but lives in a
// namespace that does NOT match NamespaceSelector. This ensures the negative
// assertion actually exercises namespace-selector filtering, rather than
// being trivially satisfied by the unrelated policy-network filter
// (InterfaceInfo.CheckPolicyNetwork).
func TestApplyPodRulesNamespaceSelectorOnlyPeer(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, testNs, mockServer, podMockInfo, err := prepareEnv(c, true)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Add an interface matching the peer pods' network attachment name so
	// applyPolicyPeersRulesSelector can match the local pod and the selected
	// pods against the same policyNetworks list (same convention as
	// TestApplyPodRules).
	policyNet := fmt.Sprintf("%s/policy-net-1", testNs)
	podMockInfo.Interfaces = append(podMockInfo.Interfaces, controllers.InterfaceInfo{
		NetattachName: policyNet,
		InterfaceType: "macvlan",
		InterfaceName: "net1",
		IPs:           []string{"10.1.1.1"},
	})
	policyNetworks := []string{"net1", "net2", policyNet}

	// allowedNs is the namespace selected by the peer's NamespaceSelector.
	// addNamespace() labels namespaces with "nsname": <name>, so selecting
	// nsname=allowedNs is sufficient to target it.
	allowedNs := "allowedns"
	addNamespace(mockServer, allowedNs)

	// blockedNs is NOT selected by NamespaceSelector, but blockedPod is
	// attached to the exact same policy network as allowedPod (by using
	// policyNet, prefixed with testNs, as its networks annotation and
	// network-status name) so the policy-network filter alone would not
	// exclude it -- only the namespace selector should.
	blockedNs := "blockedns"
	addNamespace(mockServer, blockedNs)

	allowedPod := NewFakePodWithNetAnnotation(
		allowedNs,
		"allowed-pod",
		policyNet,
		NewFakeNetworkStatus(testNs, "policy-net-1", "192.168.10.1", "10.10.10.10"),
		map[string]string{"app": "allowed"},
	)
	addPod(mockServer, allowedPod)

	blockedPod := NewFakePodWithNetAnnotation(
		blockedNs,
		"blocked-pod",
		policyNet,
		NewFakeNetworkStatus(testNs, "policy-net-1", "192.168.99.1", "10.99.99.99"),
		map[string]string{"app": "blocked"},
	)
	addPod(mockServer, blockedPod)

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: testNs,
			Annotations: map[string]string{
				PolicyNetworkAnnotation: policyNet,
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							// PodSelector intentionally left nil (not
							// &metav1.LabelSelector{}): this is the
							// regression case under test.
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"nsname": allowedNs},
							},
						},
					},
				},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeIngress,
			},
		},
	}

	_, err = nftState.applyPodRules(context.Background(), mockServer, mockServer.cfg, nftState.ingressChain, podMockInfo, mockPolicy, policyNetworks)
	if err != nil {
		t.Fatalf("applyPodRules() for ingress failed: %v", err)
	}
	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft flush failed after applying ingress rules: %v", err)
	}

	filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
	}
	if filterTable == nil {
		t.Fatalf("filterTable is nil")
	}

	ingressChain0 := fmt.Sprintf("%s-%s", ingressChain, policyRuleNamespacedName(mockPolicy))
	ingressPeerChain := fmt.Sprintf("%s-%s-0", ingressChain0, peersChainSuffix)
	ingressPeerChainActualName, err := getChainByNameInComment(c, filterTable, ingressPeerChain)
	if err != nil {
		t.Fatalf("failed to get peer chain %q: %s", ingressPeerChain, err.Error())
	}
	peerChainRules, err := c.GetRules(filterTable, &nftables.Chain{Name: ingressPeerChainActualName})
	if err != nil {
		t.Fatalf("c.GetRules(%q, %q) failed: %s", filterTable.Name, ingressPeerChainActualName, err.Error())
	}

	// Per Copilot review feedback: restrict the assertion to the specific
	// selector/peer IP set(s) actually created for this peer -- i.e. the
	// expr.Lookup sets referenced from this peer's own chain (ingressPeerChain,
	// the source-address ("saddrs" per getAddressSuffix) sets built by
	// addIPRule for this ingress peer) -- rather than aggregating elements
	// from every nftables set in the whole filter table, which could
	// accidentally include non-IP sets (ports, interfaces...) or sets
	// belonging to unrelated policies/peers.
	ipInPeerSets := make(map[string]bool)
	for _, r := range peerChainRules {
		for _, e := range r.Exprs {
			el, ok := e.(*expr.Lookup)
			if !ok {
				continue
			}
			peerSet, err := c.GetSetByName(filterTable, el.SetName)
			if err != nil {
				t.Fatalf("failed to get peer set %q: %s", el.SetName, err.Error())
			}
			setElems, err := c.GetSetElements(peerSet)
			if err != nil {
				t.Fatalf("failed to get elements for set %q: %s", el.SetName, err.Error())
			}
			for _, elem := range setElems {
				ip, ok := netip.AddrFromSlice(elem.Key)
				if !ok {
					continue
				}
				ipInPeerSets[ip.String()] = true
			}
		}
	}

	if !ipInPeerSets["10.10.10.10"] {
		t.Errorf("expected allowed pod IP 10.10.10.10 (namespace %q, matched by NamespaceSelector) to be present in peer saddrs sets, got %v", allowedNs, ipInPeerSets)
	}
	if ipInPeerSets["10.99.99.99"] {
		t.Errorf("blocked pod IP 10.99.99.99 (namespace %q, NOT matched by NamespaceSelector, but on the same policy network) must not be present in peer saddrs sets, got %v", blockedNs, ipInPeerSets)
	}
}

// TestApplyPolicyPeersRulesIPBlockExceptPreservesORSemantics verifies that an
// ipBlock peer with an "except" CIDR is wrapped in its own per-entry subchain,
// so that the except rule's VerdictReturn only exits that subchain back to the
// peers chain rather than skipping the rest of the from/to peer list. This
// exercises the real production entry point applyPolicyPeersRules (not
// applyPolicyPeersRulesIPBlock directly), so it catches chain-topology
// regressions.
//
// The except rule is identified structurally: it performs an expr.Lookup and
// terminates in a verdict without ever setting the peer-match mark (no
// expr.Bitwise mark-set), unlike the CIDR-accept rule which always sets the
// peer mark before returning. This is more robust than either matching on the
// rule comment text or on the except set's expr.Lookup.SetName: nftables set
// names longer than 31 bytes are silently replaced with a content hash (see
// updateSet), and the except set name (built from the ipBlock subchain name
// plus protocol/suffix/index) exceeds that limit in realistic topologies, so
// asserting on a "peer_ipblock_except" substring in the registered set name
// does not actually hold once the real chain-naming scheme is exercised.

func TestApplyPolicyPeersRulesIPBlockExceptPreservesORSemantics(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, _, mockServer, podMockInfo, err := prepareEnv(c, false)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Two ipBlock peers in the same from/to list: the first has an except CIDR,
	// the second does not. If OR semantics are broken, an IP inside the first
	// peer's except range would incorrectly stop evaluation before the second
	// peer is ever considered.
	peers := []multiv1beta1.MultiNetworkPolicyPeer{
		{
			IPBlock: &multiv1beta1.IPBlock{
				CIDR:   "10.0.0.0/8",
				Except: []string{"10.1.0.0/16"},
			},
		},
		{
			IPBlock: &multiv1beta1.IPBlock{
				CIDR: "192.168.0.0/16",
			},
		},
	}

	chainName := nftState.ingressChain.Name
	chain := nftState.ingressChain

	if err := nftState.applyPolicyPeersRules(context.Background(), mockServer, chainName, chain, "test-policy", peers, podMockInfo, []string{"net1", "net2"}, 0); err != nil {
		t.Fatalf("applyPolicyPeersRules() failed: %v", err)
	}

	if err := nftState.nft.Flush(); err != nil {
		t.Fatalf("nft.Flush() failed: %v", err)
	}

	filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
	if err != nil {
		t.Fatalf("ListTableOfFamily() failed: %v", err)
	}
	if filterTable == nil {
		t.Fatal("filterTable is nil")
	}

	peersChainName := nftNameWithSuffix(chainName, "-", fmt.Sprintf("%s-%d", peersChainSuffix, 0))
	peersChainRules, err := c.GetRules(filterTable, &nftables.Chain{Name: peersChainName})
	if err != nil {
		t.Fatalf("GetRules(%q) failed: %v", peersChainName, err)
	}

	// (a) both ipBlock peers must be reachable from the peers chain via JUMP,
	// proving the second peer is installed and not short-circuited by the first.
	var jumpTargets []string
	for _, r := range peersChainRules {
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump {
				jumpTargets = append(jumpTargets, v.Chain)
			}
		}
	}
	if len(jumpTargets) < 2 {
		t.Fatalf("peers chain %q has %d JUMP verdicts, want >= 2 (one per ipBlock peer): %v", peersChainName, len(jumpTargets), jumpTargets)
	}

	// isExceptRule identifies the except-CIDR rule structurally: it performs a
	// set lookup but, unlike the CIDR-accept rule, never sets the peer-match
	// mark (no expr.Bitwise) before its verdict.
	isExceptRule := func(r *nftables.Rule) bool {
		hasLookup := false
		hasMarkBitwise := false
		for _, e := range r.Exprs {
			switch e.(type) {
			case *expr.Lookup:
				hasLookup = true
			case *expr.Bitwise:
				hasMarkBitwise = true
			}
		}
		return hasLookup && !hasMarkBitwise
	}

	// (b) the except rule must not live directly in the peers chain: it must
	// be scoped inside a per-entry ipBlock subchain so its VerdictReturn
	// cannot unwind past the peers chain and skip the second peer.
	for _, r := range peersChainRules {
		if isExceptRule(r) {
			t.Errorf("except rule found directly in peers chain %q; it must be scoped to a per-entry ipBlock subchain", peersChainName)
		}
	}

	// (c) locate the except rule inside the ipBlock subchains reached via
	// JUMP, and confirm it is paired with VerdictReturn (not VerdictDrop).
	foundExceptLookupWithReturn := false
	for _, subChainName := range jumpTargets {
		subRules, err := c.GetRules(filterTable, &nftables.Chain{Name: subChainName})
		if err != nil {
			continue
		}
		for _, r := range subRules {
			if !isExceptRule(r) {
				continue
			}
			for _, e := range r.Exprs {
				v, ok := e.(*expr.Verdict)
				if !ok {
					continue
				}
				if v.Kind == expr.VerdictDrop {
					t.Errorf("except CIDR rule in subchain %q uses VerdictDrop; want VerdictReturn to allow other peers to still be evaluated", subChainName)
				}
				if v.Kind != expr.VerdictReturn {
					t.Errorf("except CIDR rule in subchain %q has verdict kind = %v; want VerdictReturn", subChainName, v.Kind)
				} else {
					foundExceptLookupWithReturn = true
				}
			}
		}
	}
	if !foundExceptLookupWithReturn {
		t.Fatal("no except-set lookup rule with VerdictReturn found in any ipBlock subchain")
	}
}

func TestApplyPolicyPortsRules(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, testNs, _, _, err := prepareEnv(c, false)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	// Define protocol variables to take their addresses
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	mockPolicy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-net-1",
			Namespace: testNs,
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/policy-for": fmt.Sprintf("%s/policy-net-1", testNs),
			},
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"test"},
					},
				},
			},
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
				{
					Ports: []multiv1beta1.MultiNetworkPolicyPort{
						{
							Protocol: &protocolTCP,
						},
						{
							Protocol: &protocolUDP,
						},
						{
							Protocol: &protocolSCTP,
						},
					},
					From: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "face::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
				{
					To: []multiv1beta1.MultiNetworkPolicyPeer{
						{
							IPBlock: &multiv1beta1.IPBlock{
								CIDR: "badc::/16",
							},
						},
						{
							PodSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "app",
										Operator: metav1.LabelSelectorOpIn,
										Values:   []string{"test2"},
									},
								},
							},
						},
					},
				},
			},
			PolicyTypes: []multiv1beta1.MultiPolicyType{
				multiv1beta1.PolicyTypeEgress,
				multiv1beta1.PolicyTypeIngress,
			},
		},
	}

	err = nftState.applyPolicyPortsRules(nftState.ingressChain.Name, nftState.ingressChain, mockPolicy.Name, []multiv1beta1.MultiNetworkPolicyPort{}, 0)
	if err != nil {
		t.Fatalf("applyPolicyPortsRules() for ingress failed: %v", err)
	}

	err = nftState.applyPolicyPortsRules(nftState.egressChain.Name, nftState.egressChain, mockPolicy.Name, []multiv1beta1.MultiNetworkPolicyPort{}, 0)
	if err != nil {
		t.Fatalf("applyPolicyPortsRules() for egress failed: %v", err)
	}

	nftState.nft.Flush()

	ingressPortChain := fmt.Sprintf("%s-%s-0", ingressChain, portsChainSuffix)
	egressPortChain := fmt.Sprintf("%s-%s-0", egressChain, portsChainSuffix)

	check := func() bool {
		filterTable, err := c.ListTableOfFamily(nftState.filter.Name, nftables.TableFamilyINet)
		if err != nil {
			t.Fatalf("c.ListTable(\"filter\") failed: %v", err)
		}
		if filterTable == nil {
			t.Errorf("filterTable is nil")
			return false
		}
		ingressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: ingressPortChain,
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", ingressChain, common), err)
		}
		egressRules, err := c.GetRules(filterTable, &nftables.Chain{
			Name: egressPortChain,
		})
		if err != nil {
			t.Fatalf("c.GetRules(%q, %q) failed: %v", filterTable.Name, fmt.Sprintf("%s-%s", egressChain, common), err)
		}

		if len(ingressRules) != 1 {
			t.Errorf("ingressRules does not have the expected number of rules: 1 != %d", len(ingressRules))
			return false
		}

		if !strings.Contains(string(ingressRules[0].UserData), "accept all") {
			t.Errorf("ingress rule is invalid")
			return false
		}

		if len(egressRules) != 1 {
			t.Errorf("egressRules does not have the expected number of rules: 1 != %d", len(egressRules))
			return false
		}

		if !strings.Contains(string(egressRules[0].UserData), "accept all") {
			t.Errorf("egress rule is invalid")
			return false
		}

		return true
	}

	if !check() {
		t.Fatal("Something in applyPodPolicyPortsRules did not complete as expected")
	}
}

// TestApplyPolicyPortsRulesNamedPortRejection tests that applyPolicyPortsRules returns
// an error for named (non-numeric) string ports and succeeds for numeric string ports.
// This covers the Cellebyte feedback: string ports like "8080" are valid, "http" is not.
func TestApplyPolicyPortsRulesNamedPortRejection(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()

	nftState, _, _, _, err := prepareEnv(c, false)
	if err != nil {
		t.Fatalf("failed to prepare test env: %s", err.Error())
	}

	proto := corev1.ProtocolTCP
	port8080Str := intstr.FromString("8080")
	portHTTPStr := intstr.FromString("http")

	t.Run("numeric string port 8080 succeeds", func(t *testing.T) {
		ports := []multiv1beta1.MultiNetworkPolicyPort{
			{Protocol: &proto, Port: &port8080Str},
		}
		if err := nftState.applyPolicyPortsRules(nftState.ingressChain.Name, nftState.ingressChain, "test-policy", ports, 10); err != nil {
			t.Fatalf("applyPolicyPortsRules() with numeric string port %q should succeed, got: %v", port8080Str.StrVal, err)
		}
	})

	t.Run("named port http rejected with error", func(t *testing.T) {
		ports := []multiv1beta1.MultiNetworkPolicyPort{
			{Protocol: &proto, Port: &portHTTPStr},
		}
		err := nftState.applyPolicyPortsRules(nftState.ingressChain.Name, nftState.ingressChain, "test-policy", ports, 11)
		if err == nil {
			t.Fatal("applyPolicyPortsRules() with named port \"http\" should return an error, got nil")
		}
		if !strings.Contains(err.Error(), "named port") {
			t.Fatalf("applyPolicyPortsRules() error = %q, want it to contain \"named port\"", err.Error())
		}
	})
}

type testPort struct {
	protocol string
	start    uint16
	end      uint16
}

func getSetPorts(c *nftables.Conn, set *nftables.Set) (*testPort, error) {
	setEls, err := c.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("failed to get set %q elements: %w", set.Name, err)
	}
	var start, end uint16
	for _, e := range setEls {
		if e.IntervalEnd {
			end = binaryutil.BigEndian.Uint16(e.Key) - 1
		} else {
			start = binaryutil.BigEndian.Uint16(e.Key)
		}
	}
	if set.Comment == "" {
		return nil, fmt.Errorf("set %q has no comment, cannot determine protocol", set.Name)
	}
	pname := strings.Split(set.Comment, "_")
	return &testPort{
		protocol: pname[len(pname)-1],
		start:    start,
		end:      end,
	}, nil
}

func checkPort(port *testPort, start, end uint16) error {
	if port.start != start {
		return fmt.Errorf("invalid %s start port configuration: is %d, shoud be %d", strings.ToUpper(port.protocol), port.start, start)
	}
	if port.end != end {
		return fmt.Errorf("invalid %s end port configuration: is %d, shoud be %d", strings.ToUpper(port.protocol), port.end, end)
	}
	return nil
}

func getChainByNameInComment(c *nftables.Conn, table *nftables.Table, chainName string) (string, error) {
	chains, err := c.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return "", fmt.Errorf("failed to get objects from table %q: %s", table.Name, err.Error())
	}
	commentChainName := fmt.Sprintf("name:%s,", chainName)
	for _, chain := range chains {
		if chain.Table.Name != table.Name {
			continue
		}

		rules, err := c.GetRules(table, chain)
		if err != nil {
			return "", fmt.Errorf("failed to get rules from chain %q in table %q: %s", chain.Name, table.Name, err.Error())
		}
		for _, rule := range rules {
			comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
			if !ok {
				return "", fmt.Errorf("failed to get comment from rule in table %q", table.Name)
			}
			if strings.Contains(comment, commentChainName) {
				return rule.Chain.Name, nil
			}
		}
	}
	return "", fmt.Errorf("chain with name %q not found in table %q", chainName, table.Name)
}

func verifyVerdicts(c *nftables.Conn, table *nftables.Table, chain, portChain, peerChain string) error {
	chainName, err := getChainByNameInComment(c, table, chain)
	if err != nil {
		return fmt.Errorf("failed to get multi-network-policy chain %q: %s", chain, err.Error())
	}
	portChainName, err := getChainByNameInComment(c, table, portChain)
	if err != nil {
		return fmt.Errorf("failed to get multi-network-policy ports chain %q: %s", portChain, err.Error())
	}
	peerChainName, err := getChainByNameInComment(c, table, peerChain)
	if err != nil {
		return fmt.Errorf("failed to get multi-network-policy peers chain %q: %s", peerChain, err.Error())
	}
	rules, err := c.GetRules(table, &nftables.Chain{
		Name: chainName,
	})
	if err != nil {
		return fmt.Errorf("failed to get ingress pod rules: %s", err.Error())
	}
	if err != nil {
		return fmt.Errorf("failed to get egress pod rules: %s", err.Error())
	}

	if !checkVerdictPresence(rules, portChainName) {
		return fmt.Errorf("chain %q does not contain %q verdict [%v]", chain, portChain, rules)
	}

	if !checkVerdictPresence(rules, peerChainName) {
		return fmt.Errorf("chain %q does not contain %q verdict [%v]", chain, peerChain, rules)
	}

	return nil
}

func checkVerdictPresence(rules []*nftables.Rule, name string) bool {
	for _, rule := range rules {
		for _, exp := range rule.Exprs {
			if e, ok := exp.(*expr.Verdict); ok && e.Chain == name {
				return true
			}
		}
	}
	return false
}

func newTestPolicyDeps() *testPolicyDeps {
	return &testPolicyDeps{
		podMap:       make(map[types.NamespacedName]controllers.PodInfo),
		namespaceMap: make(map[string]controllers.NamespaceInfo),
		netdefMap:    make(map[types.NamespacedName]string),
		pods:         make(map[types.NamespacedName]*corev1.Pod),
	}
}

func NewFakePodWithNetAnnotation(namespace, name, annot, status string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       "testUID",
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/networks": annot,
				netdefv1.NetworkStatusAnnot:   status,
			},
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "ctr1", Image: "image"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}
}

func addNamespace(s *testPolicyDeps, name string) {
	s.namespaceMap[name] = controllers.NamespaceInfo{
		Name: name,
		Labels: map[string]string{
			"nsname": name,
		},
	}
}

func addPod(s *testPolicyDeps, pod *corev1.Pod) {
	namespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}
	podInfo, err := controllers.NewPodInfoFromPod(context.Background(), pod, nil, "test-host", []string{"multi"}, s)
	if err != nil {
		panic(err)
	}
	s.podMap[namespacedName] = *podInfo
	s.pods[namespacedName] = pod.DeepCopy()
}

func NewFakeNetworkStatus(netns, netname, eth0, net1 string) string {
	// dummy interface is for testing not to include dummy ip in iptable rules
	baseStr := `
	[{
            "name": "",
            "interface": "eth0",
            "ips": [
                "%s"
            ],
            "mac": "aa:e1:20:71:15:01",
            "default": true,
            "dns": {}
        },{
            "name": "%s/%s",
            "interface": "net1",
            "ips": [
                "%s"
            ],
            "mac": "42:90:65:12:3e:bf",
            "dns": {}
        },{
            "name": "dummy-interface",
            "interface": "net2",
            "ips": [
                "244.244.244.244"
            ],
            "mac": "42:90:65:12:3e:bf",
            "dns": {}
        }]
`
	return fmt.Sprintf(baseStr, eth0, netns, netname, net1)
}

func prepareEnv(c *nftables.Conn, createServer bool) (*nftState, string, *testPolicyDeps, *controllers.PodInfo, error) {
	podMockInfo := &controllers.PodInfo{
		Name:      "mock-pod",
		Namespace: "default",
		Interfaces: []controllers.InterfaceInfo{
			{NetattachName: "net0", InterfaceType: "macvlan", InterfaceName: "eth0", IPs: []string{"10.0.0.0", "fd00::"}},
			{NetattachName: "net1", InterfaceType: "macvlan", InterfaceName: "eth1", IPs: []string{"fd01::"}},
			{NetattachName: "net2", InterfaceType: "ipvlan", InterfaceName: "eth2", IPs: []string{"10.0.0.0"}},
		},
	}

	nftState, err := bootstrapNetfilterRules(c, podMockInfo)
	if err != nil {
		return nil, "", nil, podMockInfo, fmt.Errorf("bootstrapNetfilterRules() failed: %w", err)
	}
	if nftState == nil {
		return nil, "", nil, podMockInfo, fmt.Errorf("bootstrapNetfilterRules() returned nil state")
	}
	var deps *testPolicyDeps
	testNs := "testns1"
	if createServer {
		deps = newTestPolicyDeps()
		addNamespace(deps, testNs)

		deps.netdefMap[types.NamespacedName{Namespace: testNs, Name: "policy-net-1"}] = "multi"
		deps.netdefMap[types.NamespacedName{Namespace: testNs, Name: "policy-net-2"}] = "multi"

		pod1 := NewFakePodWithNetAnnotation(
			testNs,
			"testpod1",
			"policy-net-1",
			NewFakeNetworkStatus(testNs, "policy-net-1", "192.168.1.1", "10.1.1.1"),
			map[string]string{"app": "test"})
		addPod(deps, pod1)

		pod2 := NewFakePodWithNetAnnotation(
			testNs,
			"testpod2",
			"policy-net-1",
			NewFakeNetworkStatus(testNs, "policy-net-1", "192.168.1.2", "10.1.1.2"),
			map[string]string{"app": "test2"})
		addPod(deps, pod2)
	} else {
		deps = &testPolicyDeps{
			cfg: controllers.CommonRuleConfig{
				AcceptICMPv6:   true,
				AcceptICMP:     true,
				AllowSrcPrefix: []string{"fc00::/8", "fd00::/8", "10.0.0.1/32", "10.0.1.0/24"},
				AllowDstPrefix: []string{"fe00::/8", "ff00::/8", "10.0.0.2/32", "10.0.2.0/24"},
			},
		}
	}
	err = nftState.applyCommonChainRules(deps.cfg)
	if err != nil {
		return nftState, testNs, deps, podMockInfo, fmt.Errorf("applyCommonChainRules() failed: %w", err)
	}
	err = nftState.nft.Flush()
	if err != nil {
		return nftState, testNs, deps, podMockInfo, fmt.Errorf("nftState.nft.Flush() failed: %w", err)
	}
	return nftState, testNs, deps, podMockInfo, nil
}

func TestValidatePortSpec(t *testing.T) {
	t.Parallel()

	ptr32 := func(v int32) *int32 { return &v }
	port80Int := intstr.FromInt32(80)
	port80Str := intstr.FromString("80")
	portHTTPStr := intstr.FromString("http")
	port0Int := intstr.FromInt32(0)
	portNegStr := intstr.FromString("-1")
	portBigStr := intstr.FromString("99999")

	cases := []struct {
		name       string
		port       multiv1beta1.MultiNetworkPolicyPort
		wantErr    bool
		wantErrSub string
		wantStart  uint16
		wantEnd    uint16
	}{
		{
			name: "nil port returns nil elements",
			port: multiv1beta1.MultiNetworkPolicyPort{Port: nil},
		},
		{
			name:      "int port 80 accepted",
			port:      multiv1beta1.MultiNetworkPolicyPort{Port: &port80Int},
			wantStart: 80,
			wantEnd:   81,
		},
		{
			name:      "numeric string port '80' accepted (Cellebyte feedback)",
			port:      multiv1beta1.MultiNetworkPolicyPort{Port: &port80Str},
			wantStart: 80,
			wantEnd:   81,
		},
		{
			name:       "named port 'http' rejected with clear error",
			port:       multiv1beta1.MultiNetworkPolicyPort{Port: &portHTTPStr},
			wantErr:    true,
			wantErrSub: "named port",
		},
		{
			name:       "named port '-1' (negative numeric string) rejected",
			port:       multiv1beta1.MultiNetworkPolicyPort{Port: &portNegStr},
			wantErr:    true,
			wantErrSub: "named port",
		},
		{
			name:       "named port '99999' (out-of-range numeric string) rejected",
			port:       multiv1beta1.MultiNetworkPolicyPort{Port: &portBigStr},
			wantErr:    true,
			wantErrSub: "named port",
		},
		{
			name:       "int port 0 rejected as out of range",
			port:       multiv1beta1.MultiNetworkPolicyPort{Port: &port0Int},
			wantErr:    true,
			wantErrSub: "out of range",
		},
		{
			name: "int port range 1000-2000 accepted",
			port: multiv1beta1.MultiNetworkPolicyPort{
				Port:    func() *intstr.IntOrString { p := intstr.FromInt32(1000); return &p }(),
				EndPort: ptr32(2000),
			},
			wantStart: 1000,
			wantEnd:   2001,
		},
		{
			name: "numeric string port range '1000' with EndPort 2000 accepted",
			port: multiv1beta1.MultiNetworkPolicyPort{
				Port:    func() *intstr.IntOrString { p := intstr.FromString("1000"); return &p }(),
				EndPort: ptr32(2000),
			},
			wantStart: 1000,
			wantEnd:   2001,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			elements, err := validatePortSpec(tc.port)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validatePortSpec() expected error containing %q, got nil", tc.wantErrSub)
				}
				if tc.wantErrSub != "" && !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("validatePortSpec() error = %q, want it to contain %q", err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("validatePortSpec() unexpected error: %v", err)
			}
			if tc.port.Port == nil {
				if elements != nil {
					t.Fatalf("validatePortSpec() expected nil elements for nil port, got %v", elements)
				}
				return
			}
			if len(elements) != 2 {
				t.Fatalf("validatePortSpec() expected 2 set elements, got %d", len(elements))
			}
			gotStart := binaryutil.BigEndian.Uint16(elements[0].Key)
			gotEnd := binaryutil.BigEndian.Uint16(elements[1].Key)
			if gotStart != tc.wantStart {
				t.Errorf("validatePortSpec() start port = %d, want %d", gotStart, tc.wantStart)
			}
			if gotEnd != tc.wantEnd {
				t.Errorf("validatePortSpec() end port (sentinel) = %d, want %d", gotEnd, tc.wantEnd)
			}
			if !elements[1].IntervalEnd {
				t.Errorf("validatePortSpec() last element should have IntervalEnd=true")
			}
		})
	}
}

func TestCleanupLegacyTables(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.FlushRuleset()
	defer c.CloseLasting()
	c.FlushRuleset()

	inetFamily := nftables.TableFamilyINet
	legacyFilter := &nftables.Table{Family: inetFamily, Name: legacyFilterTableName}
	c.AddTable(legacyFilter)
	legacyNat := &nftables.Table{Family: inetFamily, Name: legacyNatTableName}
	c.AddTable(legacyNat)

	c.AddChain(&nftables.Chain{
		Name:  ingressChain,
		Table: legacyFilter,
	})

	unreferencedDaemonChain := c.AddChain(&nftables.Chain{
		Name:  egressChain,
		Table: legacyFilter,
	})
	c.AddRule(&nftables.Rule{
		Table:    legacyFilter,
		Chain:    unreferencedDaemonChain,
		UserData: userDataComment("drop-remaining"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	baseChain := c.AddChain(&nftables.Chain{
		Name:  "input",
		Table: legacyFilter,
	})

	c.AddChain(&nftables.Chain{
		Name:  "foreign-chain",
		Table: legacyFilter,
	})

	c.AddRule(&nftables.Rule{
		Table:    legacyFilter,
		Chain:    baseChain,
		UserData: userDataComment(inputInterfaceFilterComment),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: ingressChain,
			},
		},
	})
	c.AddRule(&nftables.Rule{
		Table:    legacyFilter,
		Chain:    baseChain,
		UserData: userDataComment("foreign-rule"),
		Exprs: []expr.Any{
			&expr.Counter{},
		},
	})
	c.AddRule(&nftables.Rule{
		Table:    legacyFilter,
		Chain:    baseChain,
		UserData: userDataComment("foreign-jump"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: ingressChain,
			},
		},
	})
	if err := c.AddSet(&nftables.Set{
		Table:        legacyFilter,
		Name:         podInterfacesName,
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
		Comment:      "foreign set",
	}, nil); err != nil {
		t.Fatalf("failed to add foreign pod_interfaces set: %v", err)
	}
	if err := c.AddSet(&nftables.Set{
		Table:        legacyNat,
		Name:         podInterfacesName,
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
		Comment:      "Pod interfaces NAT",
	}, nil); err != nil {
		t.Fatalf("failed to add daemon pod_interfaces set: %v", err)
	}

	if err := c.Flush(); err != nil {
		t.Fatalf("setup flush failed: %v", err)
	}

	if err := CleanupLegacyTables(c); err != nil {
		t.Fatalf("CleanupLegacyTables() returned error: %v", err)
	}

	chains, err := c.ListChainsOfTableFamily(inetFamily)
	if err != nil {
		t.Fatalf("ListChainsOfTableFamily failed: %v", err)
	}

	foundIngressChain := false
	foundEgressChain := false
	for _, ch := range chains {
		if ch.Table.Name == legacyFilterTableName && ch.Name == ingressChain {
			foundIngressChain = true
		}
		if ch.Table.Name == legacyFilterTableName && ch.Name == egressChain {
			foundEgressChain = true
		}
	}
	if !foundIngressChain {
		t.Errorf("referenced daemon chain %q was incorrectly removed from legacy table", ingressChain)
	}
	if foundEgressChain {
		t.Errorf("unreferenced daemon chain %q was not removed from legacy table", egressChain)
	}

	foundForeignChain := false
	for _, ch := range chains {
		if ch.Table.Name == legacyFilterTableName && ch.Name == "foreign-chain" {
			foundForeignChain = true
		}
	}
	if !foundForeignChain {
		t.Errorf("foreign chain %q was incorrectly removed from legacy table", "foreign-chain")
	}

	rules, err := c.GetRules(legacyFilter, &nftables.Chain{Name: "input"})
	if err != nil {
		t.Fatalf("GetRules(%q, %q) failed: %v", legacyFilter.Name, "input", err)
	}
	foundForeignRule := false
	foundForeignJump := false
	for _, rule := range rules {
		comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)
		if comment == inputInterfaceFilterComment {
			t.Errorf("daemon rule %q was not removed from legacy base chain", inputInterfaceFilterComment)
		}
		if comment == "foreign-rule" {
			foundForeignRule = true
		}
		if comment == "foreign-jump" {
			foundForeignJump = true
		}
	}
	if !foundForeignRule {
		t.Errorf("foreign rule in legacy base chain was incorrectly removed")
	}
	if !foundForeignJump {
		t.Errorf("foreign jump rule in legacy base chain was incorrectly removed")
	}

	sets, err := c.GetSets(legacyFilter)
	if err != nil {
		t.Fatalf("GetSets(%q) failed: %v", legacyFilter.Name, err)
	}
	foundForeignSet := false
	for _, set := range sets {
		if set.Name == podInterfacesName && set.Comment == "foreign set" {
			foundForeignSet = true
		}
	}
	if !foundForeignSet {
		t.Errorf("foreign pod_interfaces set was incorrectly removed from legacy table")
	}

	sets, err = c.GetSets(legacyNat)
	if err != nil {
		t.Fatalf("GetSets(%q) failed: %v", legacyNat.Name, err)
	}
	for _, set := range sets {
		if set.Name == podInterfacesName {
			t.Errorf("daemon pod_interfaces set was not removed from legacy table")
		}
	}
}

func TestRuleEqualHandlesShortAndUnknownRules(t *testing.T) {
	chain := &nftables.Chain{Name: ingressChain}
	table := &nftables.Table{Name: FilterTableName}
	desired := &nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: userDataComment("desired"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
	shortExisting := &nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: userDataComment("desired"),
		Exprs:    []expr.Any{&expr.Counter{}},
	}
	if ruleEqual(desired, shortExisting) {
		t.Fatal("ruleEqual returned true for an existing rule with fewer expressions")
	}

	unknownDesired := &nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: userDataComment("desired"),
		Exprs:    []expr.Any{&expr.Immediate{}},
	}
	unknownExisting := &nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: userDataComment("desired"),
		Exprs:    []expr.Any{&expr.Immediate{}},
	}
	if ruleEqual(unknownDesired, unknownExisting) {
		t.Fatal("ruleEqual returned true for an unhandled expression type")
	}
}

func TestFindRuleReturnsFirstMatch(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.CloseLasting()
	c.FlushRuleset()
	defer c.FlushRuleset()

	podMockInfo := &controllers.PodInfo{
		Interfaces: []controllers.InterfaceInfo{
			{InterfaceName: "eth0", IPs: []string{"10.0.0.1"}},
		},
	}
	state, err := bootstrapNetfilterRules(c, podMockInfo)
	if err != nil {
		t.Fatalf("bootstrapNetfilterRules() failed: %v", err)
	}
	if state == nil {
		t.Fatalf("bootstrapNetfilterRules() returned nil state")
	}

	table := state.filter
	chain := state.ingressChain

	comment := userdata.AppendString(nil, userdata.TypeComment, "test-duplicate-rule")
	makeRule := func() *nftables.Rule {
		return &nftables.Rule{
			Table:    table,
			Chain:    chain,
			UserData: comment,
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		}
	}

	c.AddRule(makeRule())
	c.AddRule(makeRule())

	if err := c.Flush(); err != nil {
		t.Fatalf("c.Flush() failed: %v", err)
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		t.Fatalf("c.GetRules() failed: %v", err)
	}

	var firstHandle, secondHandle uint64
	matched := 0
	for _, r := range rules {
		if ruleEqual(makeRule(), r) {
			matched++
			switch matched {
			case 1:
				firstHandle = r.Handle
			case 2:
				secondHandle = r.Handle
			}
		}
	}
	if matched != 2 {
		t.Fatalf("expected 2 duplicate rules in chain, found %d", matched)
	}
	if firstHandle == secondHandle {
		t.Fatalf("kernel assigned the same handle to both rules: %d", firstHandle)
	}
	t.Logf("firstHandle=%d secondHandle=%d", firstHandle, secondHandle)

	got, err := state.findRule(makeRule())
	if err != nil {
		t.Fatalf("findRule() returned error: %v", err)
	}
	if got == nil {
		t.Fatal("findRule() returned nil, expected a rule")
	}
	if got.Handle != firstHandle {
		t.Errorf("findRule() returned handle %d, want first handle %d (last handle %d)",
			got.Handle, firstHandle, secondHandle)
	}
}

func TestCleanupChainsKeepsForeignTableChains(t *testing.T) {
	c, newNS := nftest.OpenSystemConn(t, true, DEBUG)
	defer nftest.CleanupSystemConn(t, newNS, DEBUG)
	defer c.FlushRuleset()
	defer c.CloseLasting()
	c.FlushRuleset()

	inetFamily := nftables.TableFamilyINet
	ownedTable := c.AddTable(&nftables.Table{Family: inetFamily, Name: FilterTableName})
	foreignTable := c.AddTable(&nftables.Table{Family: inetFamily, Name: "foreign-filter"})

	c.AddChain(&nftables.Chain{
		Name:  "stale-owned-chain",
		Table: ownedTable,
	})
	c.AddChain(&nftables.Chain{
		Name:  "foreign-empty-chain",
		Table: foreignTable,
	})

	if err := c.Flush(); err != nil {
		t.Fatalf("setup flush failed: %v", err)
	}

	nftState := &nftState{
		nft:    c,
		filter: ownedTable,
		nat:    &nftables.Table{Family: inetFamily, Name: NatTableName},
		chains: make(map[string]*nftables.Chain),
	}
	if err := nftState.cleanupChains(); err != nil {
		t.Fatalf("cleanupChains() returned error: %v", err)
	}

	chains, err := c.ListChainsOfTableFamily(inetFamily)
	if err != nil {
		t.Fatalf("ListChainsOfTableFamily failed: %v", err)
	}

	foundOwnedChain := false
	foundForeignChain := false
	for _, chain := range chains {
		switch {
		case chain.Table.Name == FilterTableName && chain.Name == "stale-owned-chain":
			foundOwnedChain = true
		case chain.Table.Name == foreignTable.Name && chain.Name == "foreign-empty-chain":
			foundForeignChain = true
		}
	}
	if foundOwnedChain {
		t.Errorf("unused chain in daemon-owned table was not removed")
	}
	if !foundForeignChain {
		t.Errorf("foreign empty chain was incorrectly removed")
	}
}
