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
	"fmt"
	"slices"
	"strings"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// policyNetworkAnnotation declares which secondary networks a policy targets.
//
// IMPORTANT: this MUST stay identical to pkg/server/doc.go's
// PolicyNetworkAnnotation ("k8s.v1.cni.cncf.io/policy-for"). We deliberately do
// NOT import pkg/server here because that package pulls in the nftables engine
// (github.com/google/nftables) which cannot be linked into the tc flower
// backend. The value is duplicated with this pointer; if it ever changes in
// pkg/server it must be changed here too.
const policyNetworkAnnotation = "k8s.v1.cni.cncf.io/policy-for"

// selectedPolicy pairs a policy with its resolved (namespaced, sorted) policy
// networks. It mirrors pkg/server's internalPolicy.
type selectedPolicy struct {
	policy         *multiv1beta1.MultiNetworkPolicy
	policyNetworks []string
}

// selectPolicies re-expresses the policy SELECTION logic of
// pkg/server.ApplyPolicyRulesForPodAndFamily so the tc flower backend applies
// the exact same set of policies to a pod. It returns the policies whose
// ingress / egress rules apply to the given pod.
//
// The two implementations MUST stay in sync (a later refactor may extract a
// shared selection package; for now the duplication is intentional to avoid
// importing the nftables-backed pkg/server).
func selectPolicies(policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo) (ingress, egress []selectedPolicy) {
	if pod == nil || podInfo == nil {
		return nil, nil
	}

	for _, policy := range policyMap {
		if policy.GetNamespace() != pod.Namespace {
			continue
		}
		if policy.Spec.PodSelector.Size() != 0 {
			policyPodSelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
			if err != nil {
				// bad selector: skip this policy (mirrors server.go, which logs
				// and continues).
				continue
			}
			if !policyPodSelector.Matches(labels.Set(pod.Labels)) {
				continue
			}
		}

		ingressEnable, egressEnable := enabledPolicyTypes(policy)

		policyNetworksAnnot, ok := policy.GetAnnotations()[policyNetworkAnnotation]
		if !ok {
			continue
		}
		policyNetworksAnnot = strings.ReplaceAll(policyNetworksAnnot, " ", "")
		policyNetworks := strings.Split(policyNetworksAnnot, ",")
		for pidx, networkName := range policyNetworks {
			if !strings.ContainsAny(networkName, "/") {
				policyNetworks[pidx] = fmt.Sprintf("%s/%s", policy.GetNamespace(), networkName)
			}
		}
		slices.Sort(policyNetworks)

		if !podInfo.CheckPolicyNetwork(policyNetworks) {
			continue
		}
		if ingressEnable {
			ingress = append(ingress, selectedPolicy{policy: policy, policyNetworks: policyNetworks})
		}
		if egressEnable {
			egress = append(egress, selectedPolicy{policy: policy, policyNetworks: policyNetworks})
		}
	}

	slices.SortStableFunc(ingress, compareSelectedPolicy)
	slices.SortStableFunc(egress, compareSelectedPolicy)
	return ingress, egress
}

// compareSelectedPolicy orders policies by namespace/name, mirroring
// pkg/server.CompareInternalPolicy so rule emission order is deterministic.
func compareSelectedPolicy(a, b selectedPolicy) int {
	return strings.Compare(
		fmt.Sprintf("%s/%s", a.policy.GetNamespace(), a.policy.GetName()),
		fmt.Sprintf("%s/%s", b.policy.GetNamespace(), b.policy.GetName()),
	)
}

// enabledPolicyTypes mirrors pkg/server.getEnabledPolicyTypes: it reports
// whether ingress and/or egress enforcement is enabled for the policy, honoring
// an explicit PolicyTypes list and otherwise inferring from the presence of
// ingress/egress rules.
func enabledPolicyTypes(policy *multiv1beta1.MultiNetworkPolicy) (ingressEnable, egressEnable bool) {
	if len(policy.Spec.PolicyTypes) > 0 {
		for _, v := range policy.Spec.PolicyTypes {
			if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeIngress)) {
				ingressEnable = true
			} else if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeEgress)) {
				egressEnable = true
			}
		}
		return ingressEnable, egressEnable
	}
	return len(policy.Spec.Ingress) > 0, len(policy.Spec.Egress) > 0
}
