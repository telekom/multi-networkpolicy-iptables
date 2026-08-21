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

package controller

import (
	"context"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
)

// Backend applies MultiNetworkPolicy for a single pod's interfaces using a
// specific dataplane. Two backends coexist in the same daemon, selected per
// interface (see selectBackend / partitionByBackend):
//
//   - nftBackend enforces veth-style CNI interfaces (macvlan, ipvlan, bond) by
//     programming nftables inside the pod network namespace.
//   - tcBackend enforces SR-IOV VF interfaces by programming tc flower filters
//     on the host VF representor (hardware-offloaded on switchdev NICs).
//
// A pod may have interfaces served by different backends; each backend is
// invoked with a PodInfo narrowed to only the interfaces it owns.
type Backend interface {
	// Apply programs the desired policy state for the given pod. podInfo has
	// already been narrowed to the interfaces this backend owns.
	Apply(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo, hostPrefix string) error
}

// backendKind identifies which dataplane enforces an interface.
type backendKind int

const (
	backendNFT backendKind = iota
	backendTC
)

// String returns a short label used in logs and wrapped errors.
func (k backendKind) String() string {
	switch k {
	case backendTC:
		return "tc"
	default:
		return "nftables"
	}
}

// selectBackend chooses the dataplane for a single interface. SR-IOV VF
// interfaces (which carry PCI/representor device info from the Multus
// network-status annotation) are enforced on the host via tc flower; every
// other interface uses the in-netns nftables path.
func selectBackend(iface controllers.InterfaceInfo) backendKind {
	if iface.IsSRIOV() {
		return backendTC
	}
	return backendNFT
}

// partitionByBackend groups a pod's interfaces by the dataplane that must
// enforce them, returning one narrowed PodInfo per backend that has at least
// one interface. The returned PodInfos share the scalar PodInfo fields (name,
// namespace, netns, node) and carry only their own subset of Interfaces. The
// map is empty when podInfo has no interfaces.
func partitionByBackend(podInfo *controllers.PodInfo) map[backendKind]*controllers.PodInfo {
	if podInfo == nil || len(podInfo.Interfaces) == 0 {
		return nil
	}

	grouped := map[backendKind][]controllers.InterfaceInfo{}
	for _, iface := range podInfo.Interfaces {
		kind := selectBackend(iface)
		grouped[kind] = append(grouped[kind], iface)
	}

	out := make(map[backendKind]*controllers.PodInfo, len(grouped))
	for kind, ifaces := range grouped {
		narrowed := *podInfo
		narrowed.Interfaces = ifaces
		out[kind] = &narrowed
	}
	return out
}
