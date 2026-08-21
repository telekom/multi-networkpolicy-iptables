//go:build linux

package controller

import (
	"context"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/tcflower"
	v1 "k8s.io/api/core/v1"
)

// applyTCRulesForPod enforces a pod's SR-IOV VF interfaces by programming tc
// flower filters on the host VF representor (hardware-offloaded on switchdev
// NICs). podInfo has already been narrowed to the pod's SR-IOV interfaces by
// the reconciler's per-interface backend partitioning.
//
// The tc backend aims to run the stateful conntrack-offload (CT) pipeline by
// default, mirroring the nft backend's always-on allowConntracked behavior
// (established and related return traffic is accepted statefully, so a policy
// only needs to permit the NEW direction). Whether CT is actually emitted is
// resolved PER REPRESENTOR inside tcflower.Apply from cfg.CTMode and the NIC's
// real CT-offload capability: on the default DMFS steering mode CT cannot
// hardware-offload, so CTMode=auto degrades to the stateless pipeline (and logs
// the loss) rather than leaving the interface unenforced. cfg.CTMode carries the
// operator's --tc-ct-mode choice; the empty string is "auto".
func applyTCRulesForPod(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig, policyMap controllers.PolicyMap, pod *v1.Pod, podInfo *controllers.PodInfo, hostPrefix string) error {
	return tcflower.Apply(ctx, deps, cfg, policyMap, pod, podInfo, hostPrefix)
}
