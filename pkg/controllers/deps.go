package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

// PolicyDeps provides cluster lookups needed while rendering policy rules.
type PolicyDeps interface {
	ListPods(ctx context.Context, selector labels.Selector) ([]*corev1.Pod, error)
	GetNamespaceInfo(ctx context.Context, namespace string) (*NamespaceInfo, error)
	GetPodInfo(ctx context.Context, pod *corev1.Pod) (*PodInfo, error)
}

// CommonRuleConfig contains rule options that are shared across policy renders.
type CommonRuleConfig struct {
	AcceptICMPv6   bool
	AcceptICMP     bool
	AllowSrcPrefix []string
	AllowDstPrefix []string

	// CTEnabled selects the stateful, connection-tracking (CT offload) tc
	// flower pipeline instead of the stateless first-match pipeline. It is
	// consumed only by the tc flower backend (the nft backend is always
	// stateful via its own conntrack rules); the nft engine ignores it. The
	// zero value keeps the tc backend stateless, so existing callers/tests are
	// unaffected. On Linux the tc applier no longer sets this directly: it is
	// resolved per representor from CTMode + the NIC's actual CT-offload
	// capability (see pkg/tcflower.resolveCTForRep).
	CTEnabled bool

	// CTMode governs how the tc flower backend decides whether to emit the
	// stateful conntrack pipeline, given that hardware CT offload requires SMFS
	// steering (the default DMFS cannot offload it):
	//   - "" / "auto": emit CT only where SMFS is confirmed; elsewhere DEGRADE
	//     to the stateless pipeline and log the lost capability (maximizes
	//     successfully-offloaded enforcement instead of failing closed on DMFS).
	//   - "require": always emit CT; if the NIC cannot offload it the filters are
	//     rejected and the interface is left unenforced (stateful-or-nothing).
	//   - "off": never emit CT; always stateless.
	// Consumed only by the tc flower backend; validated/normalized in
	// pkg/tcflower (see parseCTMode). The zero value ("") is auto.
	CTMode string

	// TCOffloadMode selects how the tc flower backend stamps a filter's
	// hardware-offload flags:
	//   - "" / "hardware": skip_sw — hardware-only, fail-closed. This is the
	//     production default for ConnectX switchdev NICs: a filter that the
	//     NIC cannot offload is rejected by the kernel rather than silently
	//     enforced in software.
	//   - "software": skip_hw — in-kernel (software) enforcement. Enables real
	//     dataplane enforcement on veth/netdevsim (which have no hardware
	//     offload) for CI, and graceful use on non-offload NICs.
	//   - "auto": currently rejected as unsupported (managed-filter detection
	//     relies on an explicit skip_sw/skip_hw flag).
	// It is consumed only by the tc flower backend; the nft backend ignores it.
	// The zero value ("") keeps the backend hardware-only, so existing
	// callers/tests are unaffected. The string is validated/normalized inside
	// pkg/tcflower (see parseOffloadMode).
	TCOffloadMode string
}

// NetDefResolver resolves CNI plugin metadata for network attachments.
type NetDefResolver interface {
	GetPluginType(ctx context.Context, namespacedName types.NamespacedName) (string, error)
}
