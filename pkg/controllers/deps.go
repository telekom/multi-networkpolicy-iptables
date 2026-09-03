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
	// EnableForwardFiltering additionally hooks the pod's forward chain, so that
	// traffic routed *through* the pod network namespace is filtered as well.
	// This is required for sandboxed runtimes such as Kata Containers with the
	// l3forwarding networking model, where pod traffic is L3-forwarded between
	// the CNI interface and the VM tap device instead of being delivered
	// locally (input/output).
	EnableForwardFiltering bool
}

// NetDefResolver resolves CNI plugin metadata for network attachments.
type NetDefResolver interface {
	GetPluginType(ctx context.Context, namespacedName types.NamespacedName) (string, error)
}
