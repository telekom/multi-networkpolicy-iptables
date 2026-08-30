package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	multiutils "github.com/telekom/multi-networkpolicy-nftables/pkg/utils"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	klog "k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

var _ controllers.PolicyDeps = (*NodeReconciler)(nil)

// NodeReconciler reconciles the local node's pods into nftables rules.
type NodeReconciler struct {
	NodeName       string
	Client         client.Client
	PolicyDeps     controllers.PolicyDeps
	HostPrefix     string
	NetworkPlugins []string
	CommonCfg      controllers.CommonRuleConfig
	CriClient      pb.RuntimeServiceClient
	CriConn        *grpc.ClientConn

	ContainerRuntimeEndpoint string
	criMu                    sync.Mutex

	ApplyRulesForPodFunc func(context.Context, controllers.PolicyDeps, controllers.CommonRuleConfig, controllers.PolicyMap, *corev1.Pod, *controllers.PodInfo, string) error
}

// CleanupOnShutdown removes policy rules for pods on the local node.
func CleanupOnShutdown(ctx context.Context, r *NodeReconciler, cl client.Client) error {
	return cleanupAllPods(ctx, r, cl)
}

// SetupWithManager wires node, pod, policy, namespace, and NAD watches.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(NodePredicate(r.NodeName))).
		Watches(&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(mapPodToNode(r.NodeName)),
			builder.WithPredicates(PodPredicate())).
		Watches(&multiv1beta1.MultiNetworkPolicy{},
			handler.EnqueueRequestsFromMapFunc(mapPolicyToNode(r.NodeName)),
			builder.WithPredicates(PolicyPredicate())).
		Watches(&netdefv1.NetworkAttachmentDefinition{},
			handler.EnqueueRequestsFromMapFunc(mapNetDefToNode(r.NodeName))).
		Watches(&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(mapNamespaceToNode(r.NodeName))).
		Complete(r)
}

// Reconcile applies current policy state to all relevant pods on the local node.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != r.NodeName {
		return ctrl.Result{}, nil
	}

	var policyList multiv1beta1.MultiNetworkPolicyList
	if err := r.Client.List(ctx, &policyList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list policies: %w", err)
	}
	policyMap := buildPolicyMap(policyList.Items)

	var podList corev1.PodList
	if err := r.Client.List(ctx, &podList, client.MatchingFields{PodHostnameIndex: r.NodeName}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list pods for node %s: %w", r.NodeName, err)
	}
	deps := r.policyDeps()
	retryNeeded := false
	var retryErrs []error
	for i := range podList.Items {
		pod := &podList.Items[i]
		if !controllers.IsMultiNetworkpolicyTarget(pod) {
			continue
		}

		podInfo, err := deps.GetPodInfo(ctx, pod)
		if err != nil {
			klog.Errorf("failed to get pod info for %s/%s: %v", pod.Namespace, pod.Name, err)
			retryNeeded = true
			retryErrs = append(retryErrs, fmt.Errorf("get pod info for %s/%s: %w", pod.Namespace, pod.Name, err))
			continue
		}
		if podInfo == nil || len(podInfo.Interfaces) == 0 {
			klog.V(4).Infof("pod %s/%s has no relevant interfaces, skipping", pod.Namespace, pod.Name)
			if podNeedsInterfaceRetry(pod, podInfo) {
				retryNeeded = true
			}
			continue
		}

		if err := r.applyRulesForPod(ctx, deps, r.CommonCfg, policyMap, pod, podInfo, r.HostPrefix); err != nil {
			klog.Errorf("failed to apply rules for %s/%s: %v", pod.Namespace, pod.Name, err)
			retryNeeded = true
			retryErrs = append(retryErrs, fmt.Errorf("apply rules for %s/%s: %w", pod.Namespace, pod.Name, err))
		}
	}

	if len(retryErrs) > 0 {
		return ctrl.Result{}, errors.Join(retryErrs...)
	}
	if retryNeeded {
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	}
	return ctrl.Result{}, nil
}

func podNeedsInterfaceRetry(pod *corev1.Pod, podInfo *controllers.PodInfo) bool {
	if podInfo != nil && len(podInfo.NetworkStatus) > 0 {
		return true
	}
	if pod == nil || pod.Annotations == nil {
		return false
	}

	networkAnnotation := strings.TrimSpace(pod.Annotations[netdefv1.NetworkAttachmentAnnot])
	return networkAnnotation != "" && networkAnnotation != "[]" && networkAnnotation != "null"
}

func (r *NodeReconciler) policyDeps() controllers.PolicyDeps {
	if r.PolicyDeps != nil {
		return r.PolicyDeps
	}
	return r
}

func (r *NodeReconciler) applyRulesForPod(ctx context.Context, deps controllers.PolicyDeps, cfg controllers.CommonRuleConfig, policyMap controllers.PolicyMap, pod *corev1.Pod, podInfo *controllers.PodInfo, hostPrefix string) error {
	if r.ApplyRulesForPodFunc != nil {
		return r.ApplyRulesForPodFunc(ctx, deps, cfg, policyMap, pod, podInfo, hostPrefix)
	}
	return applyRulesForPod(ctx, deps, cfg, policyMap, pod, podInfo, hostPrefix)
}

// ListPods returns pods matching the provided label selector.
func (r *NodeReconciler) ListPods(ctx context.Context, selector labels.Selector) ([]*corev1.Pod, error) {
	var podList corev1.PodList
	if err := r.Client.List(ctx, &podList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, err
	}
	result := make([]*corev1.Pod, len(podList.Items))
	for i := range podList.Items {
		result[i] = &podList.Items[i]
	}
	return result, nil
}

// GetNamespaceInfo returns the labels needed for namespace selector evaluation.
func (r *NodeReconciler) GetNamespaceInfo(ctx context.Context, namespace string) (*controllers.NamespaceInfo, error) {
	var ns corev1.Namespace
	if err := r.Client.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		return nil, err
	}
	return &controllers.NamespaceInfo{Name: ns.Name, Labels: ns.Labels}, nil
}

// GetPodInfo extracts pod interface metadata and resolves its network namespace when needed.
func (r *NodeReconciler) GetPodInfo(ctx context.Context, pod *corev1.Pod) (*controllers.PodInfo, error) {
	podInfo, err := controllers.NewPodInfoFromPod(ctx, pod, nil, r.NodeName, r.NetworkPlugins, r)
	if err != nil {
		return nil, fmt.Errorf("build pod info for %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if podInfo == nil || len(podInfo.Interfaces) == 0 || !multiutils.CheckNodeNameIdentical(r.NodeName, pod.Spec.NodeName) {
		return podInfo, nil
	}

	criClient, err := r.criRuntimeClient(ctx)
	if err != nil {
		return nil, err
	}
	netnsPath, err := controllers.GetPodNetNSPathWithContext(ctx, criClient, pod)
	if err != nil {
		return nil, fmt.Errorf("resolve pod network namespace for %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if netnsPath == "" {
		return nil, fmt.Errorf("resolve pod network namespace for %s/%s: empty netns path", pod.Namespace, pod.Name)
	}
	podInfo.NetNSPath = netnsPath
	return podInfo, nil
}

func (r *NodeReconciler) criRuntimeClient(ctx context.Context) (pb.RuntimeServiceClient, error) {
	r.criMu.Lock()
	defer r.criMu.Unlock()

	if r.CriClient != nil {
		return r.CriClient, nil
	}
	if r.ContainerRuntimeEndpoint == "" {
		return nil, fmt.Errorf("CRI runtime endpoint is empty")
	}

	criClient, criConn, err := controllers.GetCriRuntimeClientWithContext(ctx, r.ContainerRuntimeEndpoint, r.HostPrefix)
	if err != nil {
		return nil, fmt.Errorf("connect to CRI runtime %q: %w", r.ContainerRuntimeEndpoint, err)
	}
	r.CriClient = criClient
	r.CriConn = criConn
	return r.CriClient, nil
}

// CloseCRI closes any cached CRI connection.
func (r *NodeReconciler) CloseCRI() error {
	r.criMu.Lock()
	defer r.criMu.Unlock()

	var err error
	if r.CriConn != nil {
		err = r.CriConn.Close()
	}
	r.CriConn = nil
	r.CriClient = nil
	return err
}

// GetPluginType resolves the CNI plugin type for a NetworkAttachmentDefinition.
func (r *NodeReconciler) GetPluginType(ctx context.Context, namespacedName types.NamespacedName) (string, error) {
	return resolvePluginType(ctx, r.Client, namespacedName)
}

func resolvePluginType(ctx context.Context, cl client.Client, namespacedName types.NamespacedName) (string, error) {
	var nad netdefv1.NetworkAttachmentDefinition
	if err := cl.Get(ctx, namespacedName, &nad); err != nil {
		return "", fmt.Errorf("get network attachment definition: %w", err)
	}

	confBytes, err := netdefutils.GetCNIConfig(&nad, "/etc/cni/multus/net.d")
	if err != nil {
		return "", fmt.Errorf("get CNI config: %w", err)
	}

	netconfList := &cnitypes.NetConfList{}
	listErr := json.Unmarshal(confBytes, netconfList)
	if listErr == nil && len(netconfList.Plugins) > 0 {
		return netconfList.Plugins[0].Type, nil
	}

	netconf := &cnitypes.NetConf{}
	confErr := json.Unmarshal(confBytes, netconf)
	if confErr == nil && netconf.Type != "" {
		return netconf.Type, nil
	}
	if listErr != nil || confErr != nil {
		return "", fmt.Errorf("parse CNI config for network attachment %s: %w", namespacedName, errors.Join(listErr, confErr))
	}

	return "", fmt.Errorf("parse CNI config for network attachment %s: plugin type is empty", namespacedName)
}

func buildPolicyMap(policies []multiv1beta1.MultiNetworkPolicy) controllers.PolicyMap {
	pm := make(controllers.PolicyMap, len(policies))
	for i := range policies {
		p := &policies[i]
		pm[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = p
	}
	return pm
}
