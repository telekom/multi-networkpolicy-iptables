package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	testEnv    *envtest.Environment
	testScheme *runtime.Scheme
	testClient client.Client
)

type mockPolicyDeps struct {
	listPodsFunc         func(labels.Selector) ([]*corev1.Pod, error)
	getNamespaceInfoFunc func(string) (*controllers.NamespaceInfo, error)
	getPodInfoFunc       func(*corev1.Pod) (*controllers.PodInfo, error)
}

var _ controllers.PolicyDeps = (*mockPolicyDeps)(nil)

func (m *mockPolicyDeps) ListPods(_ context.Context, selector labels.Selector) ([]*corev1.Pod, error) {
	if m.listPodsFunc != nil {
		return m.listPodsFunc(selector)
	}
	return nil, nil
}

func (m *mockPolicyDeps) GetNamespaceInfo(_ context.Context, namespace string) (*controllers.NamespaceInfo, error) {
	if m.getNamespaceInfoFunc != nil {
		return m.getNamespaceInfoFunc(namespace)
	}
	return nil, nil
}

func (m *mockPolicyDeps) GetPodInfo(_ context.Context, pod *corev1.Pod) (*controllers.PodInfo, error) {
	if m.getPodInfoFunc != nil {
		return m.getPodInfoFunc(pod)
	}
	return nil, nil
}

func TestMain(m *testing.M) {
	testScheme = runtime.NewScheme()
	if err := SetupScheme(testScheme); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "SetupScheme() error: %v\n", err)
		os.Exit(1)
	}

	assetsDir, err := resolveEnvtestAssetsDir()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "resolve envtest assets error: %v\n", err)
		os.Exit(1)
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../testdata/crds"},
		ErrorIfCRDPathMissing: true,
		BinaryAssetsDirectory: assetsDir,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "envtest start error: %v\n", err)
		os.Exit(1)
	}

	testClient, err = client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "client.New() error: %v\n", err)
		_ = testEnv.Stop()
		os.Exit(1)
	}

	code := m.Run()

	if err := testEnv.Stop(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "envtest stop error: %v\n", err)
		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}

func TestSetupWithManager(t *testing.T) {
	mgr, err := ctrl.NewManager(testEnv.Config, ctrl.Options{
		Scheme:                 testScheme,
		LeaderElection:         false,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	r := &NodeReconciler{
		NodeName: "test-node",
		Client:   mgr.GetClient(),
	}

	if err := SetupIndexes(context.Background(), mgr); err != nil {
		t.Fatalf("SetupIndexes() error = %v", err)
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager() error = %v", err)
	}
}

func resolveEnvtestAssetsDir() (string, error) {
	if assetsDir := os.Getenv("KUBEBUILDER_ASSETS"); assetsDir != "" {
		return assetsDir, nil
	}

	entries, err := os.ReadDir("../../testbin/k8s")
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		return filepath.Abs(filepath.Join("../../testbin/k8s", entry.Name()))
	}

	return "", fmt.Errorf("no envtest assets found under ../../testbin/k8s")
}

func TestReconcile_NoPodsOnNode(t *testing.T) {
	namespace, nodeName := testScope(t)
	seedObjects(t,
		newNamespace(namespace, nil),
		newNode(nodeName),
	)

	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
		PolicyDeps: &mockPolicyDeps{
			listPodsFunc: func(labels.Selector) ([]*corev1.Pod, error) {
				return nil, nil
			},
		},
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
}

func TestReconcile_PodWithNoPolicy(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := newPod(namespace, "pod-no-policy", nodeName, map[string]string{"app": "demo"})
	seedObjects(t,
		newNamespace(namespace, nil),
		newNode(nodeName),
		pod,
	)
	setPodRunning(t, pod)

	applyCalled := false
	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
		PolicyDeps: &mockPolicyDeps{
			listPodsFunc: func(labels.Selector) ([]*corev1.Pod, error) {
				return []*corev1.Pod{pod}, nil
			},
			getPodInfoFunc: func(*corev1.Pod) (*controllers.PodInfo, error) {
				return &controllers.PodInfo{Name: pod.Name, Namespace: pod.Namespace, NodeName: nodeName, Interfaces: []controllers.InterfaceInfo{testInterface()}}, nil
			},
		},
		ApplyRulesForPodFunc: func(_ context.Context, _ controllers.PolicyDeps, _ controllers.CommonRuleConfig, policyMap controllers.PolicyMap, gotPod *corev1.Pod, _ *controllers.PodInfo, _ string) error {
			applyCalled = true
			if gotPod.Name != pod.Name || gotPod.Namespace != pod.Namespace {
				t.Fatalf("ApplyRulesForPodFunc pod = %s/%s, want %s/%s", gotPod.Namespace, gotPod.Name, pod.Namespace, pod.Name)
			}
			if len(policyMap) != 0 {
				t.Fatalf("ApplyRulesForPodFunc policyMap length = %d, want 0", len(policyMap))
			}
			return nil
		},
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if !applyCalled {
		t.Fatalf("expected ApplyRulesForPodFunc to be called")
	}
}

func TestReconcile_RunningPodWithNoInterfacesDoesNotRequeue(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := newPod(namespace, "pod-no-interfaces", nodeName, map[string]string{"app": "demo"})
	seedObjects(t,
		newNamespace(namespace, nil),
		newNode(nodeName),
		pod,
	)
	pod.Status.Phase = corev1.PodRunning
	if err := testClient.Status().Update(context.Background(), pod); err != nil {
		t.Fatalf("Status().Update() error = %v", err)
	}

	applyCalled := false
	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(*corev1.Pod) (*controllers.PodInfo, error) {
				return &controllers.PodInfo{Name: pod.Name, Namespace: pod.Namespace, NodeName: nodeName}, nil
			},
		},
		ApplyRulesForPodFunc: func(context.Context, controllers.PolicyDeps, controllers.CommonRuleConfig, controllers.PolicyMap, *corev1.Pod, *controllers.PodInfo, string) error {
			applyCalled = true
			return nil
		},
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("Reconcile() RequeueAfter = %s, want no requeue", result.RequeueAfter)
	}
	if applyCalled {
		t.Fatalf("ApplyRulesForPodFunc was called for pod with no interfaces")
	}
}

func TestReconcile_PendingSecondaryInterfaceRequeues(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := newPod(namespace, "pod-pending-interface", nodeName, map[string]string{"app": "demo"})
	pod.Annotations = map[string]string{
		netdefv1.NetworkAttachmentAnnot: "default/secondary",
	}
	seedObjects(t,
		newNamespace(namespace, nil),
		newNode(nodeName),
		pod,
	)
	setPodRunning(t, pod)

	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(*corev1.Pod) (*controllers.PodInfo, error) {
				return &controllers.PodInfo{Name: pod.Name, Namespace: pod.Namespace, NodeName: nodeName}, nil
			},
		},
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result.RequeueAfter != 2*time.Second {
		t.Fatalf("Reconcile() RequeueAfter = %s, want 2s", result.RequeueAfter)
	}
}

func TestReconcile_PodWithMatchingPolicy(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := newPod(namespace, "pod-with-policy", nodeName, map[string]string{"app": "selected"})
	policy := newPolicy(namespace, "allow-selected", map[string]string{"app": "selected"}, nil)
	seedObjects(t,
		newNamespace(namespace, nil),
		newNode(nodeName),
		pod,
		policy,
	)
	setPodRunning(t, pod)

	applyCalled := false
	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
		PolicyDeps: &mockPolicyDeps{
			listPodsFunc: func(labels.Selector) ([]*corev1.Pod, error) {
				return []*corev1.Pod{pod}, nil
			},
			getNamespaceInfoFunc: func(string) (*controllers.NamespaceInfo, error) {
				return &controllers.NamespaceInfo{Name: namespace}, nil
			},
			getPodInfoFunc: func(*corev1.Pod) (*controllers.PodInfo, error) {
				return &controllers.PodInfo{Name: pod.Name, Namespace: pod.Namespace, NodeName: nodeName, Interfaces: []controllers.InterfaceInfo{testInterface()}}, nil
			},
		},
		ApplyRulesForPodFunc: func(_ context.Context, _ controllers.PolicyDeps, _ controllers.CommonRuleConfig, policyMap controllers.PolicyMap, gotPod *corev1.Pod, _ *controllers.PodInfo, _ string) error {
			applyCalled = true
			if gotPod.Name != pod.Name || gotPod.Namespace != pod.Namespace {
				t.Fatalf("ApplyRulesForPodFunc pod = %s/%s, want %s/%s", gotPod.Namespace, gotPod.Name, pod.Namespace, pod.Name)
			}
			if _, ok := policyMap[types.NamespacedName{Namespace: namespace, Name: policy.Name}]; !ok {
				t.Fatalf("ApplyRulesForPodFunc policyMap missing %s/%s", namespace, policy.Name)
			}
			return nil
		},
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if !applyCalled {
		t.Fatalf("expected ApplyRulesForPodFunc to be called")
	}
}

func TestReconcile_RequeuesWhenApplyRulesFails(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := newPod(namespace, "pod-apply-fails", nodeName, map[string]string{"app": "selected"})
	seedObjects(t,
		newNamespace(namespace, nil),
		newNode(nodeName),
		pod,
	)
	pod.Status.Phase = corev1.PodRunning
	if err := testClient.Status().Update(context.Background(), pod); err != nil {
		t.Fatalf("Status().Update() error = %v", err)
	}

	called := false
	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
		PolicyDeps: &mockPolicyDeps{
			getPodInfoFunc: func(*corev1.Pod) (*controllers.PodInfo, error) {
				return &controllers.PodInfo{
					Name:      pod.Name,
					Namespace: pod.Namespace,
					NodeName:  nodeName,
					Interfaces: []controllers.InterfaceInfo{{
						NetattachName: "net1",
						InterfaceName: "net1",
					}},
				}, nil
			},
		},
		ApplyRulesForPodFunc: func(context.Context, controllers.PolicyDeps, controllers.CommonRuleConfig, controllers.PolicyMap, *corev1.Pod, *controllers.PodInfo, string) error {
			called = true
			return fmt.Errorf("apply failed")
		},
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err == nil {
		t.Fatal("Reconcile() error = nil, want apply failure")
	}
	if !strings.Contains(err.Error(), "apply rules for") || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("Reconcile() error = %v, want apply failure context", err)
	}
	if !called {
		t.Fatalf("expected applyRulesForPod to be called")
	}
	if result.RequeueAfter != 0 {
		t.Fatalf("Reconcile() RequeueAfter = %s, want controller-runtime error backoff", result.RequeueAfter)
	}
}

func TestReconcile_PodDeletedBeforeReconcile(t *testing.T) {
	namespace, nodeName := testScope(t)
	pod := newPod(namespace, "deleted-pod", nodeName, map[string]string{"app": "gone"})
	seedObjects(t,
		newNamespace(namespace, nil),
		newNode(nodeName),
		pod,
	)

	if err := testClient.Delete(context.Background(), pod); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
}

func TestReconcile_NamespaceSelector(t *testing.T) {
	namespace, nodeName := testScope(t)
	namespaceLabels := map[string]string{"team": "frontend"}
	pod := newPod(namespace, "ns-selector-pod", nodeName, map[string]string{"app": "selected"})
	policy := newPolicy(namespace, "allow-frontend", map[string]string{"app": "selected"}, namespaceLabels)
	seedObjects(t,
		newNamespace(namespace, namespaceLabels),
		newNode(nodeName),
		pod,
		policy,
	)
	setPodRunning(t, pod)

	applyCalled := false
	r := &NodeReconciler{
		NodeName: nodeName,
		Client:   testClient,
		PolicyDeps: &mockPolicyDeps{
			listPodsFunc: func(labels.Selector) ([]*corev1.Pod, error) {
				return []*corev1.Pod{pod}, nil
			},
			getNamespaceInfoFunc: func(string) (*controllers.NamespaceInfo, error) {
				return &controllers.NamespaceInfo{Name: namespace, Labels: namespaceLabels}, nil
			},
			getPodInfoFunc: func(*corev1.Pod) (*controllers.PodInfo, error) {
				return &controllers.PodInfo{Name: pod.Name, Namespace: pod.Namespace, NodeName: nodeName, Interfaces: []controllers.InterfaceInfo{testInterface()}}, nil
			},
		},
		ApplyRulesForPodFunc: func(_ context.Context, _ controllers.PolicyDeps, _ controllers.CommonRuleConfig, policyMap controllers.PolicyMap, gotPod *corev1.Pod, _ *controllers.PodInfo, _ string) error {
			applyCalled = true
			if gotPod.Name != pod.Name || gotPod.Namespace != pod.Namespace {
				t.Fatalf("ApplyRulesForPodFunc pod = %s/%s, want %s/%s", gotPod.Namespace, gotPod.Name, pod.Namespace, pod.Name)
			}
			if _, ok := policyMap[types.NamespacedName{Namespace: namespace, Name: policy.Name}]; !ok {
				t.Fatalf("ApplyRulesForPodFunc policyMap missing %s/%s", namespace, policy.Name)
			}
			return nil
		},
	}

	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if !applyCalled {
		t.Fatalf("expected ApplyRulesForPodFunc to be called")
	}
}

func testScope(t *testing.T) (string, string) {
	t.Helper()
	base := strings.ToLower(t.Name())
	replacer := strings.NewReplacer("/", "-", "_", "-")
	base = replacer.Replace(base)
	return base + "-ns", base + "-node"
}

func seedObjects(t *testing.T, objs ...client.Object) {
	t.Helper()
	for _, obj := range objs {
		if obj == nil {
			continue
		}
		if err := testClient.Create(context.Background(), obj); err != nil {
			t.Fatalf("Create(%T) error = %v", obj, err)
		}
	}
}

func setPodRunning(t *testing.T, pod *corev1.Pod) {
	t.Helper()
	pod.Status.Phase = corev1.PodRunning
	if err := testClient.Status().Update(context.Background(), pod); err != nil {
		t.Fatalf("Status().Update() error = %v", err)
	}
}

func testInterface() controllers.InterfaceInfo {
	return controllers.InterfaceInfo{
		NetattachName: "net1",
		InterfaceName: "net1",
		IPs:           []string{"10.0.0.1"},
	}
}

func newNamespace(name string, labelSet map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labelSet}}
}

func newNode(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func newPod(namespace, name, nodeName string, labelSet map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labelSet},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "registry.k8s.io/pause:3.10",
			}},
		},
	}
}

func newPolicy(namespace, name string, podSelectorLabels, namespaceSelectorLabels map[string]string) *multiv1beta1.MultiNetworkPolicy {
	policy := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podSelectorLabels},
		},
	}

	if namespaceSelectorLabels != nil {
		policy.Spec.Ingress = []multiv1beta1.MultiNetworkPolicyIngressRule{{
			From: []multiv1beta1.MultiNetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: namespaceSelectorLabels},
			}},
		}}
	}

	return policy
}
