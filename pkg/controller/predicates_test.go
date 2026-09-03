package controller

import (
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"testing"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestPodPredicate_Create(t *testing.T) {
	if !PodPredicate().Create(event.CreateEvent{Object: &corev1.Pod{}}) {
		t.Fatal("expected create event to pass")
	}
}

func TestPodPredicate_Update_PhaseChanged(t *testing.T) {
	pred := PodPredicate()
	oldPod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}, ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}}}
	newPod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}, ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}}}

	if !pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}) {
		t.Fatal("expected phase change to pass")
	}
}

func TestPodPredicate_Update_NoChange(t *testing.T) {
	pred := PodPredicate()
	oldPod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}, ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}}}
	newPod := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}, ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}}}

	if pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}) {
		t.Fatal("expected unchanged pod to be filtered")
	}
}

func TestPodPredicate_Update_NodeNameChanged(t *testing.T) {
	pred := PodPredicate()
	oldPod := &corev1.Pod{Spec: corev1.PodSpec{}, Status: corev1.PodStatus{Phase: corev1.PodPending}}
	newPod := &corev1.Pod{Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodPending}}

	if !pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}) {
		t.Fatal("expected nodeName change to pass")
	}
}

func TestPodPredicate_Update_NetworkStatusAnnotationChanged(t *testing.T) {
	pred := PodPredicate()
	oldPod := &corev1.Pod{
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}},
	}
	newPod := &corev1.Pod{
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
		ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{"a": "1"},
			Annotations: map[string]string{"k8s.v1.cni.cncf.io/network-status": "[{\"name\":\"net1\"}]"},
		},
	}

	if !pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}) {
		t.Fatal("expected network-status annotation change to pass")
	}
}

func TestPodPredicate_Update_DefaultNetworkAnnotationChanged(t *testing.T) {
	pred := PodPredicate()
	oldPod := &corev1.Pod{
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}},
	}
	newPod := &corev1.Pod{
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
		ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{"a": "1"},
			Annotations: map[string]string{controllers.DefaultNetworkAnnotation: "ns-a/net-a"},
		},
	}

	if !pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}) {
		t.Fatal("expected default-network annotation change to pass")
	}
}

func TestPodPredicate_Update_ContainerIDChanged(t *testing.T) {
	pred := PodPredicate()
	oldPod := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://old",
			}},
		},
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}},
	}
	newPod := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://new",
			}},
		},
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}},
	}

	if !pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}) {
		t.Fatal("expected container ID change to pass")
	}
}

func TestPodPredicate_Update_ContainerStatusOrderOnly(t *testing.T) {
	pred := PodPredicate()
	oldPod := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://app"},
				{Name: "sidecar", ContainerID: "containerd://sidecar"},
			},
		},
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}},
	}
	newPod := &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "sidecar", ContainerID: "containerd://sidecar"},
				{Name: "app", ContainerID: "containerd://app"},
			},
		},
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"a": "1"}},
	}

	if pred.Update(event.UpdateEvent{ObjectOld: oldPod, ObjectNew: newPod}) {
		t.Fatal("expected container status reorder to be filtered")
	}
}

func TestPodPredicate_Delete(t *testing.T) {
	if !PodPredicate().Delete(event.DeleteEvent{Object: &corev1.Pod{}}) {
		t.Fatal("expected delete event to pass")
	}
}

func TestPolicyPredicate_Update_GenerationChanged(t *testing.T) {
	oldObj := &multiv1beta1.MultiNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Generation: 1}}
	newObj := &multiv1beta1.MultiNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Generation: 2}}

	if !PolicyPredicate().Update(event.UpdateEvent{ObjectOld: oldObj, ObjectNew: newObj}) {
		t.Fatal("expected generation change to pass")
	}
}

func TestPolicyPredicate_Update_StatusOnly(t *testing.T) {
	oldObj := &multiv1beta1.MultiNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Generation: 3}}
	newObj := &multiv1beta1.MultiNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Generation: 3}}

	if PolicyPredicate().Update(event.UpdateEvent{ObjectOld: oldObj, ObjectNew: newObj}) {
		t.Fatal("expected same generation to be filtered")
	}
}

func TestPolicyPredicate_Update_PolicyNetworkAnnotationChanged(t *testing.T) {
	oldObj := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 3,
			Annotations: map[string]string{
				policyNetworkAnnotation: "net-a",
			},
		},
	}
	newObj := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 3,
			Annotations: map[string]string{
				policyNetworkAnnotation: "net-b",
			},
		},
	}

	if !PolicyPredicate().Update(event.UpdateEvent{ObjectOld: oldObj, ObjectNew: newObj}) {
		t.Fatal("expected policy network annotation change to pass")
	}
}

func TestPolicyPredicate_Update_UnrelatedAnnotationOnly(t *testing.T) {
	oldObj := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 3,
			Annotations: map[string]string{
				"example.com/other": "old",
			},
		},
	}
	newObj := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 3,
			Annotations: map[string]string{
				"example.com/other": "new",
			},
		},
	}

	if PolicyPredicate().Update(event.UpdateEvent{ObjectOld: oldObj, ObjectNew: newObj}) {
		t.Fatal("expected unrelated annotation change to be filtered")
	}
}

func TestNodePredicate_MatchingNode(t *testing.T) {
	pred := NodePredicate("node-a")
	if !pred.Create(event.CreateEvent{Object: &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}}) {
		t.Fatal("expected matching node to pass")
	}
}

func TestNodePredicate_OtherNode(t *testing.T) {
	pred := NodePredicate("node-a")
	if pred.Update(event.UpdateEvent{ObjectNew: &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}}}) {
		t.Fatal("expected non-matching node to be filtered")
	}
}
