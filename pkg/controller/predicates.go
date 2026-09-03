package controller

import (
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1 "k8s.io/api/core/v1"
)

const policyNetworkAnnotation = "k8s.v1.cni.cncf.io/policy-for"

// PodPredicate filters pod events: allows Create/Delete, allows Update only if
// pod phase, labels, container IDs, or network-related annotations changed.
func PodPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		DeleteFunc: func(event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, okOld := e.ObjectOld.(*corev1.Pod)
			newPod, okNew := e.ObjectNew.(*corev1.Pod)
			if !okOld || !okNew {
				return false
			}

			if oldPod.Status.Phase != newPod.Status.Phase {
				return true
			}
			if oldPod.Spec.NodeName != newPod.Spec.NodeName {
				return true
			}
			if labelsChanged(oldPod.Labels, newPod.Labels) {
				return true
			}
			if containerStatusesChanged(oldPod.Status.ContainerStatuses, newPod.Status.ContainerStatuses) {
				return true
			}
			return networkAnnotationsChanged(oldPod.Annotations, newPod.Annotations)
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// PolicyPredicate filters policy events: allows Create/Delete, allows Update when
// spec generation or network-selection annotation changed.
func PolicyPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		DeleteFunc: func(event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
				return true
			}
			return policyNetworkAnnotationChanged(e.ObjectOld.GetAnnotations(), e.ObjectNew.GetAnnotations())
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// NodePredicate filters node events to only the named node.
func NodePredicate(nodeName string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return e.Object.GetName() == nodeName },
		DeleteFunc:  func(e event.DeleteEvent) bool { return e.Object.GetName() == nodeName },
		UpdateFunc:  func(e event.UpdateEvent) bool { return e.ObjectNew.GetName() == nodeName },
		GenericFunc: func(e event.GenericEvent) bool { return e.Object.GetName() == nodeName },
	}
}

func labelsChanged(oldLabels, newLabels map[string]string) bool {
	if len(oldLabels) != len(newLabels) {
		return true
	}

	for key, oldVal := range oldLabels {
		if newVal, ok := newLabels[key]; !ok || newVal != oldVal {
			return true
		}
	}

	return false
}

func containerStatusesChanged(oldStatuses, newStatuses []corev1.ContainerStatus) bool {
	if len(oldStatuses) != len(newStatuses) {
		return true
	}

	oldByName := make(map[string]string, len(oldStatuses))
	for _, status := range oldStatuses {
		oldByName[status.Name] = status.ContainerID
	}

	for _, status := range newStatuses {
		oldID, ok := oldByName[status.Name]
		if !ok || oldID != status.ContainerID {
			return true
		}
	}
	return false
}

var networkAnnotationKeys = []string{
	"k8s.v1.cni.cncf.io/network-status",
	"k8s.v1.cni.cncf.io/networks",
	// A pod can also be attached to a net-attach-def as its primary network.
	controllers.DefaultNetworkAnnotation,
}

func networkAnnotationsChanged(oldAnnotations, newAnnotations map[string]string) bool {
	for _, key := range networkAnnotationKeys {
		if oldAnnotations[key] != newAnnotations[key] {
			return true
		}
	}
	return false
}

func policyNetworkAnnotationChanged(oldAnnotations, newAnnotations map[string]string) bool {
	return oldAnnotations[policyNetworkAnnotation] != newAnnotations[policyNetworkAnnotation]
}
