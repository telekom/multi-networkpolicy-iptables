package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	multiutils "github.com/telekom/multi-networkpolicy-nftables/pkg/utils"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog/v2"
)

// GetPodNetNSPathWithContext resolves the pod network namespace path via CRI.
func GetPodNetNSPathWithContext(ctx context.Context, criClient pb.RuntimeServiceClient, pod *corev1.Pod) (string, error) {
	netnsPath := ""

	if pod.Status.Phase != corev1.PodRunning {
		return "", fmt.Errorf("pod is not running")
	}

	if len(pod.Status.ContainerStatuses) == 0 {
		return "", fmt.Errorf("no container status")
	}

	containerIDRaw := selectContainerID(pod.Status.ContainerStatuses)
	if containerIDRaw == "" {
		return "", fmt.Errorf("no container ID")
	}
	runtimeKind, containerID, ok := strings.Cut(containerIDRaw, "://")
	if !ok || containerID == "" {
		return "", fmt.Errorf("invalid container ID %q", containerIDRaw)
	}

	switch runtimeKind {
	default:
		if criClient == nil {
			return "", fmt.Errorf("cannot find cri client")
		}
		request := &pb.ContainerStatusRequest{
			ContainerId: containerID,
			Verbose:     true,
		}
		rpcCtx, rpcCancel := context.WithTimeout(ctx, 10*time.Second)
		defer rpcCancel()
		r, err := criClient.ContainerStatus(rpcCtx, request)
		if err != nil {
			return "", fmt.Errorf("cannot get containerStatus: %w", err)
		}

		info := r.GetInfo()
		var infop interface{}
		err = json.Unmarshal([]byte(info["info"]), &infop)
		if err != nil {
			return "", fmt.Errorf("cannot unmarshal containerStatus info: %w", err)
		}
		pid, ok := infop.(map[string]interface{})["pid"].(float64)
		if !ok {
			return "", fmt.Errorf("cannot get pid from containerStatus info")
		}
		netnsPath = fmt.Sprintf("/proc/%d/ns/net", int(pid))
	}

	return netnsPath, nil
}

func selectContainerID(statuses []corev1.ContainerStatus) string {
	for _, status := range statuses {
		if status.ContainerID != "" && status.State.Running != nil {
			return status.ContainerID
		}
	}
	for _, status := range statuses {
		if status.ContainerID != "" {
			return status.ContainerID
		}
	}
	return ""
}

// parseInterfaceIPs converts the string IPs reported by the Multus
// network-status annotation into typed netip.Addr values. Unparseable entries
// are logged and skipped rather than failing the whole pod.
func parseInterfaceIPs(ips []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			klog.V(4).Infof("skipping unparseable interface IP %q: %v", s, err)
			continue
		}
		out = append(out, addr)
	}
	return out
}

// NewPodInfoFromPod builds PodInfo for a pod using CRI and network definitions.
func NewPodInfoFromPod(ctx context.Context, pod *corev1.Pod, criClient pb.RuntimeServiceClient, hostname string, networkPlugins []string, netdefResolver NetDefResolver) (*PodInfo, error) {
	var statuses []netdefv1.NetworkStatus
	var netnsPath string
	var netifs []InterfaceInfo
	// get network information only if the pod is ready
	if IsMultiNetworkpolicyTarget(pod) {
		networks, err := netdefutils.ParsePodNetworkAnnotation(pod)
		if err != nil {
			if _, ok := err.(*netdefv1.NoK8sNetworkError); !ok {
				klog.Errorf("failed to get pod network annotation: %v", err)
			}
		}
		// parse networkStatus
		statuses, err = netdefutils.GetNetworkStatus(pod)
		if err != nil {
			klog.Errorf("failed to get pod(%s/%s) network status: %v", pod.Namespace, pod.Name, err)
		}

		klog.V(1).Infof("pod:%s/%s %s/%s", pod.Namespace, pod.Name, hostname, pod.Spec.NodeName)

		// netdefname -> plugin name map
		networkPluginsMap := make(map[types.NamespacedName]string)
		if networks == nil {
			klog.V(8).Infof("%s/%s: NO NET", pod.Namespace, pod.Name)
		} else {
			klog.V(8).Infof("%s/%s: net: %v", pod.Namespace, pod.Name, networks)
		}
		for _, n := range networks {
			namespace := pod.Namespace
			if n.Namespace != "" {
				namespace = n.Namespace
			}
			namespacedName := types.NamespacedName{Namespace: namespace, Name: n.Name}
			if _, ok := networkPluginsMap[namespacedName]; ok {
				continue
			}
			pluginType, err := netdefResolver.GetPluginType(ctx, namespacedName)
			if err != nil {
				return nil, fmt.Errorf("resolve plugin type for network attachment %s: %w", namespacedName, err)
			}
			klog.V(8).Infof("networkPlugins[%s], %v", namespacedName, pluginType)
			networkPluginsMap[namespacedName] = pluginType
		}
		klog.V(6).Infof("netdef->pluginMap: %v", networkPluginsMap)

		// match it with
		for _, s := range statuses {
			var netNamespace, netName string
			slashItems := strings.Split(s.Name, "/")
			if len(slashItems) == 2 {
				netNamespace = strings.TrimSpace(slashItems[0])
				netName = slashItems[1]
			} else {
				netNamespace = pod.Namespace
				netName = s.Name
			}
			namespacedName := types.NamespacedName{Namespace: netNamespace, Name: netName}

			for _, pluginName := range networkPlugins {
				if networkPluginsMap[namespacedName] == pluginName {
					iface := InterfaceInfo{
						NetattachName: s.Name,
						InterfaceName: s.Interface,
						InterfaceType: networkPluginsMap[namespacedName],
						IPs:           parseInterfaceIPs(s.IPs),
					}
					// Carry SR-IOV device info (VF PCI address, PF PCI address,
					// host representor netdev) when the CNI reported it, so the
					// interface can be enforced on its VF representor via tc flower.
					if s.DeviceInfo != nil && s.DeviceInfo.Pci != nil {
						iface.PCIAddress = s.DeviceInfo.Pci.PciAddress
						iface.PFPCIAddress = s.DeviceInfo.Pci.PfPciAddress
						iface.RepresentorDevice = s.DeviceInfo.Pci.RepresentorDevice
					}
					netifs = append(netifs, iface)
				}
			}
		}

		if len(netifs) > 0 && multiutils.CheckNodeNameIdentical(hostname, pod.Spec.NodeName) && criClient != nil {
			netnsPath, err = GetPodNetNSPathWithContext(ctx, criClient, pod)
			if err != nil {
				return nil, fmt.Errorf("resolve pod network namespace: %w", err)
			}
			klog.V(8).Infof("NetnsPath: %s", netnsPath)
		}

		klog.V(6).Infof("Pod: %s/%s netns:%s netIF:%v", pod.Namespace, pod.Name, netnsPath, netifs)
	} else {
		klog.V(1).Infof("Pod:%s/%s %s/%s, not ready", pod.Namespace, pod.Name, hostname, pod.Spec.NodeName)
	}

	slices.SortFunc(netifs, func(a, b InterfaceInfo) int {
		return strings.Compare(a.InterfaceName, b.InterfaceName)
	})

	return &PodInfo{
		Name:          pod.Name,
		Namespace:     pod.Namespace,
		NetworkStatus: statuses,
		NetNSPath:     netnsPath,
		NodeName:      pod.Spec.NodeName,
		Interfaces:    netifs,
	}, nil
}
