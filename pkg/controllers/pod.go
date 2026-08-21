/*
Copyright 2020 The Kubernetes Authors.

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

package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	v1 "k8s.io/api/core/v1"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	k8sutils "k8s.io/cri-client/pkg/util"
)

// RuntimeKind is enum type variable for container runtime
type RuntimeKind string

const (
	// Cri based runtime (e.g. cri-o)
	Cri = "cri"
)

// Set specifies container runtime kind
func (rk *RuntimeKind) Set(s string) error {
	runtime := strings.ToLower(s)
	switch runtime {
	case Cri:
		*rk = RuntimeKind(runtime)
		return nil
	}
	return fmt.Errorf("invalid container-runtime option %q (possible values: \"cri\")", s)
}

// String returns current runtime kind
func (rk RuntimeKind) String() string { return string(rk) }

// Type implements pflag.Value.
func (rk RuntimeKind) Type() string { return "RuntimeKind" }

// InterfaceInfo ...
type InterfaceInfo struct {
	NetattachName string
	InterfaceName string
	InterfaceType string
	IPs           []netip.Addr

	// SR-IOV device information, populated from the Multus network-status
	// annotation's device-info.pci field when the interface is backed by an
	// SR-IOV virtual function. When set, the interface is enforced on the host
	// via tc flower on its VF representor instead of nftables inside the pod
	// network namespace. Empty for veth-style CNIs (macvlan, ipvlan, bond).
	PCIAddress        string
	PFPCIAddress      string
	RepresentorDevice string
}

// IsSRIOV reports whether the interface is backed by an SR-IOV virtual function
// and must therefore be enforced on its host VF representor via tc flower.
func (info *InterfaceInfo) IsSRIOV() bool {
	return info.PCIAddress != "" || info.RepresentorDevice != ""
}

// CheckPolicyNetwork checks whether given interface is target or not,
// based on policyNetworks
func (info *InterfaceInfo) CheckPolicyNetwork(policyNetworks []string) bool {
	for _, policyNetworkName := range policyNetworks {
		if policyNetworkName == info.NetattachName {
			return true
		}
	}
	return false
}

// PodInfo contains information that defines a pod.
type PodInfo struct {
	Name          string
	Namespace     string
	NetNSPath     string
	NetworkStatus []netdefv1.NetworkStatus
	NodeName      string
	Interfaces    []InterfaceInfo
}

// CheckPolicyNetwork checks whether given pod is target or not,
// based on policyNetworks
func (info *PodInfo) CheckPolicyNetwork(policyNetworks []string) bool {
	for _, intf := range info.Interfaces {
		for _, policyNetworkName := range policyNetworks {
			if policyNetworkName == intf.NetattachName {
				return true
			}
		}
	}
	return false
}

// IsMultiNetworkpolicyTarget ...
func IsMultiNetworkpolicyTarget(pod *v1.Pod) bool {
	if pod.Status.Phase != v1.PodRunning {
		return false
	}

	if pod.Spec.HostNetwork {
		return false
	}
	return true
}

// GetCriRuntimeClientWithContext retrieves a CRI gRPC client using the supplied context.
func GetCriRuntimeClientWithContext(ctx context.Context, runtimeEndpoint, hostPrefix string) (pb.RuntimeServiceClient, *grpc.ClientConn, error) {
	hostRuntimeEndpoint := fmt.Sprintf("unix://%s%s", hostPrefix, runtimeEndpoint)
	addr, dialer, err := k8sutils.GetAddressAndDialer(hostRuntimeEndpoint)
	if err != nil {
		return nil, nil, err
	}

	target := "passthrough:///" + addr
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialer))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gRPC client for %s: %w", hostRuntimeEndpoint, err)
	}
	conn.Connect()

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			break
		}
		if !conn.WaitForStateChange(ctx, state) {
			_ = conn.Close()
			if err := ctx.Err(); err != nil {
				return nil, nil, fmt.Errorf("timed out waiting for gRPC connection to %s to become ready (last state: %s): %w", hostRuntimeEndpoint, state, err)
			}
			return nil, nil, fmt.Errorf("timed out waiting for gRPC connection to %s to become ready (last state: %s)", hostRuntimeEndpoint, state)
		}
	}

	return pb.NewRuntimeServiceClient(conn), conn, nil
}
