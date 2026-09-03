package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type fakeRuntimeConn struct {
	t               *testing.T
	response        *pb.ContainerStatusResponse
	err             error
	gotContainerID  string
	statusCallCount int
}

func (f *fakeRuntimeConn) Invoke(_ context.Context, method string, args interface{}, reply interface{}, _ ...grpc.CallOption) error {
	f.t.Helper()
	if method != pb.RuntimeService_ContainerStatus_FullMethodName {
		f.t.Fatalf("Invoke() method = %q, want %q", method, pb.RuntimeService_ContainerStatus_FullMethodName)
	}
	req, ok := args.(*pb.ContainerStatusRequest)
	if !ok {
		f.t.Fatalf("Invoke() args = %T, want *ContainerStatusRequest", args)
	}
	f.statusCallCount++
	f.gotContainerID = req.ContainerId
	if f.err != nil {
		return f.err
	}
	got, ok := reply.(*pb.ContainerStatusResponse)
	if !ok {
		f.t.Fatalf("Invoke() reply = %T, want *ContainerStatusResponse", reply)
	}
	if f.response != nil {
		proto.Merge(got, f.response)
	}
	return nil
}

func (f *fakeRuntimeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	f.t.Helper()
	return nil, fmt.Errorf("unexpected stream call")
}

func TestGetPodNetNSPathWithContext(t *testing.T) {
	t.Parallel()

	criErr := errors.New("container status failed")
	tests := []struct {
		name            string
		statuses        []corev1.ContainerStatus
		response        *pb.ContainerStatusResponse
		criErr          error
		wantPath        string
		wantContainerID string
		wantErr         string
	}{
		{
			name: "selects running status with container ID",
			statuses: []corev1.ContainerStatus{
				{Name: "init"},
				{Name: "app", ContainerID: "cri-o://container-a", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			},
			response:        containerStatusWithInfo(`{"pid":1234}`),
			wantPath:        "/proc/1234/ns/net",
			wantContainerID: "container-a",
		},
		{
			name: "falls back to first non-empty container ID",
			statuses: []corev1.ContainerStatus{
				{Name: "init"},
				{Name: "app", ContainerID: "containerd://container-b"},
			},
			response:        containerStatusWithInfo(`{"pid":4321}`),
			wantPath:        "/proc/4321/ns/net",
			wantContainerID: "container-b",
		},
		{
			name:     "rejects all empty container IDs",
			statuses: []corev1.ContainerStatus{{Name: "app"}},
			wantErr:  "no container ID",
		},
		{
			name:     "rejects malformed container ID",
			statuses: []corev1.ContainerStatus{{Name: "app", ContainerID: "container-a"}},
			wantErr:  "invalid container ID",
		},
		{
			name:            "returns CRI errors",
			statuses:        []corev1.ContainerStatus{{Name: "app", ContainerID: "cri-o://container-a", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}},
			criErr:          criErr,
			wantContainerID: "container-a",
			wantErr:         criErr.Error(),
		},
		{
			name:            "rejects missing pid",
			statuses:        []corev1.ContainerStatus{{Name: "app", ContainerID: "cri-o://container-a", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}},
			response:        containerStatusWithInfo(`{"state":"running"}`),
			wantContainerID: "container-a",
			wantErr:         "cannot get pid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := &fakeRuntimeConn{t: t, response: tt.response, err: tt.criErr}
			got, err := GetPodNetNSPathWithContext(context.Background(), pb.NewRuntimeServiceClient(conn), podWithContainerStatuses(tt.statuses))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("GetPodNetNSPathWithContext() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetPodNetNSPathWithContext() error = %v", err)
			}
			if got != tt.wantPath {
				t.Fatalf("GetPodNetNSPathWithContext() = %q, want %q", got, tt.wantPath)
			}
			if conn.gotContainerID != tt.wantContainerID {
				t.Fatalf("CRI container ID = %q, want %q", conn.gotContainerID, tt.wantContainerID)
			}
		})
	}
}

func TestNewPodInfoFromPodSkipsNetNSWithoutRelevantInterfaces(t *testing.T) {
	t.Parallel()

	conn := &fakeRuntimeConn{t: t, response: containerStatusWithInfo(`{"pid":1234}`)}
	pod := podWithNetworkAnnotations()

	podInfo, err := NewPodInfoFromPod(context.Background(), pod, pb.NewRuntimeServiceClient(conn), "node-a", []string{"macvlan"}, &mockNetDefResolver{pluginType: "bridge"})
	if err != nil {
		t.Fatalf("NewPodInfoFromPod() error = %v", err)
	}
	if len(podInfo.Interfaces) != 0 {
		t.Fatalf("interfaces length = %d, want 0", len(podInfo.Interfaces))
	}
	if podInfo.NetNSPath != "" {
		t.Fatalf("NetNSPath = %q, want empty", podInfo.NetNSPath)
	}
	if conn.statusCallCount != 0 {
		t.Fatalf("ContainerStatus calls = %d, want 0", conn.statusCallCount)
	}
}

func TestNewPodInfoFromPodPropagatesNetNSError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("container not found")
	pod := podWithNetworkAnnotations()
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", ContainerID: "cri-o://container-a", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}

	_, err := NewPodInfoFromPod(context.Background(), pod, pb.NewRuntimeServiceClient(&fakeRuntimeConn{t: t, err: wantErr}), "node-a", []string{"bridge"}, &mockNetDefResolver{pluginType: "bridge"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewPodInfoFromPod() error = %v, want %v", err, wantErr)
	}
}

func podWithContainerStatuses(statuses []corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "ns-a"},
		Status: corev1.PodStatus{
			Phase:             corev1.PodRunning,
			ContainerStatuses: statuses,
		},
	}
}

func containerStatusWithInfo(info string) *pb.ContainerStatusResponse {
	return &pb.ContainerStatusResponse{
		Info: map[string]string{"info": info},
	}
}

// TestNewPodInfoFromPodDefaultNetwork covers pods whose primary network is a
// net-attach-def selected with the Multus default-network annotation. Such pods
// have no "k8s.v1.cni.cncf.io/networks" annotation, but must still be policed.
func TestNewPodInfoFromPodDefaultNetwork(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		annotations   map[string]string
		networkPlugin string
		wantIfaces    []InterfaceInfo
	}{
		{
			name: "default network only",
			annotations: map[string]string{
				DefaultNetworkAnnotation: "ns-a/net-a",
				"k8s.v1.cni.cncf.io/network-status": `[{
					"name": "ns-a/net-a",
					"interface": "eth0",
					"ips": ["10.0.0.2"],
					"default": true
				}]`,
			},
			networkPlugin: "macvlan",
			wantIfaces: []InterfaceInfo{
				{NetattachName: "ns-a/net-a", InterfaceName: "eth0", InterfaceType: "macvlan", IPs: []string{"10.0.0.2"}},
			},
		},
		{
			name: "default network without namespace defaults to pod namespace",
			annotations: map[string]string{
				DefaultNetworkAnnotation: "net-a",
				"k8s.v1.cni.cncf.io/network-status": `[{
					"name": "net-a",
					"interface": "eth0",
					"ips": ["10.0.0.2"],
					"default": true
				}]`,
			},
			networkPlugin: "macvlan",
			wantIfaces: []InterfaceInfo{
				{NetattachName: "net-a", InterfaceName: "eth0", InterfaceType: "macvlan", IPs: []string{"10.0.0.2"}},
			},
		},
		{
			name: "default network combined with a secondary network",
			annotations: map[string]string{
				DefaultNetworkAnnotation:      "ns-a/net-a",
				"k8s.v1.cni.cncf.io/networks": "net-b",
				"k8s.v1.cni.cncf.io/network-status": `[{
					"name": "ns-a/net-a",
					"interface": "eth0",
					"ips": ["10.0.0.2"],
					"default": true
				},{
					"name": "net-b",
					"interface": "net1",
					"ips": ["10.1.0.2"]
				}]`,
			},
			networkPlugin: "macvlan",
			wantIfaces: []InterfaceInfo{
				{NetattachName: "ns-a/net-a", InterfaceName: "eth0", InterfaceType: "macvlan", IPs: []string{"10.0.0.2"}},
				{NetattachName: "net-b", InterfaceName: "net1", InterfaceType: "macvlan", IPs: []string{"10.1.0.2"}},
			},
		},
		{
			name: "default network with a plugin type that is not configured",
			annotations: map[string]string{
				DefaultNetworkAnnotation: "ns-a/net-a",
				"k8s.v1.cni.cncf.io/network-status": `[{
					"name": "ns-a/net-a",
					"interface": "eth0",
					"ips": ["10.0.0.2"],
					"default": true
				}]`,
			},
			networkPlugin: "bridge",
			wantIfaces:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "ns-a", Annotations: tc.annotations},
				Spec:       corev1.PodSpec{NodeName: "node-a"},
				Status: corev1.PodStatus{
					Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "app", ContainerID: "cri-o://container-a", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
					},
				},
			}
			conn := &fakeRuntimeConn{t: t, response: containerStatusWithInfo(`{"pid":1234}`)}

			podInfo, err := NewPodInfoFromPod(context.Background(), pod, pb.NewRuntimeServiceClient(conn), "node-a",
				[]string{tc.networkPlugin}, &mockNetDefResolver{pluginType: "macvlan"})
			if err != nil {
				t.Fatalf("NewPodInfoFromPod() error = %v", err)
			}
			if len(podInfo.Interfaces) != len(tc.wantIfaces) {
				t.Fatalf("interfaces = %+v, want %+v", podInfo.Interfaces, tc.wantIfaces)
			}
			for i, want := range tc.wantIfaces {
				got := podInfo.Interfaces[i]
				if got.NetattachName != want.NetattachName || got.InterfaceName != want.InterfaceName ||
					got.InterfaceType != want.InterfaceType || strings.Join(got.IPs, ",") != strings.Join(want.IPs, ",") {
					t.Errorf("interfaces[%d] = %+v, want %+v", i, got, want)
				}
			}
			if len(tc.wantIfaces) == 0 {
				if podInfo.NetNSPath != "" {
					t.Errorf("NetNSPath = %q, want empty", podInfo.NetNSPath)
				}
				return
			}
			if podInfo.NetNSPath != "/proc/1234/ns/net" {
				t.Errorf("NetNSPath = %q, want /proc/1234/ns/net", podInfo.NetNSPath)
			}
		})
	}
}

// TestParseDefaultNetworkAnnotation covers the annotation parsing itself,
// including the JSON form and the absent/empty cases.
func TestParseDefaultNetworkAnnotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		annotation    map[string]string
		wantLen       int
		wantName      string
		wantNamespace string
		wantErr       bool
	}{
		{name: "absent", annotation: nil, wantLen: 0},
		{name: "empty", annotation: map[string]string{DefaultNetworkAnnotation: "  "}, wantLen: 0},
		{
			name:       "plain name",
			annotation: map[string]string{DefaultNetworkAnnotation: "net-a"},
			wantLen:    1, wantName: "net-a", wantNamespace: "ns-a",
		},
		{
			name:       "namespaced name",
			annotation: map[string]string{DefaultNetworkAnnotation: "other-ns/net-a"},
			wantLen:    1, wantName: "net-a", wantNamespace: "other-ns",
		},
		{
			name:       "json form",
			annotation: map[string]string{DefaultNetworkAnnotation: `[{"name":"net-a","namespace":"other-ns"}]`},
			wantLen:    1, wantName: "net-a", wantNamespace: "other-ns",
		},
		{
			name:       "invalid json",
			annotation: map[string]string{DefaultNetworkAnnotation: `[{"name":`},
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-a", Namespace: "ns-a", Annotations: tc.annotation}}
			networks, err := parseDefaultNetworkAnnotation(pod)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseDefaultNetworkAnnotation() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDefaultNetworkAnnotation() error = %v", err)
			}
			if len(networks) != tc.wantLen {
				t.Fatalf("networks = %+v, want %d entries", networks, tc.wantLen)
			}
			if tc.wantLen == 0 {
				return
			}
			if networks[0].Name != tc.wantName || networks[0].Namespace != tc.wantNamespace {
				t.Errorf("networks[0] = %s/%s, want %s/%s", networks[0].Namespace, networks[0].Name, tc.wantNamespace, tc.wantName)
			}
		})
	}
}
