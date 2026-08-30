package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
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

func TestNewPodInfoFromPodUsesSecondaryStatusWithoutNetworksAnnotation(t *testing.T) {
	t.Parallel()

	pod := podWithContainerStatuses(nil)
	pod.Annotations = map[string]string{
		"k8s.v1.cni.cncf.io/network-status": `[{
			"name": "net-a",
			"interface": "net1",
			"ips": ["10.0.0.2"]
		}]`,
	}

	podInfo, err := NewPodInfoFromPod(context.Background(), pod, nil, "other-node", []string{"bridge"}, &mockNetDefResolver{pluginType: "bridge"})
	if err != nil {
		t.Fatalf("NewPodInfoFromPod() error = %v", err)
	}
	if len(podInfo.Interfaces) != 1 {
		t.Fatalf("interfaces length = %d, want 1 (%#v)", len(podInfo.Interfaces), podInfo.Interfaces)
	}
	if got := podInfo.Interfaces[0]; got.NetattachName != "net-a" || got.InterfaceName != "net1" {
		t.Fatalf("interface = %#v, want net-a/net1", got)
	}
}

func TestNetworkStatusForPod(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{}
	tests := []struct {
		name     string
		networks []*netdefv1.NetworkSelectionElement
		wantErr  bool
	}{
		{
			name: "skips status lookup without additional networks",
		},
		{
			name: "requires status for additional networks",
			networks: []*netdefv1.NetworkSelectionElement{{
				Name: "net-a",
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			statuses, err := networkStatusForPod(pod, tt.networks)
			if tt.wantErr && err == nil {
				t.Fatal("networkStatusForPod() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("networkStatusForPod() error = %v", err)
			}
			if len(statuses) != 0 {
				t.Fatalf("networkStatusForPod() statuses = %#v, want empty", statuses)
			}
		})
	}
}

func TestNetworkStatusForPodRetainsLookupForUnparsedNetworkAnnotation(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/networks": `{"name":"net-a","interface":"net1"}`,
			},
		},
	}

	if _, err := networkStatusForPod(pod, nil); err == nil {
		t.Fatal("networkStatusForPod() error = nil, want missing network status error")
	}
}

func TestNetworkStatusForPodUsesStatusWithoutNetworksAnnotation(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/network-status": `[{
					"name": "net-a",
					"interface": "net1",
					"ips": ["10.0.0.2"]
				}]`,
			},
		},
	}

	statuses, err := networkStatusForPod(pod, nil)
	if err != nil {
		t.Fatalf("networkStatusForPod() error = %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("networkStatusForPod() statuses = %#v, want one status", statuses)
	}
	if got := statuses[0]; got.Name != "net-a" || got.Interface != "net1" {
		t.Fatalf("networkStatusForPod() status = %#v, want net-a/net1", got)
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
