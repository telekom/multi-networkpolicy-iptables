/*
Copyright 2026 Deutsche Telekom AG.

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

package controller

import (
	"testing"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

func TestSelectBackend(t *testing.T) {
	tests := []struct {
		name  string
		iface controllers.InterfaceInfo
		want  backendKind
	}{
		{
			name:  "macvlan interface uses nftables",
			iface: controllers.InterfaceInfo{NetattachName: "net1", InterfaceName: "net1", InterfaceType: "macvlan"},
			want:  backendNFT,
		},
		{
			name:  "sriov interface with pci address uses tc",
			iface: controllers.InterfaceInfo{NetattachName: "sriov-net", InterfaceName: "net1", PCIAddress: "0000:04:00.2"},
			want:  backendTC,
		},
		{
			name:  "sriov interface with only representor uses tc",
			iface: controllers.InterfaceInfo{NetattachName: "sriov-net", InterfaceName: "net1", RepresentorDevice: "enp4s0f0_3"},
			want:  backendTC,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectBackend(tc.iface); got != tc.want {
				t.Fatalf("selectBackend() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPartitionByBackend(t *testing.T) {
	nft := controllers.InterfaceInfo{NetattachName: "macvlan-net", InterfaceName: "net1", InterfaceType: "macvlan"}
	tcA := controllers.InterfaceInfo{NetattachName: "sriov-a", InterfaceName: "net2", PCIAddress: "0000:04:00.2"}
	tcB := controllers.InterfaceInfo{NetattachName: "sriov-b", InterfaceName: "net3", RepresentorDevice: "enp4s0f0_5"}

	t.Run("nil pod info", func(t *testing.T) {
		if got := partitionByBackend(nil); got != nil {
			t.Fatalf("partitionByBackend(nil) = %v, want nil", got)
		}
	})

	t.Run("no interfaces", func(t *testing.T) {
		if got := partitionByBackend(&controllers.PodInfo{Name: "p"}); got != nil {
			t.Fatalf("partitionByBackend(empty) = %v, want nil", got)
		}
	})

	t.Run("only nft", func(t *testing.T) {
		got := partitionByBackend(&controllers.PodInfo{Interfaces: []controllers.InterfaceInfo{nft}})
		if len(got) != 1 {
			t.Fatalf("got %d groups, want 1", len(got))
		}
		if _, ok := got[backendTC]; ok {
			t.Fatalf("unexpected tc group for nft-only pod")
		}
		if n := len(got[backendNFT].Interfaces); n != 1 {
			t.Fatalf("nft group has %d interfaces, want 1", n)
		}
	})

	t.Run("mixed pod splits into both backends", func(t *testing.T) {
		podInfo := &controllers.PodInfo{
			Name:       "mixed",
			Namespace:  "ns",
			NetNSPath:  "/proc/1/ns/net",
			NodeName:   "node-1",
			Interfaces: []controllers.InterfaceInfo{nft, tcA, tcB},
		}
		got := partitionByBackend(podInfo)
		if len(got) != 2 {
			t.Fatalf("got %d groups, want 2 (nft + tc)", len(got))
		}

		nftGroup, ok := got[backendNFT]
		if !ok {
			t.Fatal("missing nft group")
		}
		if len(nftGroup.Interfaces) != 1 || nftGroup.Interfaces[0].NetattachName != "macvlan-net" {
			t.Fatalf("nft group interfaces = %+v, want just macvlan-net", nftGroup.Interfaces)
		}

		tcGroup, ok := got[backendTC]
		if !ok {
			t.Fatal("missing tc group")
		}
		if len(tcGroup.Interfaces) != 2 {
			t.Fatalf("tc group has %d interfaces, want 2", len(tcGroup.Interfaces))
		}

		// Scalar PodInfo fields are preserved on each narrowed copy, and the
		// narrowing must not mutate the original slice.
		if tcGroup.Name != "mixed" || tcGroup.NetNSPath != "/proc/1/ns/net" || tcGroup.NodeName != "node-1" {
			t.Fatalf("tc group lost scalar PodInfo fields: %+v", tcGroup)
		}
		if len(podInfo.Interfaces) != 3 {
			t.Fatalf("original PodInfo.Interfaces mutated: len = %d, want 3", len(podInfo.Interfaces))
		}
	})
}

func TestBackendKindString(t *testing.T) {
	if backendNFT.String() != "nftables" {
		t.Fatalf("backendNFT.String() = %q, want nftables", backendNFT.String())
	}
	if backendTC.String() != "tc" {
		t.Fatalf("backendTC.String() = %q, want tc", backendTC.String())
	}
}
