//go:build linux

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

package tcflower

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	tc "github.com/florianl/go-tc"
)

// Layer B — control-plane integration test against a netdevsim netdev.
//
// This drives the REAL netlinkDriver (go-tc over rtnetlink) end to end:
//
//	NewDriver -> EnsureClsact -> AddFilter(flower from FlowerRule.toObject)
//	          -> ListFilters (assert present + expected keys) -> DelFilter
//	          -> ListFilters (assert gone)
//
// It exercises the actual netlink marshaling/round-trip in CI without Mellanox
// hardware. It does NOT assert that the (skip_sw) filter drops packets: stock
// netdevsim's TC_SETUP_CLSFLOWER is a no-op, so an offloaded filter is installed
// in bookkeeping only. Packet-drop correctness is proven for the software path
// by test/emulation/veth-flower-enforcement.sh, and the true offloaded-drop
// semantics remain gated to real CX5+ hardware.
//
// The test self-skips (never fails CI) when: running under -short, not root, or
// netdevsim is unavailable/unwritable.
const (
	nsimBus = "/sys/bus/netdevsim"
	// A high, unlikely-to-collide instance id for the test device.
	nsimTestID = "2026"
)

func TestNetdevsimFlowerControlPlane(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping netdevsim integration test in -short mode")
	}
	if os.Geteuid() != 0 {
		t.Skip("netdevsim integration test requires root (CAP_NET_ADMIN)")
	}
	if !netdevsimWritable(t) {
		t.Skipf("netdevsim unavailable: %s/new_device not writable (module not loaded?)", nsimBus)
	}

	dev := createNetdevsim(t)
	ifindex := dev.ifindex

	drv, err := NewDriver()
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	t.Cleanup(func() {
		if cerr := drv.Close(); cerr != nil {
			t.Logf("driver close: %v", cerr)
		}
	})

	if err := drv.EnsureClsact(ifindex); err != nil {
		t.Fatalf("EnsureClsact on netdevsim ifindex %d: %v", ifindex, err)
	}

	// A representative stateless rule: policy ingress, accept TCP dport 8080
	// from a /24 source. toObject stamps skip_sw + the flower keys we assert on.
	rule := FlowerRule{
		Rep:       dev.name,
		Direction: DirIngress,
		Priority:  1,
		Proto:     ipProtoTCP,
		Family:    familyV4,
		Src:       netip.MustParsePrefix("192.168.7.0/24"),
		HasPort:   true,
		PortMin:   8080,
		PortMax:   8080,
		Verdict:   VerdictAccept,
	}
	obj := rule.toObject(ifindex)

	if err := drv.AddFilter(obj); err != nil {
		// A NIC/driver that cannot offload the skip_sw filter rejects it
		// (EOPNOTSUPP). On such a kernel netdevsim does not accept the offload,
		// which is a legitimate SKIP rather than a test failure — the control
		// plane is what we exercise, and it is hardware/kernel dependent.
		if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP) {
			t.Skipf("netdevsim rejected skip_sw flower offload (EOPNOTSUPP); "+
				"this kernel's netdevsim does not accept flower offload: %v", err)
		}
		t.Fatalf("AddFilter: %v", err)
	}

	parent := int(DirIngress.parentHandle())
	got := listManaged(t, drv, ifindex, parent, obj.Handle)
	if got == nil {
		t.Fatalf("installed flower filter (handle %#x) not found after AddFilter", obj.Handle)
	}

	// Assert the round-tripped filter carries the expected match keys.
	assertFlowerKeys(t, *got, rule)

	if err := drv.DelFilter(obj); err != nil {
		t.Fatalf("DelFilter: %v", err)
	}

	if still := listManaged(t, drv, ifindex, parent, obj.Handle); still != nil {
		t.Fatalf("flower filter (handle %#x) still present after DelFilter", obj.Handle)
	}
}

// assertFlowerKeys checks the keys we care about survived the netlink round trip.
func assertFlowerKeys(t *testing.T, obj tc.Object, want FlowerRule) {
	t.Helper()
	if obj.Kind != "flower" || obj.Flower == nil {
		t.Fatalf("installed filter is not flower: kind=%q flower=%v", obj.Kind, obj.Flower)
	}
	fl := obj.Flower
	if fl.Flags == nil || (*fl.Flags&tc.SkipSw) == 0 {
		t.Errorf("flower filter missing SkipSw flag: %v", fl.Flags)
	}
	if fl.KeyEthType == nil || *fl.KeyEthType != ethTypeIPv4 {
		t.Errorf("KeyEthType = %v, want %#x (IPv4)", fl.KeyEthType, ethTypeIPv4)
	}
	if fl.KeyIPProto == nil || *fl.KeyIPProto != uint8(want.Proto) {
		t.Errorf("KeyIPProto = %v, want %d (tcp)", fl.KeyIPProto, want.Proto)
	}
	if fl.KeyIPv4Src == nil {
		t.Errorf("KeyIPv4Src missing; want source %s", want.Src)
	} else {
		wantIP := want.Src.Masked().Addr().As4()
		if !fl.KeyIPv4Src.Equal(net.IP(wantIP[:])) {
			t.Errorf("KeyIPv4Src = %v, want %v", *fl.KeyIPv4Src, net.IP(wantIP[:]))
		}
	}
	if fl.KeyTCPDst == nil || *fl.KeyTCPDst != want.PortMin {
		t.Errorf("KeyTCPDst = %v, want %d", fl.KeyTCPDst, want.PortMin)
	}
}

// listManaged returns the managed filter with the given handle on (ifindex,
// parent), or nil if absent.
func listManaged(t *testing.T, drv Driver, ifindex, parent int, handle uint32) *tc.Object {
	t.Helper()
	objs, err := drv.ListFilters(ifindex, parent)
	if err != nil {
		t.Fatalf("ListFilters(ifindex=%d parent=%#x): %v", ifindex, parent, err)
	}
	for i := range objs {
		if objs[i].Handle == handle && isManagedFilter(objs[i]) {
			return &objs[i]
		}
	}
	return nil
}

type nsimDevice struct {
	name    string
	ifindex int
}

// netdevsimWritable reports whether netdevsim can be driven (module loaded, sysfs
// control file writable).
func netdevsimWritable(t *testing.T) bool {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(nsimBus, "new_device"), os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// createNetdevsim creates a netdevsim instance with one port and returns its
// netdev name + ifindex, registering cleanup that deletes the instance.
func createNetdevsim(t *testing.T) nsimDevice {
	t.Helper()

	// Remove any stale instance from a previous aborted run, then create fresh.
	delNetdevsim()
	if err := os.WriteFile(filepath.Join(nsimBus, "new_device"), []byte(nsimTestID+" 1"), 0o200); err != nil {
		t.Skipf("could not create netdevsim instance: %v", err)
	}
	t.Cleanup(delNetdevsim)

	// The instance's netdev appears under devices/netdevsim<id>/net/<name>.
	netDir := filepath.Join(nsimBus, "devices", "netdevsim"+nsimTestID, "net")
	name := waitForNetdev(t, netDir)
	if name == "" {
		t.Skipf("netdevsim instance created but no netdev appeared under %s", netDir)
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Skipf("resolving netdevsim netdev %q: %v", name, err)
	}
	// Bring it up so tc operations behave as on a real link.
	// (Best-effort: EnsureClsact does not strictly require the link to be up.)
	return nsimDevice{name: name, ifindex: iface.Index}
}

// waitForNetdev polls netDir briefly for the first netdev to appear.
func waitForNetdev(t *testing.T, netDir string) string {
	t.Helper()
	for i := 0; i < 50; i++ {
		entries, err := os.ReadDir(netDir)
		if err == nil {
			for _, e := range entries {
				if n := strings.TrimSpace(e.Name()); n != "" {
					return n
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return ""
}

// delNetdevsim best-effort deletes the test netdevsim instance.
func delNetdevsim() {
	_ = os.WriteFile(filepath.Join(nsimBus, "del_device"), []byte(nsimTestID), 0o200)
}
