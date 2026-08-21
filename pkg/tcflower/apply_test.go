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
	"net/netip"
	"testing"

	tc "github.com/florianl/go-tc"
)

// fakeDriver records filter add/delete calls for reconcile tests. It does NOT
// touch netlink, so this test runs without root; the real netlink round-trip is
// exercised only by integration tests on Linux+root hardware.
type fakeDriver struct {
	installed []tc.Object
	added     []tc.Object
	deleted   []tc.Object
}

func (d *fakeDriver) EnsureClsact(_ int) error { return nil }

func (d *fakeDriver) ListFilters(ifindex, parent int) ([]tc.Object, error) {
	var out []tc.Object
	for _, o := range d.installed {
		if o.Parent == uint32(parent) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (d *fakeDriver) AddFilter(obj tc.Object) error {
	d.added = append(d.added, obj)
	return nil
}

func (d *fakeDriver) DelFilter(obj tc.Object) error {
	d.deleted = append(d.deleted, obj)
	return nil
}

func (d *fakeDriver) Close() error { return nil }

var _ Driver = (*fakeDriver)(nil)

// TestIsManagedFilterRecognizesBothModes asserts that isManagedFilter treats
// both a hardware (skip_sw) and a software (skip_hw) flower filter as managed,
// while leaving a foreign (non-flower) filter and a flag-less flower filter
// untouched.
func TestIsManagedFilterRecognizesBothModes(t *testing.T) {
	hw := FlowerRule{Rep: testRep, Direction: DirIngress, Priority: 1, Verdict: VerdictDrop}
	sw := hw
	sw.Offload = OffloadSoftware

	if !isManagedFilter(hw.toObject(1)) {
		t.Errorf("hardware-mode (skip_sw) filter must be managed")
	}
	if !isManagedFilter(sw.toObject(1)) {
		t.Errorf("software-mode (skip_hw) filter must be managed")
	}

	// A foreign non-flower filter is not managed.
	foreign := tc.Object{Attribute: tc.Attribute{Kind: "u32"}}
	if isManagedFilter(foreign) {
		t.Errorf("non-flower filter must not be managed")
	}

	// A flower filter with no offload flags (e.g. a plain software filter added
	// out-of-band) is not ours.
	noFlags := tc.Object{Attribute: tc.Attribute{Kind: "flower", Flower: &tc.Flower{}}}
	if isManagedFilter(noFlags) {
		t.Errorf("flag-less flower filter must not be managed")
	}
}

func TestReconcileAddsMissingAndDeletesStale(t *testing.T) {
	const ifindex = 10

	desired := []FlowerRule{
		{Rep: testRep, Direction: DirIngress, Priority: 1, Src: netip.MustParsePrefix("192.168.1.0/24"), Verdict: VerdictAccept},
		{Rep: testRep, Direction: DirIngress, Priority: 2, Verdict: VerdictDrop},
	}

	// Pre-seed a stale managed filter (skip_sw flower) that is NOT in desired,
	// plus a foreign filter that must be left untouched.
	staleRule := FlowerRule{Rep: testRep, Direction: DirIngress, Priority: 9, Src: netip.MustParsePrefix("172.16.0.0/12"), Verdict: VerdictAccept}
	stale := staleRule.toObject(ifindex)

	foreign := tc.Object{
		Msg:       tc.Msg{Ifindex: ifindex, Parent: DirIngress.parentHandle(), Handle: 0xdead},
		Attribute: tc.Attribute{Kind: "u32"}, // not flower => not managed
	}

	drv := &fakeDriver{installed: []tc.Object{stale, foreign}}

	if err := reconcile(drv, testRep, ifindex, desired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// All desired filters must be added.
	if len(drv.added) != len(desired) {
		t.Errorf("expected %d adds, got %d", len(desired), len(drv.added))
	}

	// The stale managed filter must be deleted; the foreign one must not.
	if len(drv.deleted) != 1 {
		t.Fatalf("expected exactly 1 delete (the stale managed filter), got %d: %+v", len(drv.deleted), drv.deleted)
	}
	if drv.deleted[0].Handle != stale.Handle {
		t.Errorf("deleted wrong filter: got handle %#x, want stale %#x", drv.deleted[0].Handle, stale.Handle)
	}
	for _, d := range drv.deleted {
		if d.Kind == "u32" {
			t.Errorf("foreign (non-managed) filter must not be deleted")
		}
	}
}
