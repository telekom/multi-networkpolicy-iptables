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

// listErrDriver wraps fakeDriver but returns an error from ListFilters, to model
// a representor with no clsact qdisc (flushRepresentor must treat that as
// already-clean, not an error).
type listErrDriver struct {
	fakeDriver
	err error
}

func (d *listErrDriver) ListFilters(int, int) ([]tc.Object, error) {
	return nil, d.err
}

func TestFlushRepresentorDeletesOnlyManaged(t *testing.T) {
	const ifindex = 7

	managedIngress := FlowerRule{Rep: testRep, Direction: DirIngress, Priority: 1, Src: netip.MustParsePrefix("10.0.0.0/8"), Verdict: VerdictAccept}.toObject(ifindex)
	managedEgress := FlowerRule{Rep: testRep, Direction: DirEgress, Priority: 1, Dst: netip.MustParsePrefix("10.0.0.0/8"), Verdict: VerdictAccept}.toObject(ifindex)
	foreign := tc.Object{
		Msg:       tc.Msg{Ifindex: ifindex, Parent: DirIngress.parentHandle(), Handle: 0xbeef},
		Attribute: tc.Attribute{Kind: "u32"}, // not flower => not managed
	}

	drv := &fakeDriver{installed: []tc.Object{managedIngress, managedEgress, foreign}}

	if err := flushRepresentor(drv, ifindex); err != nil {
		t.Fatalf("flushRepresentor: %v", err)
	}

	if len(drv.deleted) != 2 {
		t.Fatalf("expected 2 managed filters deleted (ingress+egress), got %d: %+v", len(drv.deleted), drv.deleted)
	}
	for _, d := range drv.deleted {
		if d.Kind == "u32" {
			t.Errorf("foreign (non-managed) filter must not be deleted")
		}
	}
}

func TestFlushRepresentorToleratesMissingQdisc(t *testing.T) {
	// A representor whose clsact qdisc is gone surfaces as a ListFilters error;
	// flushRepresentor must treat it as already-clean and return nil.
	drv := &listErrDriver{err: errNoQdisc{}}
	if err := flushRepresentor(drv, 3); err != nil {
		t.Fatalf("flushRepresentor should tolerate a missing qdisc, got: %v", err)
	}
	if len(drv.deleted) != 0 {
		t.Fatalf("expected no deletes, got %d", len(drv.deleted))
	}
}

// errNoQdisc is a stand-in error for "no clsact qdisc / no such object".
type errNoQdisc struct{}

func (errNoQdisc) Error() string { return "no such file or directory" }
