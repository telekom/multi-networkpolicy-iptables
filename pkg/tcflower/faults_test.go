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

// Hardware-limit / failure-simulation coverage for the reconcile loop and the
// flush path. Everything here drives a fault-injecting fake Driver, so it runs
// WITHOUT root and WITHOUT netlink — but the code under test (reconcile,
// flushRepresentor, addErrorReason, the apply-error metric) lives in the
// linux-tagged apply.go, so this file carries the same //go:build linux tag.
// No production seam is required: reconcile already takes a Driver, and the
// fail-closed apply-error counter is observable through the vendored
// client_model dto (prometheus/client_golang/prometheus/testutil is NOT
// vendored, so counters are read directly via Counter.Write(&dto.Metric{})).

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"testing"

	tc "github.com/florianl/go-tc"
	dto "github.com/prometheus/client_model/go"
)

// faultDriver is a programmable fake Driver that can be told to fail specific
// operations with specific (typically errno-backed) errors. It records adds and
// deletes and counts calls so a test can assert both the daemon's error
// handling (fail-closed / aggregation) and how far the loop progressed
// (best-effort continuation vs. abort-on-first-error).
type faultDriver struct {
	installed []tc.Object // served by ListFilters, filtered by parent

	// Static per-op errors (applied to every matching call).
	ensureErr error
	listErr   error
	addErr    error
	delErr    error

	// Predicate faults: return a non-nil error to fail THAT specific object.
	// Keyed on the object so a test can fail one representor (Ifindex) or one
	// filter shape while letting the rest succeed.
	failAddIf func(tc.Object) error
	failDelIf func(tc.Object) error

	// Call counters (post-invocation totals, including the failing call).
	ensureCalls int
	listCalls   int
	addCalls    int
	delCalls    int

	added   []tc.Object
	deleted []tc.Object
}

var _ Driver = (*faultDriver)(nil)

func (d *faultDriver) EnsureClsact(_ int) error {
	d.ensureCalls++
	return d.ensureErr
}

func (d *faultDriver) ListFilters(_, parent int) ([]tc.Object, error) {
	d.listCalls++
	if d.listErr != nil {
		return nil, d.listErr
	}
	var out []tc.Object
	for _, o := range d.installed {
		if o.Parent == uint32(parent) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (d *faultDriver) AddFilter(obj tc.Object) error {
	d.addCalls++
	if d.addErr != nil {
		return d.addErr
	}
	if d.failAddIf != nil {
		if err := d.failAddIf(obj); err != nil {
			return err
		}
	}
	d.added = append(d.added, obj)
	return nil
}

func (d *faultDriver) DelFilter(obj tc.Object) error {
	d.delCalls++
	if d.delErr != nil {
		return d.delErr
	}
	if d.failDelIf != nil {
		if err := d.failDelIf(obj); err != nil {
			return err
		}
	}
	d.deleted = append(d.deleted, obj)
	return nil
}

func (d *faultDriver) Close() error { return nil }

// applyErrorCount reads the current value of the fail-closed apply-error counter
// for (rep, reason). The counter is a global (registered once), so tests use a
// unique representor label and/or a before/after delta to stay isolated.
func applyErrorCount(t *testing.T, rep, reason string) float64 {
	t.Helper()
	var m dto.Metric
	if err := filterApplyErrors.WithLabelValues(rep, reason).Write(&m); err != nil {
		t.Fatalf("read apply-error counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// hwRule / swRule build a single-filter desired set so the (map-ordered)
// AddFilter loop hits exactly one object and the recorded metric reason is
// deterministic.
func hwRule() FlowerRule {
	return FlowerRule{Rep: testRep, Direction: DirIngress, Priority: 1,
		Src: netip.MustParsePrefix("192.168.1.0/24"), Verdict: VerdictAccept} // OffloadHardware (skip_sw)
}

func swRule() FlowerRule {
	r := hwRule()
	r.Offload = OffloadSoftware // skip_hw
	return r
}

// errno wraps a realistic errno the way a netlink driver would (fmt.Errorf with
// %w), so errors.Is in addErrorReason/reconcile still unwraps to the errno.
func errno(op string, e syscall.Errno) error {
	return fmt.Errorf("%s: %w", op, e)
}

// --- 1. skip_sw offload rejection (EOPNOTSUPP on AddFilter) ---

func TestReconcileOffloadRejectionFailsClosedSkipSw(t *testing.T) {
	const rep = "rep-eopnotsupp-hw"
	before := applyErrorCount(t, rep, reasonSkipSw)

	drv := &faultDriver{addErr: errno("add flower filter", syscall.EOPNOTSUPP)}
	err := reconcile(drv, rep, 10, []FlowerRule{hwRule()})
	if err == nil {
		t.Fatal("reconcile must fail closed when a skip_sw filter cannot be offloaded (EOPNOTSUPP)")
	}
	if !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Errorf("surfaced error must wrap EOPNOTSUPP, got %v", err)
	}
	if got := applyErrorCount(t, rep, reasonSkipSw); got != before+1 {
		t.Errorf("skip_sw apply-error counter = %v, want %v (fail-closed offload-rejection signal)", got, before+1)
	}
}

func TestReconcileOffloadRejectionSoftwareFilterIsPlainAdd(t *testing.T) {
	// A software (skip_hw) filter never triggers an offload rejection, so an
	// EOPNOTSUPP installing one is classified as a plain add error, NOT skip_sw.
	const rep = "rep-eopnotsupp-sw"
	beforeAdd := applyErrorCount(t, rep, reasonAdd)
	beforeSkip := applyErrorCount(t, rep, reasonSkipSw)

	drv := &faultDriver{addErr: errno("add flower filter", syscall.EOPNOTSUPP)}
	if err := reconcile(drv, rep, 10, []FlowerRule{swRule()}); err == nil {
		t.Fatal("reconcile must surface the add failure for a software filter too")
	}
	if got := applyErrorCount(t, rep, reasonAdd); got != beforeAdd+1 {
		t.Errorf("add counter = %v, want %v", got, beforeAdd+1)
	}
	if got := applyErrorCount(t, rep, reasonSkipSw); got != beforeSkip {
		t.Errorf("skip_sw counter must NOT move for a software filter, moved to %v", got)
	}
}

// addErrorReason classification is the seam between the errno and the metric
// reason; assert it directly for the full matrix.
func TestAddErrorReasonClassification(t *testing.T) {
	hwObj := hwRule().toObject(1) // carries SkipSw
	swObj := swRule().toObject(1) // carries SkipHw

	tests := []struct {
		name string
		obj  tc.Object
		err  error
		want string
	}{
		{"skip_sw filter + EOPNOTSUPP => skip_sw", hwObj, syscall.EOPNOTSUPP, reasonSkipSw},
		{"skip_sw filter + ENOTSUP => skip_sw", hwObj, syscall.ENOTSUP, reasonSkipSw},
		{"skip_sw filter + wrapped EOPNOTSUPP => skip_sw", hwObj, errno("add", syscall.EOPNOTSUPP), reasonSkipSw},
		{"skip_sw filter + ENOSPC => add (not an offload reject)", hwObj, syscall.ENOSPC, reasonAdd},
		{"skip_sw filter + generic => add", hwObj, errors.New("netlink boom"), reasonAdd},
		{"software filter + EOPNOTSUPP => add", swObj, syscall.EOPNOTSUPP, reasonAdd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addErrorReason(tt.obj, tt.err); got != tt.want {
				t.Errorf("addErrorReason = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- 2. Flow/CT table exhaustion (ENOSPC on AddFilter) ---

func TestReconcileTableExhaustionSurfacedAndCounted(t *testing.T) {
	// ENOSPC models the eSwitch flow table (or, conceptually, the conntrack
	// table whose entries scale ~2x with committed connections) being full: the
	// insertion is refused and reconcile must surface it fail-closed. It is NOT
	// an offload rejection, so it is counted as a plain add error.
	const rep = "rep-enospc"
	before := applyErrorCount(t, rep, reasonAdd)

	drv := &faultDriver{addErr: errno("add flower filter", syscall.ENOSPC)}
	err := reconcile(drv, rep, 10, []FlowerRule{hwRule()})
	if err == nil {
		t.Fatal("reconcile must surface ENOSPC (table exhaustion), not swallow it")
	}
	if !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("surfaced error must wrap ENOSPC, got %v", err)
	}
	if got := applyErrorCount(t, rep, reasonAdd); got != before+1 {
		t.Errorf("add counter = %v, want %v", got, before+1)
	}
}

// --- 3. Representor disappears mid-op ---

func TestReconcileRepresentorGoneOnAddSurfaced(t *testing.T) {
	// A mid-reconcile ENODEV on AddFilter (VF representor removed) must surface,
	// not be silently ignored — the interface would otherwise be left
	// unenforced.
	drv := &faultDriver{addErr: errno("add flower filter", syscall.ENODEV)}
	err := reconcile(drv, "rep-gone", 10, []FlowerRule{hwRule()})
	if err == nil {
		t.Fatal("reconcile must surface an ENODEV AddFilter (representor gone)")
	}
	if !errors.Is(err, syscall.ENODEV) {
		t.Errorf("surfaced error must wrap ENODEV, got %v", err)
	}
}

func TestFlushRepresentorToleratesENODEVOnList(t *testing.T) {
	// ListFilters returning ENODEV (representor/qdisc gone) is treated as
	// already-clean by flushRepresentor — no error, no deletes attempted.
	drv := &faultDriver{listErr: errno("list", syscall.ENODEV)}
	if err := flushRepresentor(drv, 3); err != nil {
		t.Fatalf("flushRepresentor must tolerate ENODEV on ListFilters, got %v", err)
	}
	if drv.delCalls != 0 {
		t.Errorf("no deletes should be attempted when the qdisc is gone, got %d", drv.delCalls)
	}

	// os.ErrNotExist (the other "gone" shape) is equally tolerated.
	drv2 := &faultDriver{listErr: os.ErrNotExist}
	if err := flushRepresentor(drv2, 3); err != nil {
		t.Fatalf("flushRepresentor must tolerate os.ErrNotExist on ListFilters, got %v", err)
	}
}

func TestFlushRepresentorContinuesPastDelFilterENODEV(t *testing.T) {
	// flushRepresentor is BEST-EFFORT: a DelFilter that fails ENODEV mid-flush
	// must not abort the sweep — it attempts every managed filter on both
	// parents and returns the joined error. (Contrast with reconcile, which
	// aborts on the first delete error — see TestReconcileDelFilterAbortsOnFirstError.)
	const ifindex = 7
	managedIngress := hwRule().toObject(ifindex)
	egress := FlowerRule{Rep: testRep, Direction: DirEgress, Priority: 1,
		Dst: netip.MustParsePrefix("10.0.0.0/8"), Verdict: VerdictAccept}.toObject(ifindex)

	drv := &faultDriver{
		installed: []tc.Object{managedIngress, egress},
		delErr:    errno("delete", syscall.ENODEV),
	}
	err := flushRepresentor(drv, ifindex)
	if err == nil {
		t.Fatal("flushRepresentor must return the joined DelFilter errors")
	}
	if !errors.Is(err, syscall.ENODEV) {
		t.Errorf("joined error must wrap ENODEV, got %v", err)
	}
	// Both managed filters (one per parent) were attempted despite the failures.
	if drv.delCalls != 2 {
		t.Errorf("best-effort flush must attempt both managed deletes, got %d calls", drv.delCalls)
	}
}

// --- 4. EnsureClsact failure surfaces through the apply-style loop ---

func TestEnsureClsactFailureSkipsReconcile(t *testing.T) {
	// Mirror Apply's per-representor sequence (ensure-qdisc THEN reconcile): a
	// representor that is not clsact-capable fails EnsureClsact, so reconcile is
	// never attempted and the interface is not silently "enforced". The error is
	// collected.
	drv := &faultDriver{ensureErr: errno("add clsact qdisc", syscall.EOPNOTSUPP)}
	err := applyReconcileLoop(drv, []repWork{{rep: "rep-noclsact", ifindex: 10, desired: []FlowerRule{hwRule()}}})
	if err == nil {
		t.Fatal("EnsureClsact failure must surface through the apply loop")
	}
	if drv.addCalls != 0 {
		t.Errorf("reconcile (AddFilter) must NOT run after EnsureClsact fails, got %d adds", drv.addCalls)
	}
}

// --- 5. Partial failure across interfaces: one rep fails, the other succeeds ---

func TestApplyLoopAggregatesPartialFailure(t *testing.T) {
	// ifindex 10 fails on AddFilter (ENOSPC); ifindex 20 succeeds. The
	// successful representor must still be programmed, and the failing one's
	// error must be aggregated (errors.Join), not lost.
	drv := &faultDriver{
		failAddIf: func(obj tc.Object) error {
			if obj.Ifindex == 10 {
				return errno("add flower filter", syscall.ENOSPC)
			}
			return nil
		},
	}
	err := applyReconcileLoop(drv, []repWork{
		{rep: "rep-fail", ifindex: 10, desired: []FlowerRule{hwRule()}},
		{rep: "rep-ok", ifindex: 20, desired: []FlowerRule{hwRule()}},
	})
	if err == nil {
		t.Fatal("expected an aggregated error for the failing representor")
	}
	if !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("aggregated error must wrap the failing rep's ENOSPC, got %v", err)
	}
	// The healthy representor (ifindex 20) was still programmed.
	okProgrammed := false
	for _, o := range drv.added {
		if o.Ifindex == 20 {
			okProgrammed = true
		}
	}
	if !okProgrammed {
		t.Errorf("the healthy representor (ifindex 20) must still be programmed; added=%+v", drv.added)
	}
}

// --- 6. ListFilters error during the reconcile diff is surfaced ---

func TestReconcileListFiltersErrorSurfaced(t *testing.T) {
	// A ListFilters failure while gathering installed filters must be returned,
	// NOT treated as "no installed filters" (which would silently skip
	// stale-filter deletion and drift the dataplane).
	drv := &faultDriver{listErr: errno("list filters", syscall.EIO)}
	err := reconcile(drv, "rep-listerr", 10, []FlowerRule{hwRule()})
	if err == nil {
		t.Fatal("reconcile must surface a ListFilters error, not treat it as an empty install set")
	}
	if !errors.Is(err, syscall.EIO) {
		t.Errorf("surfaced error must wrap the ListFilters errno, got %v", err)
	}
}

// --- 7. DelFilter failure on a stale filter is surfaced/counted; reconcile
// aborts on the first delete error (matches apply.go) ---

func TestReconcileDelFilterAbortsOnFirstError(t *testing.T) {
	const rep = "rep-delerr"
	before := applyErrorCount(t, rep, reasonDelete)

	// Two stale managed filters, none desired => reconcile must try to delete
	// them. DelFilter fails ENODEV; per apply.go the loop returns on the FIRST
	// delete error, so exactly one delete is attempted and the error/counter is
	// recorded.
	const ifindex = 10
	stale1 := hwRule().toObject(ifindex)
	stale2 := FlowerRule{Rep: testRep, Direction: DirIngress, Priority: 2,
		Src: netip.MustParsePrefix("172.16.0.0/12"), Verdict: VerdictAccept}.toObject(ifindex)

	drv := &faultDriver{
		installed: []tc.Object{stale1, stale2},
		delErr:    errno("delete flower filter", syscall.ENODEV),
	}
	err := reconcile(drv, rep, ifindex, nil) // nothing desired => both are stale
	if err == nil {
		t.Fatal("reconcile must surface a stale-filter DelFilter failure")
	}
	if !errors.Is(err, syscall.ENODEV) {
		t.Errorf("surfaced error must wrap ENODEV, got %v", err)
	}
	if drv.delCalls != 1 {
		t.Errorf("reconcile aborts on the first delete error: want 1 DelFilter call, got %d", drv.delCalls)
	}
	if got := applyErrorCount(t, rep, reasonDelete); got != before+1 {
		t.Errorf("delete counter = %v, want %v", got, before+1)
	}
}

// --- apply-loop helper (mirrors Apply's per-representor ensure→reconcile
// sequence + errors.Join aggregation) so the loop-level behaviors above can be
// exercised cross-driver without NewDriver/netlink. ---

type repWork struct {
	rep     string
	ifindex int
	desired []FlowerRule
}

func applyReconcileLoop(drv Driver, work []repWork) error {
	var errs []error
	for _, w := range work {
		if err := drv.EnsureClsact(w.ifindex); err != nil {
			errs = append(errs, fmt.Errorf("ensure clsact %q: %w", w.rep, err))
			continue
		}
		if err := reconcile(drv, w.rep, w.ifindex, w.desired); err != nil {
			errs = append(errs, fmt.Errorf("reconcile %q: %w", w.rep, err))
			continue
		}
	}
	return errors.Join(errs...)
}
