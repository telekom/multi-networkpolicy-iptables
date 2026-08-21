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
	"fmt"
	"syscall"
	"testing"

	tc "github.com/florianl/go-tc"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"net/netip"
)

// gaugeVal reads the current value of a GaugeVec cell. prometheus testutil is
// not vendored, so read via the dto directly (GaugeVec.WithLabelValues returns
// a prometheus.Gauge, which implements Write).
func gaugeVal(t *testing.T, gv *prometheus.GaugeVec, lvs ...string) float64 {
	t.Helper()
	var m dto.Metric
	if err := gv.WithLabelValues(lvs...).Write(&m); err != nil {
		t.Fatalf("gauge Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

func counterVal(t *testing.T, cv *prometheus.CounterVec, lvs ...string) float64 {
	t.Helper()
	var m dto.Metric
	if err := cv.WithLabelValues(lvs...).Write(&m); err != nil {
		t.Fatalf("counter Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestResolutionErrorReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"not switchdev", fmt.Errorf("wrap: %w", ErrNotSwitchdev), resolveReasonNotSwitchdev},
		{"not vf", fmt.Errorf("wrap: %w", ErrNotVF), resolveReasonNotVF},
		{"no representor", fmt.Errorf("wrap: %w", ErrNoRepresentor), resolveReasonNotFound},
		{"unknown", errors.New("boom"), resolveReasonNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolutionErrorReason(tt.err); got != tt.want {
				t.Errorf("resolutionErrorReason(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// hwStateDriver returns a fixed set of installed filters per parent so
// publishHWState can be exercised without a kernel.
type hwStateDriver struct {
	fakeDriver
	byParent map[uint32][]tc.Object
}

func (d *hwStateDriver) ListFilters(_ int, parent int) ([]tc.Object, error) {
	return d.byParent[uint32(parent)], nil //nolint:gosec // parent is a tc handle
}

// flowerWithFlags builds a managed (skip_sw) flower object carrying an extra
// offload flag bit (tc.InHw / tc.NotInHw / 0).
func flowerWithFlags(parent, handle, extra uint32) tc.Object {
	flags := tc.SkipSw | extra
	return tc.Object{
		Msg:       tc.Msg{Parent: parent, Handle: handle},
		Attribute: tc.Attribute{Kind: "flower", Flower: &tc.Flower{Flags: &flags}},
	}
}

func TestPublishHWState(t *testing.T) {
	const rep = "test-rep-hwstate"
	ingressParent := DirIngress.parentHandle()
	egressParent := DirEgress.parentHandle()

	drv := &hwStateDriver{byParent: map[uint32][]tc.Object{
		// Ingress: 2 in_hw, 1 not_in_hw.
		ingressParent: {
			flowerWithFlags(ingressParent, 1, tc.InHw),
			flowerWithFlags(ingressParent, 2, tc.InHw),
			flowerWithFlags(ingressParent, 3, tc.NotInHw),
		},
		// Egress: 1 in_hw, plus a foreign (non-managed) filter that must be ignored.
		egressParent: {
			flowerWithFlags(egressParent, 4, tc.InHw),
			{Msg: tc.Msg{Parent: egressParent, Handle: 9}, Attribute: tc.Attribute{Kind: "u32"}},
		},
	}}

	publishHWState(drv, rep, 123)

	if v := gaugeVal(t, filtersInHW, rep, DirIngress.String()); v != 2 {
		t.Errorf("in_hw ingress = %v, want 2", v)
	}
	if v := gaugeVal(t, filtersNotInHW, rep, DirIngress.String()); v != 1 {
		t.Errorf("not_in_hw ingress = %v, want 1", v)
	}
	if v := gaugeVal(t, filtersInHW, rep, DirEgress.String()); v != 1 {
		t.Errorf("in_hw egress = %v, want 1 (foreign u32 filter must be ignored)", v)
	}
	if v := gaugeVal(t, filtersNotInHW, rep, DirEgress.String()); v != 0 {
		t.Errorf("not_in_hw egress = %v, want 0", v)
	}
}

func TestReconcilePublishesFiltersInstalledAndHWState(t *testing.T) {
	const rep = "test-rep-reconcile-metrics"
	ingressParent := DirIngress.parentHandle()

	// A driver that "installs" nothing but reports one in_hw filter on the
	// ingress parent after reconcile, so we can assert both gauges are set.
	drv := &hwStateDriver{byParent: map[uint32][]tc.Object{
		ingressParent: {flowerWithFlags(ingressParent, 7, tc.InHw)},
	}}

	desired := []FlowerRule{
		{Rep: rep, Direction: DirIngress, Priority: 1, Src: netip.MustParsePrefix("10.0.0.0/24"), Verdict: VerdictAccept, Offload: OffloadHardware},
	}
	if err := reconcile(drv, rep, 55, desired); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if v := gaugeVal(t, filtersInstalled, rep, DirIngress.String()); v != 1 {
		t.Errorf("filters_installed ingress = %v, want 1", v)
	}
	if v := gaugeVal(t, filtersInstalled, rep, DirEgress.String()); v != 0 {
		t.Errorf("filters_installed egress = %v, want 0", v)
	}
	if v := gaugeVal(t, filtersInHW, rep, DirIngress.String()); v != 1 {
		t.Errorf("filters_in_hw ingress = %v, want 1", v)
	}
}

func TestApplyErrorReasonClassificationMetric(t *testing.T) {
	// A hardware (skip_sw) filter rejected with EOPNOTSUPP is the offload-reject
	// signal; a software (skip_hw) filter failing is a plain add error.
	skipSwObj := FlowerRule{Rep: "r", Direction: DirIngress, Offload: OffloadHardware, Verdict: VerdictDrop}.toObject(1)
	if got := addErrorReason(skipSwObj, syscall.EOPNOTSUPP); got != reasonSkipSw {
		t.Errorf("hardware filter + EOPNOTSUPP => %q, want %q", got, reasonSkipSw)
	}
	swObj := FlowerRule{Rep: "r", Direction: DirIngress, Offload: OffloadSoftware, Verdict: VerdictDrop}.toObject(1)
	if got := addErrorReason(swObj, syscall.EOPNOTSUPP); got != reasonAdd {
		t.Errorf("software filter + EOPNOTSUPP => %q, want %q", got, reasonAdd)
	}

	// Sanity: the resolution-error counter is a live collector (smoke read).
	_ = counterVal(t, representorResolutionErrors, resolveReasonNotFound)
}
