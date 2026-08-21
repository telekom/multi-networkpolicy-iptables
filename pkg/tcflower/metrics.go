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

// Observability for the SR-IOV tc-flower backend.
//
// These metrics are pure Go (no netlink), so this file carries NO build tag and
// compiles on both linux and darwin. The linux apply.go calls the small helpers
// below; the non-linux stub never does, but the symbols still exist so the
// package builds identically everywhere.
//
// Metrics are registered into controller-runtime's Prometheus registry
// (sigs.k8s.io/controller-runtime/pkg/metrics.Registry), which the manager
// already exposes on its /metrics endpoint, so no separate HTTP server is
// needed. Registration is guarded by a sync.Once so importing the package more
// than once (e.g. across test binaries) cannot panic on duplicate collectors.

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Apply-error reasons for multinetworkpolicy_tc_filter_apply_errors_total. This
// counter is the key FAIL-CLOSED signal: any increment means a flower filter
// that should be enforcing policy on a VF representor could not be installed or
// removed, so the eSwitch dataplane no longer matches desired state.
const (
	// reasonAdd: AddFilter (tc filter replace) failed for a non-offload reason.
	reasonAdd = "add"
	// reasonDelete: DelFilter failed removing a stale managed filter.
	reasonDelete = "delete"
	// reasonSkipSw: AddFilter was rejected because the NIC could not offload the
	// skip_sw (hardware-only) filter. This is the security-critical case — the
	// filter carries SkipSw, so the kernel refuses software fallback and the rule
	// is simply not enforced.
	reasonSkipSw = "skip_sw"
)

// Representor-resolution failure reasons for
// multinetworkpolicy_tc_representor_resolution_errors_total.
const (
	// resolveReasonNotFound: no VF representor could be resolved for the interface
	// (annotation absent/stale and sysfs walk found nothing).
	resolveReasonNotFound = "not_found"
	// resolveReasonNotSwitchdev: the parent PF is not in switchdev mode, so no
	// representors exist.
	resolveReasonNotSwitchdev = "not_switchdev"
	// resolveReasonNotVF: the PCI device is not an SR-IOV virtual function.
	resolveReasonNotVF = "not_vf"
	// resolveReasonNoIfindex: the representor resolved but has no usable ifindex.
	resolveReasonNoIfindex = "no_ifindex"
	// resolveReasonOffloadNotReady: the representor exists but TC hardware offload
	// is not enabled on it (VerifyOffloadReady failed).
	resolveReasonOffloadNotReady = "offload_not_ready"
)

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

var (
	// filtersInstalled tracks the number of managed flower filters desired (and,
	// on success, installed) per representor and direction. Set from the desired
	// rule count in Apply after a successful reconcile; drops to 0 for a
	// direction when all its policies are removed.
	filtersInstalled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "multinetworkpolicy_tc_filters_installed",
		Help: "Number of managed tc flower filters desired/installed on a VF representor per direction.",
	}, []string{"representor", "direction"})

	// filtersInHW / filtersNotInHW report the HARDWARE-OFFLOAD state read back from
	// the kernel per representor+direction: how many managed filters the driver
	// actually programmed into the eSwitch (in_hw) vs. how many are present but NOT
	// offloaded (not_in_hw). For a healthy CX5+ switchdev NIC every skip_sw filter
	// should be in_hw; a non-zero not_in_hw is a hardware-offload problem even
	// though the filter installed without error.
	filtersInHW = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "multinetworkpolicy_tc_filters_in_hw",
		Help: "Number of managed tc flower filters confirmed offloaded to hardware (in_hw) on a VF representor per direction.",
	}, []string{"representor", "direction"})
	filtersNotInHW = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "multinetworkpolicy_tc_filters_not_in_hw",
		Help: "Number of managed tc flower filters present but NOT offloaded to hardware (not_in_hw) on a VF representor per direction. Non-zero indicates a hardware-offload problem.",
	}, []string{"representor", "direction"})

	// filterApplyErrors counts filter install/remove failures by representor and
	// reason. reason=skip_sw is the fail-closed offload-rejection signal.
	filterApplyErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "multinetworkpolicy_tc_filter_apply_errors_total",
		Help: "Total tc flower filter apply failures, labeled by representor and reason (add|delete|skip_sw). Any increase means a VF representor is not enforcing desired policy (fail-closed).",
	}, []string{"representor", "reason"})

	// representorResolutionErrors counts failures to map a pod's SR-IOV VF to its
	// host representor (or to confirm offload readiness), labeled by reason. Each
	// increment is an SR-IOV interface left unenforced (fail-closed).
	representorResolutionErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "multinetworkpolicy_tc_representor_resolution_errors_total",
		Help: "Total failures resolving a pod VF to its host representor / confirming offload readiness, by reason (not_found|not_switchdev|not_vf|no_ifindex|offload_not_ready).",
	}, []string{"reason"})

	// offloadReady is 1 when a representor is present and TC hardware offload is
	// enabled on it, 0 otherwise. It reflects the last VerifyOffloadReady result.
	offloadReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "multinetworkpolicy_tc_offload_ready",
		Help: "1 if a VF representor is present and TC hardware offload (hw-tc-offload) is enabled, 0 otherwise.",
	}, []string{"representor"})

	// ctOffloadReady is 1 when the representor's eSwitch is in SMFS steering mode
	// (required for conntrack offload), 0 when it is not, and unset when it cannot
	// be introspected (no devlink). Set by probeCTCapability.
	ctOffloadReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "multinetworkpolicy_tc_ct_offload_ready",
		Help: "1 if the VF representor's eSwitch uses SMFS steering (conntrack-offload capable), 0 if not. Unset when devlink cannot introspect it.",
	}, []string{"representor"})

	// ctMaxOffloadedConns exposes the mlx5 devlink ct_max_offloaded_conns capacity
	// (the hardware conntrack table limit) per representor, when resolvable. This
	// is the hardware CT-offload ceiling operators alert against (ENOSPC on
	// insertion once exceeded). The live offloaded-connection count is not exposed:
	// it is not a devlink param and has no cheap, reliable source, so publishing an
	// always-unset gauge would be misleading.
	ctMaxOffloadedConns = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "multinetworkpolicy_tc_ct_max_offloaded_conns",
		Help: "Hardware conntrack-offload capacity (mlx5 devlink ct_max_offloaded_conns) per VF representor, when resolvable via devlink.",
	}, []string{"representor"})

	// reconcileDuration observes how long enforcing one representor's filters
	// takes inside Apply (build + ensure-qdisc + reconcile), labeled by
	// representor.
	reconcileDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "multinetworkpolicy_tc_reconcile_duration_seconds",
		Help:    "Duration of enforcing tc flower filters on a single VF representor within Apply.",
		Buckets: prometheus.DefBuckets,
	}, []string{"representor"})

	registerMetricsOnce sync.Once
)

// registerMetrics registers the backend's collectors into controller-runtime's
// Prometheus registry exactly once. Safe to call repeatedly.
func registerMetrics() {
	registerMetricsOnce.Do(func() {
		ctrlmetrics.Registry.MustRegister(
			filtersInstalled,
			filtersInHW,
			filtersNotInHW,
			filterApplyErrors,
			representorResolutionErrors,
			offloadReady,
			ctOffloadReady,
			ctMaxOffloadedConns,
			reconcileDuration,
		)
	})
}

func init() { registerMetrics() }

// setFiltersInstalled records the desired/installed filter count for a
// representor+direction.
func setFiltersInstalled(rep, direction string, n int) {
	filtersInstalled.WithLabelValues(rep, direction).Set(float64(n))
}

// setFiltersHWState records the read-back hardware-offload state
// (in_hw / not_in_hw counts) for a representor+direction.
func setFiltersHWState(rep, direction string, inHW, notInHW int) {
	filtersInHW.WithLabelValues(rep, direction).Set(float64(inHW))
	filtersNotInHW.WithLabelValues(rep, direction).Set(float64(notInHW))
}

// incFilterApplyError bumps the fail-closed apply-error counter.
func incFilterApplyError(rep, reason string) {
	filterApplyErrors.WithLabelValues(rep, reason).Inc()
}

// incRepresentorResolutionError bumps the discovery/offload-readiness failure
// counter (each increment = an SR-IOV interface left unenforced).
func incRepresentorResolutionError(reason string) {
	representorResolutionErrors.WithLabelValues(reason).Inc()
}

// setOffloadReady records whether a representor is present + offload-ready.
func setOffloadReady(rep string, ready bool) {
	offloadReady.WithLabelValues(rep).Set(boolToFloat(ready))
}

// setCTOffloadReady records whether the representor's eSwitch is SMFS (CT-offload
// capable).
func setCTOffloadReady(rep string, ready bool) {
	ctOffloadReady.WithLabelValues(rep).Set(boolToFloat(ready))
}

// setCTMaxOffloadedConns records the hardware conntrack-offload capacity.
func setCTMaxOffloadedConns(rep string, n int) {
	ctMaxOffloadedConns.WithLabelValues(rep).Set(float64(n))
}

// observeReconcileDuration records the time spent enforcing one representor.
func observeReconcileDuration(rep string, since time.Time) {
	reconcileDuration.WithLabelValues(rep).Observe(time.Since(since).Seconds())
}
