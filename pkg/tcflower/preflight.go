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
	"regexp"
	"strconv"
	"sync"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"k8s.io/klog/v2"
)

// ctMaxConnsRe extracts the integer value from a devlink param show line such as
//
//	pci/0000:03:00.0: name ct_max_offloaded_conns type driver-specific
//	  values:
//	    cmode runtime value 1048576
var ctMaxConnsRe = regexp.MustCompile(`value\s+(\d+)`)

// ctCapability is the introspected hardware conntrack-offload capability of a
// representor's parent eSwitch. It is derived best-effort via devlink; fields
// carry a "known" companion because devlink may be unavailable (unprivileged
// container, no binary) in which case we degrade gracefully rather than guess.
type ctCapability struct {
	// SteeringMode is the mlx5 flow_steering_mode ("smfs"/"dmfs"/"hmfs"), or ""
	// when it could not be read.
	SteeringMode string
	// SteeringKnown is true when SteeringMode was read successfully.
	SteeringKnown bool
	// CTOffloadable reports whether the steering mode can hardware-offload the
	// conntrack pipeline. Only SMFS is confirmed to support CT offload; see
	// steeringModeSupportsCTOffload.
	CTOffloadable bool
	// MaxConns is the mlx5 ct_max_offloaded_conns capacity, valid only when
	// MaxConnsKnown is true.
	MaxConns      int
	MaxConnsKnown bool
}

// ctCapCache memoizes probeCTCapability by PCI address. The eSwitch steering
// mode is set once at provisioning and effectively static for the daemon's
// lifetime, so caching avoids shelling out to devlink on every reconcile. An
// operator who changes steering mode restarts the daemon (it is a node-level
// provisioning change), which clears the cache.
var ctCapCache sync.Map // pciAddress(string) -> ctCapability

// steeringModeSupportsCTOffload reports whether an mlx5 flow_steering_mode can
// hardware-offload the conntrack pipeline.
//
// Only SMFS is CONFIRMED (upstream/NVIDIA docs) to support CT offload. DMFS (the
// default) cannot. HMFS (hardware-managed steering, CX6 Dx+) is newer and its CT
// offload support is UNCONFIRMED from primary sources, so auto mode treats it as
// non-offloadable (fall back to stateless) rather than optimistically emitting
// skip_sw CT filters that might be rejected and leave the interface unenforced.
// --tc-ct-mode=require can force an attempt on HMFS.
func steeringModeSupportsCTOffload(mode string) bool {
	return mode == "smfs"
}

// probeCTCapability introspects (and caches, keyed by PCI) the representor's
// hardware conntrack-offload capability via devlink, publishing the CT metrics
// as a side effect. It never fails: missing devlink / PCI simply yields an
// all-unknown capability, which callers treat as "cannot confirm CT offload".
func probeCTCapability(hostPrefix, repName, pci string) ctCapability {
	if pci != "" {
		if v, ok := ctCapCache.Load(pci); ok {
			cap := v.(ctCapability) //nolint:errcheck // only ctCapability is ever stored
			publishCTMetrics(repName, cap)
			return cap
		}
	}
	cap := probeCTCapabilityUncached(hostPrefix, repName, pci)
	if pci != "" {
		ctCapCache.Store(pci, cap)
	}
	return cap
}

func probeCTCapabilityUncached(hostPrefix, repName, pci string) ctCapability {
	klog.V(4).Infof("tcflower CT probe: representor=%q pci=%q hostPrefix=%q", repName, pci, hostPrefix)

	var cap ctCapability
	if pci == "" {
		klog.Warningf("tcflower CT probe: no PCI address for representor %q; cannot introspect steering mode", repName)
		publishCTMetrics(repName, cap)
		return cap
	}
	handle := "pci/" + pci

	if mode, ok := devlinkParamValue(handle, "flow_steering_mode"); ok {
		cap.SteeringMode = mode
		cap.SteeringKnown = true
		cap.CTOffloadable = steeringModeSupportsCTOffload(mode)
	} else {
		klog.Warningf("tcflower CT probe: could not read flow_steering_mode for %q (devlink unavailable or "+
			"unprivileged). CT hardware offload needs SMFS; verify with: devlink dev param show %s "+
			"name flow_steering_mode", handle, handle)
	}

	if v, ok := devlinkParamValue(handle, "ct_max_offloaded_conns"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			cap.MaxConns = n
			cap.MaxConnsKnown = true
		}
	}

	publishCTMetrics(repName, cap)
	return cap
}

// resolveCTForRep decides, per representor, whether the stateful conntrack (CT)
// pipeline should be emitted, honoring --tc-ct-mode and the hardware's actual
// CT-offload capability. It returns a COPY of cfg with CTEnabled set
// accordingly, and logs — at most once per representor — what is enforced and
// what stateful capability (and thus which config change) would improve it.
//
// Behavior by mode:
//   - CTModeOff:     never CT. Stateless pipeline. (Logged once as info.)
//   - CTModeRequire: always CT, even on DMFS. If the NIC cannot offload it the
//     skip_sw filters are rejected at insertion (fail-closed) — the operator
//     asked for stateful-or-nothing.
//   - CTModeAuto:    CT only when hardware CT offload is confirmed (SMFS). On
//     DMFS / HMFS / unknown, DEGRADE to the stateless pipeline and WARN with the
//     exact remediation (switch to SMFS), so the maximum offloadable subset is
//     still enforced instead of the interface going dark.
//
// Software offload mode (--tc-offload-mode=software) enforces in the kernel
// datapath where CT always works, so CT is kept on there regardless of steering.
func resolveCTForRep(cfg controllers.CommonRuleConfig, hostPrefix, repName, pci string) controllers.CommonRuleConfig {
	out := cfg
	ctMode, err := parseCTMode(cfg.CTMode)
	if err != nil {
		// Fail closed on an invalid mode string by treating it as auto; the flag
		// layer validates, so this is defense in depth.
		klog.Warningf("tcflower: %v; treating as auto for representor %q", err, repName)
		ctMode = CTModeAuto
	}

	if ctMode == CTModeOff {
		out.CTEnabled = false
		logCTDecisionOnce(repName, "stateless (CT disabled by --tc-ct-mode=off)", "")
		return out
	}

	// In software enforcement mode the kernel datapath handles conntrack, so CT
	// does not depend on the eSwitch steering mode. Still probe for metrics.
	offMode, _ := parseOffloadMode(cfg.TCOffloadMode)
	if offMode == OffloadSoftware {
		probeCTCapability(hostPrefix, repName, pci)
		out.CTEnabled = true
		return out
	}

	cap := probeCTCapability(hostPrefix, repName, pci)

	switch ctMode {
	case CTModeRequire:
		out.CTEnabled = true
		if cap.SteeringKnown && !cap.CTOffloadable {
			klog.Warningf("tcflower: --tc-ct-mode=require on representor %q but steering mode %q cannot hardware-offload "+
				"conntrack (needs smfs); the stateful CT filters will be REJECTED at insertion and this interface "+
				"left UNENFORCED (fail-closed). Switch to SMFS (before switchdev) or use --tc-ct-mode=auto to degrade "+
				"to stateless enforcement.", repName, cap.SteeringMode)
		}
		return out

	default: // CTModeAuto
		switch {
		case cap.CTOffloadable:
			out.CTEnabled = true
			logCTDecisionOnce(repName, "stateful (CT offload, SMFS)", "")
		case cap.SteeringKnown:
			// DMFS / HMFS / other: CT won't offload — degrade to stateless.
			out.CTEnabled = false
			logCTDecisionOnce(repName, "stateless (STATEFUL DEGRADED)",
				"steering mode "+cap.SteeringMode+" cannot hardware-offload conntrack; established/related "+
					"return traffic is NOT statefully tracked. To enable stateful CT offload, set the eSwitch to "+
					"SMFS (devlink dev param set pci/<pf> name flow_steering_mode value smfs cmode runtime) BEFORE "+
					"switching to switchdev mode. Stateless allow/deny (5-tuple, CIDR, ports) is fully enforced.")
		default:
			// Steering mode unknown (no devlink): cannot confirm offload, so
			// degrade rather than risk rejected filters + an unenforced interface.
			out.CTEnabled = false
			logCTDecisionOnce(repName, "stateless (STATEFUL DEGRADED, steering unknown)",
				"could not read the eSwitch steering mode (devlink unavailable/unprivileged), so hardware CT "+
					"offload cannot be confirmed; defaulting to stateless enforcement. Grant devlink access or "+
					"set --tc-ct-mode=require to force the CT pipeline.")
		}
		return out
	}
}

// ctDecisionLogged dedupes the per-representor CT-decision log so a busy
// reconcile loop does not spam identical lines. Keyed by representor+summary so
// a genuine change (e.g. operator switches to SMFS and restarts) is re-logged.
var ctDecisionLogged sync.Map // string(rep+"\x00"+summary) -> struct{}

// logCTDecisionOnce logs the resolved enforcement level for a representor once.
// summary is the always-logged headline; improvement (when non-empty) is the
// remediation guidance logged at Warning level.
func logCTDecisionOnce(repName, summary, improvement string) {
	key := repName + "\x00" + summary
	if _, loaded := ctDecisionLogged.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	if improvement == "" {
		klog.Infof("tcflower: representor %q enforcing %s", repName, summary)
		return
	}
	klog.Warningf("tcflower: representor %q enforcing %s. %s", repName, summary, improvement)
}

// publishCTMetrics reflects a capability into the CT gauges.
func publishCTMetrics(repName string, cap ctCapability) {
	if cap.SteeringKnown {
		setCTOffloadReady(repName, cap.CTOffloadable)
	}
	if cap.MaxConnsKnown {
		setCTMaxOffloadedConns(repName, cap.MaxConns)
	}
}
