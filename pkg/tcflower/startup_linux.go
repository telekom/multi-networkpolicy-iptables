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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

// mlxVendorID is the PCI vendor id for Mellanox / NVIDIA networking devices.
const mlxVendorID = "0x15b3"

// mlx5Models maps the PCI device id of an mlx5 physical function to a
// human-readable ConnectX model. Source: the kernel mlx5 driver PCI id table
// (drivers/net/ethernet/mellanox/mlx5/core/main.c) cross-referenced with the
// public pci.ids database. VF device ids (e.g. 0x101e) are deliberately absent:
// we only classify PFs. Unknown ids are logged with the raw device id so a new
// card is still reported, just without a friendly name.
var mlx5Models = map[string]string{
	"0x1013": "ConnectX-4",
	"0x1015": "ConnectX-4 Lx",
	"0x1017": "ConnectX-5",
	"0x1019": "ConnectX-5 Ex",
	"0x101b": "ConnectX-6",
	"0x101d": "ConnectX-6 Dx",
	"0x101f": "ConnectX-6 Lx",
	"0x1021": "ConnectX-7",
	"0x1023": "ConnectX-8",
}

// pfOffloadInfo is the sysfs-derived offload-relevant state of one Mellanox /
// NVIDIA SR-IOV physical function. It is populated purely from sysfs (testable
// against a fake tree); the ethtool/devlink fields that need a running host are
// filled in best-effort by LogHostOffloadConfig.
type pfOffloadInfo struct {
	PCI       string // PF PCI address, e.g. "0000:03:00.0"
	DeviceID  string // PCI device id, e.g. "0x101f"
	Model     string // resolved ConnectX model, or "" if unknown
	Driver    string // bound driver, e.g. "mlx5_core"
	Uplink    string // uplink netdev name, or "" if none found
	Switchdev bool   // true when the uplink carries a phys_switch_id
	NumVFs    int    // currently configured VFs (sriov_numvfs)
	TotalVFs  int    // maximum VFs the PF supports (sriov_totalvfs)
}

// LogHostOffloadConfig logs, once at daemon startup, a summary of the host's
// SR-IOV offload configuration and every limit that would prevent the
// tc-flower backend from enforcing policy in hardware. It is best-effort and
// never fails: missing sysfs entries, absent ethtool/devlink, or an
// unprivileged container simply yield less detail.
//
// offloadModeText is the raw --tc-offload-mode value; ctModeText is the raw
// --tc-ct-mode value. Warnings are emitted for the conditions that make a filter
// fail to offload: a PF not in switchdev mode, hw-tc-offload disabled, or (when
// CT is not forced off) a steering mode other than SMFS. When CT mode is "auto"
// a non-SMFS PF is reported as a graceful DEGRADE to stateless (info-level
// "improvement available"), not a hard warning, since enforcement still lands.
func LogHostOffloadConfig(hostPrefix, offloadModeText, ctModeText string) {
	mode, err := parseOffloadMode(offloadModeText)
	if err != nil {
		klog.Warningf("tcflower startup: %v; assuming hardware (skip_sw) mode for this summary", err)
	}
	ctMode, cterr := parseCTMode(ctModeText)
	if cterr != nil {
		klog.Warningf("tcflower startup: %v; assuming auto for this summary", cterr)
	}

	pfs := discoverMLX5PFs(hostPrefix)
	klog.Infof("tcflower startup: SR-IOV tc-flower backend ENABLED (offload-mode=%s, ct-mode=%s); "+
		"found %d Mellanox/NVIDIA SR-IOV PF(s) under %s/sys", mode, ctMode, len(pfs), hostPrefix)

	if len(pfs) == 0 {
		klog.Warningf("tcflower startup: no Mellanox/NVIDIA SR-IOV physical function found in sysfs. " +
			"SR-IOV interfaces cannot be enforced until a switchdev-capable mlx5 NIC is present. " +
			"If this node has no SR-IOV NICs, consider running with --enable-tc-backend=false.")
		return
	}

	hardwareMode := mode == OffloadHardware
	for _, pf := range pfs {
		logPFOffloadConfig(pf, hardwareMode, ctMode)
	}
}

// logPFOffloadConfig emits the INFO summary line for one PF plus any WARNING
// lines for offload-blocking conditions. hardwareMode reports whether filters
// carry skip_sw (so hw-tc-offload being off is fatal rather than merely
// degrading). ctMode tunes the steering-mode message: under CTModeAuto a
// non-SMFS PF is a graceful DEGRADE-to-stateless (info), under CTModeRequire it
// is a hard offload-blocking WARNING, and under CTModeOff steering is irrelevant.
func logPFOffloadConfig(pf pfOffloadInfo, hardwareMode bool, ctMode CTMode) {
	model := pf.Model
	if model == "" {
		model = "unknown mlx5 device " + pf.DeviceID
	}
	klog.Infof("tcflower startup: PF %s [%s, driver=%s] switchdev=%t vfs=%d/%d",
		pf.PCI, model, pf.Driver, pf.Switchdev, pf.NumVFs, pf.TotalVFs)

	if !pf.Switchdev {
		klog.Warningf("tcflower startup: PF %s (%s) is NOT in switchdev mode; its VFs have no representors "+
			"and CANNOT be enforced by the tc-flower backend. Enable with: "+
			"devlink dev eswitch set pci/%s mode switchdev", pf.PCI, model, pf.PCI)
		return
	}

	if pf.NumVFs == 0 {
		klog.Infof("tcflower startup: PF %s is in switchdev mode but has 0 VFs configured (sriov_numvfs=0); "+
			"nothing to enforce yet on this PF", pf.PCI)
	}

	// hw-tc-offload: without it, skip_sw filters are rejected by the kernel
	// (fail-closed) and skip_hw filters silently do not offload.
	if pf.Uplink != "" {
		if on, known := ethtoolHWTCOffload(pf.Uplink); known && !on {
			if hardwareMode {
				klog.Warningf("tcflower startup: hw-tc-offload is OFF on uplink %s (PF %s); in hardware (skip_sw) "+
					"mode every flower filter will be REJECTED at insertion and pods on this PF's VFs left "+
					"UNENFORCED (fail-closed). Enable with: ethtool -K %s hw-tc-offload on",
					pf.Uplink, pf.PCI, pf.Uplink)
			} else {
				klog.Warningf("tcflower startup: hw-tc-offload is OFF on uplink %s (PF %s); in software mode "+
					"filters are enforced in the kernel datapath (no hardware offload). Enable with: "+
					"ethtool -K %s hw-tc-offload on", pf.Uplink, pf.PCI, pf.Uplink)
			}
		}
	}

	// Steering mode + CT capacity (mlx5 devlink). SMFS is required for hardware
	// conntrack offload; DMFS (the default) cannot offload the CT pipeline.
	// Whether a non-SMFS mode is a hard problem or a graceful degrade depends on
	// --tc-ct-mode: 'off' ignores CT entirely, 'auto' degrades to stateless (and
	// still fully enforces stateless allow/deny), 'require' fails closed.
	handle := "pci/" + pf.PCI
	ctRelevant := ctMode != CTModeOff
	steering, steeringKnown := devlinkParamValue(handle, "flow_steering_mode")
	if steeringKnown {
		klog.Infof("tcflower startup: PF %s flow_steering_mode=%s", pf.PCI, steering)
		if ctRelevant && steering != "smfs" {
			switch ctMode {
			case CTModeRequire:
				klog.Warningf("tcflower startup: --tc-ct-mode=require but PF %s steering mode is %q (need smfs); "+
					"the stateful CT filters will be REJECTED at insertion and this PF's VFs left UNENFORCED "+
					"(fail-closed). Switch with: devlink dev param set %s name flow_steering_mode value smfs "+
					"cmode runtime (BEFORE switchdev), or use --tc-ct-mode=auto to degrade to stateless.",
					pf.PCI, steering, handle)
			default: // CTModeAuto
				klog.Infof("tcflower startup: PF %s steering mode is %q (not smfs); conntrack offload is NOT "+
					"available, so --tc-ct-mode=auto DEGRADES this PF to STATELESS enforcement (stateless "+
					"allow/deny is fully enforced; established/related return traffic is not statefully tracked). "+
					"IMPROVEMENT: switch to SMFS (devlink dev param set %s name flow_steering_mode value smfs "+
					"cmode runtime, BEFORE switchdev) to enable stateful CT offload.", pf.PCI, steering, handle)
			}
		}
	} else if ctRelevant {
		klog.Warningf("tcflower startup: could not read flow_steering_mode for PF %s (devlink unavailable or "+
			"unprivileged). Conntrack offload needs SMFS; --tc-ct-mode=auto will DEGRADE to stateless when it "+
			"cannot confirm SMFS. Verify manually with: devlink dev param show %s name flow_steering_mode",
			pf.PCI, handle)
	}

	if ctRelevant {
		if v, known := devlinkParamValue(handle, "ct_max_offloaded_conns"); known {
			klog.Infof("tcflower startup: PF %s ct_max_offloaded_conns=%s (hardware conntrack-offload capacity; "+
				"new connections beyond this are not tracked in hardware)", pf.PCI, v)
		}
	}
}

// discoverMLX5PFs enumerates Mellanox/NVIDIA SR-IOV physical functions from
// sysfs under hostPrefix. A PF is a PCI device with the Mellanox vendor id that
// exposes sriov_totalvfs and is not itself a VF (no physfn link). Results are
// derived purely from sysfs so the function is unit-testable against a fake
// tree.
func discoverMLX5PFs(hostPrefix string) []pfOffloadInfo {
	pciRoot := filepath.Join(hostPrefix, "sys", "bus", "pci", "devices")
	entries, err := os.ReadDir(pciRoot)
	if err != nil {
		return nil
	}

	var pfs []pfOffloadInfo
	for _, e := range entries {
		pci := e.Name()
		dir := pciDeviceDir(hostPrefix, pci)

		if readTrimmedFile(filepath.Join(dir, "vendor")) != mlxVendorID {
			continue
		}
		totalVFs := readTrimmedFile(filepath.Join(dir, "sriov_totalvfs"))
		if totalVFs == "" {
			continue // not an SR-IOV-capable PF
		}
		// A VF has a physfn symlink back to its PF; PFs do not.
		if _, err := os.Lstat(filepath.Join(dir, "physfn")); err == nil {
			continue
		}

		devID := readTrimmedFile(filepath.Join(dir, "device"))
		driver, _ := readLinkBase(filepath.Join(dir, "driver"))
		uplink, switchdev := pfUplinkNetdev(hostPrefix, dir)

		pfs = append(pfs, pfOffloadInfo{
			PCI:       pci,
			DeviceID:  devID,
			Model:     mlx5Models[devID],
			Driver:    driver,
			Uplink:    uplink,
			Switchdev: switchdev,
			NumVFs:    atoiOrZero(readTrimmedFile(filepath.Join(dir, "sriov_numvfs"))),
			TotalVFs:  atoiOrZero(totalVFs),
		})
	}
	return pfs
}

// pfUplinkNetdev returns the PF's uplink netdev name and whether it is in
// switchdev mode (uplink carries a phys_switch_id). Among the PF's netdevs it
// prefers the physical uplink port (a phys_port_name that is not a VF
// representor); switchdev status is reported if any of the PF's netdevs has a
// phys_switch_id.
func pfUplinkNetdev(hostPrefix, pfDir string) (string, bool) {
	netDir := filepath.Join(pfDir, "net")
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", false
	}
	var uplink string
	switchdev := false
	for _, e := range entries {
		dev := e.Name()
		if readTrimmedFile(filepath.Join(netClassDir(hostPrefix), dev, "phys_switch_id")) != "" {
			switchdev = true
		}
		portName := readTrimmedFile(filepath.Join(netClassDir(hostPrefix), dev, "phys_port_name"))
		if _, isVF := parseVFIndexFromPortName(portName); isVF {
			continue // a VF representor, not the uplink
		}
		if uplink == "" {
			uplink = dev
		}
	}
	if uplink == "" && len(entries) > 0 {
		uplink = entries[0].Name() // fall back to any netdev
	}
	return uplink, switchdev
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// ethtoolHWTCOffload reports the hw-tc-offload feature state of a netdev via
// `ethtool -k`. The second return is false when ethtool is unavailable or the
// feature line cannot be parsed (best-effort; never fails).
func ethtoolHWTCOffload(netdev string) (on bool, known bool) {
	bin, err := exec.LookPath("ethtool")
	if err != nil {
		return false, false
	}
	out, err := exec.Command(bin, "-k", netdev).CombinedOutput() //nolint:gosec // netdev is a sysfs-derived interface name, not user input
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "hw-tc-offload:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "hw-tc-offload:"))
		// The value may carry a "[fixed]" suffix; only the first token matters.
		if fields := strings.Fields(val); len(fields) > 0 {
			return fields[0] == "on", true
		}
	}
	return false, false
}

// devlinkParamValue reads a single mlx5 devlink parameter value for a device
// handle (e.g. "pci/0000:03:00.0"). The second return is false when devlink is
// unavailable or the parameter cannot be read/parsed (best-effort).
func devlinkParamValue(handle, name string) (string, bool) {
	bin, err := exec.LookPath("devlink")
	if err != nil {
		return "", false
	}
	out, err := exec.Command(bin, "dev", "param", "show", handle, "name", name).CombinedOutput() //nolint:gosec // handle is a device PCI address, not user input
	if err != nil {
		return "", false
	}
	text := strings.TrimSpace(string(out))
	// Numeric params (e.g. ct_max_offloaded_conns) match the shared value regex;
	// string params (e.g. flow_steering_mode "smfs"/"dmfs") are captured by the
	// "value <token>" form.
	if m := ctMaxConnsRe.FindStringSubmatch(text); m != nil {
		return m[1], true
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "value" {
			return fields[1], true
		}
	}
	return "", false
}
