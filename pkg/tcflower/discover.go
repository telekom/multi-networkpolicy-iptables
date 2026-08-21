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

// Package tcflower resolves the host-side enforcement point for a pod's
// SR-IOV virtual function (VF): its VF representor netdev. Once resolved, a
// later phase programs tc flower filters (hardware-offloaded on switchdev
// NICs) on that representor to enforce MultiNetworkPolicy.
//
// The sysfs resolution algorithm mirrors the one implemented by
// github.com/Mellanox/sriovnet (Apache-2.0). We deliberately do NOT depend on
// sriovnet: it hardcodes "/sys" and therefore cannot honor the daemon's
// configurable --host-prefix, nor can it be unit-tested against a fake sysfs
// tree. This implementation reimplements the same algorithm in a prefix-aware,
// testable form using only the standard library.
package tcflower

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

// Sentinel errors returned by ResolveRepresentor / VerifyOffloadReady. Callers
// use errors.Is to distinguish them and fail closed (leaving an SR-IOV
// interface unenforced is a security failure, so these are always propagated).
var (
	// ErrNotVF indicates the given PCI device is not an SR-IOV virtual
	// function (it has no physfn link).
	ErrNotVF = errors.New("pci device is not an SR-IOV virtual function")
	// ErrNotSwitchdev indicates the parent PF is not in switchdev mode, so no
	// VF representors exist to enforce policy on.
	ErrNotSwitchdev = errors.New("pf is not in switchdev mode")
	// ErrNoRepresentor indicates no VF representor netdev could be resolved for
	// the interface.
	ErrNoRepresentor = errors.New("no vf representor found")
)

// RepresentorInfo is the resolved host-side enforcement point for a pod VF.
type RepresentorInfo struct {
	Name    string // host netdev name of the VF representor, e.g. "enp3s0f0_3"
	IfIndex int    // its ifindex (0 if not resolved from a real netlink/sysfs ifindex; see note)
}

// ResolveRepresentor maps a pod's SR-IOV VF (described by iface) to its host
// VF representor netdev. hostPrefix is prepended to every sysfs path.
// Resolution order:
//  1. If iface.RepresentorDevice != "" (CNI already told us), trust it: verify
//     the netdev dir exists at <hostPrefix>/sys/class/net/<rep> and return it.
//  2. Else resolve from iface.PCIAddress via sysfs (see algorithm below).
//
// Returns a typed error (see ErrNoRepresentor / ErrNotSwitchdev) on failure so
// callers can fail closed.
func ResolveRepresentor(hostPrefix string, iface controllers.InterfaceInfo) (RepresentorInfo, error) {
	// 1. Annotation-first: trust the CNI-supplied representor, but verify it
	// actually exists on the host.
	if iface.RepresentorDevice != "" {
		rep := iface.RepresentorDevice
		if !dirExists(netdevDir(hostPrefix, rep)) {
			return RepresentorInfo{}, fmt.Errorf("annotated representor %q: %w", rep, ErrNoRepresentor)
		}
		return RepresentorInfo{Name: rep, IfIndex: readIfIndex(hostPrefix, rep)}, nil
	}

	// 2. Resolve from the VF PCI address via sysfs.
	vfpci := iface.PCIAddress
	if vfpci == "" {
		return RepresentorInfo{}, fmt.Errorf("interface has neither representor device nor PCI address: %w", ErrNoRepresentor)
	}

	// 2a. PF PCI address from the VF's physfn symlink.
	pfpci, err := readLinkBase(pciPhysfn(hostPrefix, vfpci))
	if err != nil {
		return RepresentorInfo{}, fmt.Errorf("reading physfn for VF %q: %w", vfpci, ErrNotVF)
	}

	// 2b. VF index: the virtfnN link under the PF whose target basename == vfpci.
	vfIndex, err := vfIndexForPF(hostPrefix, pfpci, vfpci)
	if err != nil {
		return RepresentorInfo{}, fmt.Errorf("resolving VF index for %q under PF %q: %w", vfpci, pfpci, err)
	}

	// 2c. The PF's uplink switch id (present only in switchdev mode).
	switchID, err := pfSwitchID(hostPrefix, pfpci)
	if err != nil {
		return RepresentorInfo{}, err
	}

	// 2d. Enumerate candidate representors and match by switch id + vf index.
	rep, err := findRepresentor(hostPrefix, switchID, vfIndex)
	if err != nil {
		return RepresentorInfo{}, err
	}

	return RepresentorInfo{Name: rep, IfIndex: readIfIndex(hostPrefix, rep)}, nil
}

// VerifyOffloadReady confirms the representor exists and TC hardware offload is
// usable, returning a typed error otherwise (fail-closed; the caller must not
// silently leave the interface unenforced).
//
// For Phase 1 this only verifies that the representor netdev directory exists
// in sysfs. The actual "hw-tc-offload on" enforcement/verification happens at
// the tc layer in a later phase; we deliberately do not shell out to ethtool
// here so the check stays pure and unit-testable against a fake sysfs tree.
func VerifyOffloadReady(hostPrefix, repName string) error {
	if !dirExists(netdevDir(hostPrefix, repName)) {
		return fmt.Errorf("representor %q not present in sysfs: %w", repName, ErrNoRepresentor)
	}
	return nil
}

// vfIndexForPF returns the VF index N (from virtfnN) whose target device
// basename equals vfpci.
func vfIndexForPF(hostPrefix, pfpci, vfpci string) (int, error) {
	pfDevDir := pciDeviceDir(hostPrefix, pfpci)
	entries, err := os.ReadDir(pfDevDir)
	if err != nil {
		return 0, fmt.Errorf("listing PF device dir %q: %w", pfDevDir, ErrNoRepresentor)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "virtfn") {
			continue
		}
		target, err := readLinkBase(filepath.Join(pfDevDir, name))
		if err != nil {
			continue
		}
		if target != vfpci {
			continue
		}
		idx, err := strconv.Atoi(strings.TrimPrefix(name, "virtfn"))
		if err != nil {
			return 0, fmt.Errorf("parsing VF index from %q: %w", name, ErrNoRepresentor)
		}
		return idx, nil
	}
	return 0, fmt.Errorf("no virtfn link matches VF %q: %w", vfpci, ErrNoRepresentor)
}

// pfSwitchID reads the phys_switch_id of the PF's (single) netdev. An
// empty/absent value means the NIC is not in switchdev mode.
func pfSwitchID(hostPrefix, pfpci string) (string, error) {
	netDir := filepath.Join(pciDeviceDir(hostPrefix, pfpci), "net")
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", fmt.Errorf("listing PF net dir %q: %w", netDir, ErrNotSwitchdev)
	}
	for _, e := range entries {
		pfNet := e.Name()
		id := readTrimmedFile(filepath.Join(netDir, pfNet, "phys_switch_id"))
		if id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("PF %q has no phys_switch_id: %w", pfpci, ErrNotSwitchdev)
}

// findRepresentor scans /sys/class/net for the netdev whose phys_switch_id
// matches the PF's switch id and whose phys_port_name parses to vfIndex. It
// never identifies a representor by parsing the netdev name directly.
func findRepresentor(hostPrefix, switchID string, vfIndex int) (string, error) {
	netRoot := netClassDir(hostPrefix)
	entries, err := os.ReadDir(netRoot)
	if err != nil {
		return "", fmt.Errorf("listing net class dir %q: %w", netRoot, ErrNoRepresentor)
	}
	for _, e := range entries {
		dev := e.Name()
		id := readTrimmedFile(filepath.Join(netRoot, dev, "phys_switch_id"))
		if id == "" || id != switchID {
			continue
		}
		portName := readTrimmedFile(filepath.Join(netRoot, dev, "phys_port_name"))
		idx, ok := parseVFIndexFromPortName(portName)
		if !ok || idx != vfIndex {
			continue
		}
		return dev, nil
	}
	return "", fmt.Errorf("no representor with switch id %q and VF index %d: %w", switchID, vfIndex, ErrNoRepresentor)
}

// parseVFIndexFromPortName extracts N from a VF representor phys_port_name such
// as "pf0vf3", "pf1vf10", or the bare "vf3" form. It returns false when the
// name does not describe a VF representor (e.g. an uplink port or a PF port).
func parseVFIndexFromPortName(portName string) (int, bool) {
	if portName == "" {
		return 0, false
	}
	i := strings.LastIndex(portName, "vf")
	if i < 0 {
		return 0, false
	}
	suffix := portName[i+len("vf"):]
	if suffix == "" {
		return 0, false
	}
	idx, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return idx, true
}

// --- path helpers, all rooted at hostPrefix ---

func pciDeviceDir(hostPrefix, pci string) string {
	return filepath.Join(hostPrefix, "sys", "bus", "pci", "devices", pci)
}

func pciPhysfn(hostPrefix, vfpci string) string {
	return filepath.Join(pciDeviceDir(hostPrefix, vfpci), "physfn")
}

func netClassDir(hostPrefix string) string {
	return filepath.Join(hostPrefix, "sys", "class", "net")
}

func netdevDir(hostPrefix, dev string) string {
	return filepath.Join(netClassDir(hostPrefix), dev)
}

// --- small filesystem helpers ---

// readLinkBase reads a symlink and returns the basename of its target. It works
// with both relative (e.g. "../0000:04:00.0") and absolute link targets, since
// only the final path component is significant for PCI address comparison.
func readLinkBase(link string) (string, error) {
	target, err := os.Readlink(link)
	if err != nil {
		return "", err
	}
	return filepath.Base(target), nil
}

// readTrimmedFile returns the trimmed content of a sysfs file, or "" if it is
// absent or unreadable.
func readTrimmedFile(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // sysfs path under the daemon-controlled host prefix; reading device attrs is the intended behavior
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readIfIndex parses <net>/<dev>/ifindex. A missing or unparseable file yields
// 0 with no error; the tc layer can resolve the ifindex later.
func readIfIndex(hostPrefix, dev string) int {
	s := readTrimmedFile(filepath.Join(netdevDir(hostPrefix, dev), "ifindex"))
	if s == "" {
		return 0
	}
	idx, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return idx
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
