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
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

// fakeSysfs materializes a fake host sysfs tree under a temp root and returns
// the root (usable as hostPrefix). All the sysfs objects the resolver reads are
// created via its builder methods.
type fakeSysfs struct {
	t    *testing.T
	root string
}

func newFakeSysfs(t *testing.T) *fakeSysfs {
	t.Helper()
	return &fakeSysfs{t: t, root: t.TempDir()}
}

func (f *fakeSysfs) mkdirAll(parts ...string) string {
	f.t.Helper()
	dir := filepath.Join(append([]string{f.root}, parts...)...)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatalf("mkdir %q: %v", dir, err)
	}
	return dir
}

func (f *fakeSysfs) writeFile(content string, parts ...string) {
	f.t.Helper()
	path := filepath.Join(append([]string{f.root}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatalf("mkdir for %q: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatalf("write %q: %v", path, err)
	}
}

// pciDevice ensures the PCI device dir exists.
func (f *fakeSysfs) pciDevice(pci string) {
	f.t.Helper()
	f.mkdirAll("sys", "bus", "pci", "devices", pci)
}

// vf wires up a VF: creates its device dir, the physfn link back to the PF, and
// the PF's virtfnN link back to the VF. Uses relative symlink targets so
// basename resolution matches the real kernel layout.
func (f *fakeSysfs) vf(vfpci, pfpci string, vfIndex int) {
	f.t.Helper()
	f.pciDevice(vfpci)
	f.pciDevice(pfpci)
	devices := filepath.Join(f.root, "sys", "bus", "pci", "devices")

	physfn := filepath.Join(devices, vfpci, "physfn")
	if err := os.Symlink(filepath.Join("..", pfpci), physfn); err != nil {
		f.t.Fatalf("symlink physfn: %v", err)
	}
	virtfn := filepath.Join(devices, pfpci, "virtfn"+strconv.Itoa(vfIndex))
	if err := os.Symlink(filepath.Join("..", vfpci), virtfn); err != nil {
		f.t.Fatalf("symlink virtfn: %v", err)
	}
}

// pfNet attaches a netdev with a phys_switch_id under the PF's net/ dir.
func (f *fakeSysfs) pfNet(pfpci, pfNetdev, switchID string) {
	f.t.Helper()
	f.writeFile(switchID, "sys", "bus", "pci", "devices", pfpci, "net", pfNetdev, "phys_switch_id")
}

// netdev creates a /sys/class/net entry with the given attributes. Empty
// strings for switchID/portName/ifindex skip that file.
func (f *fakeSysfs) netdev(dev, switchID, portName, ifindex string) {
	f.t.Helper()
	f.mkdirAll("sys", "class", "net", dev)
	if switchID != "" {
		f.writeFile(switchID, "sys", "class", "net", dev, "phys_switch_id")
	}
	if portName != "" {
		f.writeFile(portName, "sys", "class", "net", dev, "phys_port_name")
	}
	if ifindex != "" {
		f.writeFile(ifindex, "sys", "class", "net", dev, "ifindex")
	}
}

func TestResolveRepresentor(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(f *fakeSysfs)
		iface       controllers.InterfaceInfo
		wantName    string
		wantIfIndex int
		wantErr     error // sentinel expected via errors.Is; nil means success
	}{
		{
			name: "annotation-first: rep dir exists",
			setup: func(f *fakeSysfs) {
				f.netdev("enp3s0f0_3", "aabbccddeeff", "pf0vf3", "42")
			},
			iface:       controllers.InterfaceInfo{RepresentorDevice: "enp3s0f0_3"},
			wantName:    "enp3s0f0_3",
			wantIfIndex: 42,
		},
		{
			name:    "annotation set but dir absent",
			setup:   func(f *fakeSysfs) {},
			iface:   controllers.InterfaceInfo{RepresentorDevice: "missing0"},
			wantErr: ErrNoRepresentor,
		},
		{
			name: "full sysfs walk resolves via switch_id + pf0vf3",
			setup: func(f *fakeSysfs) {
				f.vf("0000:04:00.2", "0000:04:00.0", 1)
				f.pfNet("0000:04:00.0", "enp4s0f0", "112233445566")
				f.netdev("enp4s0f0_1", "112233445566", "pf0vf1", "77")
			},
			iface:       controllers.InterfaceInfo{PCIAddress: "0000:04:00.2"},
			wantName:    "enp4s0f0_1",
			wantIfIndex: 77,
		},
		{
			name: "multiple reps: only matching switch_id AND vf index selected",
			setup: func(f *fakeSysfs) {
				f.vf("0000:04:00.4", "0000:04:00.0", 3)
				f.pfNet("0000:04:00.0", "enp4s0f0", "cafebabe0001")
				// decoy: same switch id, different vf index
				f.netdev("enp4s0f0_9", "cafebabe0001", "pf0vf9", "91")
				// decoy: different switch id, same vf index
				f.netdev("enp9s0f0_3", "deadbeef0002", "pf0vf3", "93")
				// the real target
				f.netdev("enp4s0f0_3", "cafebabe0001", "pf0vf3", "95")
			},
			iface:       controllers.InterfaceInfo{PCIAddress: "0000:04:00.4"},
			wantName:    "enp4s0f0_3",
			wantIfIndex: 95,
		},
		{
			name: "physfn missing -> ErrNotVF",
			setup: func(f *fakeSysfs) {
				f.pciDevice("0000:04:00.2")
			},
			iface:   controllers.InterfaceInfo{PCIAddress: "0000:04:00.2"},
			wantErr: ErrNotVF,
		},
		{
			name: "PF netdev phys_switch_id empty -> ErrNotSwitchdev",
			setup: func(f *fakeSysfs) {
				f.vf("0000:04:00.2", "0000:04:00.0", 1)
				f.pfNet("0000:04:00.0", "enp4s0f0", "") // empty switch id
			},
			iface:   controllers.InterfaceInfo{PCIAddress: "0000:04:00.2"},
			wantErr: ErrNotSwitchdev,
		},
		{
			name: "no matching representor -> ErrNoRepresentor",
			setup: func(f *fakeSysfs) {
				f.vf("0000:04:00.2", "0000:04:00.0", 1)
				f.pfNet("0000:04:00.0", "enp4s0f0", "112233445566")
				// only a rep with a non-matching vf index
				f.netdev("enp4s0f0_5", "112233445566", "pf0vf5", "50")
			},
			iface:   controllers.InterfaceInfo{PCIAddress: "0000:04:00.2"},
			wantErr: ErrNoRepresentor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeSysfs(t)
			tt.setup(f)

			got, err := ResolveRepresentor(f.root, tt.iface)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.IfIndex != tt.wantIfIndex {
				t.Errorf("IfIndex = %d, want %d", got.IfIndex, tt.wantIfIndex)
			}
		})
	}
}

func TestResolveRepresentorIfIndexAbsent(t *testing.T) {
	f := newFakeSysfs(t)
	// rep exists but has no ifindex file -> IfIndex 0, no error.
	f.netdev("rep0", "aabbcc", "pf0vf0", "")

	got, err := ResolveRepresentor(f.root, controllers.InterfaceInfo{RepresentorDevice: "rep0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IfIndex != 0 {
		t.Errorf("IfIndex = %d, want 0", got.IfIndex)
	}
}

func TestVerifyOffloadReady(t *testing.T) {
	f := newFakeSysfs(t)
	f.netdev("present0", "aabbcc", "pf0vf0", "10")

	if err := VerifyOffloadReady(f.root, "present0"); err != nil {
		t.Errorf("VerifyOffloadReady(present0) = %v, want nil", err)
	}

	err := VerifyOffloadReady(f.root, "absent0")
	if !errors.Is(err, ErrNoRepresentor) {
		t.Errorf("VerifyOffloadReady(absent0) = %v, want ErrNoRepresentor", err)
	}
}

func TestParseVFIndexFromPortName(t *testing.T) {
	tests := []struct {
		portName string
		wantIdx  int
		wantOK   bool
	}{
		{"pf0vf3", 3, true},
		{"pf1vf10", 10, true},
		{"vf7", 7, true},
		{"pf0", 0, false},
		{"", 0, false},
		{"p0", 0, false},
		{"vf", 0, false},
	}
	for _, tt := range tests {
		idx, ok := parseVFIndexFromPortName(tt.portName)
		if ok != tt.wantOK || (ok && idx != tt.wantIdx) {
			t.Errorf("parseVFIndexFromPortName(%q) = (%d, %v), want (%d, %v)", tt.portName, idx, ok, tt.wantIdx, tt.wantOK)
		}
	}
}
