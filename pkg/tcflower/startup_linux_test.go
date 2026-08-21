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
	"path/filepath"
	"testing"
)

// fakeSysfs builds a minimal sysfs tree under a temp dir for PF discovery tests.
// It returns the hostPrefix to pass to discoverMLX5PFs.
type fakePF struct {
	pci       string
	vendor    string
	device    string
	driver    string // driver dir basename the "driver" symlink points at
	totalVFs  string // "" omits sriov_totalvfs (makes it a non-SR-IOV device)
	numVFs    string
	uplinkNet string // uplink netdev name ("" = none)
	switchID  string // phys_switch_id on the uplink ("" = not switchdev)
	isVF      bool   // create a physfn link (marks device as a VF, not a PF)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func buildFakeSysfs(t *testing.T, pfs []fakePF) string {
	t.Helper()
	root := t.TempDir()
	for _, pf := range pfs {
		dev := filepath.Join(root, "sys", "bus", "pci", "devices", pf.pci)
		writeFile(t, filepath.Join(dev, "vendor"), pf.vendor)
		writeFile(t, filepath.Join(dev, "device"), pf.device)
		if pf.totalVFs != "" {
			writeFile(t, filepath.Join(dev, "sriov_totalvfs"), pf.totalVFs)
		}
		if pf.numVFs != "" {
			writeFile(t, filepath.Join(dev, "sriov_numvfs"), pf.numVFs)
		}
		if pf.driver != "" {
			// driver is a symlink; only its basename matters.
			drvTarget := filepath.Join(root, "sys", "bus", "pci", "drivers", pf.driver)
			if err := os.MkdirAll(drvTarget, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(drvTarget, filepath.Join(dev, "driver")); err != nil {
				t.Fatal(err)
			}
		}
		if pf.isVF {
			// physfn link presence marks this as a VF (should be skipped).
			pfTarget := filepath.Join(root, "sys", "bus", "pci", "devices", "0000:ff:00.0")
			if err := os.MkdirAll(pfTarget, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(pfTarget, filepath.Join(dev, "physfn")); err != nil {
				t.Fatal(err)
			}
		}
		if pf.uplinkNet != "" {
			// The PF's net/ dir lists its netdevs; each also appears under
			// /sys/class/net for the phys_switch_id / phys_port_name reads.
			writeFile(t, filepath.Join(dev, "net", pf.uplinkNet, ".keep"), "")
			netClass := filepath.Join(root, "sys", "class", "net", pf.uplinkNet)
			writeFile(t, filepath.Join(netClass, "phys_switch_id"), pf.switchID)
			// An uplink port has an integer-or-non-vf phys_port_name; "p0" is fine.
			writeFile(t, filepath.Join(netClass, "phys_port_name"), "p0")
		}
	}
	return root
}

func findPF(pfs []pfOffloadInfo, pci string) (pfOffloadInfo, bool) {
	for _, pf := range pfs {
		if pf.PCI == pci {
			return pf, true
		}
	}
	return pfOffloadInfo{}, false
}

func TestDiscoverMLX5PFs(t *testing.T) {
	root := buildFakeSysfs(t, []fakePF{
		{ // a switchdev CX6 Lx PF with VFs
			pci: "0000:03:00.0", vendor: mlxVendorID, device: "0x101f", driver: "mlx5_core",
			totalVFs: "16", numVFs: "8", uplinkNet: "enp3s0f0", switchID: "aabbccddeeff",
		},
		{ // a legacy (non-switchdev) CX5 PF, no switch id
			pci: "0000:04:00.0", vendor: mlxVendorID, device: "0x1017", driver: "mlx5_core",
			totalVFs: "8", numVFs: "0", uplinkNet: "enp4s0f0", switchID: "",
		},
		{ // an Intel NIC (wrong vendor) — must be ignored
			pci: "0000:05:00.0", vendor: "0x8086", device: "0x1572", driver: "i40e",
			totalVFs: "64", numVFs: "4", uplinkNet: "eno1",
		},
		{ // a VF of the CX6 (has physfn) — must be ignored
			pci: "0000:03:00.2", vendor: mlxVendorID, device: "0x101e", driver: "mlx5_core",
			totalVFs: "16", isVF: true,
		},
		{ // a Mellanox device with no SR-IOV capability — must be ignored
			pci: "0000:06:00.0", vendor: mlxVendorID, device: "0x1017", driver: "mlx5_core",
			totalVFs: "",
		},
	})

	pfs := discoverMLX5PFs(root)
	if len(pfs) != 2 {
		t.Fatalf("discoverMLX5PFs found %d PFs, want 2: %+v", len(pfs), pfs)
	}

	cx6, ok := findPF(pfs, "0000:03:00.0")
	if !ok {
		t.Fatal("CX6 Lx PF 0000:03:00.0 not discovered")
	}
	if cx6.Model != "ConnectX-6 Lx" {
		t.Errorf("model = %q, want ConnectX-6 Lx", cx6.Model)
	}
	if cx6.Driver != "mlx5_core" {
		t.Errorf("driver = %q, want mlx5_core", cx6.Driver)
	}
	if !cx6.Switchdev {
		t.Error("expected switchdev=true for a PF with a phys_switch_id")
	}
	if cx6.NumVFs != 8 || cx6.TotalVFs != 16 {
		t.Errorf("vfs = %d/%d, want 8/16", cx6.NumVFs, cx6.TotalVFs)
	}
	if cx6.Uplink != "enp3s0f0" {
		t.Errorf("uplink = %q, want enp3s0f0", cx6.Uplink)
	}

	cx5, ok := findPF(pfs, "0000:04:00.0")
	if !ok {
		t.Fatal("CX5 PF 0000:04:00.0 not discovered")
	}
	if cx5.Model != "ConnectX-5" {
		t.Errorf("model = %q, want ConnectX-5", cx5.Model)
	}
	if cx5.Switchdev {
		t.Error("expected switchdev=false for a PF with no phys_switch_id")
	}
}

func TestDiscoverMLX5PFsEmptyTree(t *testing.T) {
	if pfs := discoverMLX5PFs(t.TempDir()); pfs != nil {
		t.Fatalf("expected no PFs for an empty sysfs tree, got %+v", pfs)
	}
}

// TestLogHostOffloadConfigDoesNotPanic exercises the top-level entrypoint end to
// end against a fake tree (and the no-PF path). It has no assertions beyond "runs
// without panicking / erroring"; the ethtool/devlink calls self-skip when the
// binaries are absent.
func TestLogHostOffloadConfigDoesNotPanic(t *testing.T) {
	root := buildFakeSysfs(t, []fakePF{
		{pci: "0000:03:00.0", vendor: mlxVendorID, device: "0x101d", driver: "mlx5_core",
			totalVFs: "16", numVFs: "4", uplinkNet: "enp3s0f0", switchID: "aabbcc"},
	})
	LogHostOffloadConfig(root, "hardware", "auto")
	LogHostOffloadConfig(root, "software", "off")
	LogHostOffloadConfig(root, "hardware", "require")
	LogHostOffloadConfig(t.TempDir(), "hardware", "auto") // no PFs
	LogHostOffloadConfig(root, "bogus-mode", "bogus-ct")  // invalid modes: warn, continue
}

func TestMLX5ModelKnownIDs(t *testing.T) {
	for id, want := range map[string]string{
		"0x1017": "ConnectX-5",
		"0x101d": "ConnectX-6 Dx",
		"0x101f": "ConnectX-6 Lx",
		"0x1021": "ConnectX-7",
	} {
		if got := mlx5Models[id]; got != want {
			t.Errorf("mlx5Models[%s] = %q, want %q", id, got, want)
		}
	}
}
