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
	"testing"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
)

func TestSteeringModeSupportsCTOffload(t *testing.T) {
	// Only SMFS is confirmed to support hardware CT offload. DMFS cannot; HMFS is
	// unconfirmed and treated as non-offloadable in auto mode (fail safe).
	for mode, want := range map[string]bool{
		"smfs": true,
		"dmfs": false,
		"hmfs": false,
		"":     false,
		"SMFS": false, // devlink reports lowercase; anything else is not smfs
	} {
		if got := steeringModeSupportsCTOffload(mode); got != want {
			t.Errorf("steeringModeSupportsCTOffload(%q) = %v, want %v", mode, got, want)
		}
	}
}

// TestResolveCTForRep_NoDevlink verifies the per-representor CT resolution when
// the steering mode cannot be introspected (devlink absent, as in CI). This is
// the "steering unknown" branch: auto degrades to stateless, require forces CT
// on, off stays off, and software offload mode keeps CT on regardless.
//
// The test does not depend on devlink being present: it asserts the mode-driven
// decision that holds when the capability probe returns all-unknown. A pci="" is
// used so probeCTCapability short-circuits without shelling out.
func TestResolveCTForRep_NoDevlink(t *testing.T) {
	tests := []struct {
		name        string
		ctMode      string
		offloadMode string
		wantCT      bool
	}{
		{"auto degrades to stateless when steering unknown", "auto", "hardware", false},
		{"empty ctMode == auto", "", "hardware", false},
		{"require forces CT on even when unconfirmable", "require", "hardware", true},
		{"off is always stateless", "off", "hardware", false},
		{"software offload keeps CT on (kernel datapath)", "auto", "software", true},
		{"off wins over software offload", "off", "software", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := controllers.CommonRuleConfig{CTMode: tt.ctMode, TCOffloadMode: tt.offloadMode}
			// Distinct rep name per case so the once-logging cache does not
			// interfere across subtests, and pci="" to avoid a devlink shell-out.
			got := resolveCTForRep(cfg, "", "rep-"+tt.name, "")
			if got.CTEnabled != tt.wantCT {
				t.Fatalf("resolveCTForRep CTEnabled = %v, want %v", got.CTEnabled, tt.wantCT)
			}
			// The returned cfg must be a copy: the input is never mutated.
			if cfg.CTEnabled {
				t.Fatal("input cfg was mutated (CTEnabled set on the caller's copy)")
			}
		})
	}
}

// TestResolveCTForRep_SMFSEnablesCT drives the decision directly from a cached
// capability so the SMFS "CT stays on" branch is covered without real hardware.
// It seeds ctCapCache for a synthetic PCI so probeCTCapability returns SMFS.
func TestResolveCTForRep_SMFSEnablesCT(t *testing.T) {
	const pci = "0000:de:ad.0"
	ctCapCache.Store(pci, ctCapability{
		SteeringMode: "smfs", SteeringKnown: true, CTOffloadable: true,
		MaxConns: 1000000, MaxConnsKnown: true,
	})
	t.Cleanup(func() { ctCapCache.Delete(pci) })

	cfg := controllers.CommonRuleConfig{CTMode: "auto", TCOffloadMode: "hardware"}
	if got := resolveCTForRep(cfg, "", "rep-smfs", pci); !got.CTEnabled {
		t.Fatal("SMFS + auto should enable CT, got CTEnabled=false")
	}

	// A DMFS cache entry must degrade auto to stateless.
	const pciD = "0000:de:ad.1"
	ctCapCache.Store(pciD, ctCapability{SteeringMode: "dmfs", SteeringKnown: true, CTOffloadable: false})
	t.Cleanup(func() { ctCapCache.Delete(pciD) })
	if got := resolveCTForRep(cfg, "", "rep-dmfs", pciD); got.CTEnabled {
		t.Fatal("DMFS + auto should degrade to stateless, got CTEnabled=true")
	}
}
