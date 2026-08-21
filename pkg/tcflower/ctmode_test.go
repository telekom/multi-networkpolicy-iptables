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

import "testing"

func TestParseCTMode(t *testing.T) {
	tests := []struct {
		in      string
		want    CTMode
		wantErr bool
	}{
		{"", CTModeAuto, false},
		{"auto", CTModeAuto, false},
		{"require", CTModeRequire, false},
		{"off", CTModeOff, false},
		{"AUTO", CTModeAuto, true}, // case-sensitive: not accepted
		{"stateful", CTModeAuto, true},
	}
	for _, tt := range tests {
		got, err := parseCTMode(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseCTMode(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if got != tt.want {
			t.Errorf("parseCTMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCTModeString(t *testing.T) {
	for m, want := range map[CTMode]string{
		CTModeAuto:    "auto",
		CTModeRequire: "require",
		CTModeOff:     "off",
	} {
		if got := m.String(); got != want {
			t.Errorf("CTMode(%d).String() = %q, want %q", m, got, want)
		}
	}
}
