//go:build !linux

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
	"fmt"
	"runtime"

	tc "github.com/florianl/go-tc"
)

// Driver abstracts the tc/netlink operations the reconcile loop needs.
//
// The real implementation is Linux-only (go-tc's netlink socket requires
// NETLINK_ROUTE). On other platforms only the stub below exists so the package
// still compiles for cross-platform tooling and the cross-platform unit tests.
type Driver interface {
	EnsureClsact(ifindex int) error
	ListFilters(ifindex, parent int) ([]tc.Object, error)
	AddFilter(obj tc.Object) error
	DelFilter(obj tc.Object) error
	Close() error
}

// NewDriver is unsupported on non-Linux platforms.
func NewDriver() (Driver, error) {
	return nil, fmt.Errorf("tc flower driver is unsupported on GOOS=%s", runtime.GOOS)
}
