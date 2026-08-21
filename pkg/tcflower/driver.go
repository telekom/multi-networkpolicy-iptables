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
	"os"

	tc "github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
)

// Driver abstracts the tc/netlink operations the reconcile loop needs. It is an
// interface so Apply can be unit-tested with a fake and so a future backend
// (e.g. a shelling-out driver) can be dropped in.
type Driver interface {
	// EnsureClsact makes sure a clsact qdisc exists on the interface so that
	// both the ingress and egress filter parents are available.
	EnsureClsact(ifindex int) error
	// ListFilters returns the installed filters on (ifindex, parent).
	ListFilters(ifindex, parent int) ([]tc.Object, error)
	// AddFilter installs a filter. It fails (fail-closed) if the object cannot
	// be offloaded to hardware, because every managed filter carries SkipSw.
	AddFilter(obj tc.Object) error
	// DelFilter removes a filter.
	DelFilter(obj tc.Object) error
	// Close releases the netlink socket.
	Close() error
}

// netlinkDriver implements Driver over github.com/florianl/go-tc.
type netlinkDriver struct {
	rtnl *tc.Tc
}

var _ Driver = (*netlinkDriver)(nil)

// NewDriver opens an rtnetlink socket for traffic control.
func NewDriver() (Driver, error) {
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, fmt.Errorf("open rtnetlink socket: %w", err)
	}
	return &netlinkDriver{rtnl: rtnl}, nil
}

// EnsureClsact installs a clsact qdisc on the interface (idempotent: an
// already-present qdisc is treated as success).
func (d *netlinkDriver) EnsureClsact(ifindex int) error {
	qdisc := tc.Object{
		Msg: tc.Msg{
			Ifindex: uint32(ifindex), //nolint:gosec // ifindex is a small positive netdev index
			Handle:  core.BuildHandle(0xffff, 0),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{Kind: "clsact"},
	}
	if err := d.rtnl.Qdisc().Add(&qdisc); err != nil {
		// An already-present clsact qdisc surfaces as EEXIST; treat as success.
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("add clsact qdisc on ifindex %d: %w", ifindex, err)
	}
	return nil
}

// ListFilters dumps filters attached to (ifindex, parent).
func (d *netlinkDriver) ListFilters(ifindex, parent int) ([]tc.Object, error) {
	msg := tc.Msg{
		Ifindex: uint32(ifindex), //nolint:gosec // ifindex is a small positive netdev index
		Parent:  uint32(parent),  //nolint:gosec // parent is a tc handle
	}
	objs, err := d.rtnl.Filter().Get(&msg)
	if err != nil {
		return nil, fmt.Errorf("list filters on ifindex %d parent %#x: %w", ifindex, parent, err)
	}
	return objs, nil
}

// AddFilter installs (replaces) a filter. Replace is used so a re-applied,
// unchanged filter is a no-op instead of an EEXIST error.
func (d *netlinkDriver) AddFilter(obj tc.Object) error {
	if err := d.rtnl.Filter().Replace(&obj); err != nil {
		return fmt.Errorf("add flower filter (handle %#x parent %#x prio %d): %w",
			obj.Handle, obj.Parent, filterPriority(obj.Info), err)
	}
	return nil
}

// DelFilter removes a filter.
func (d *netlinkDriver) DelFilter(obj tc.Object) error {
	if err := d.rtnl.Filter().Delete(&obj); err != nil {
		return fmt.Errorf("delete flower filter (handle %#x parent %#x prio %d): %w",
			obj.Handle, obj.Parent, filterPriority(obj.Info), err)
	}
	return nil
}

// Close closes the netlink socket.
func (d *netlinkDriver) Close() error {
	return d.rtnl.Close()
}

// filterPriority extracts the priority (major half) from a tc filter Info word.
func filterPriority(info uint32) uint16 {
	maj, _ := core.SplitHandle(info)
	return uint16(maj) //nolint:gosec // priority fits in uint16 by construction
}
