/*
Copyright 2020 The Kubernetes Authors.

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

package server

import (
	"flag"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"

	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"
)

const defaultSyncPeriod = 30

// Options stores option for the command
type Options struct {
	// kubeconfig is the path to a KubeConfig file.
	Kubeconfig string
	// master is used to override the kubeconfig's URL to the apiserver
	master                   string
	hostnameOverride         string
	hostPrefix               string
	containerRuntime         controllers.RuntimeKind
	containerRuntimeEndpoint string
	networkPlugins           []string
	syncPeriod               int
	acceptICMPv6             bool
	acceptICMP               bool
	allowSrcPrefixText       string
	allowDstPrefixText       string
	// healthPort is the TCP port the health HTTP server listens on (0 = disabled).
	healthPort int
	// healthBindAddress is the IP address the health HTTP server binds to.
	// Defaults to "" (all interfaces); set to "127.0.0.1" to restrict to loopback.
	healthBindAddress string
	tcOffloadMode     string
	tcCTMode          string
	enableTCBackend   bool

	// updated by command line parsing
	allowSrcPrefix []string
	allowDstPrefix []string
}

// ReconcilerConfig holds all configuration values needed to construct a NodeReconciler.
type ReconcilerConfig struct {
	Kubeconfig               string
	Master                   string
	NodeName                 string
	HostPrefix               string
	ContainerRuntimeEndpoint string
	NetworkPlugins           []string
	SyncPeriodSeconds        int
	EnableTCBackend          bool
	CommonRuleConfig         controllers.CommonRuleConfig
}

// AddFlags adds command line flags into command
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	klog.InitFlags(nil)
	fs.SortFlags = false
	fs.Var(&o.containerRuntime, "container-runtime", "Container runtime using for the cluster. Possible values: 'cri'. ")
	fs.StringVar(&o.containerRuntimeEndpoint, "container-runtime-endpoint", o.containerRuntimeEndpoint, "Path to cri socket.")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", o.Kubeconfig, "Path to kubeconfig file with authorization information (the master location is set by the master flag).")
	fs.StringVar(&o.master, "master", o.master, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	fs.StringVar(&o.hostnameOverride, "hostname-override", o.hostnameOverride, "If non-empty, will use this string as identification instead of the actual hostname.")
	fs.StringVar(&o.hostPrefix, "host-prefix", o.hostPrefix, "If non-empty, will use this string as prefix for host filesystem.")
	fs.StringSliceVar(&o.networkPlugins, "network-plugins", []string{"macvlan"}, "List of network plugins to be be considered for network policies.")
	deprecatedIptablesStatePath := ""
	fs.StringVar(&deprecatedIptablesStatePath, "pod-iptables", "", "Deprecated: pod iptables state is no longer persisted.")
	_ = fs.MarkDeprecated("pod-iptables", "no longer used; pod iptables state is no longer persisted")
	_ = fs.MarkHidden("pod-iptables")
	fs.IntVar(&o.syncPeriod, "sync-period", defaultSyncPeriod, "sync period in seconds for reconciliation")
	fs.BoolVar(&o.acceptICMP, "accept-icmp", false, "accept all ICMP traffic")
	fs.BoolVar(&o.acceptICMPv6, "accept-icmpv6", false, "accept all ICMPv6 traffic")
	fs.StringVar(&o.allowSrcPrefixText, "allow-src-prefix", "", "Accept source IP prefix list, comma separated CIDRs (e.g. \"fe80::/10\")")
	fs.StringVar(&o.allowDstPrefixText, "allow-dst-prefix", "", "Accept destination IP prefix list, comma separated CIDRs (e.g. \"fe80::/10,ff00::/8\")")
	fs.IntVar(&o.healthPort, "health-port", 0, "TCP port for the health HTTP server (0 to disable, 1-65535 to enable).")
	fs.StringVar(&o.healthBindAddress, "health-bind-address", "", "IP address the health HTTP server binds to (empty = all interfaces, 127.0.0.1 = loopback only).")
	fs.StringVar(&o.tcOffloadMode, "tc-offload-mode", "hardware", "tc flower offload mode for the SR-IOV backend: 'hardware' (skip_sw, hardware-only, fail-closed; production default) or 'software' (skip_hw, in-kernel software enforcement). Ignored by the nft backend.")
	fs.StringVar(&o.tcCTMode, "tc-ct-mode", "auto", "Stateful conntrack (CT) offload policy for the SR-IOV backend. 'auto' (default): use CT where the NIC can hardware-offload it (SMFS steering), otherwise degrade to the stateless pipeline and log the lost stateful tracking (DMFS cannot offload CT). 'require': always emit CT; if the NIC cannot offload it the filters are rejected and the interface is left unenforced (fail-closed, stateful-or-nothing). 'off': never use CT (always stateless). Ignored by the nft backend.")
	fs.BoolVar(&o.enableTCBackend, "enable-tc-backend", true, "Enable the SR-IOV tc-flower dataplane backend for VF-representor interfaces. When false, SR-IOV interfaces are NOT enforced by this daemon (only the nftables backend runs). Default: true.")
	fs.AddGoFlagSet(flag.CommandLine)
}

func parseIPPrefixText(prefixText string, prefixList *[]string) error {
	if prefixText != "" {
		*prefixList = []string{}
		for _, addrRaw := range strings.Split(prefixText, ",") {
			addr := strings.TrimSpace(addrRaw)
			_, _, err := net.ParseCIDR(addr)
			if err != nil {
				return err
			}
			*prefixList = append(*prefixList, addr)
		}
	}
	return nil
}

// Validate checks several options and fill processed value
func (o *Options) Validate() error {

	if o.healthPort < 0 || o.healthPort > 65535 {
		return fmt.Errorf("health-port %d is out of range [0, 65535]", o.healthPort)
	}
	if o.healthBindAddress != "" {
		if ip := net.ParseIP(o.healthBindAddress); ip == nil {
			return fmt.Errorf("health-bind-address %q is not a valid IP address", o.healthBindAddress)
		}
	}

	if err := parseIPPrefixText(o.allowSrcPrefixText, &o.allowSrcPrefix); err != nil {
		return err
	}

	if err := parseIPPrefixText(o.allowDstPrefixText, &o.allowDstPrefix); err != nil {
		return err
	}
	o.containerRuntimeEndpoint = strings.TrimSpace(o.containerRuntimeEndpoint)
	if o.containerRuntimeEndpoint == "" {
		return fmt.Errorf("container-runtime-endpoint must not be empty")
	}
	if strings.Contains(o.containerRuntimeEndpoint, "://") {
		return fmt.Errorf("container-runtime-endpoint must be an absolute filesystem path, not a URL")
	}
	if !filepath.IsAbs(o.containerRuntimeEndpoint) {
		return fmt.Errorf("container-runtime-endpoint must be an absolute filesystem path")
	}
	return nil
}

// BuildReconcilerConfig resolves all configuration needed to build a NodeReconciler.
// It resolves hostname, parses prefix lists, and packages everything into a ReconcilerConfig.
func (o *Options) BuildReconcilerConfig() (*ReconcilerConfig, error) {
	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("options validation: %w", err)
	}

	hostname, err := nodeutil.GetHostname(o.hostnameOverride)
	if err != nil {
		return nil, fmt.Errorf("get hostname: %w", err)
	}

	return &ReconcilerConfig{
		Kubeconfig:               o.Kubeconfig,
		Master:                   o.master,
		NodeName:                 hostname,
		HostPrefix:               o.hostPrefix,
		ContainerRuntimeEndpoint: o.containerRuntimeEndpoint,
		NetworkPlugins:           o.networkPlugins,
		SyncPeriodSeconds:        o.syncPeriod,
		EnableTCBackend:          o.enableTCBackend,
		CommonRuleConfig: controllers.CommonRuleConfig{
			AcceptICMP:     o.acceptICMP,
			AcceptICMPv6:   o.acceptICMPv6,
			AllowSrcPrefix: o.allowSrcPrefix,
			AllowDstPrefix: o.allowDstPrefix,
			TCOffloadMode:  o.tcOffloadMode,
			CTMode:         o.tcCTMode,
		},
	}, nil
}

// NewOptions initializes Options
func NewOptions() *Options {
	return &Options{
		containerRuntime: controllers.Cri,
		// The SR-IOV tc-flower backend is on by default; AddFlags also sets this
		// default for the CLI path, but set it here too so an Options built
		// programmatically without AddFlags still defaults to enabled.
		enableTCBackend: true,
	}
}

// HealthEnabled reports whether the health HTTP server should be started
// (i.e. --health-port was set to a non-zero value).
func (o *Options) HealthEnabled() bool {
	return o.healthPort != 0
}

// HealthAddr returns the address the health HTTP server should bind to, in
// "host:port" form suitable for net.Listen. Only meaningful when
// HealthEnabled() is true.
func (o *Options) HealthAddr() string {
	return net.JoinHostPort(o.healthBindAddress, strconv.Itoa(o.healthPort))
}
