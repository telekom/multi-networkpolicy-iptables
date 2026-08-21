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

// This is a Kubernetes controller to generate nftables rules for
// multi-networkpolicy.
// It reads multiNetworkpolicy object and generates nftables rules into
// container network namespaces.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/spf13/cobra"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controller"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/server"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/tcflower"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

type managerStarter interface {
	Start(context.Context) error
}

// healthSyncRunnable populates the daemon's readiness state (the
// policySynced/netdefSynced/nsSynced flags backing /readyz) once the shared
// informer caches for policies, network attachment definitions, and
// namespaces have synced. It is added to the manager as a non-leader-election
// runnable so it starts right after the initial cache sync, whether or not
// leader election is enabled.
//
// GetInformer blocks until the specific informer's HasSynced() is true, so
// this is correct even if it races with controller-runtime's own internal
// cache-sync bookkeeping.
type healthSyncRunnable struct {
	cache cache.Cache
	state *server.Server
}

// NeedLeaderElection implements manager.LeaderElectionRunnable so this
// runnable is started unconditionally rather than only on the leader (the
// daemon does not use leader election, but being explicit avoids surprises
// if that ever changes).
func (h *healthSyncRunnable) NeedLeaderElection() bool { return false }

func (h *healthSyncRunnable) Start(ctx context.Context) error {
	targets := []struct {
		obj  client.Object
		mark func()
	}{
		{&multiv1beta1.MultiNetworkPolicy{}, h.state.MarkPolicySynced},
		{&netdefv1.NetworkAttachmentDefinition{}, h.state.MarkNetDefSynced},
		{&corev1.Namespace{}, h.state.MarkNSSynced},
	}
	for _, t := range targets {
		if _, err := h.cache.GetInformer(ctx, t.obj); err != nil {
			return fmt.Errorf("wait for informer sync (%T): %w", t.obj, err)
		}
		t.mark()
	}
	return nil
}

func run(opts *server.Options) error {
	cfg, err := opts.BuildReconcilerConfig()
	if err != nil {
		return fmt.Errorf("build reconciler config: %w", err)
	}

	klog.Infof("hostname: %v", cfg.NodeName)

	// Log a one-shot summary of the host's SR-IOV offload configuration and any
	// limits that would prevent hardware enforcement (switchdev off, hw-tc-offload
	// off, non-SMFS steering when CT is wanted, ...). Only relevant when the tc
	// backend is enabled. The CT mode governs whether a non-SMFS PF is reported
	// as a hard block (require) or a graceful degrade to stateless (auto).
	if cfg.EnableTCBackend {
		tcflower.LogHostOffloadConfig(cfg.HostPrefix, cfg.CommonRuleConfig.TCOffloadMode, cfg.CommonRuleConfig.CTMode)
	}

	var restCfg *rest.Config
	if cfg.Kubeconfig == "" {
		klog.Info("No kubeconfig specified. Falling back to in-cluster config.")
		restCfg, err = rest.InClusterConfig()
	} else {
		restCfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.Kubeconfig},
			&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: cfg.Master}},
		).ClientConfig()
	}
	if err != nil {
		return fmt.Errorf("build kubeconfig: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := controller.SetupScheme(scheme); err != nil {
		return fmt.Errorf("setup scheme: %w", err)
	}

	ctrl.SetLogger(klog.NewKlogr())

	syncPeriod := time.Duration(cfg.SyncPeriodSeconds) * time.Second
	gracefulTimeout := 10 * time.Second
	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                  scheme,
		LeaderElection:          false,
		Metrics:                 metricsserver.Options{BindAddress: "0"},
		Cache:                   cache.Options{SyncPeriod: &syncPeriod},
		GracefulShutdownTimeout: &gracefulTimeout,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	ctx := ctrl.SetupSignalHandler()
	if err := controller.SetupIndexes(ctx, mgr); err != nil {
		return fmt.Errorf("setup indexes: %w", err)
	}

	// healthState backs the /healthz and /readyz endpoints served by the
	// health HTTP server below. It starts out "not ready"; healthSyncRunnable
	// flips each Synced flag once the corresponding informer's cache has
	// synced, and the shutdown handler below flips shuttingDown once the
	// daemon starts tearing down.
	healthState := server.NewServer()
	if err := mgr.Add(&healthSyncRunnable{cache: mgr.GetCache(), state: healthState}); err != nil {
		return fmt.Errorf("add health sync runnable: %w", err)
	}

	var healthServer *server.HealthServer
	var shutdownWatcherWG sync.WaitGroup
	if opts.HealthEnabled() {
		healthServer = server.NewHealthServer(opts.HealthAddr(), healthState)
		if err := healthServer.Start(); err != nil {
			return fmt.Errorf("start health server: %w", err)
		}
		defer healthServer.Stop()

		// watcherCtx is canceled either when ctx is (a real shutdown signal)
		// or when run() returns for any other reason, so the watcher
		// goroutine below always exits and shutdownWatcherWG.Wait() below
		// can't deadlock on an error path that never triggers ctx.Done().
		// Defers run LIFO, so cancelWatcher (registered last) runs first,
		// unblocking the goroutine before Wait is reached.
		watcherCtx, cancelWatcher := context.WithCancel(ctx)
		defer shutdownWatcherWG.Wait()
		defer cancelWatcher()

		// SetupSignalHandler cancels ctx as soon as a shutdown signal is
		// received (before the manager's graceful shutdown completes), so
		// this is the earliest point at which /readyz should start
		// reporting 503.
		shutdownWatcherWG.Add(1)
		go func() {
			defer shutdownWatcherWG.Done()
			<-watcherCtx.Done()
			if ctx.Err() != nil {
				healthState.MarkShuttingDown()
			}
		}()
	}

	reconciler := &controller.NodeReconciler{
		NodeName:                 cfg.NodeName,
		Client:                   mgr.GetClient(),
		HostPrefix:               cfg.HostPrefix,
		NetworkPlugins:           cfg.NetworkPlugins,
		CommonCfg:                cfg.CommonRuleConfig,
		ContainerRuntimeEndpoint: cfg.ContainerRuntimeEndpoint,
		TCBackendDisabled:        !cfg.EnableTCBackend,
	}
	defer func() {
		if cerr := reconciler.CloseCRI(); cerr != nil {
			klog.Errorf("failed to close CRI connection: %v", cerr)
		}
	}()
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup reconciler: %w", err)
	}

	directClient, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("create direct client for cleanup: %w", err)
	}

	klog.Infof("Starting manager for node %s", cfg.NodeName)
	return startManagerAndCleanup(ctx, mgr, 45*time.Second, func(cleanupCtx context.Context) error {
		return controller.CleanupOnShutdown(cleanupCtx, reconciler, directClient)
	})
}

func startManagerAndCleanup(
	ctx context.Context,
	mgr managerStarter,
	cleanupTimeout time.Duration,
	cleanup func(context.Context) error,
) error {
	startErr := mgr.Start(ctx)
	if startErr != nil && ctx.Err() == nil {
		klog.Errorf("manager stopped with error, skipping post-shutdown cleanup: %v", startErr)
		return startErr
	}
	if startErr != nil {
		klog.Errorf("manager stopped during shutdown with error, running post-shutdown cleanup: %v", startErr)
	} else {
		klog.Info("Manager stopped, running post-shutdown cleanup")
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	cleanupErr := cleanup(cleanupCtx)
	if startErr != nil || cleanupErr != nil {
		return errors.Join(startErr, cleanupErr)
	}
	return nil
}

func main() {
	defer klog.Flush()
	opts := server.NewOptions()

	cmd := &cobra.Command{
		Use:  "multi-networkpolicy-node",
		Long: `Run the multi-networkpolicy nftables controller on a node.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(opts)
		},
	}
	opts.AddFlags(cmd.Flags())

	if err := cmd.Execute(); err != nil {
		klog.Infof("Execute failed: %v", err)
		os.Exit(1)
	}
}
