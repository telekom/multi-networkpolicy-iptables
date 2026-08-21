//go:build !linux

package controller

import (
	"context"
	"fmt"
	"runtime"

	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	v1 "k8s.io/api/core/v1"
)

func applyTCRulesForPod(_ context.Context, _ controllers.PolicyDeps, _ controllers.CommonRuleConfig, _ controllers.PolicyMap, _ *v1.Pod, _ *controllers.PodInfo, _ string) error {
	return fmt.Errorf("tc flower enforcement is unsupported on %s", runtime.GOOS)
}
