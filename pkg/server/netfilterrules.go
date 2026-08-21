/*
Copyright 2025 Deutsche Telekom AG.

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
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"

	nftables "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/telekom/multi-networkpolicy-nftables/pkg/controllers"
	"go4.org/netipx"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
)

const (
	// IPv4OffSet is the byte offset where IPv4 addresses start in a network header.
	IPv4OffSet = uint32(12) // IPs start at byte 12 in the NetworkBaseHeader
	// IPv6OffSet is the byte offset where IPv6 addresses start in a network header.
	IPv6OffSet = uint32(8) // IPv6 IPs start at byte 8 in the NetworkBaseHeader
)

type nftState struct {
	nft *nftables.Conn
	// Tables
	filter *nftables.Table
	nat    *nftables.Table

	// Interface set
	interfaceFilterSet *nftables.Set
	interfaceNatSet    *nftables.Set
	// Interface

	// Common Chains
	input      *nftables.Chain
	output     *nftables.Chain
	prerouting *nftables.Chain

	// multi-networkpolicy chains
	ingressChain       *nftables.Chain
	egressChain        *nftables.Chain
	commonIngressChain *nftables.Chain
	commonEgressChain  *nftables.Chain

	rules  map[string]*nftables.Rule
	sets   map[string]*nftables.Set
	chains map[string]*nftables.Chain
}

func policyRuleNamespacedName(o *multiv1beta1.MultiNetworkPolicy) string {
	if o == nil {
		return "<nil>"
	}
	return o.GetNamespace() + "-" + o.GetName()
}

const nftNameMaxLen = 255

func sanitizeNftChar(r rune) rune {
	if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
		return r
	}
	return '_'
}

func truncateNftName(name string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	sanitized := strings.Map(sanitizeNftChar, name)
	if len(sanitized) <= maxLen {
		return sanitized
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	// Use %08x for a deterministic 8-digit zero-padded suffix (9 chars with leading dash).
	suffix := fmt.Sprintf("-%08x", h.Sum32())
	if maxLen <= len(suffix) {
		// maxLen is too small for the prefix+suffix; return the hash truncated to maxLen.
		hash := suffix[1:] // drop the leading dash
		if maxLen < len(hash) {
			return hash[:maxLen]
		}
		return hash
	}
	prefix := sanitized[:maxLen-len(suffix)]
	return prefix + suffix
}

func nftNameWithSuffix(base, separator, suffix string) string {
	sanitizedSeparator := strings.Map(sanitizeNftChar, separator)
	sanitizedSuffix := strings.Map(sanitizeNftChar, suffix)
	suffixLen := len(sanitizedSeparator) + len(sanitizedSuffix)
	if suffixLen == 0 {
		return truncateNftName(base, nftNameMaxLen)
	}
	if suffixLen >= nftNameMaxLen {
		return truncateNftName(base+sanitizedSeparator+sanitizedSuffix, nftNameMaxLen)
	}
	return truncateNftName(base, nftNameMaxLen-suffixLen) + sanitizedSeparator + sanitizedSuffix
}

func bootstrapNetfilterChains(nftState *nftState) error {
	// the netfilter hook system
	// ref: https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
	// Create our chains if they don't already exist
	// nft add chain inet filter input { type filter hook input priority 0 \; }
	var err error
	if nftState.input, err = nftState.addChain(&nftables.Chain{
		Name:     "input",
		Table:    nftState.filter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	}); err != nil {
		return fmt.Errorf("failed to create input chain: %w", err)
	}
	// nft add chain inet filter output { type filter hook output priority 0 \; }
	if nftState.output, err = nftState.addChain(&nftables.Chain{
		Name:     "output",
		Table:    nftState.filter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	}); err != nil {
		return fmt.Errorf("failed to create output chain: %w", err)
	}
	// nft add chain inet filter prerouting { type filter hook prerouting priority 0 \; }
	if nftState.prerouting, err = nftState.addChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    nftState.nat,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	}); err != nil {
		return fmt.Errorf("failed to create prerouting chain: %w", err)
	}
	// add chain inet filter MULTI-INGRESS
	if nftState.ingressChain, err = nftState.addChain(&nftables.Chain{
		Name:  ingressChain,
		Table: nftState.filter,
	}); err != nil {
		return fmt.Errorf("failed to create %s chain: %w", ingressChain, err)
	}
	// add chain inet filter MULTI-EGRESS
	if nftState.egressChain, err = nftState.addChain(&nftables.Chain{
		Name:  egressChain,
		Table: nftState.filter,
	}); err != nil {
		return fmt.Errorf("failed to create %s chain: %w", egressChain, err)
	}
	// nft add chain inet filter MULTI-INGRESS-COMMON
	if nftState.commonIngressChain, err = nftState.addChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%s", ingressChain, common),
		Table: nftState.filter,
	}); err != nil {
		return fmt.Errorf("failed to create %s-%s chain: %w", ingressChain, common, err)
	}
	// nft add chain inet filter MULTI-EGRESS-COMMON
	if nftState.commonEgressChain, err = nftState.addChain(&nftables.Chain{
		Name:  fmt.Sprintf("%s-%s", egressChain, common),
		Table: nftState.filter,
	}); err != nil {
		return fmt.Errorf("failed to create %s-%s chain: %w", egressChain, common, err)
	}
	return nil
}

func addTable(nft *nftables.Conn, table *nftables.Table) (*nftables.Table, error) {
	t, err := nft.ListTableOfFamily(table.Name, table.Family)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to check existence of table %q: %w", table.Name, err)
	} else if err != nil && errors.Is(err, os.ErrNotExist) {
		klog.V(8).Infof("adding table %q", table.Name)
		t = nft.AddTable(table)
	}

	return t, nil
}

const (
	inputInterfaceFilterComment  = "input-interface-filter"
	outputInterfaceFilterComment = "output-interface-filter"
	natFilterRuleComment         = "nat-filter-rule"
)

var legacyDaemonChainNames = map[string]bool{
	ingressChain: true,
	egressChain:  true,
	fmt.Sprintf("%s-%s", ingressChain, common): true,
	fmt.Sprintf("%s-%s", egressChain, common):  true,
}

var legacyDaemonBaseChainNames = map[string]bool{
	"input":      true,
	"output":     true,
	"prerouting": true,
}

var legacyDaemonRuleComments = map[string]bool{
	inputInterfaceFilterComment:  true,
	outputInterfaceFilterComment: true,
	natFilterRuleComment:         true,
}

var legacyDaemonSetComments = map[string]bool{
	"Pod interfaces":     true,
	"Pod interfaces NAT": true,
}

// CleanupLegacyTables removes only daemon-owned objects that older daemon
// versions created in generic "filter" and "nat" inet tables. It must not
// delete the shared tables themselves.
func CleanupLegacyTables(nft *nftables.Conn) error {
	legacyNames := map[string]bool{
		legacyFilterTableName: true,
		legacyNatTableName:    true,
	}

	allTables, err := nft.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("cleanup legacy tables: list inet tables: %w", err)
	}

	for _, table := range allTables {
		if !legacyNames[table.Name] {
			continue
		}

		chains, err := nft.ListChainsOfTableFamily(nftables.TableFamilyINet)
		if err != nil {
			return fmt.Errorf("cleanup legacy tables: list chains for table %q: %w", table.Name, err)
		}

		for _, chain := range chains {
			if chain.Table.Name != table.Name || !legacyDaemonBaseChainNames[chain.Name] {
				continue
			}
			rules, err := nft.GetRules(table, chain)
			if err != nil {
				return fmt.Errorf("cleanup legacy tables: list rules for chain %q in table %q: %w", chain.Name, table.Name, err)
			}
			deletedBaseRules := false
			for _, rule := range rules {
				if !legacyDaemonRule(rule) {
					continue
				}
				comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)
				klog.V(2).Infof("removing daemon-owned legacy rule %q from chain %q in table %q", comment, chain.Name, table.Name)
				if err := nft.DelRule(rule); err != nil {
					klog.Errorf("failed to delete daemon-owned legacy rule %q from chain %q in table %q: %v", comment, chain.Name, table.Name, err)
					continue
				}
				deletedBaseRules = true
			}
			if deletedBaseRules {
				if err := nft.Flush(); err != nil {
					return fmt.Errorf("cleanup legacy tables: flush daemon-owned rule deletes for chain %q in table %q: %w", chain.Name, table.Name, err)
				}
			}
		}

		flushed := false
		for _, chain := range chains {
			if chain.Table.Name != table.Name || !legacyDaemonChainNames[chain.Name] {
				continue
			}
			hasRemainingRules, err := cleanupLegacyDaemonChainRules(nft, table, chain)
			if err != nil {
				return err
			}
			referenced, err := legacyChainReferenced(nft, table, chain.Name)
			if err != nil {
				return err
			}
			if referenced {
				klog.V(2).Infof("preserving daemon-owned legacy chain %q in table %q because remaining rules still reference it", chain.Name, table.Name)
				continue
			}
			if hasRemainingRules {
				klog.V(2).Infof("preserving daemon-owned legacy chain %q in table %q because it still contains foreign rules", chain.Name, table.Name)
				continue
			}
			klog.V(2).Infof("removing daemon-owned legacy chain %q from table %q", chain.Name, table.Name)
			nft.DelChain(chain)
			flushed = true
		}

		sets, err := nft.GetSets(table)
		if err != nil {
			return fmt.Errorf("cleanup legacy tables: list sets for table %q: %w", table.Name, err)
		}
		for _, set := range sets {
			if !legacyDaemonSet(set) {
				continue
			}
			klog.V(2).Infof("removing daemon-owned legacy set %q from table %q", set.Name, table.Name)
			nft.DelSet(set)
			flushed = true
		}
		if flushed {
			if err := nft.Flush(); err != nil {
				return fmt.Errorf("cleanup legacy tables: flush: %w", err)
			}
		}
	}
	return nil
}

func legacyDaemonRule(rule *nftables.Rule) bool {
	comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
	return ok && legacyDaemonRuleComments[comment]
}

func legacyDaemonSet(set *nftables.Set) bool {
	return set.Name == podInterfacesName && legacyDaemonSetComments[set.Comment]
}

func cleanupLegacyDaemonChainRules(nft *nftables.Conn, table *nftables.Table, chain *nftables.Chain) (bool, error) {
	rules, err := nft.GetRules(table, chain)
	if err != nil {
		return false, fmt.Errorf("cleanup legacy tables: list rules for daemon chain %q in table %q: %w", chain.Name, table.Name, err)
	}

	deleted := false
	for _, rule := range rules {
		if !legacyDaemonChainRule(rule) {
			continue
		}
		comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)
		klog.V(2).Infof("removing daemon-owned legacy rule %q from chain %q in table %q", comment, chain.Name, table.Name)
		if err := nft.DelRule(rule); err != nil {
			return false, fmt.Errorf("cleanup legacy tables: delete daemon-owned rule from chain %q in table %q: %w", chain.Name, table.Name, err)
		}
		deleted = true
	}
	if deleted {
		if err := nft.Flush(); err != nil {
			return false, fmt.Errorf("cleanup legacy tables: flush daemon-owned rule deletes for chain %q in table %q: %w", chain.Name, table.Name, err)
		}
		rules, err = nft.GetRules(table, chain)
		if err != nil {
			return false, fmt.Errorf("cleanup legacy tables: list remaining rules for daemon chain %q in table %q: %w", chain.Name, table.Name, err)
		}
	}

	return len(rules) > 0, nil
}

func legacyDaemonChainRule(rule *nftables.Rule) bool {
	comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
	if !ok {
		return false
	}
	if legacyDaemonRuleComments[comment] {
		return true
	}
	if comment == "common-ingress-chain" ||
		comment == "common-egress-chain" ||
		comment == "allow-ipv6-ndp-discovery" ||
		comment == allowConntrackRuleName ||
		comment == "drop-remaining" {
		return true
	}
	return strings.HasPrefix(comment, "policy:") ||
		strings.HasPrefix(comment, "common rule:") ||
		strings.HasPrefix(comment, "allow_icmp_")
}

func legacyChainReferenced(nft *nftables.Conn, table *nftables.Table, chainName string) (bool, error) {
	chains, err := nft.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return false, fmt.Errorf("cleanup legacy tables: list chains for table %q: %w", table.Name, err)
	}
	for _, chain := range chains {
		if chain.Table.Name != table.Name {
			continue
		}
		rules, err := nft.GetRules(table, chain)
		if err != nil {
			return false, fmt.Errorf("cleanup legacy tables: list rules for chain %q in table %q: %w", chain.Name, table.Name, err)
		}
		for _, rule := range rules {
			if ruleReferencesChain(rule, chainName) {
				return true, nil
			}
		}
	}
	return false, nil
}

func ruleReferencesChain(rule *nftables.Rule, chainName string) bool {
	for i := len(rule.Exprs) - 1; i >= 0; i-- {
		verdict, ok := rule.Exprs[i].(*expr.Verdict)
		if !ok {
			continue
		}
		if verdict.Chain == chainName && (verdict.Kind == expr.VerdictJump || verdict.Kind == expr.VerdictGoto) {
			return true
		}
	}
	return false
}

func bootstrapNetfilterRules(nft *nftables.Conn, podInfo *controllers.PodInfo) (*nftState, error) {
	if podInfo == nil || len(podInfo.Interfaces) == 0 {
		return nil, fmt.Errorf("podInfo or podInfo.Interfaces is nil/empty")
	}

	if err := CleanupLegacyTables(nft); err != nil {
		return nil, err
	}

	filterTable, err := addTable(nft, &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   FilterTableName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add table: %w", err)
	}

	natTable, err := addTable(nft, &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   NatTableName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add table: %w", err)
	}

	nftState := &nftState{
		nft: nft,
		// Create filter and nat tables if they don't already exist
		filter: filterTable,
		nat:    natTable,
		rules:  make(map[string]*nftables.Rule),
		sets:   make(map[string]*nftables.Set),
		chains: make(map[string]*nftables.Chain),
	}

	if err := bootstrapNetfilterChains(nftState); err != nil {
		return nil, err
	}

	slices.SortStableFunc(podInfo.Interfaces, func(a, b controllers.InterfaceInfo) int {
		return strings.Compare(a.InterfaceName, b.InterfaceName)
	})

	nftState.interfaceFilterSet = &nftables.Set{
		Table:        nftState.filter,
		Name:         podInterfacesName,
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
		Counter:      true,
		Comment:      "Pod interfaces",
	}
	nftState.interfaceNatSet = &nftables.Set{
		Table:        nftState.nat,
		Name:         podInterfacesName,
		KeyType:      nftables.TypeIFName,
		KeyByteOrder: binaryutil.NativeEndian,
		Counter:      true,
		Comment:      "Pod interfaces NAT",
	}

	interfaceSetElements := []nftables.SetElement{}
	for index, multiIF := range podInfo.Interfaces {
		interfaceSetElements = append(interfaceSetElements, nftables.SetElement{
			Key:     ifname(multiIF.InterfaceName),
			Comment: fmt.Sprintf("pod interface [%d]: %s", index, multiIF.InterfaceName),
		})
	}

	if err := nftState.updateSet(nftState.interfaceFilterSet, interfaceSetElements); err != nil {
		return nftState, fmt.Errorf("failed to update set %q: %w", nftState.interfaceFilterSet.Name, err)
	}

	filterInputRule := &nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.input,
		UserData: userDataComment(inputInterfaceFilterComment),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 0x1},
			&expr.Lookup{
				SetName:        nftState.interfaceFilterSet.Name,
				SetID:          nftState.interfaceFilterSet.ID,
				SourceRegister: 0x1,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.ingressChain.Name,
			},
		},
	}

	if _, err := nftState.updateRule(filterInputRule, nft.InsertRule, false); err != nil {
		return nftState, fmt.Errorf("failed to install rule: %w", err)
	}

	filterOutputRule := &nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.output,
		UserData: userDataComment(outputInterfaceFilterComment),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 0x1},
			&expr.Lookup{
				SetName:        nftState.interfaceFilterSet.Name,
				SetID:          nftState.interfaceFilterSet.ID,
				SourceRegister: 0x1,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.egressChain.Name,
			},
		},
	}

	if _, err := nftState.updateRule(filterOutputRule, nft.InsertRule, false); err != nil {
		return nftState, fmt.Errorf("failed to install rule: %w", err)
	}

	if err := nftState.updateSet(nftState.interfaceNatSet, interfaceSetElements); err != nil {
		return nftState, fmt.Errorf("failed to update set %q: %w", nftState.interfaceNatSet.Name, err)
	}

	if _, err := nftState.updateRule(&nftables.Rule{
		Table:    nftState.nat,
		Chain:    nftState.prerouting,
		UserData: userDataComment(natFilterRuleComment),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 0x1},
			&expr.Lookup{
				SetName:        nftState.interfaceNatSet.Name,
				SetID:          nftState.interfaceNatSet.ID,
				SourceRegister: 0x1,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	}, nft.InsertRule, false); err != nil {
		return nftState, err
	}

	if _, err := nftState.updateRule(&nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.ingressChain,
		UserData: userDataComment("common-ingress-chain"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.commonIngressChain.Name,
			},
		},
	}, nft.InsertRule, false); err != nil {
		return nftState, err
	}

	if _, err := nftState.updateRule(&nftables.Rule{
		Table:    nftState.filter,
		Chain:    nftState.egressChain,
		UserData: userDataComment("common-egress-chain"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: nftState.commonEgressChain.Name,
			},
		},
	}, nft.InsertRule, false); err != nil {
		return nftState, err
	}

	return nftState, nil
}

func (n *nftState) updateRule(rule *nftables.Rule, action func(r *nftables.Rule) *nftables.Rule, forceUpdate bool) (bool, error) {
	comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)

	existingRule, err := n.findRule(rule)
	if err != nil {
		return false, fmt.Errorf("failed to get rule by comment: %w", err)
	}

	isNew := false
	if existingRule != nil && !forceUpdate {
		klog.V(10).Infof("found rule comment:%q chain:%s", comment, rule.Chain.Name)
		rule = existingRule
	} else if existingRule != nil {
		klog.V(8).Infof("forcing rule update comment:%q chain:%s", comment, rule.Chain.Name)
		counterCopied := false
		for i := range existingRule.Exprs {
			if _, ok := existingRule.Exprs[i].(*expr.Counter); ok {
				for j := range rule.Exprs {
					if _, ok := rule.Exprs[j].(*expr.Counter); ok {
						// let's use the same counter in both rules instead of copying counter values
						rule.Exprs[j] = existingRule.Exprs[i]
						counterCopied = true
						break
					}
				}
			}
			if counterCopied {
				break
			}
		}
		if err := n.nft.DelRule(existingRule); err != nil {
			return isNew, fmt.Errorf("failed to delete existing rule: %w", err)
		}
		action(rule)
	} else {
		klog.V(8).Infof("adding rule comment:%q chain:%s", comment, rule.Chain.Name)
		action(rule)
		isNew = true
	}

	key, err := hash(rule)
	if err != nil {
		return isNew, fmt.Errorf("failed to get hash for rule comment:%q: %w", comment, err)
	}
	n.rules[key] = rule

	return isNew, nil
}

func ruleEqual(a, b *nftables.Rule) bool {
	if a.Chain.Name != b.Chain.Name {
		return false
	}
	if a.Table.Name != b.Table.Name {
		return false
	}
	if len(a.Exprs) != len(b.Exprs) {
		return false
	}

	if !bytes.Equal(a.UserData, b.UserData) {
		return false
	}

	for i := range a.Exprs {
		switch a.Exprs[i].(type) {
		case *expr.Meta:
			if !exprEqual(&expr.Meta{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Lookup:
			if !exprEqual(&expr.Lookup{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Verdict:
			if !exprEqual(&expr.Verdict{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Cmp:
			if !exprEqual(&expr.Cmp{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Payload:
			if !exprEqual(&expr.Payload{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Ct:
			if !exprEqual(&expr.Ct{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Bitwise:
			if !exprEqual(&expr.Bitwise{}, a.Exprs[i], b.Exprs[i]) {
				return false
			}
		case *expr.Counter:
			if _, ok := b.Exprs[i].(*expr.Counter); !ok {
				return false
			}
		default:
			return false
		}
	}

	return true
}

func exprEqual[V *expr.Meta | *expr.Lookup | *expr.Verdict | *expr.Cmp | *expr.Payload | *expr.Ct | *expr.Bitwise](_ V, aExpr, bExpr expr.Any) bool {
	aExprCast, ok := aExpr.(V)
	if !ok {
		return false
	}
	bExprCast, ok := bExpr.(V)
	if !ok {
		return false
	}
	if reflect.DeepEqual(aExprCast, bExprCast) {
		return true
	}
	return false
}

func (n *nftState) updateSet(set *nftables.Set, elements []nftables.SetElement) error {
	if len(set.Name) > 31 {
		var err error
		set.Name, err = hash(set.Name)
		if err != nil {
			return fmt.Errorf("failed to hash set name %q: %w", set.Name, err)
		}
	}
	existingSet, err := n.nft.GetSetByName(set.Table, set.Name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to get set: %w", err)
	}

	exists := err == nil && existingSet != nil

	if exists {
		existingElements, err := n.nft.GetSetElements(existingSet)
		if err != nil {
			return fmt.Errorf("failed to get elements for set %q, table %q", existingSet.Name, existingSet.Table.Name)
		}

		toAdd, toDel := processElements(elements, existingElements)

		if len(toAdd) > 0 || len(toDel) > 0 {
			klog.V(8).Infof("updating set %q, table %q", existingSet.Name, existingSet.Table.Name)
			if len(toDel) > 0 {
				if err := n.nft.SetDeleteElements(existingSet, toDel); err != nil {
					return fmt.Errorf("failed to remove elements from set %q: %w", existingSet.Name, err)
				}
			}

			if len(toAdd) > 0 {
				if err := n.nft.SetAddElements(existingSet, toAdd); err != nil {
					return fmt.Errorf("failed to add elements to set %q: %w", existingSet.Name, err)
				}
			}
		}

		n.sets[fmt.Sprintf("%s-%s", set.Table.Name, set.Name)] = existingSet

		return nil
	}

	klog.V(8).Infof("adding set %q, table %q", set.Name, set.Table.Name)
	if err := n.nft.AddSet(set, elements); err != nil {
		return fmt.Errorf("failed to add set %q to table %q: %w", set.Name, set.Table.Name, err)
	}

	n.sets[fmt.Sprintf("%s-%s", set.Table.Name, set.Name)] = set
	return nil
}

func processElements(newEls, existingEls []nftables.SetElement) (toAdd, toDel []nftables.SetElement) {
	toAdd = findNonCommon(newEls, existingEls)
	toDel = findNonCommon(existingEls, newEls)
	return
}

func findNonCommon(a, b []nftables.SetElement) []nftables.SetElement {
	nonCommon := []nftables.SetElement{}
	for i := range a {
		if !isPresent(a[i], b) {
			nonCommon = append(nonCommon, a[i])
		}
	}
	return nonCommon
}

func isPresent(toCheck nftables.SetElement, elements []nftables.SetElement) bool {
	for _, e := range elements {
		if slices.Compare(toCheck.Key, e.Key) == 0 {
			return true
		}
	}

	return false
}

func (n *nftState) allowICMP(chain *nftables.Chain, icmpv6 bool) error {
	data := []byte{unix.IPPROTO_ICMP}
	proto := protoIPv4
	if icmpv6 {
		data = []byte{unix.IPPROTO_ICMPV6}
		proto = protoIPv6
	}

	_, err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("allow_icmp_%s", proto)),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 0x1},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpEq,
				Data:     data,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}, n.nft.AddRule, false)

	return err
}

func (n *nftState) allowNeighborDiscovery(chain *nftables.Chain) error {
	ndpSetName := "ndp_set"

	ndpSet := &nftables.Set{
		Table:   n.filter,
		Name:    ndpSetName,
		KeyType: nftables.TypeICMP6Type,
		Counter: true,
	}

	ndpElements := []nftables.SetElement{
		{
			Key: []byte{byte(ipv6.ICMPTypeRouterSolicitation)},
		},
		{
			Key: []byte{byte(ipv6.ICMPTypeRouterAdvertisement)},
		},
		{
			Key: []byte{byte(ipv6.ICMPTypeNeighborSolicitation)},
		},
		{
			Key: []byte{byte(ipv6.ICMPTypeNeighborAdvertisement)},
		},
	}

	if err := n.updateSet(ndpSet, ndpElements); err != nil {
		return fmt.Errorf("failed to update NDP set: %w", err)
	}

	if _, err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment("allow-ipv6-ndp-discovery"),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 0x1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 0x1,
				Data:     []byte{uint8(unix.NFPROTO_IPV6)},
			},
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 0x1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 0x1,
				Data:     []byte{unix.IPPROTO_ICMPV6}, //binaryutil.NativeEndian.PutUint32(0x0000003a),
			},
			&expr.Payload{
				DestRegister: 0x1,
				Base:         expr.PayloadBaseTransportHeader,
				Len:          1,
			},
			&expr.Lookup{
				SourceRegister: 0x1,
				SetName:        ndpSet.Name,
				SetID:          ndpSet.ID,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}, n.nft.InsertRule, false); err != nil {
		return fmt.Errorf("failed to add IPv6 NDP discovery rule: %w", err)
	}

	return nil
}

func getPrefixesAsSetInterval(prefixes []string) ([]nftables.SetElement, []nftables.SetElement, error) {
	v4Prefixes := []nftables.SetElement{}
	v6Prefixes := []nftables.SetElement{}
	for index, addr := range prefixes {
		net, err := netip.ParsePrefix(addr) // validate
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse CIDR %q prefix[%d]: %w", addr, index, err)
		}
		if net.Addr().Is4() {
			// specific first element to inform nftables this is an interval set
			if index == 0 {
				v4Prefixes = append(v4Prefixes, nftables.SetElement{
					Key:         netip.IPv4Unspecified().AsSlice(),
					IntervalEnd: true,
				})
			}
			v4Prefixes = append(v4Prefixes, convertPrefixToSet(net)...)
		} else {
			// specific first element to inform nftables this is an interval set
			if index == 0 {
				v6Prefixes = append(v6Prefixes, nftables.SetElement{
					Key:         netip.IPv6Unspecified().AsSlice(),
					IntervalEnd: true,
				})
			}
			v6Prefixes = append(v6Prefixes, convertPrefixToSet(net)...)
		}
	}
	return v4Prefixes, v6Prefixes, nil
}

func (n *nftState) applyCommonPrefixRules(chain *nftables.Chain, prefixes []string, prefix string) error {
	v4Set := &nftables.Set{
		Table:    n.filter,
		Name:     fmt.Sprintf("%s_%s_%s", prefix, protoIPv4, getAddressSuffix(chain.Name)),
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	v6Set := &nftables.Set{
		Table:    n.filter,
		Name:     fmt.Sprintf("%s_%s_%s", prefix, protoIPv6, getAddressSuffix(chain.Name)),
		KeyType:  nftables.TypeIP6Addr,
		Interval: true,
	}
	v4Prefixes, v6Prefixes, err := getPrefixesAsSetInterval(prefixes)
	if err != nil {
		return fmt.Errorf("failed to get prefix sets of prefixes [%s]: %w", prefixes, err)
	}

	if len(v4Prefixes) > 0 {
		if err := n.updateSet(v4Set, v4Prefixes); err != nil {
			return fmt.Errorf("failed to update set: %w", err)
		}

		// Add rule to accept traffic from allowed IPv4 source prefixes
		// destination address offset is 16, source address offset is 12
		// for ingress chain use offset 12, for egress chain use offset 16
		// nft add rule inet filter MULTI-INGRESS-COMMON ip saddr @allowed_src_prefix_ipv4 accept
		offset := IPv4OffSet
		if !isIngressChain(chain.Name) {
			offset = IPv4OffSet + net.IPv4len
		}

		if _, err := n.updateRule(&nftables.Rule{
			Table:    n.filter,
			Chain:    chain,
			UserData: userDataComment(fmt.Sprintf("common rule:%s", v4Set.Name)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 0x1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 0x1,
					Data:     []byte{uint8(unix.NFPROTO_IPV4)},
				},
				&expr.Payload{
					DestRegister: 0x1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          uint32(net.IPv4len),
				},
				&expr.Lookup{
					SetName:        v4Set.Name,
					SetID:          v4Set.ID,
					SourceRegister: 0x1,
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}, n.nft.AddRule, false); err != nil {
			return err
		}
	}
	if len(v6Prefixes) > 0 {
		if err := n.updateSet(v6Set, v6Prefixes); err != nil {
			return fmt.Errorf("failed to update set: %w", err)
		}

		offset := IPv6OffSet
		if !isIngressChain(chain.Name) {
			offset = IPv6OffSet + uint32(net.IPv6len)
		}
		if _, err := n.updateRule(&nftables.Rule{
			Table:    n.filter,
			Chain:    chain,
			UserData: userDataComment(fmt.Sprintf("common rule:%s", v6Set.Name)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 0x1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 0x1,
					Data:     []byte{uint8(unix.NFPROTO_IPV6)},
				},
				&expr.Payload{
					DestRegister: 0x1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,              // IPv6 offset
					Len:          uint32(net.IPv6len), // IPv6 byte length
				},
				&expr.Lookup{
					SetName:        v6Set.Name,
					SetID:          v6Set.ID,
					SourceRegister: 0x1,
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}, n.nft.AddRule, false); err != nil {
			return err
		}
	}
	return nil
}

func (n *nftState) allowConntracked(chain *nftables.Chain) error {
	// nft add rule inet filter MULTI-<chain>-COMMON ct state related,established accept
	_, err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(allowConntrackRuleName),
		Exprs: []expr.Any{
			&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(zeroRuleMark),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []byte{0, 0, 0, 0}},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}, n.nft.AddRule, false)
	return err
}

func (n *nftState) applyCommonChainRules(cfg controllers.CommonRuleConfig) error {
	klog.V(8).Info("applying common chain rules")
	if cfg.AcceptICMPv6 {
		if err := n.allowICMP(n.commonIngressChain, true); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 in common ingress chain: %w", err)
		}
		if err := n.allowICMP(n.commonEgressChain, true); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 in common egress chain: %w", err)
		}
	} else {
		if err := n.allowNeighborDiscovery(n.commonIngressChain); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 neighbor discovery in common ingress chain: %w", err)
		}
		if err := n.allowNeighborDiscovery(n.commonEgressChain); err != nil {
			return fmt.Errorf("failed to allow ICMPv6 neighbor discovery in common egress chain: %w", err)
		}
	}
	if cfg.AcceptICMP {
		if err := n.allowICMP(n.commonIngressChain, false); err != nil {
			return fmt.Errorf("failed to allow ICMP in common ingress chain: %w", err)
		}
		if err := n.allowICMP(n.commonEgressChain, false); err != nil {
			return fmt.Errorf("failed to allow ICMP in common egress chain: %w", err)
		}
	}

	if len(cfg.AllowSrcPrefix) != 0 {
		if err := n.applyCommonPrefixRules(n.commonIngressChain, cfg.AllowSrcPrefix, common); err != nil {
			return fmt.Errorf("failed to apply common ingress rules: %w", err)
		}
	}

	if len(cfg.AllowDstPrefix) != 0 {
		if err := n.applyCommonPrefixRules(n.commonEgressChain, cfg.AllowDstPrefix, common); err != nil {
			return fmt.Errorf("failed to apply common egress rules: %w", err)
		}
	}
	// Always allow conntracked connections
	if err := n.allowConntracked(n.commonIngressChain); err != nil {
		return fmt.Errorf("failed to apply common ingress conntrack rules: %w", err)
	}
	if err := n.allowConntracked(n.commonEgressChain); err != nil {
		return fmt.Errorf("failed to apply common egress conntrack rules: %w", err)
	}

	return nil
}

func convertPrefixToSet(prefix netip.Prefix) []nftables.SetElement {
	// nftables needs half-open intervals [firstIP, lastIP) for prefixes
	// e.g. 10.0.0.0/24 becomes [10.0.0.0, 10.0.1.0), 10.1.1.1/32 becomes [10.1.1.1, 10.1.1.2) etc
	firstIP := prefix.Masked().Addr()
	lastIP := netipx.PrefixLastIP(prefix).Next()
	elements := []nftables.SetElement{
		{Key: firstIP.AsSlice()},
	}
	// It seems .Next does not return a valid IP for the all-0s address
	// So we need to special case that here
	if (lastIP == netip.Addr{}) {
		// we had a turnover, so add the all-0s address as the interval end
		if firstIP.Is4() {
			return append(elements, nftables.SetElement{Key: netip.IPv4Unspecified().AsSlice(), IntervalEnd: true})
		}
		return append(elements, nftables.SetElement{Key: netip.IPv6Unspecified().AsSlice(), IntervalEnd: true})
	}

	return append(elements, nftables.SetElement{Key: lastIP.AsSlice(), IntervalEnd: true})
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

// userDataCommentMaxLen is the maximum length of a comment string in userdata.
// userdata.AppendString encodes the string length in a single byte (0-255),
// and appends a null terminator, so the effective maximum for the comment
// string itself is 254 bytes.
const userDataCommentMaxLen = 254

func userDataComment(comment string) []byte {
	if len(comment) > userDataCommentMaxLen {
		comment = comment[:userDataCommentMaxLen]
	}
	return userdata.AppendString([]byte{}, userdata.TypeComment, comment)
}

func (n *nftState) applyPodInterfaceRules(chain, policyChain *nftables.Chain, policy *multiv1beta1.MultiNetworkPolicy, podInterface controllers.InterfaceInfo) (bool, error) {
	// add rule to jump to MULTI-INGRESS-<idx> from MULTI-INGRESS
	// -A MULTI-INGRESS -m comment --comment "policy:policy1 net-attach-def:net-attach-def1" -i net1 -j MULTI-INGRESS-0
	// -A MULTI-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN

	klog.V(8).Infof("applying pod interface:%s [%q] policy %q chain: %s", podInterface.InterfaceName, podInterface.InterfaceType, policyNamespacedName(policy), policyChain.Name)

	return n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, net-attach-def:%s, interface:%s, cni:%s, jump:%s", policyNamespacedName(policy), chain.Name, podInterface.NetattachName, podInterface.InterfaceName, podInterface.InterfaceType, policyChain.Name)),
		Exprs: []expr.Any{
			&expr.Meta{Key: getMetaKeyInterface(chain.Name), Register: 0x1},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpEq,
				Data:     ifname(podInterface.InterfaceName),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: policyChain.Name,
			},
		},
	}, n.nft.AddRule, false)
}

func (n *nftState) applyGeneralMarkCheck(chain *nftables.Chain, policy *multiv1beta1.MultiNetworkPolicy) error {
	_, err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, check mark 0x30000", policyNamespacedName(policy))),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: false, Register: 0x1},
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(matchRuleMark),
				Xor:            binaryutil.NativeEndian.PutUint32(zeroRuleMark),
			},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpEq,
				Data:     binaryutil.NativeEndian.PutUint32(matchRuleMark),
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictReturn},
		}}, n.nft.AddRule, false)
	return err
}

// reset previous mark bits
func (n *nftState) applyMarkReset(policyChainName string, policyChain *nftables.Chain, policyName string, index int) error {
	klog.V(8).Infof("applying mark reset %q: %s", policyName, policyChain.Name)
	_, err := n.updateRule(&nftables.Rule{
		Table:    n.filter,
		Chain:    policyChain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s ingress:%d: reset", policyName, policyChainName, index)),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(^matchRuleMark), // 0xfffcffff
				Xor:            binaryutil.NativeEndian.PutUint32(zeroRuleMark),
			},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
			&expr.Counter{},
		},
	}, n.nft.AddRule, false)
	return err
}

// Check if we matched something and do a early return
func (n *nftState) applyMarkCheck(policyChainName string, policyChain *nftables.Chain, policyName string, index int) error {
	klog.V(8).Infof("applying mark check %q: %s", policyName, policyChain.Name)
	_, err := n.updateRule(&nftables.Rule{
		Table:    policyChain.Table,
		Chain:    policyChain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s ingress:%d return", policyName, policyChainName, index)),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(matchRuleMark),
				Xor:            binaryutil.NativeEndian.PutUint32(zeroRuleMark),
			},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpEq,
				Data:     binaryutil.NativeEndian.PutUint32(matchRuleMark),
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictReturn},
		}}, n.nft.AddRule, false)
	return err
}

func getSetName(str string) string {
	return strings.ReplaceAll(str, "-", "_")
}

// Drop remaining traffic that did not match any policy
func (n *nftState) applyDropRemaining(chain *nftables.Chain, force bool) error {
	_, err := n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment("drop-remaining"),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	}, n.nft.AddRule, force)
	return err
}

func isIngressChain(chainName string) bool {
	return strings.HasPrefix(chainName, ingressChain)
}

func getMetaKeyInterface(chainName string) expr.MetaKey {
	if isIngressChain(chainName) {
		return expr.MetaKeyIIFNAME
	}
	return expr.MetaKeyOIFNAME
}

func getProtocolInfo(protocol v1.Protocol) (string, []byte) {
	switch protocol {
	case v1.ProtocolUDP:
		return "udp", []byte{unix.IPPROTO_UDP}
	case v1.ProtocolSCTP:
		return "sctp", []byte{unix.IPPROTO_SCTP}
	default:
		return "tcp", []byte{unix.IPPROTO_TCP}
	}
}

func getAddressSuffix(chainName string) string {
	if isIngressChain(chainName) {
		return sourceAddressSuffix
	}
	return destinationAddressSuffix
}

func (n *nftState) applyPrefixes(chainName string, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer, peerIndex int, prefixes, exceptPrefixes []nftables.SetElement, isV6 bool) error {

	protocol := protoIPv4
	keyType := nftables.TypeIPAddr
	payloadLen := uint32(net.IPv4len)
	if isV6 {
		protocol = protoIPv6
		keyType = nftables.TypeIP6Addr
		payloadLen = uint32(net.IPv6len)
	}

	if len(prefixes) > 0 {
		offset := IPv4OffSet

		nfProtocol := uint8(unix.NFPROTO_IPV4)
		if isV6 {
			offset = IPv6OffSet
			nfProtocol = uint8(unix.NFPROTO_IPV6)
		}
		if !isIngressChain(chainName) {
			if !isV6 {
				offset += net.IPv4len
			} else {
				offset += net.IPv6len
			}
		}
		if len(exceptPrefixes) > 0 {
			setName := fmt.Sprintf("%s_%s_%s_%s_%d", chainName, peerIPBlockExceptPrefix, protocol, getAddressSuffix(chainName), peerIndex)
			ruleComment := fmt.Sprintf("policy:%s, name:%s, cidr:%s, deny", policyName, chainName, peer.IPBlock.CIDR)

			exceptSet := &nftables.Set{
				Table:    chain.Table,
				Name:     setName,
				Counter:  true,
				KeyType:  keyType,
				Interval: true,
			}

			if err := n.updateSet(exceptSet, exceptPrefixes); err != nil {
				return fmt.Errorf("failed to update set: %w", err)
			}

			if _, err := n.updateRule(&nftables.Rule{
				Table:    chain.Table,
				Chain:    chain,
				UserData: userDataComment(ruleComment),
				Exprs: []expr.Any{
					&expr.Meta{
						Key:            expr.MetaKeyNFPROTO,
						SourceRegister: false,
						Register:       0x1,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 0x1,
						Data:     []byte{nfProtocol},
					},
					&expr.Payload{
						DestRegister: 0x1,
						Base:         expr.PayloadBaseNetworkHeader,
						Offset:       offset,
						Len:          payloadLen,
					},
					&expr.Lookup{
						SetName:        exceptSet.Name,
						SetID:          exceptSet.ID,
						SourceRegister: 0x1,
					},
					&expr.Counter{},
					&expr.Verdict{
						Kind: expr.VerdictDrop,
					},
				},
			}, n.nft.AddRule, false); err != nil {
				return err
			}
		}

		prefixesSet := &nftables.Set{
			Table:    chain.Table,
			Name:     fmt.Sprintf("%s_%s_%s_%s_%d", chainName, peerIPBlockPrefix, protocol, getAddressSuffix(chainName), peerIndex),
			Constant: true,
			Counter:  true,
			KeyType:  keyType,
			Interval: true,
		}

		if err := n.updateSet(prefixesSet, prefixes); err != nil {
			return fmt.Errorf("failed to update set: %w", err)
		}

		if _, err := n.updateRule(&nftables.Rule{
			Table:    chain.Table,
			Chain:    chain,
			UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, cidr:%s, accept", policyName, chainName, peer.IPBlock.CIDR)),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 0x1,
					Data:     []byte{nfProtocol},
				},
				&expr.Payload{
					DestRegister: 0x1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       offset,
					Len:          payloadLen,
				},
				&expr.Lookup{
					SetName:        prefixesSet.Name,
					SetID:          prefixesSet.ID,
					SourceRegister: 0x1,
				},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
				&expr.Bitwise{
					SourceRegister: 0x1,
					DestRegister:   0x1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(^peerRuleMark), // 0xfffdffff
					Xor:            binaryutil.NativeEndian.PutUint32(peerRuleMark),
				},
				&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictReturn,
				},
			},
		}, n.nft.AddRule, false); err != nil {
			return err
		}
	}

	return nil
}

func (n *nftState) applyPolicyPeersRulesIPBlock(chainName string, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer, peerIndex int) error {
	v4ExceptPrefixes, v6ExceptPrefixes, err := getPrefixesAsSetInterval(peer.IPBlock.Except)
	if err != nil {
		return fmt.Errorf("failed to get except prefix sets of prefixes [%s]: %w", peer.IPBlock.Except, err)
	}
	v4Prefixes, v6Prefixes, err := getPrefixesAsSetInterval([]string{peer.IPBlock.CIDR})
	if err != nil {
		return fmt.Errorf("failed to get prefix sets of prefixes [%s]: %w", peer.IPBlock.CIDR, err)
	}

	if err := n.applyPrefixes(chainName, chain, policyName, peer, peerIndex, v4Prefixes, v4ExceptPrefixes, false); err != nil {
		return fmt.Errorf("failed to apply %s prefixes for policy %q: %w", protoIPv4, policyName, err)
	}

	if err := n.applyPrefixes(chainName, chain, policyName, peer, peerIndex, v6Prefixes, v6ExceptPrefixes, true); err != nil {
		return fmt.Errorf("failed to apply %s prefixes for policy %q: %w", protoIPv6, policyName, err)
	}

	return nil
}

func (n *nftState) applyPolicyPeersRulesSelector(ctx context.Context, deps controllers.PolicyDeps, chainName string, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer,
	podInfo *controllers.PodInfo, policyNetworks []string, peerIndex int) error {
	if peer.PodSelector != nil {
		klog.V(8).Infof("applying peers rules with pod selector: %s", peer.PodSelector.String())
	} else {
		klog.V(8).Info("applying peers rules with namespace selector only (all pods in matched namespaces)")
	}
	var podSelector labels.Selector
	if peer.PodSelector != nil {
		var err error
		podSelector, err = metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			return fmt.Errorf("pod selector: %w", err)
		}
	} else {
		podSelector = labels.Everything()
	}

	pods, err := deps.ListPods(ctx, podSelector)
	if err != nil {
		return fmt.Errorf("pod list failed: %w", err)
	}

	var nsSelector labels.Selector
	if peer.NamespaceSelector != nil {
		klog.V(8).Infof("applying peers rules with namespace selector: %s", peer.NamespaceSelector.String())
		var err error
		nsSelector, err = metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			return fmt.Errorf("namespace selector: %w", err)
		}
	}
	var podIntfIPs []string
	podIntfsIPsMap := make(map[string]any)
	for _, sPod := range pods {
		nsLabels, err := deps.GetNamespaceInfo(ctx, sPod.Namespace)
		if err != nil {
			klog.Errorf("cannot get namespace info: %v %v", sPod.Name, err)
			continue
		}
		if nsSelector != nil && !nsSelector.Matches(labels.Set(nsLabels.Labels)) {
			continue
		}
		sPodinfo, err := deps.GetPodInfo(ctx, sPod)
		if err != nil {
			klog.Errorf("cannot get %s/%s podInfo: %v", sPod.Namespace, sPod.Name, err)
			continue
		}

		for _, podIntf := range podInfo.Interfaces {
			if !podIntf.CheckPolicyNetwork(policyNetworks) {
				continue
			}
			for _, sPodIntf := range sPodinfo.Interfaces {
				if !sPodIntf.CheckPolicyNetwork(policyNetworks) {
					continue
				}

				for _, ip := range podIntf.IPs {
					podIntfsIPsMap[ip.String()] = nil
				}

				for _, ip := range sPodIntf.IPs {
					podIntfsIPsMap[ip.String()] = nil
				}

				for ip := range podIntfsIPsMap {
					podIntfIPs = append(podIntfIPs, ip)
				}
			}
		}
	}

	if err := n.addIPRules(chainName, podIntfIPs, chain, policyName, peer, peerIndex); err != nil {
		return fmt.Errorf("add selector IP rules: %w", err)
	}

	return nil
}

func (n *nftState) addIPRule(chainName string, addrs []string, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer,
	peerIndex int) error {

	if len(addrs) < 1 {
		return nil
	}

	offset := IPv4OffSet
	payloadLen := uint32(net.IPv4len)
	keyType := nftables.TypeIPAddr
	protocol := protoIPv4
	nfProtocol := uint8(unix.NFPROTO_IPV4)
	if net.ParseIP(addrs[0]).To4() == nil {
		offset = IPv6OffSet
		payloadLen = uint32(net.IPv6len)
		keyType = nftables.TypeIP6Addr
		protocol = protoIPv6
		nfProtocol = uint8(unix.NFPROTO_IPV6)
	}

	if !isIngressChain(chainName) {
		offset += payloadLen
	}

	var selectorStr string
	if peer.PodSelector != nil {
		selectorStr = peer.PodSelector.String()
	} else {
		selectorStr = "<all>"
	}
	selectorHash, err := hash(selectorStr)
	if err != nil {
		return fmt.Errorf("failed to hash pod selector %q: %w", selectorStr, err)
	}

	ipSet := &nftables.Set{
		Name:    fmt.Sprintf("%s_%s_%d_%s_%s", chainName, getAddressSuffix(chainName), peerIndex, protocol, selectorHash),
		Table:   chain.Table,
		KeyType: keyType,
	}

	ipSetElements := []nftables.SetElement{}
	for _, addr := range addrs {
		parsedIP := net.ParseIP(addr).To4()
		if parsedIP == nil {
			parsedIP = net.ParseIP(addr).To16()
		}
		ipSetElements = append(ipSetElements, nftables.SetElement{
			Key: []byte(parsedIP),
		})
	}

	if err := n.updateSet(ipSet, ipSetElements); err != nil {
		return err
	}

	_, err = n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, selector-for:%s, protocol:%s", policyName, chainName, selectorHash, protocol)),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 0x1,
				Data:     []byte{nfProtocol},
			},
			&expr.Payload{
				DestRegister: 0x1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          payloadLen,
			},
			&expr.Lookup{
				SourceRegister: 0x1,
				SetName:        ipSet.Name,
				SetID:          ipSet.ID,
			},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(^peerRuleMark),
				Xor:            binaryutil.NativeEndian.PutUint32(peerRuleMark),
			},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	}, n.nft.AddRule, false)

	return err
}

func (n *nftState) addIPRules(chainName string, addrs []string, chain *nftables.Chain, policyName string, peer multiv1beta1.MultiNetworkPolicyPeer,
	peerIndex int) error {

	var v4Addrs, v6Addrs []string
	for _, addr := range addrs {
		ipAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("failed to parse address %q", addr)
		}
		if ipAddr.Is6() {
			v6Addrs = append(v6Addrs, addr)
		} else {
			v4Addrs = append(v4Addrs, addr)
		}
	}

	if err := n.addIPRule(chainName, v4Addrs, chain, policyName, peer, peerIndex); err != nil {
		return fmt.Errorf("failed to add IPv4 rules: %w", err)
	}

	if err := n.addIPRule(chainName, v6Addrs, chain, policyName, peer, peerIndex); err != nil {
		return fmt.Errorf("failed to add IPv6 rules: %w", err)
	}

	return nil
}

func (n *nftState) applyPolicyPeersRules(ctx context.Context, deps controllers.PolicyDeps, chainName string, chain *nftables.Chain, policyName string, peers []multiv1beta1.MultiNetworkPolicyPeer,
	podInfo *controllers.PodInfo, policyNetworks []string, peerIndex int) error {
	peersName := nftNameWithSuffix(chainName, "-", fmt.Sprintf("%s-%d", peersChainSuffix, peerIndex))

	peersChain, err := n.addChain(&nftables.Chain{
		Name:  peersName,
		Table: chain.Table,
	})
	if err != nil {
		return fmt.Errorf("failed to create peers chain: %w", err)
	}

	if _, err := n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, jump:%s", policyName, chainName, peersChain.Name)),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: peersChain.Name,
			},
		}}, n.nft.AddRule, false); err != nil {
		return err
	}
	for index, peer := range peers {
		if peer.IPBlock != nil {
			if err := n.applyPolicyPeersRulesIPBlock(peersName, peersChain, policyName, peer, index); err != nil {
				return fmt.Errorf("apply IPBlock peer rules at index %d: %w", index, err)
			}
			continue
		}
		if peer.PodSelector != nil || peer.NamespaceSelector != nil {
			if err := n.applyPolicyPeersRulesSelector(ctx, deps, peersName, peersChain, policyName, peer, podInfo, policyNetworks, index); err != nil {
				return fmt.Errorf("apply selector peer rules at index %d: %w", index, err)
			}
			continue
		}
		return fmt.Errorf("unknown peer rule at index %d: %+v", index, peer)
	}

	if len(peers) == 0 {
		// if no peers are specified, accept all peers
		if _, err := n.updateRule(&nftables.Rule{
			Table:    chain.Table,
			Chain:    peersChain,
			UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, no peers skipped accept all", policyName, peersName)),
			Exprs: []expr.Any{
				&expr.Counter{},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
				&expr.Bitwise{
					SourceRegister: 0x1,
					DestRegister:   0x1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(^peerRuleMark),
					Xor:            binaryutil.NativeEndian.PutUint32(peerRuleMark), // 0x200000
				},
				&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
			}}, n.nft.AddRule, false); err != nil {
			return err
		}

	}
	return nil
}

func (n *nftState) findRule(rule *nftables.Rule) (*nftables.Rule, error) {
	rules, err := n.nft.GetRules(rule.Table, rule.Chain)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules in table %q, chain %q: %w", rule.Table.Name, rule.Chain.Name, err)
	}

	for _, r := range rules {
		if ruleEqual(rule, r) {
			return r, nil
		}
	}

	return nil, nil
}

func (n *nftState) getInetSet(chain *nftables.Chain, portsName, suffix string) *nftables.Set {
	setName := nftNameWithSuffix(getSetName(portsName), "_", suffix)
	return &nftables.Set{
		Table:    chain.Table,
		Name:     setName,
		Comment:  setName,
		Constant: true,
		Counter:  true,
		KeyType:  nftables.TypeInetService,
		Interval: true,
	}
}

func (n *nftState) applyProtoPortsRules(chainName string, chain *nftables.Chain, policyName string, set *nftables.Set, unixProto []byte) error {
	_, err := n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, set:%s", policyName, chainName, set.Name)),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpEq,
				Data:     unixProto,
			},
			&expr.Payload{
				DestRegister: 0x1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // l4 offset
				Len:          2, // l4 offset
			},
			&expr.Lookup{
				SetName:        set.Name,
				SetID:          set.ID,
				SourceRegister: 0x1,
			},
			&expr.Counter{},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
			// implement the mark as follows:
			// clear the 0x10000 bit
			// set the 0x10000 bit
			// this allows us to check if we matched any port rule
			// without affecting any other bits that might be in use
			// e.g. 0x20000 for address detection
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(^portRuleMark),
				Xor:            binaryutil.NativeEndian.PutUint32(portRuleMark),
			},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
		},
	}, n.nft.AddRule, false)
	return err
}

// validatePortSpec validates a single port specification and returns the nftables set elements
// representing the port range. Named ports are rejected since nftables operates on numeric ports only.
func validatePortSpec(port multiv1beta1.MultiNetworkPolicyPort) ([]nftables.SetElement, error) {
	if port.Port == nil {
		return nil, nil
	}

	if port.Port.Type == intstr.String {
		portNum, err := strconv.Atoi(port.Port.StrVal)
		if err != nil || portNum < 1 || portNum > math.MaxUint16 {
			return nil, fmt.Errorf("named port %q is not supported; numeric ports are required", port.Port.StrVal)
		}
		port.Port = &intstr.IntOrString{Type: intstr.Int, IntVal: int32(portNum)} //nolint:gosec // G109: portNum validated in range [1, 65535] above
	}
	portNum := port.Port.IntValue()
	if portNum < 1 || portNum > math.MaxUint16 {
		return nil, fmt.Errorf("port %d out of range, must be between 1 and %d", portNum, math.MaxUint16)
	}

	portVal := uint16(portNum) //nolint:gosec // G115: value validated in range [1, 65535] above
	elements := []nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(portVal)},
	}

	if port.EndPort != nil && *port.EndPort > int32(portNum) { //nolint:gosec // G115: value validated in range [1, 65535] above
		if *port.EndPort < 1 || *port.EndPort > math.MaxUint16 {
			return nil, fmt.Errorf("port %d out of range, must be between 1 and %d", portNum, math.MaxUint16)
		}
		// keep the half open interval semantics of nftables
		// e.g. 1000-2000 becomes [1000, 2001)
		// so we need to add 1 to the end port
		elements = append(elements, nftables.SetElement{
			Key:         binaryutil.BigEndian.PutUint16(uint16(*port.EndPort) + 1), //nolint:gosec // G115: wrapping to 0 when EndPort==65535 is the correct nftables past-max sentinel for inet_service interval sets
			IntervalEnd: true,
		})
	} else {
		// keep the half open interval semantics of nftables
		// e.g. 1000 becomes [1000, 1001)
		// so we need to add 1 to the port
		elements = append(elements, nftables.SetElement{
			Key:         binaryutil.BigEndian.PutUint16(portVal + 1), //nolint:gosec // G115: portVal is validated in [1,65535] but +1 wrap at 65535 is the correct nftables past-max sentinel
			IntervalEnd: true,
		})
	}
	return elements, nil
}

func (n *nftState) applyPolicyPortsRules(chainName string, chain *nftables.Chain, policyName string, ports []multiv1beta1.MultiNetworkPolicyPort, portIndex int) error {
	portsName := nftNameWithSuffix(chainName, "-", fmt.Sprintf("%s-%d", portsChainSuffix, portIndex))
	// create ports chain
	portChain, err := n.addChain(&nftables.Chain{
		Name:  portsName,
		Table: chain.Table,
	})
	if err != nil {
		return fmt.Errorf("failed to create ports chain: %w", err)
	}

	klog.V(8).Infof("applying port rules for policy %q in the chain %q", policyName, portChain.Name)
	if _, err := n.updateRule(&nftables.Rule{
		Table:    chain.Table,
		Chain:    chain,
		UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, jump:%s", policyName, chainName, portChain.Name)),
		Exprs: []expr.Any{
			&expr.Counter{},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: portChain.Name,
			},
		}}, n.nft.AddRule, false); err != nil {
		return err
	}

	portsTCP := []nftables.SetElement{}
	portsUDP := []nftables.SetElement{}
	portsSCTP := []nftables.SetElement{}
	for _, port := range ports {
		if port.Port == nil && port.Protocol != nil {
			port.Port = &intstr.IntOrString{Type: intstr.Int, IntVal: 1}
			port.EndPort = new(int32)
			*port.EndPort = math.MaxUint16
		}

		portElements, err := validatePortSpec(port)
		if err != nil {
			return err
		}

		if port.Protocol != nil {
			switch *port.Protocol {
			case v1.ProtocolUDP:
				portsUDP = append(portsUDP, portElements...)
			case v1.ProtocolSCTP:
				portsSCTP = append(portsSCTP, portElements...)
			default:
				portsTCP = append(portsTCP, portElements...)
			}
		} else {
			portsTCP = append(portsTCP, portElements...)
		}

	}
	if len(portsTCP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolTCP)
		tcpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.updateSet(tcpSet, portsTCP); err != nil {
			return err
		}
		if err := n.applyProtoPortsRules(portsName, portChain, policyName, tcpSet, unixFlag); err != nil {
			return fmt.Errorf("failed to apply tcp port rules for set %q: %w", tcpSet.Name, err)
		}
	}
	if len(portsUDP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolUDP)
		udpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.updateSet(udpSet, portsUDP); err != nil {
			return err
		}
		if err := n.applyProtoPortsRules(portsName, portChain, policyName, udpSet, unixFlag); err != nil {
			return fmt.Errorf("failed to apply udp port rules for set %q: %w", udpSet.Name, err)
		}
	}
	if len(portsSCTP) > 0 {
		suffix, unixFlag := getProtocolInfo(v1.ProtocolSCTP)
		sctpSet := n.getInetSet(chain, portsName, suffix)
		if err := n.updateSet(sctpSet, portsSCTP); err != nil {
			return err
		}
		if err := n.applyProtoPortsRules(portsName, portChain, policyName, sctpSet, unixFlag); err != nil {
			return fmt.Errorf("failed to apply sctp port rules for set %q: %w", sctpSet.Name, err)
		}
	}

	if len(ports) == 0 || (len(portsTCP) == 0 && len(portsUDP) == 0 && len(portsSCTP) == 0) {
		// if no ports are specified, accept all ports
		if _, err := n.updateRule(&nftables.Rule{
			Table:    chain.Table,
			Chain:    portChain,
			UserData: userDataComment(fmt.Sprintf("policy:%s, name:%s, no ports skipped accept all", policyName, portsName)),
			Exprs: []expr.Any{
				&expr.Counter{},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 0x1},
				&expr.Bitwise{
					SourceRegister: 0x1,
					DestRegister:   0x1,
					Len:            4,
					Mask:           binaryutil.NativeEndian.PutUint32(^portRuleMark),
					Xor:            binaryutil.NativeEndian.PutUint32(portRuleMark),
				},
				&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
			}}, n.nft.AddRule, false); err != nil {
			return err
		}
	}
	return nil
}

func (n *nftState) applyPodRules(ctx context.Context, deps controllers.PolicyDeps, _ controllers.CommonRuleConfig, chain *nftables.Chain, podInfo *controllers.PodInfo, policy *multiv1beta1.MultiNetworkPolicy, policyNetworks []string) (bool, error) {
	// add chain inet filter <chainName>-<idx>
	entryChainName := chain.Name
	policyPart := truncateNftName(policyRuleNamespacedName(policy), nftNameMaxLen-len(entryChainName)-1)
	policyChainName := fmt.Sprintf("%s-%s", entryChainName, policyPart)
	policyChain, err := n.addChain(&nftables.Chain{
		Name:  policyChainName,
		Table: n.filter,
	})
	if err != nil {
		return false, fmt.Errorf("failed to create policy chain: %w", err)
	}

	newRules := false
	for _, podIntf := range podInfo.Interfaces {
		if podIntf.CheckPolicyNetwork(policyNetworks) {
			newRule, err := n.applyPodInterfaceRules(chain, policyChain, policy, podIntf)
			if err != nil {
				return newRules, fmt.Errorf("failed to apply pod interface rules for policy %q: %w", policyNamespacedName(policy), err)
			}
			if newRule {
				newRules = true
			}
		}
	}

	if isIngressChain(policyChainName) {
		for index, ingress := range policy.Spec.Ingress {
			if err := n.applyMarkReset(policyChainName, policyChain, policyNamespacedName(policy), index); err != nil {
				return newRules, fmt.Errorf("failed to apply ingress mark reset for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPortsRules(policyChainName, policyChain, policyNamespacedName(policy), ingress.Ports, index); err != nil {
				return newRules, fmt.Errorf("failed to apply ingress ports for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPeersRules(ctx, deps, policyChainName, policyChain, policyNamespacedName(policy), ingress.From, podInfo, policyNetworks, index); err != nil {
				return newRules, fmt.Errorf("failed to apply ingress address rules for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyMarkCheck(policyChainName, policyChain, policyNamespacedName(policy), index); err != nil {
				return newRules, fmt.Errorf("failed to apply egress mark check for policy %q: %w", policyNamespacedName(policy), err)
			}
		}
	} else {
		for index, egress := range policy.Spec.Egress {
			if err := n.applyMarkReset(policyChainName, policyChain, policy.Name, index); err != nil {
				return newRules, fmt.Errorf("failed to apply egress mark reset for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPortsRules(policyChainName, policyChain, policyNamespacedName(policy), egress.Ports, index); err != nil {
				return newRules, fmt.Errorf("failed to apply egress ports for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyPolicyPeersRules(ctx, deps, policyChainName, policyChain, policyNamespacedName(policy), egress.To, podInfo, policyNetworks, index); err != nil {
				return newRules, fmt.Errorf("failed to apply egress address rules for policy %q: %w", policyNamespacedName(policy), err)
			}
			if err := n.applyMarkCheck(policyChainName, policyChain, policyNamespacedName(policy), index); err != nil {
				return newRules, fmt.Errorf("failed to apply egress mark check for policy %q: %w", policyNamespacedName(policy), err)
			}
		}
	}
	return newRules, nil
}

func (n *nftState) addChain(chain *nftables.Chain) (*nftables.Chain, error) {
	if len(chain.Name) > 31 {
		var err error
		chain.Name, err = hash(chain.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to hash chain name %q: %w", chain.Name, err)
		}

	}
	existingChain, err := n.nft.ListChain(chain.Table, chain.Name)
	var c *nftables.Chain
	if (err != nil && errors.Is(err, os.ErrNotExist)) || existingChain == nil {
		klog.V(8).Infof("adding chain %q", chain.Name)
		c = n.nft.AddChain(chain)
	} else if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("failed to configure chain %q in table %q: %w", chain.Name, chain.Table.Name, err)
	} else {
		c = existingChain
	}

	n.chains[chainID(c)] = c
	return c, nil
}

func chainID(c *nftables.Chain) string {
	return fmt.Sprintf("%s-%s", c.Table.Name, c.Name)
}

func (n *nftState) cleanup() error {
	defer func() {
		n.rules = make(map[string]*nftables.Rule)
		n.sets = make(map[string]*nftables.Set)
		n.chains = make(map[string]*nftables.Chain)
	}()

	if err := n.cleanupRules(n.filter); err != nil {
		return fmt.Errorf("failed to cleanup %q table: %w", n.filter.Name, err)
	}

	if err := n.cleanupRules(n.nat); err != nil {
		return fmt.Errorf("failed to cleanup %q table: %w", n.nat.Name, err)
	}

	if err := n.cleanupChains(); err != nil {
		return fmt.Errorf("failed to cleanup chains: %w", err)
	}

	return nil
}

func (n *nftState) cleanupRules(table *nftables.Table) error {
	chains, err := n.nft.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}

	performFlush := false
	var cleanupErrs []error

	for _, chain := range chains {
		if chain.Table.Name == table.Name {
			rules, err := n.nft.GetRules(table, chain)
			if err != nil {
				return fmt.Errorf("failed to list rules for table %q, chain %q: %w", table.Name, chain.Name, err)
			}
			for _, rule := range rules {
				key, err := hash(rule)
				if err != nil {
					comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)
					klog.Warningf("failed to get key for rule %q in chain %q: %v — deleting as stale", comment, rule.Chain.Name, err)
					if delErr := n.nft.DelRule(rule); delErr != nil {
						klog.Errorf("failed to delete unhashable rule %q in chain %q: %v", comment, rule.Chain.Name, delErr)
						cleanupErrs = append(cleanupErrs, fmt.Errorf("delete unhashable rule %q in chain %q: %w", comment, rule.Chain.Name, delErr))
					} else {
						performFlush = true
					}
					continue
				}
				if _, exists := n.rules[key]; !exists {
					comment, _ := userdata.GetString(rule.UserData, userdata.TypeComment)
					klog.V(8).Infof("deleting rule %q in chain %q", comment, rule.Chain.Name)
					err = n.nft.DelRule(rule)
					if err != nil {
						klog.Errorf("failed to delete rule %q in chain %q: %v", comment, rule.Chain.Name, err)
						cleanupErrs = append(cleanupErrs, fmt.Errorf("delete rule %q in chain %q: %w", comment, rule.Chain.Name, err))
						continue
					}
					performFlush = true
				}
			}
		}
	}

	sets, err := n.nft.GetSets(table)
	if err != nil {
		return fmt.Errorf("failed to list sets for table %q: %w", table.Name, err)
	}
	for _, set := range sets {
		if _, exists := n.sets[fmt.Sprintf("%s-%s", set.Table.Name, set.Name)]; !exists && !set.Anonymous {
			klog.V(8).Infof("deleting set %q in table %q", set.Name, set.Table.Name)
			n.nft.DelSet(set)
			performFlush = true
		}
	}

	if performFlush {
		if err := n.nft.Flush(); err != nil {
			return fmt.Errorf("failed to flush rules/sets cleanup: %w", err)
		}
	}
	if len(cleanupErrs) > 0 {
		return errors.Join(cleanupErrs...)
	}

	return nil
}

func (n *nftState) cleanupChains() error {
	chains, err := n.nft.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("failed to list chains: %w", err)
	}

	performFlush := false
	managedTableNames := map[string]bool{
		n.filter.Name: true,
		n.nat.Name:    true,
	}
	for _, chain := range chains {
		if !managedTableNames[chain.Table.Name] {
			continue
		}
		rules, err := n.nft.GetRules(chain.Table, chain)
		if err != nil {
			return fmt.Errorf("failed to get rules for table %q, chain %q: %w", chain.Table.Name, chain.Name, err)
		}
		if _, used := n.chains[chainID(chain)]; !used && len(rules) < 1 {
			klog.V(8).Infof("deleting chain %q in table %q", chain.Name, chain.Table.Name)
			n.nft.DelChain(chain)
			performFlush = true
		}
	}

	if performFlush {
		if err := n.nft.Flush(); err != nil {
			return fmt.Errorf("failed to flush chains cleanup: %w", err)
		}
	}

	return nil
}
