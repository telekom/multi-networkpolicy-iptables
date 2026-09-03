#!/usr/bin/env bats

# Note:
# These test cases cover --enable-forward-filtering, which is required for sandboxed
# runtimes that L3-forward pod traffic instead of terminating it locally (e.g. Kata
# Containers with internetworking_model=l3forwarding). pod-router routes between two
# macvlan networks, so traffic between the clients and the server traverses the
# nftables forward hook in the routing pod's network namespace and never its
# input/output chains.

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "common"
	export MANIFEST_FILE="forward-filtering.yml"

	ensure_daemonset_running
	enable_forward_filtering

	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-forward-filtering wait --for=condition=ready -l app=test-forward-filtering pod --timeout=${kubewait_timeout}
	wait_for_nft_rules "test-forward-filtering" "pod-router" "testnetwork-policy-forward-1"
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"

	server_net1=$(wait_for_net1_ip "test-forward-filtering" "pod-server")
	router_net1=$(wait_for_net1_ip "test-forward-filtering" "pod-router")
	router_net2=$(wait_for_net2_ip "test-forward-filtering" "pod-router")
}

teardown_file() {
	teardown_file_common
}

@test "forward chain is created in the routing pod" {
	run kubectl -n test-forward-filtering exec pod-router -- sh -c "nft list ruleset | grep -q 'hook forward'"
	[ "$status" -eq "0" ]
}

@test "forward chain classifies both directions by pod interface" {
	run kubectl -n test-forward-filtering exec pod-router -- sh -c \
		"nft list chain inet multi-networkpolicy-filter forward | grep -q 'iifname @pod_interfaces .*multi-ingress'"
	[ "$status" -eq "0" ]
	run kubectl -n test-forward-filtering exec pod-router -- sh -c \
		"nft list chain inet multi-networkpolicy-filter forward | grep -q 'oifname @pod_interfaces .*multi-egress'"
	[ "$status" -eq "0" ]
}

@test "routing pod has both policy interfaces addressed" {
	[ "${router_net1}" = "2.2.40.254" ]
	[ "${router_net2}" = "2.2.41.254" ]
}

@test "allowed client reaches the server through the routing pod" {
	run retry_until_allow 30 kubectl -n test-forward-filtering exec pod-client-a -- \
		sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq "0" ]
}

@test "denied client is blocked by the routing pod" {
	run retry_until_deny 30 kubectl -n test-forward-filtering exec pod-client-b -- \
		sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq "0" ]
}

@test "forwarded traffic is not filtered once forward filtering is disabled" {
	disable_forward_filtering

	# The forward chain has no rules left and is removed by the regular cleanup.
	run wait_for_nft_rule_absent "test-forward-filtering" "pod-router" "hook forward"
	[ "$status" -eq "0" ]

	# Without the forward hook the routing pod no longer enforces the policy.
	run retry_until_allow 30 kubectl -n test-forward-filtering exec pod-client-b -- \
		sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq "0" ]
}
