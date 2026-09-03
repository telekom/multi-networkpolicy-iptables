#!/usr/bin/env bats

# Note:
# These test cases cover pods whose primary network is a net-attach-def selected
# with the Multus "v1.multus-cni.io/default-network" annotation. Such pods carry no
# "k8s.v1.cni.cncf.io/networks" annotation, so the daemon has to pick the network up
# from the default-network annotation, and the policed interface is eth0.

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "common"
	export MANIFEST_FILE="default-network.yml"

	ensure_daemonset_running
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-default-network wait --for=condition=ready -l app=test-default-network pod --timeout=${kubewait_timeout}
	wait_for_nft_rules "test-default-network" "pod-server" "testnetwork-policy-defnet-1"
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
}

teardown_file() {
	teardown_file_common
}

@test "policy is applied to the default network interface" {
	run kubectl -n test-default-network exec pod-server -- sh -c \
		"nft list set inet multi-networkpolicy-filter pod_interfaces | grep -q 'eth0'"
	[ "$status" -eq "0" ]
}

@test "rules are only generated for the policy target" {
	run kubectl -n test-default-network exec pod-server -it -- sh -c "nft list ruleset | grep testnetwork-policy-defnet-1"
	[ "$status" -eq "0" ]
	run kubectl -n test-default-network exec pod-client-a -it -- sh -c "nft list ruleset | grep testnetwork-policy-defnet-1"
	[ "$status" -eq "1" ]
}

@test "allowed client reaches the server on the default network" {
	run retry_until_allow 30 kubectl -n test-default-network exec pod-client-a -- \
		sh -c "echo x | nc -w 1 2.2.42.1 5555"
	[ "$status" -eq "0" ]
}

@test "denied client is blocked on the default network" {
	run retry_until_deny 30 kubectl -n test-default-network exec pod-client-b -- \
		sh -c "echo x | nc -w 1 2.2.42.1 5555"
	[ "$status" -eq "0" ]
}
