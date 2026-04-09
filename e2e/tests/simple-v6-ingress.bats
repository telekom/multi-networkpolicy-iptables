#!/usr/bin/env bats

# Note:
# These test cases, simple, will create simple (one policy for ingress) and test the 
# traffic policying by ncat (nc) command. In addition, these cases also verifies that
# simple nftables generation check by nftables-save and pod-iptable in multi-networkpolicy pod.


setup_file() {
	cd $BATS_TEST_DIRNAME
	load "common"
	export MANIFEST_FILE="simple-v6-ingress.yml"
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-simple-v6-ingress wait --for=condition=ready -l app=test-simple-v6-ingress pod --timeout=${kubewait_timeout}
	wait_for_nft_rules "test-simple-v6-ingress" "pod-server" "test-multinetwork-policy-simple-1"
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"
	server_net1=$(wait_for_net1_ip6 "test-simple-v6-ingress" "pod-server")
	client_a_net1=$(wait_for_net1_ip6 "test-simple-v6-ingress" "pod-client-a")
	client_b_net1=$(wait_for_net1_ip6 "test-simple-v6-ingress" "pod-client-b")
}

teardown_file() {
	teardown_file_common
}


@test "check generated nft rules" {
	# wait for pod-server to have multi-networkpolicy nftables rules for ingress
	run wait_for_nft_rules test-simple-v6-ingress pod-server test-multinetwork-policy-simple-1
	[ "$status" -eq  "0" ]
	# check pod-client-a has NO multi-networkpolicy nftables rules for ingress
	run kubectl -n test-simple-v6-ingress exec pod-client-a -- sh -c "nft list ruleset | grep test-multinetwork-policy-simple-1"
	[ "$status" -eq  "1" ]
	# check pod-client-b has NO multi-networkpolicy nftables rules for ingress
	run kubectl -n test-simple-v6-ingress exec pod-client-b -- sh -c "nft list ruleset | grep test-multinetwork-policy-simple-1"
	[ "$status" -eq  "1" ]
}

@test "test-simple-v6-ingress check client-a -> server" {
	# nc should succeed from client-a to server by policy
	run retry_until_success 15 kubectl -n test-simple-v6-ingress exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v6-ingress check client-b -> server" {
	# nc should NOT succeed from client-b to server by policy
	run retry_until_deny 30 kubectl -n test-simple-v6-ingress exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v6-ingress check server -> client-a" {
	# nc should succeed from server to client-a by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v6-ingress exec pod-server -- sh -c "echo x | nc -w 1 ${client_a_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-simple-v6-ingress check server -> client-b" {
	# nc should succeed from server to client-b by no policy definition for direction (egress for pod-server)
	run kubectl -n test-simple-v6-ingress exec pod-server -- sh -c "echo x | nc -w 1 ${client_b_net1} 5555"
	[ "$status" -eq  "0" ]
}

@test "disable multi-networkpolicy and check nftables rules" {
 	# disable multi-networkpolicy pods by adding invalid nodeSelector
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 -p '{"spec": {"template": {"spec": {"nodeSelector": {"non-existing": "true"}}}}}'
	# check multi-networkpolicy pod is deleted
	kubectl -n kube-system wait --for=delete -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}

	# check nft rules in pod-server
	wait_for_nft_rule_absent "test-simple-v6-ingress" "pod-server" "test-multinetwork-policy-simple-1"

	# enable multi-networkpolicy again
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 --type json -p='[{"op": "remove", "path": "/spec/template/spec/nodeSelector/non-existing"}]'
	kubectl -n kube-system rollout status daemonset/multi-networkpolicy-ds-amd64 --timeout=${kubewait_timeout}
	kubectl -n kube-system wait --for=condition=ready -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}
	wait_for_nft_rules "test-simple-v6-ingress" "pod-server" "test-multinetwork-policy-simple-1"
}


