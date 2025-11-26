#!/usr/bin/env bats

# Note:
# These test cases, stacked, will create stacked policy rules in one multi-networkpolicy and test the
# traffic policying by ncat (nc) command.

setup() {
	cd $BATS_TEST_DIRNAME
	load "common"

	server_net2=$(get_net2_ip "test-complex-v4-ingress-multi" "pod-server")
	pod_client_a_net1=$(get_net1_ip "test-complex-v4-ingress-multi" "pod-client-a")
	pod_client_a_net2=$(get_net2_ip "test-complex-v4-ingress-multi" "pod-client-a")
	pod_client_b_net1=$(get_net1_ip "test-complex-v4-ingress-multi" "pod-client-b")
	pod_client_b_net2=$(get_net2_ip "test-complex-v4-ingress-multi" "pod-client-b")
}

@test "setup test-complex-v4-ingress-multi test environments" {
	kubectl apply --wait --timeout=${kubewait_timeout} -f complex-v4-ingress-multi.yml
	run kubectl -n test-complex-v4-ingress-multi wait --for=condition=ready -l app=test-complex-v4-ingress-multi pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
	sleep 5
}

@test "test-complex-v4-ingress-multi check client-a -> server" {
	run kubectl -n test-complex-v4-ingress-multi exec pod-client-a -- sh -c "echo x | nc -w 1 ${server_net2} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-complex-v4-ingress-multi check client-b -> server" {
	run kubectl -n test-complex-v4-ingress-multi exec pod-client-b -- sh -c "echo x | nc -w 1 ${server_net2} 5555"
	[ "$status" -eq  "0" ]
}

@test "test-complex-v4-ingress-multi check client-a -> client-b" {
	run kubectl -n test-complex-v4-ingress-multi exec pod-client-a -- sh -c "echo x | nc -w 1 ${pod_client_b_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "test-complex-v4-ingress-multi check client-b -> client-a" {
	run kubectl -n test-complex-v4-ingress-multi exec pod-client-b -- sh -c "echo x | nc -w 1 ${pod_client_a_net1} 5555"
	[ "$status" -eq  "1" ]
}

@test "cleanup environments" {
  kubectl delete --wait --timeout=${kubewait_timeout} -f complex-v4-ingress-multi.yml
	run kubectl -n test-complex-v4-ingress-multi wait --for=delete -l app=test-complex-v4-ingress-multi pod --timeout=${kubewait_timeout}
	[ "$status" -eq  "0" ]
}
