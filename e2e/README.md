## e2e test with kind


### How to test e2e

This requires [Bats](https://github.com/bats-core/bats-core) for test runner. Please install bats (e.g. dnf, apt and so on).

```
$ git clone https://github.com/k8snetworkplumbingwg/multi-networkpolicy-nftables
$ cd multi-networkpolicy-nftables/e2e
$ ./get_tools.sh
$ ./setup_cluster.sh
$ ./tests/simple-v4-ingress.bats
```

### How to teardown cluster

```
$ kind delete cluster
$ docker kill kind-registry
$ docker rm kind-registry
```

### How to deploy server image with new changes

After making changes to the code, it is possible to update the server Daemonset image with the script:

```
./update_image_on_cluster.sh
```

### Forward filtering test

`tests/forward-filtering.bats` covers `--enable-forward-filtering`, which is needed
for sandboxed runtimes that L3-forward pod traffic (e.g. Kata Containers with
`internetworking_model = "l3forwarding"`). Kata itself is not installed in the kind
cluster; instead a routing pod attached to two macvlan networks forwards traffic
between clients and a server, which exercises the same nftables `forward` hook in the
pod network namespace.

The suite patches `--enable-forward-filtering` into the DaemonSet during
`setup_file` and removes it again in `teardown_file`, so it can be run together with
all other suites (`./run_all_tests.sh`) or on its own:

```
$ ./run_single_test.sh forward-filtering
```
