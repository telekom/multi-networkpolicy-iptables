## Multi-networkpolicy-nftables Configurations


### Command Line Options

Most command line options have description in help, so please execute with `--help` to see the option.

```
$ ./multi-networkpolicy-nftables --help
```

### Advanced Options

#### Host paths used by the DaemonSet

The sample DaemonSet mounts the host filesystem at `/host`. Keep the
controller flag aligned with that mount:

```
--host-prefix=/host
```

If a cluster uses a CRI socket other than the default shown in `deploy.yml`,
set `--container-runtime-endpoint` to the absolute host socket path. Do not use
a `unix://` URL here; the controller adds the CRI transport internally.

`deploy.yml` is generated from `config/manager/overlays/default`. The e2e
install manifest is generated from the same base plus
`config/manager/overlays/e2e`, so host paths, RBAC, and shared mounts remain
aligned between normal deployments and tests.

#### Compatibility notes

Pod iptables state is no longer persisted. The old `--pod-iptables` flag is
still accepted as a hidden, deprecated no-op so older manifests do not fail at
startup while they are being migrated.

File-mounted custom rule ConfigMaps are not used by the nftables controller.
Use the command line options below for supported exceptional traffic handling.

#### Add exceptional IP prefix address to accept

Some networks may require accepting traffic from/to specific address prefixes for the network, such as multicast address (all routers multicast address, link-local address and so on). You can configure `--allow-src-prefix` and `--allow-dst-prefix` to specify which prefix should be accepted (even though network policy does not have it). Both options accept a comma-separated CIDR list.

```
--allow-src-prefix=fe80::/10
--allow-dst-prefix=fe80::/10,ff00::/8
```

#### Pods using a net-attach-def as their primary network

Multus can replace a pod's primary network with a NetworkAttachmentDefinition via
the `v1.multus-cni.io/default-network` annotation. Such pods have no
`k8s.v1.cni.cncf.io/networks` annotation, and their net-attach-def backed
interface is `eth0` rather than `net1`.

These pods are policed like any other: the network from the default-network
annotation is resolved the same way as the secondary networks, so a
MultiNetworkPolicy with `k8s.v1.cni.cncf.io/policy-for: <namespace>/<net-attach-def>`
applies to the primary interface.

As with secondary networks, the plugin type of the net-attach-def must be listed in
`--network-plugins` (default: `macvlan`), so a pod whose default network uses a
plugin outside that list stays unfiltered.

#### Sandboxed runtimes that L3-forward pod traffic (e.g. Kata Containers)

By default the controller filters traffic in the pod network namespace on the
`input` and `output` hooks, which is where traffic terminates for regular
runtimes such as runc.

With sandboxed runtimes the workload runs inside a VM, so traffic is not
delivered locally in the pod network namespace but passed on to a VM-side
device. For Kata Containers with `internetworking_model = "l3forwarding"` the
packets are L3-routed between the CNI interface and the VM-side device inside
the pod network namespace, i.e. they traverse the `forward` hook and never
`input`/`output`. Enable the `forward` hook on such nodes:

```
--enable-forward-filtering
```

With the flag enabled, an additional `forward` base chain is created in the
pod's `multi-networkpolicy-filter` table. Direction is classified with the same
pod interface set used by `input`/`output`: a packet entering the namespace on a
pod interface is treated as ingress, a packet leaving the namespace on a pod
interface as egress. Policy, peer, port and conntrack handling are identical to
the default path, since the `forward` hook is a regular netfilter hook with
working connection tracking.

Notes:

* The flag is off by default and has no effect on regular runc pods. It is safe
  to leave it disabled on nodes without sandboxed runtimes. Turning it off again
  removes the `forward` chain on the next sync.
* Enable it only on nodes that actually L3-forward pod traffic. On a node with
  multi-homed pods that route between their own interfaces, enabling it makes
  that routed traffic subject to network policies as well, which may drop
  traffic that was previously unfiltered.
* Kata's `tcfilter` networking model is **not** supported: TC `mirred redirect`
  takes the packet before netfilter, so no nftables hook in the pod network
  namespace sees the traffic.
