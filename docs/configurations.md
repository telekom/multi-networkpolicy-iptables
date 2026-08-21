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

#### SR-IOV tc-flower backend

For enforcing `MultiNetworkPolicy` on SR-IOV VFs in switchdev mode (via tc
flower on the host VF representor, offloaded to the NIC eSwitch), see
[SR-IOV tc-flower dataplane backend](sriov-tc-backend.md). It covers backend
selection, prerequisites, the `--enable-tc-backend` / `--tc-offload-mode`
flags, and the T-CaaS bm4x deployment caveat.
