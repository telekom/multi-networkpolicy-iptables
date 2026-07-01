#!/bin/sh
set -o errexit

export PATH=./bin:${PATH}

# define the OCI binary to be used. Acceptable values are `docker`, `podman`.
# Defaults to `docker`.
OCI_BIN="${OCI_BIN:-docker}"

kind_network='kind'

$OCI_BIN build -t localhost:5000/multi-networkpolicy-nftables:e2e -f ../Dockerfile ..
$OCI_BIN build -t localhost:5000/multi-networkpolicy-nftables:e2e-test -f Dockerfile .
$OCI_BIN build -t localhost:5000/install-cni:e2e -f cni.Dockerfile .

# deploy cluster with kind
cat <<EOF | HTTP_PROXY=$DOCKER_PROXY HTTPS_PROXY=$DOCKER_PROXY NO_PROXY="$DOCKER_NO_PROXY,$LOCAL_REGISTRY_NAME" kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

# load multus image from container host to kind node
kind load docker-image localhost:5000/multi-networkpolicy-nftables:e2e
kind load docker-image localhost:5000/multi-networkpolicy-nftables:e2e-test
kind load docker-image localhost:5000/install-cni:e2e

kind export kubeconfig

# install calico
kubectl apply --wait --timeout=10s -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.1/manifests/calico.yaml
kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true FELIX_XDPENABLED=false
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
kubectl -n kube-system wait --for=condition=available deploy/coredns --timeout=300s

#install multus
kubectl apply --wait --timeout=10s -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset.yml
kubectl -n kube-system wait --for=condition=ready -l name=multus pod --timeout=660s
kubectl apply --wait --timeout=10s -f cni-install.yml
kubectl -n kube-system rollout status daemonset/install-cni-plugins --timeout=300s

#install bond-cni
kubectl apply --wait --timeout=10s -f  https://raw.githubusercontent.com/k8snetworkplumbingwg/bond-cni/refs/heads/master/manifests/bond-cni.yaml

# install multi-networkpolicy API
kubectl apply --wait --timeout=10s -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy/master/scheme.yml

# install multi-networkpolicy-nftables
kubectl apply --wait --timeout=10s -f multi-network-policy-nftables-e2e.yml
kubectl -n kube-system rollout status daemonset/multi-networkpolicy-ds-amd64 --timeout=300s
kubectl -n kube-system wait --for=condition=ready -l name=multi-networkpolicy pod --timeout=300s

echo "Kind cluster with multi-networkpolicy-nftables is ready"
