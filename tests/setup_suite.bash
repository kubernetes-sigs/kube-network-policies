#!/bin/bash

set -eu

function setup_suite {
  export BATS_TEST_TIMEOUT=120
  # Define the name of the kind cluster
  export CLUSTER_NAME="netpol-test-cluster"
  export IMAGE_NAME="registry.k8s.io/networking/kube-network-policies"
  # Build the image
  docker build -t "$IMAGE_NAME":test -f Dockerfile "$BATS_TEST_DIRNAME"/.. --load

  mkdir -p _artifacts
  rm -rf _artifacts/*
  # create cluster
  cat <<EOF | kind create cluster \
  --name $CLUSTER_NAME           \
  -v7 --wait 1m --retain --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: dual
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

  # Install kube-network-policies
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/main/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/main/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml
  kind load docker-image "$IMAGE_NAME":test --name "$CLUSTER_NAME"
  _install=$(sed s#"$IMAGE_NAME".*#"$IMAGE_NAME":test# < "$BATS_TEST_DIRNAME"/../install-anp.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kube-network-policies

  # stop kindnet of checking network policies
  kubectl -n kube-system delete clusterrolebinding kindnet
  
  # Expose a webserver in the default namespace
  kubectl run web --image=httpd:2 --labels="app=web" --expose --port=80

  # test depend on external connectivity that can be very flaky
  sleep 5
}

function teardown_suite {
    kind export logs "$BATS_TEST_DIRNAME"/../_artifacts --name "$CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
}