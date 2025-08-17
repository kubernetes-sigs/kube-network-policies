#!/bin/bash

set -eu

function setup_suite {
  export BATS_TEST_TIMEOUT=120
  # Define the name of the kind cluster
  export CLUSTER_NAME="netpol-test-cluster"
  export REGISTRY="registry.k8s.io/networking"
  export IMAGE_NAME="kube-network-policies"
  export TAG="test"
  # Build the image
  (
    cd "$BATS_TEST_DIRNAME"/..
    TAG="test" make image-build-npa-v1alpha1
    mkdir -p _artifacts
    rm -rf _artifacts/*
  )

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
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG"-npa-v1alpha1 --name "$CLUSTER_NAME"
  _install=$(sed s#"$REGISTRY/$IMAGE_NAME".*#"$REGISTRY/$IMAGE_NAME:$TAG"-npa-v1alpha1# < "$BATS_TEST_DIRNAME"/../install-anp.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kube-network-policies

  # stop kindnet of applying network policies
  kubectl -n kube-system set image ds kindnet kindnet-cni=docker.io/kindest/kindnetd:v20230809-80a64d96
  
  # Expose a webserver in the default namespace
  kubectl run web --image=httpd:2 --labels="app=web" --expose --port=80

  # test depend on external connectivity that can be very flaky
  sleep 5
}

function teardown_suite {
    kind export logs "$BATS_TEST_DIRNAME"/../_artifacts --name "$CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
}