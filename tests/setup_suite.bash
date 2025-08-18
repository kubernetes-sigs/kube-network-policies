#!/bin/bash

set -eu

function setup_suite {
  export BATS_TEST_TIMEOUT=120
  # Define the name of the kind cluster
  export CLUSTER_NAME="netpol-test-cluster"

  # Create cluster
  cat <<EOF | kind create cluster \
    --name $CLUSTER_NAME \
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

  # Stop kindnet from applying network policies
  kubectl -n kube-system set image ds kindnet kindnet-cni=docker.io/kindest/kindnetd:v20230809-80a64d96
  # Expose a webserver in the default namespace
  kubectl run web --image=httpd:2 --labels="app=web" --expose --port=80
}

function teardown_suite {
    kind export logs "$BATS_TEST_DIRNAME"/../_artifacts --name "$CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
}