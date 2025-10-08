#!/usr/bin/env bats

setup_file() {
  export REGISTRY="registry.k8s.io/networking"
  export IMAGE_NAME="kube-network-policies"
  export TAG="test"

  # Build the image for the specific binary and architecture
  (
    cd "$BATS_TEST_DIRNAME"/..
    TAG="$TAG" make image-build-npa-v1alpha2
  )

  # Apply CRDs required ClusterNetworkPolicy, use experimental for FQDN support
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/main/config/crd/experimental/policy.networking.k8s.io_clusternetworkpolicies.yaml

  # Load the Docker image into the kind cluster
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG"-npa-v1alpha2 --name "$CLUSTER_NAME"

  # Install kube-network-policies
  _install=$(sed "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-npa-v1alpha2#" < "$BATS_TEST_DIRNAME"/../install-cnp.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kube-network-policies
}

teardown_file() {
  _install=$(sed "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-npa-v1alpha2#" < "$BATS_TEST_DIRNAME"/../install-cnp.yaml)
  printf '%s' "${_install}" | kubectl delete -f -

  kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/main/config/crd/experimental/policy.networking.k8s.io_clusternetworkpolicies.yaml
}

setup() {
  kubectl create namespace dev
  kubectl label namespace/dev purpose=testing

  kubectl create namespace prod
  kubectl label namespace/prod purpose=production
}

teardown() {
  kubectl delete namespace prod
  kubectl delete namespace dev
}

@test "Maintaining an allowlist of domains" {
  # https://network-policy-api.sigs.k8s.io/npeps/npep-133-fqdn-egress-selector/#maintaining-an-allowlist-of-domains

  kubectl apply -f - <<EOF
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: allow-internal-egress
spec:
  tier: Admin
  priority: 45
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-cluster"
    action: "Accept"
    to:
    - networks:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
---
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata:
  name: allow-domains-egress
spec:
  tier: Admin
  priority: 55
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-to-my-service"
    action: "Accept"
    to:
    - domainNames:
      - "blog.kubernetes.io"
      - "*.k8s.io"
    ports:
    - portNumber:
        protocol: TCP
        port: 80
    - portNumber:
        protocol: TCP
        port: 443
  - name: "default-deny"
    action: "Deny"
    to:
    - networks:
      - "0.0.0.0/0"
EOF
  # propagation delay
  sleep 2
  # query should be blocked
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://go.dev/ && echo ok || echo fail")
  echo "Connect to webserver should fail: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "fail"

  # query should work
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://blog.kubernetes.io && echo ok || echo fail")
  echo "Connect to webserver should work: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "ok"

 # query should work
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://network-policy-api.sigs.k8s.io && echo ok || echo fail")
  echo "Connect to webserver should work: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "ok"

  # cleanup
  kubectl delete clusternetworkpolicy allow-internal-egress
  kubectl delete clusternetworkpolicy allow-domains-egress
}
