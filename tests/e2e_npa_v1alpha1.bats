#!/usr/bin/env bats

setup_file() {
  export REGISTRY="registry.k8s.io/networking"
  export IMAGE_NAME="kube-network-policies"
  export TAG="test"

  # Build the image for the specific binary and architecture
  (
    cd "$BATS_TEST_DIRNAME"/..
    TAG="$TAG" make image-build-npa-v1alpha1
  )

  # Apply CRDs required for this binary
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/8c1c5fa535ef0e72b05287190520b22fd2ed1003/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/8c1c5fa535ef0e72b05287190520b22fd2ed1003/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml

  # Load the Docker image into the kind cluster
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG"-npa-v1alpha1 --name "$CLUSTER_NAME"

  # Install kube-network-policies
  _install=$(sed "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-npa-v1alpha1#" < "$BATS_TEST_DIRNAME"/../install-anp.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kube-network-policies
}

teardown_file() {
  _install=$(sed "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-npa-v1alpha1#" < "$BATS_TEST_DIRNAME"/../install-anp.yaml)
  printf '%s' "${_install}" | kubectl delete -f -

  kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/main/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml
  kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/8c1c5fa535ef0e72b05287190520b22fd2ed1003/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml
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
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-internal-egress
spec:
  priority: 45
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-cluster"
    action: "Allow"
    to:
    - networks:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
---
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-domains-egress
spec:
  priority: 55
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-to-my-service"
    action: "Allow"
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
  kubectl delete adminnetworkpolicy allow-internal-egress
  kubectl delete adminnetworkpolicy allow-domains-egress
}
