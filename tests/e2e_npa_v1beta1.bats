#!/usr/bin/env bats

setup_file() {
  export REGISTRY="registry.k8s.io/networking"
  export IMAGE_NAME="kube-network-policies"
  export TAG="test"

  # Build the image for the specific binary and architecture
  (
    cd "$BATS_TEST_DIRNAME"/..
    TAG="$TAG" make image-build-npa-v1beta1
  )

  # Apply CRDs required ClusterNetworkPolicy, use experimental for FQDN support
  kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/main/config/crd/experimental/policy.networking.k8s.io_clusternetworkpolicies.yaml

  # Load the Docker image into the kind cluster
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG"-npa-v1beta1 --name "$CLUSTER_NAME"

  # Install kube-network-policies
  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-npa-v1beta1#" -e "s/--v=2/--v=4/" < "$BATS_TEST_DIRNAME"/../install-cnp.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kube-network-policies
}

teardown_file() {
  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-npa-v1beta1#" -e "s/--v=2/--v=4/" < "$BATS_TEST_DIRNAME"/../install-cnp.yaml)
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
apiVersion: policy.networking.k8s.io/v1beta1
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
apiVersion: policy.networking.k8s.io/v1beta1
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
    protocols:
    - tcp:
        destinationPort:
          number: 80
    - tcp:
        destinationPort:
          number: 443
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

# https://github.com/kubernetes-sigs/kube-network-policies/issues/443
@test "a domain rule allows connections to a pod on another node" {
  # A packet between Pods on two nodes goes through the agents of both nodes. Only the node
  # of the client sees the DNS answers of the client, so it is the one that evaluates the
  # egress policies of the client. The node of the server must not evaluate them again, it
  # never saw the answer and would deny the connection.
  CLIENT_OVERRIDES="{\"apiVersion\":\"v1\",\"spec\":{\"nodeName\":\"${CLUSTER_NAME}-worker\"}}"
  SERVER_OVERRIDES="{\"apiVersion\":\"v1\",\"spec\":{\"nodeName\":\"${CLUSTER_NAME}-worker2\"}}"

  # Two echo servers on the other node, reachable through the DNS record of their headless
  # Service. The policy only allows the first one.
  for name in allowed forbidden; do
    kubectl -n prod run "$name" --image=alpine/socat --labels=app="$name" --overrides="$SERVER_OVERRIDES" -- TCP-LISTEN:8080,fork EXEC:cat
    kubectl -n prod expose pod "$name" --name="$name" --port=8080 --cluster-ip=None
  done
  kubectl -n prod wait --for=condition=ready pod/allowed pod/forbidden --timeout=60s

  kubectl apply -f - <<EOF
apiVersion: policy.networking.k8s.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: allow-dns-egress
spec:
  tier: Admin
  priority: 45
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-dns"
    action: "Accept"
    to:
    - namespaces:
        matchLabels:
          kubernetes.io/metadata.name: "kube-system"
    protocols:
    - udp:
        destinationPort:
          number: 53
    - tcp:
        destinationPort:
          number: 53
---
apiVersion: policy.networking.k8s.io/v1beta1
kind: ClusterNetworkPolicy
metadata:
  name: allow-server-by-domain
spec:
  tier: Admin
  priority: 55
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-server"
    action: "Accept"
    to:
    - domainNames:
      - "allowed.prod.svc.cluster.local"
    protocols:
    - tcp:
        destinationPort:
          number: 8080
  - name: "default-deny"
    action: "Deny"
    to:
    - networks:
      - "0.0.0.0/0"
      - "::/0"
EOF
  # propagation delay
  sleep 2

  # The client waits before connecting so the agents know the IP of the new Pod. Each
  # server echoes its own name back if the connection is allowed.
  output=$(kubectl -n dev run test-$RANDOM --image=alpine/socat --overrides="$CLIENT_OVERRIDES" --restart=Never -i --command -- sh -c "sleep 3; for name in allowed forbidden; do echo \$name | socat -T 3 STDIO TCP:\$name.prod.svc.cluster.local:8080,connect-timeout=3; done; true" || true)
  echo "Servers that answered: '$output'"
  kubectl delete clusternetworkpolicy allow-dns-egress allow-server-by-domain --ignore-not-found
  test "$output" = "allowed"
}
