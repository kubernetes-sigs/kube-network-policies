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

# Checks if the last line of a file matches an expected string
check_last_line() {
  local file="$1"
  local expected_string="$2"
  local last_line=$(tail -n 1 "$file" 2>/dev/null || true)

  if [ "$last_line" = "$expected_string" ]; then
    return 0 # Match found
  else
    echo "Expected: '$expected_string', but got: '$last_line'"
    return 1 # No match
  fi
}

# Polls a check function twice per second for up to 5 seconds
busywait() {
  local check_function="$1"
  shift # Remove function name from arguments
  local retries="10"
  local interval="0.5"

  for i in $(seq 1 "$retries"); do
    if "$check_function" "$@"; then
      return 0 # Success
    fi
    sleep "$interval"
  done

  return 1 # Timeout
}

# Prints the number of runs of the firewall enforcer logged by the agent on the node
enforcer_runs() {
  local node="$1"
  local pod
  pod=$(kubectl -n kube-system get pods -l k8s-app=kube-network-policies --field-selector spec.nodeName="$node" -o name)
  kubectl -n kube-system logs "$pod" | grep -c "Completed enforcing firewall policies" || true
}

# Waits until the firewall enforcer on the node completed more runs than the given count,
# the runner coalesces the runs so it can take up to 30 seconds
wait_for_enforcer() {
  local node="$1"
  local runs_before="$2"
  for i in $(seq 1 60); do
    if [ "$(enforcer_runs "$node")" -gt "$runs_before" ]; then
      return 0
    fi
    sleep 1
  done
  echo "the firewall enforcer did not run on $node"
  return 1
}

# https://github.com/kubernetes-sigs/kube-network-policies/issues/439
@test "established connections to a domain survive the expiry of the DNS answer" {
  # The firewall enforcer of the strict mode re-evaluates the established connections on
  # every dataplane sync. A connection allowed only by a domainNames peer must stay allowed
  # after the TTL of the DNS answer that admitted its IP expired, the expiry only stops new
  # connections. Both pods run on the same node, the one whose agent saw the DNS answer.
  NODE="${CLUSTER_NAME}-worker"
  OVERRIDES="{\"apiVersion\":\"v1\",\"spec\":{\"nodeName\":\"$NODE\"}}"

  # An echo server, reachable through the DNS record of a headless Service: CoreDNS answers
  # with the Pod IP and the TTL kubeadm configures for cluster records, 30 seconds.
  kubectl -n prod run server --image=alpine/socat --labels=app=server --overrides="$OVERRIDES" -- TCP-LISTEN:8080,fork EXEC:cat
  kubectl -n prod wait --for=condition=ready pod/server --timeout=60s
  kubectl -n prod expose pod server --name=server --port=8080 --cluster-ip=None

  # The client can resolve names and connect to the server only by its domain name.
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
      - "server.prod.svc.cluster.local"
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

  # The client resolves the name and opens one connection that it keeps for the whole test.
  TMPFILEIN=$(mktemp)
  TMPFILEOUT=$(mktemp)
  tail -f "$TMPFILEIN" | kubectl -n dev run -i client --image alpine/socat --overrides="$OVERRIDES" -- -ddd STDIO "TCP:server.prod.svc.cluster.local:8080" >> "$TMPFILEOUT" 2>/dev/null &
  CLIENT_PID=$!

  # Wait for the client to start running, since kubectl run is asynchronous
  sleep 2
  kubectl -n dev wait --for=condition=ready pod/client --timeout=60s

  echo "Hello World" >> "$TMPFILEIN"
  busywait check_last_line "$TMPFILEOUT" "Hello World"
  echo "Initial connection established."

  # Let the DNS answer expire from the cache of the agent with no new lookup. The check
  # with a new connection at the end verifies that it did expire.
  sleep 32

  # A NetworkPolicy that selects a Pod on the node triggers a dataplane sync, so a run of
  # the firewall enforcer on the established connections. Allowing all ingress to the client
  # changes nothing for its connection.
  RUNS_BEFORE=$(enforcer_runs "$NODE")
  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: trigger-enforcer
  namespace: dev
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - {}
EOF
  wait_for_enforcer "$NODE" "$RUNS_BEFORE"
  echo "The firewall enforcer re-evaluated the established connections."

  echo "Hello after the TTL" >> "$TMPFILEIN"
  if ! busywait check_last_line "$TMPFILEOUT" "Hello after the TTL"; then
    echo "The connection to the domain was revoked after the DNS answer expired."
    kubectl -n kube-system logs -l k8s-app=kube-network-policies --tail=50 || true
    kill "$CLIENT_PID" > /dev/null 2>&1 || true
    kubectl delete clusternetworkpolicy allow-dns-egress allow-server-by-domain --ignore-not-found
    rm -f "$TMPFILEIN" "$TMPFILEOUT"
    return 1
  fi
  echo "The connection to the domain survived the expiry of the DNS answer."

  # A new connection after the TTL needs a new lookup, the expired answer does not allow it.
  # The client waits before connecting so the agent knows the IP of the new Pod.
  SERVER_IP=$(kubectl -n prod get pod server -o jsonpath='{.status.podIP}')
  output=$(kubectl -n dev run test-$RANDOM --image=alpine/socat --overrides="$OVERRIDES" --restart=Never -i --command -- sh -c "sleep 3; echo new connection | socat -T 3 STDIO TCP:$SERVER_IP:8080,connect-timeout=3" || true)
  echo "New connection to the IP without a lookup: '$output'"
  test "$output" != "new connection"

  kill "$CLIENT_PID" > /dev/null 2>&1 || true
  kubectl delete clusternetworkpolicy allow-dns-egress allow-server-by-domain --ignore-not-found
  rm -f "$TMPFILEIN" "$TMPFILEOUT"
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
