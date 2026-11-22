#!/usr/bin/env bats

setup_file() {
  export REGISTRY="registry.k8s.io/networking"
  export IMAGE_NAME="kube-network-policies"
  export TAG="test"

  # Build the image for the dht binary
  (
    cd "$BATS_TEST_DIRNAME"/..
    TAG="$TAG" make image-build-dht
  )

  # Load the Docker image into the kind cluster
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG"-dht --name "$CLUSTER_NAME"

  # Install kube-network-policies in 1-Hop Agent DHT mode
  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-dht#" -e "s/--v=2/--v=4/" < "$BATS_TEST_DIRNAME"/../install-dht.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kube-network-policies --timeout=120s
  # Wait for EndpointSlices and initial DHT ring sync across all nodes.
  sleep 2
}

teardown_file() {
  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG-dht#" -e "s/--v=2/--v=4/" < "$BATS_TEST_DIRNAME"/../install-dht.yaml)
  printf '%s' "${_install}" | kubectl delete -f -
  kubectl wait --for=delete pods --namespace=kube-system -l k8s-app=kube-network-policies --timeout=60s || true
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

pick_two_nodes() {
  NODES=($(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[*].metadata.name}'))
  if [ "${#NODES[@]}" -lt 2 ]; then
    NODES=($(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'))
  fi
  test "${#NODES[@]}" -ge 2
  NODE_A="${NODES[0]}"
  NODE_B="${NODES[1]}"
}

@test "dht: liveness probes with default-deny-all" {
  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: dev
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF
  sleep 1

  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
  namespace: dev
  labels:
    app: myapp
spec:
  containers:
    - name: agnhost
      image: registry.k8s.io/e2e-test-images/agnhost:2.39
      args:
        - netexec
        - --http-port=1234
      livenessProbe:
        failureThreshold: 5
        periodSeconds: 2
        tcpSocket:
          port: 1234
      readinessProbe:
        failureThreshold: 5
        periodSeconds: 2
        tcpSocket:
          port: 1234
      ports:
        - containerPort: 1234
          name: tcp1234
EOF

  kubectl -n dev wait --for=condition=ready pod/myapp-pod --timeout=20s
  restart_count=$(kubectl get pod myapp-pod -n dev -o jsonpath='{.status.containerStatuses[0].restartCount}')
  test "$restart_count" = "0"

  kubectl -n dev delete pod myapp-pod
  kubectl -n dev delete networkpolicy default-deny-all
}

@test "dht: cross-node allow from namespace and react to pod label mutation" {
  pick_two_nodes

  # Pin server pod on NODE_A and client pods on NODE_B so traffic MUST cross
  # nodes and resolve remote PodInfo via the 1-hop DHT.
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: web-target
  namespace: prod
  labels:
    app: web-target
spec:
  nodeName: ${NODE_A}
  containers:
    - name: agnhost
      image: registry.k8s.io/e2e-test-images/agnhost:2.39
      args:
        - netexec
        - --http-port=8080
      ports:
        - containerPort: 8080
          name: http
EOF

  kubectl apply -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-allow-prods
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: web-target
  policyTypes:
  - Ingress
  ingress:
  - ports:
    - protocol: TCP
      port: http
    from:
    - namespaceSelector:
        matchLabels:
          purpose: production
      podSelector:
        matchLabels:
          access: allowed
EOF

  kubectl -n prod wait --for=condition=ready pod/web-target --timeout=30s
  TARGET_IP=$(kubectl -n prod get pod web-target -o jsonpath='{.status.podIP}')
  test -n "$TARGET_IP"

  # Client in dev namespace on NODE_B must be blocked.
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: client-dev
  namespace: dev
  labels:
    access: allowed
spec:
  nodeName: ${NODE_B}
  containers:
    - name: agnhost
      image: registry.k8s.io/e2e-test-images/agnhost:2.39
      command: ["sleep", "3600"]
EOF
  kubectl -n dev wait --for=condition=ready pod/client-dev --timeout=30s

  output=$(kubectl -n dev exec client-dev -- bash -c "curl -q -s --connect-timeout 3 --output /dev/null http://${TARGET_IP}:8080 && echo ok || echo fail")
  test "$output" = "fail"

  # Client in prod namespace on NODE_B without access=allowed is blocked, then
  # allowed after live label mutation once CacheTTL (10s) refreshes.
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: client-mut
  namespace: prod
spec:
  nodeName: ${NODE_B}
  containers:
    - name: agnhost
      image: registry.k8s.io/e2e-test-images/agnhost:2.39
      command: ["sleep", "3600"]
EOF
  kubectl -n prod wait --for=condition=ready pod/client-mut --timeout=30s

  output=$(kubectl -n prod exec client-mut -- bash -c "curl -q -s --connect-timeout 3 --output /dev/null http://${TARGET_IP}:8080 && echo ok || echo fail")
  test "$output" = "fail"

  kubectl -n prod label pod client-mut access=allowed

  # Poll past CacheTTL (10s) for cross-node convergence.
  passed="false"
  for _ in $(seq 1 15); do
    output=$(kubectl -n prod exec client-mut -- bash -c "curl -q -s --connect-timeout 2 --output /dev/null http://${TARGET_IP}:8080 && echo ok || echo fail")
    if [ "$output" = "ok" ]; then
      passed="true"
      break
    fi
    sleep 1
  done
  test "$passed" = "true"

  kubectl -n dev delete pod client-dev
  kubectl -n prod delete pod client-mut web-target
  kubectl -n prod delete networkpolicy web-allow-prods
}

@test "dht: cross-node ICMPv6 ping6 with network policies" {
  pick_two_nodes

  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  namespace: dev
  name: client-pod
spec:
  nodeName: ${NODE_B}
  containers:
    - name: busybox
      image: registry.k8s.io/busybox:1.27
      command:
        - sleep
        - "3600"
      securityContext:
        privileged: true
EOF

  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  namespace: prod
  name: target-pod
spec:
  nodeName: ${NODE_A}
  containers:
    - name: busybox
      image: registry.k8s.io/busybox:1.27
      command:
        - sleep
        - "3600"
      securityContext:
        privileged: true
EOF

  kubectl -n dev wait --for=condition=ready pod/client-pod --timeout=30s
  kubectl -n prod wait --for=condition=ready pod/target-pod --timeout=30s

  TARGET_IPv6=$(kubectl get pod target-pod -n prod -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' | grep ':' | head -n 1)
  test -n "$TARGET_IPv6"

  output=$(kubectl exec client-pod -n dev -- ping6 -c 2 -W 5 "$TARGET_IPv6" > /dev/null 2>&1 && echo ok || echo fail)
  test "$output" = "ok"

  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  namespace: prod
  name: allow-same-namespace
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
EOF
  sleep 2

  output=$(kubectl exec client-pod -n dev -- ping6 -c 2 -W 5 "$TARGET_IPv6" > /dev/null 2>&1 && echo ok || echo fail)
  test "$output" = "fail"

  kubectl -n dev delete pod client-pod
  kubectl -n prod delete pod target-pod
  kubectl -n prod delete networkpolicy allow-same-namespace
}
