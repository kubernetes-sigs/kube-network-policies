#!/usr/bin/env bats

setup_file() {
  export REGISTRY="registry.k8s.io/networking"
  export IMAGE_NAME="kube-network-policies"
  export TAG="test-standard"

  # Build the image for the standard binary and amd64 architecture
  (
    cd "$BATS_TEST_DIRNAME"/..
    TAG="$TAG" make image-build-standard
  )

  # Load the Docker image into the kind cluster
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG" --name "$CLUSTER_NAME"

  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG#" -e "s/--v=2/--v=4/" < "$BATS_TEST_DIRNAME"/../install.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl wait --for=condition=ready pods --namespace=kube-system -l k8s-app=kube-network-policies
}

teardown_file() {
  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG#" -e "s/--v=2/--v=4/" < "$BATS_TEST_DIRNAME"/../install.yaml)
  printf '%s' "${_install}" | kubectl delete -f -
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

# Polls a check function 10 times per second for up to 5 seconds
busywait() {
  local check_function="$1"
  shift # Remove function name from arguments
  # "$@" now contains all remaining arguments (e.g., file and string)

  # Calculate retries (10 per second)
  local retries="10" # 5 seconds timeout
  local interval="0.5"

  for i in $(seq 1 "$retries"); do
    # Call the function (e.g., "check_last_line" "$outputfile" "$string")
    if "$check_function" "$@"; then
      return 0 # Success
    fi
    sleep "$interval"
  done

  return 1 # Timeout
}

# https://github.com/kubernetes-sigs/kube-network-policies/issues/150
@test "liveness probes" {
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
  # propagation delay
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
  echo "Pod is ready."
  restart_count=$(kubectl get pod myapp-pod -n dev -o jsonpath='{.status.containerStatuses[0].restartCount}')
  echo "Pod restarted $restart_count times"
  test "$restart_count" = "0"
  # cleanup
  kubectl -n dev delete pod myapp-pod
  kubectl -n dev delete networkpolicy default-deny-all
}

@test "allow traffic from a namespace" {
  # https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/06-allow-traffic-from-a-namespace.md

  kubectl apply -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-allow-prods
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          purpose: production
EOF
  # propagation delay
  sleep 1
  # query should be blocked
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://web.default && echo ok || echo fail")
  echo "Connect to webserver should fail: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "fail"

  # query should work
  output=$(kubectl run test-$RANDOM --namespace=prod --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://web.default && echo ok || echo fail")
  echo "Connect to webserver should work: $output"
  kubectl --namespace=prod get pods -o wide
  test "$output" = "ok"

  # cleanup
  kubectl delete networkpolicy web-allow-prods
}


@test "ICMPv6 ping6 with network policies" {
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  namespace: dev
  name: client-pod
spec:
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

  TARGET_IPv6=$(kubectl get pod target-pod -n prod -o jsonpath='{.status.podIPs[1].ip}' 2>/dev/null || echo "")
  test -n "$TARGET_IPv6"

  # query should work
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

  # propagation delay
  sleep 2

  # query should be blocked
  output=$(kubectl exec client-pod -n dev -- ping6 -c 2 -W 5 "$TARGET_IPv6" > /dev/null 2>&1 && echo ok || echo fail)
  test "$output" = "fail"

  # cleanup
  kubectl -n dev delete pod client-pod
  kubectl -n prod delete pod target-pod
  kubectl -n prod delete networkpolicy allow-same-namespace
}


@test "network policy drops established connections" {
  # Create webserver pod in the 'prod' namespace
  kubectl -n prod run webserver --image=alpine/socat --labels=app=web -- TCP-LISTEN:8080,fork SYSTEM:"while true; do cat; done"

  kubectl -n prod wait --for=condition=ready pod/webserver --timeout=30s
  WEBSERVER_IP=$(kubectl get pod webserver -n prod -o jsonpath='{.status.podIP}')

  # Allow connection from 'dev' namespace to 'prod' namespace
  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-client
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          purpose: testing
EOF
  sleep 2

  # Create client pod in the 'dev' namespace that connects to the webserver
  TMPFILEIN=$(mktemp)
  TMPFILEOUT=$(mktemp)
  tail -f "$TMPFILEIN" | kubectl -n dev run -i client --image alpine/socat -- -ddd STDIO "TCP:$WEBSERVER_IP:8080" >> "$TMPFILEOUT" 2>/dev/null &
  CLIENT_PID=$!

  # Wait for the client to start running, since kubectl run is asynchronous
  sleep 2
  kubectl -n dev wait --for=condition=ready pod/client --timeout=30s

  echo "Hello World" >> "$TMPFILEIN"
  busywait check_last_line "$TMPFILEOUT" "Hello World"
  echo "Initial connection established."

  # Delete the allow-client policy
  kubectl -n prod delete networkpolicy allow-client
  sleep 2
  # The client should be working because no network policy is applied
  kubectl -n dev wait --for=condition=ready pod/client --timeout=30s
  echo "Keepalive without policies" >> "$TMPFILEIN"
  busywait check_last_line "$TMPFILEOUT" "Keepalive without policies"
  echo "Connection still active after deleting allow-client policy."

  # Deny all ingress traffic to the webserver
  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
EOF

  # enforcer runs every 30 seconds, wait a bit longer
  sleep 31

  echo "Keepalive default-deny-ingress policy" >> "$TMPFILEIN"
  if busywait check_last_line "$TMPFILEOUT" "Keepalive default-deny-ingress policy"; then
    echo "Connection still active after applying default-deny-ingress policy."
    kill "$CLIENT_PID" > /dev/null 2>&1 || true
    kubectl delete pod webserver -n prod --ignore-not-found
    kubectl delete pod client -n dev --ignore-not-found
    kubectl delete networkpolicy default-deny-ingress -n prod --ignore-not-found
    echo "Input file: $TMPFILEIN , Output file: $TMPFILEOUT"
    return 1
  fi
  echo "Connection forbidden after applying default-deny-ingress policy."
  # Check that new messages are not received
  busywait check_last_line "$TMPFILEOUT" "Keepalive without policies"

  kill "$CLIENT_PID" > /dev/null 2>&1 || true
  # Cleanup: delete resources created by this test
  kubectl delete pod webserver -n prod --ignore-not-found
  kubectl delete pod client -n dev --ignore-not-found
  kubectl delete networkpolicy default-deny-ingress -n prod --ignore-not-found
  rm -f "$TMPFILEIN" "$TMPFILEOUT"
}
