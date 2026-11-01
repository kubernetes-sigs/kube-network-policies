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

# https://github.com/kubernetes-sigs/kube-network-policies/issues/380
# https://github.com/kubernetes-sigs/kube-network-policies/issues/379
@test "hostNetwork pods do not cause node IP leakage into managed IPs" {
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hostnet-server
  namespace: dev
spec:
  hostNetwork: true
  containers:
  - name: agnhost
    image: registry.k8s.io/e2e-test-images/agnhost:2.39
    args:
    - netexec
    - --http-port=9999
EOF

  kubectl -n dev wait --for=condition=ready pod/hostnet-server --timeout=30s

  NODE_NAME=$(kubectl get pod hostnet-server -n dev -o jsonpath='{.spec.nodeName}')
  NODE_IP=$(kubectl get pod hostnet-server -n dev -o jsonpath='{.status.podIP}')

  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-client
  namespace: dev
spec:
  nodeName: ${NODE_NAME}
  containers:
  - name: busybox
    image: registry.k8s.io/busybox:1.27
    command:
    - sleep
    - "3600"
EOF

  kubectl -n dev wait --for=condition=ready pod/test-client --timeout=30s

  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: dev
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

  sleep 2

  # Client pod on the same node should be able to connect to hostnet-server on NODE_IP:9999
  kubectl -n dev exec test-client -- wget -T 5 -q -O - "http://${NODE_IP}:9999/hostname"

  kubectl delete pod hostnet-server -n dev --ignore-not-found
  kubectl delete pod test-client -n dev --ignore-not-found
  kubectl delete networkpolicy default-deny-ingress -n dev --ignore-not-found
}


# https://github.com/kubernetes-sigs/kube-network-policies/issues/415
@test "denied connections are logged with the default manifest" {
  # Run the agent with the verbosity of the manifest, the denied packets are
  # logged by default (--log-verdicts=deny) without the per-packet trace of --v=4
  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG#" < "$BATS_TEST_DIRNAME"/../install.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl -n kube-system rollout status ds/kube-network-policies --timeout=120s
  args=$(kubectl -n kube-system get ds kube-network-policies -o jsonpath='{.spec.template.spec.containers[0].args}')
  echo "Agent args: $args"
  echo "$args" | grep -q -- '--v=2'
  ! echo "$args" | grep -q -- '--log-verdicts'

  kubectl apply -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-deny-all
spec:
  podSelector:
    matchLabels:
      app: web
  ingress: []
EOF
  # propagation delay
  sleep 1

  # query should be blocked
  client="test-$RANDOM"
  output=$(kubectl run "$client" --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://web.default && echo ok || echo fail")
  echo "Connect to webserver should fail: $output"
  test "$output" = "fail"

  # the denial is logged by the agent on the node of the webserver, the pod that the policy selects
  logs=$(kubectl -n kube-system logs -l k8s-app=kube-network-policies --tail=-1 | grep '"Packet verdict"' || true)
  echo "Verdicts logged: $logs"
  echo "$logs" | grep -q 'verdict="deny"'
  echo "$logs" | grep -q "srcPod=\"dev/$client\""
  echo "$logs" | grep -q 'dstPod="default/web"'
  echo "$logs" | grep -q 'direction="ingress"'
  echo "$logs" | grep -q 'evaluator="StandardNetworkPolicy"'
  # the trace is not logged
  ! kubectl -n kube-system logs -l k8s-app=kube-network-policies --tail=-1 | grep -q '"Evaluating packet"'

  # cleanup
  kubectl delete networkpolicy web-deny-all
  _install=$(sed -e "s#$REGISTRY/$IMAGE_NAME.*#$REGISTRY/$IMAGE_NAME:$TAG#" -e "s/--v=2/--v=4/" < "$BATS_TEST_DIRNAME"/../install.yaml)
  printf '%s' "${_install}" | kubectl apply -f -
  kubectl -n kube-system rollout status ds/kube-network-policies --timeout=120s
}

# agent_logged returns 0 if the kube-network-policies pod on the node logged the string
agent_logged() {
  local agent
  agent=$(kubectl -n kube-system get pods -l k8s-app=kube-network-policies --field-selector "spec.nodeName=$1" -o name)
  test -n "$agent" && kubectl -n kube-system logs "$agent" --tail=-1 | grep -q -- "$2"
}

# move_ipam_cursor_before makes host-local hand out the given IPv4 and IPv6
# addresses on the next allocation on the node. kindnet uses host-local IPAM
# and allocates the address after the last reserved one.
move_ipam_cursor_before() {
  local node="$1" a4="$2" a6="$3" ipam_dir="/run/cni-ipam-state/kindnet"
  local prev4 prev6
  prev4="${a4%.*}.$(( ${a4##*.} - 1 ))"
  prev6="${a6%:*}:$(printf '%x' $(( 16#${a6##*:} - 1 )))"
  echo "moving the IPAM cursors to $prev4 and $prev6"
  docker exec "$node" flock "$ipam_dir/lock" sh -c "printf '%s' '$prev4' > '$ipam_dir/last_reserved_ip.0' && printf '%s' '$prev6' > '$ipam_dir/last_reserved_ip.1'"
}

# wait_ipam_released waits until host-local removed the reservation files of the IPs
wait_ipam_released() {
  local node="$1" a4="$2" a6="$3" ipam_dir="/run/cni-ipam-state/kindnet" i
  for i in $(seq 1 20); do
    if ! docker exec "$node" test -e "$ipam_dir/$a4" && ! docker exec "$node" test -e "$ipam_dir/$a6"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# https://github.com/kubernetes-sigs/kube-network-policies/issues/414
# A finished pod keeps its IPs in the apiserver, a new pod that gets those IPs
# must be evaluated with its own policies from its first packet. kindnet uses
# host-local IPAM, so the reuse is forced by moving the allocation cursor back.
@test "a pod reusing the IPs of a finished pod is denied from its first packet" {
  local node="${CLUSTER_NAME}-worker"

  # The test only means something if the agent on the node is connected to the runtime
  if ! agent_logged "$node" "Synchronized state with the runtime"; then
    skip "NRI is not enabled on $node"
  fi

  local web4 web6
  web4=$(kubectl get pod web -o jsonpath='{.status.podIPs[0].ip}')
  web6=$(kubectl get pod web -o jsonpath='{.status.podIPs[1].ip}')
  echo "web server at $web4 and $web6"

  # Pod A is selected by a policy that allows everything, so its IPs stay in
  # the dataplane set after it finishes. Pod B is denied all egress.
  kubectl apply -f - <<EOP
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-pod-a
  namespace: dev
spec:
  podSelector:
    matchLabels:
      app: pod-a
  policyTypes:
  - Egress
  egress:
  - {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-pod-b
  namespace: dev
spec:
  podSelector:
    matchLabels:
      app: pod-b
  policyTypes:
  - Egress
EOP
  sleep 1

  kubectl -n dev run pod-a --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --labels="app=pod-a" --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$node\"}}" --command -- sleep 1
  kubectl -n dev wait --for=jsonpath='{.status.phase}'=Succeeded pod/pod-a --timeout=60s
  local a4 a6
  a4=$(kubectl -n dev get pod pod-a -o jsonpath='{.status.podIPs[0].ip}')
  a6=$(kubectl -n dev get pod pod-a -o jsonpath='{.status.podIPs[1].ip}')
  echo "pod-a finished with $a4 and $a6"

  wait_ipam_released "$node" "$a4" "$a6"
  move_ipam_cursor_before "$node" "$a4" "$a6"

  # Pod B connects to the server from its first instant
  kubectl -n dev run pod-b --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --labels="app=pod-b" --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$node\"}}" --command -- bash -c "
      for i in \$(seq 1 5); do
        curl -s --connect-timeout 1 -o /dev/null http://$web4/ && echo ok4 || echo fail4
        curl -g -s --connect-timeout 1 -o /dev/null http://[$web6]/ && echo ok6 || echo fail6
      done"
  kubectl -n dev wait --for=jsonpath='{.status.phase}'=Succeeded pod/pod-b --timeout=60s
  local b4 b6
  b4=$(kubectl -n dev get pod pod-b -o jsonpath='{.status.podIPs[0].ip}')
  b6=$(kubectl -n dev get pod pod-b -o jsonpath='{.status.podIPs[1].ip}')
  echo "pod-b got $b4 and $b6"
  test "$b4" = "$a4"
  test "$b6" = "$a6"

  local output
  output=$(kubectl -n dev logs pod-b)
  echo "pod-b connections: $output"
  test "$(grep -c '^ok' <<<"$output")" = "0"
  test "$(grep -c '^fail' <<<"$output")" = "10"

  # Positive control, the server is reachable from a pod without policies.
  # The output is read from the logs, kubectl run -i may print it twice when
  # the attach falls back to streaming the logs.
  kubectl -n dev run pod-c --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$node\"}}" --command -- bash -c "curl -s --connect-timeout 5 -o /dev/null http://$web4/ && echo ok || echo fail"
  kubectl -n dev wait --for=jsonpath='{.status.phase}'=Succeeded pod/pod-c --timeout=60s
  output=$(kubectl -n dev logs pod-c)
  echo "connect to webserver should work: $output"
  test "$output" = "ok"

  kubectl -n dev delete networkpolicy allow-pod-a deny-pod-b
}

# The fix for issue 414 relies on the runtime: NRI releases the IPs when the
# pod finishes, while the apiserver still shows them; a reconnect to the
# runtime does not bring the finished pod back as the owner; and the late
# removal of the finished pod, with the IPs that belong to another pod now,
# does not change the verdict for that pod.
@test "the owner of a reused IP survives a runtime reconnect and the removal of the finished pod" {
  local node="${CLUSTER_NAME}-worker"

  if ! agent_logged "$node" "Synchronized state with the runtime"; then
    skip "NRI is not enabled on $node"
  fi

  local web4
  web4=$(kubectl get pod web -o jsonpath='{.status.podIPs[0].ip}')

  kubectl apply -f - <<EOP
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-pod-b
  namespace: dev
spec:
  podSelector:
    matchLabels:
      app: pod-b
  policyTypes:
  - Egress
EOP
  sleep 1

  kubectl -n dev run pod-a --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --labels="app=pod-a" --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$node\"}}" --command -- sleep 1
  kubectl -n dev wait --for=jsonpath='{.status.phase}'=Succeeded pod/pod-a --timeout=60s
  local a4 a6
  a4=$(kubectl -n dev get pod pod-a -o jsonpath='{.status.podIPs[0].ip}')
  a6=$(kubectl -n dev get pod pod-a -o jsonpath='{.status.podIPs[1].ip}')
  echo "pod-a finished, the apiserver still shows $a4 and $a6"
  test -n "$a4" && test -n "$a6"

  # The runtime released the IPs when the pod finished
  busywait agent_logged "$node" "Stopping Pod dev/pod-a"
  wait_ipam_released "$node" "$a4" "$a6"

  # Reconnect to the runtime, the snapshot lists the stopped sandbox of pod-a
  kubectl -n kube-system delete pod -l k8s-app=kube-network-policies --field-selector "spec.nodeName=$node" --wait=true
  local i
  for i in $(seq 1 30); do
    kubectl -n kube-system get pods -l k8s-app=kube-network-policies --field-selector "spec.nodeName=$node" -o name | grep -q . && break
    sleep 1
  done
  kubectl -n kube-system wait --for=condition=ready pods -l k8s-app=kube-network-policies --field-selector "spec.nodeName=$node" --timeout=60s
  busywait agent_logged "$node" "Synchronized state with the runtime"

  move_ipam_cursor_before "$node" "$a4" "$a6"
  kubectl -n dev run pod-b --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --labels="app=pod-b" --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$node\"}}" --command -- sleep 3600
  kubectl -n dev wait --for=condition=ready pod/pod-b --timeout=60s
  local b4
  b4=$(kubectl -n dev get pod pod-b -o jsonpath='{.status.podIPs[0].ip}')
  echo "pod-b got $b4"
  test "$b4" = "$a4"

  # The finished pod is deleted, the kubelet removes its sandbox later and the
  # event carries the IPs that belong to pod-b now
  kubectl -n dev delete pod pod-a --wait=false
  for i in $(seq 1 90); do agent_logged "$node" "Removing Pod dev/pod-a" && break; sleep 1; done
  agent_logged "$node" "Removing Pod dev/pod-a"

  local output
  output=$(kubectl -n dev exec pod-b -- bash -c "curl -s --connect-timeout 2 -o /dev/null http://$web4/ && echo ok || echo fail")
  echo "pod-b connection after the removal of pod-a: $output"
  test "$output" = "fail"

  kubectl -n dev delete networkpolicy deny-pod-b
}
