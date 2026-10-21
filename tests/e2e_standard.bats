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


# --- Pod IP reuse ---
# https://github.com/kubernetes-sigs/kube-network-policies/issues/414
#
# A new Pod B gets the IPs of a completed Pod A, whose object still has them,
# by moving the host-local allocation cursors of the node before B starts.

# reuse_diagnostics prints the state that explains a failure of the IP reuse test.
reuse_diagnostics() {
  echo "--- IP reuse diagnostics"
  echo "node=${REUSE_NODE:-} agent=${REUSE_AGENT:-} ipam=${REUSE_IPAM_DIR:-}"
  echo "pod A IPs: ${REUSE_A4:-} ${REUSE_A6:-}, server IPs: ${REUSE_S4:-} ${REUSE_S6:-}"
  kubectl get pods -A -o wide --field-selector "spec.nodeName=${REUSE_NODE:-}" || true
  kubectl -n dev get pods,networkpolicies -o wide || true
  kubectl -n prod get pods -o wide || true
  for pod in ${REUSE_A:-} ${REUSE_B:-}; do
    kubectl -n dev get pod "$pod" -o jsonpath='{.metadata.name} {.metadata.uid} {.status.phase} {.status.podIPs}{"\n"}' || true
  done
  if [ -n "${REUSE_B:-}" ]; then
    kubectl -n dev logs "$REUSE_B" || true
  fi
  if [ -n "${REUSE_IPAM_DIR:-}" ]; then
    docker exec "$REUSE_NODE" sh -c 'ls -la "$1"; for f in "$1"/last_reserved_ip.*; do echo "$f: $(cat "$f")"; done' _ "$REUSE_IPAM_DIR" || true
  fi
  if [ -n "${REUSE_AGENT:-}" ]; then
    kubectl -n kube-system logs "$REUSE_AGENT" |
      grep -E "Synchronized state|nri|NRI|Starting Pod dev/|Stopping Pod dev/|Packet denied|Unresolved Pod IP|srcPod=\"dev/" |
      tail -n 100 || true
  fi
}

# reuse_fail prints the reason and the diagnostics, and fails the test.
reuse_fail() {
  echo "IP reuse test failed: $*"
  reuse_diagnostics
  return 1
}

# reuse_pod_ip prints the IPv4 or IPv6 address of the Pod.
reuse_pod_ip() {
  local namespace="$1" pod="$2" family="$3"
  kubectl -n "$namespace" get pod "$pod" -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' |
    if [ "$family" = ipv6 ]; then grep ':' || true; else grep -v ':' || true; fi
}

# reuse_wait_finished waits for the Pod to complete and prints its phase.
reuse_wait_finished() {
  local namespace="$1" pod="$2" seconds="$3" phase=""
  for _ in $(seq 1 $((seconds * 2))); do
    phase=$(kubectl -n "$namespace" get pod "$pod" -o jsonpath='{.status.phase}')
    if [ "$phase" = Succeeded ] || [ "$phase" = Failed ]; then
      break
    fi
    sleep 0.5
  done
  echo "$phase"
}

# reuse_previous_ip prints the address before the IP. The last IPv4 octet or
# IPv6 group must not be zero, host-local never allocates those addresses.
reuse_previous_ip() {
  local ip="$1" last
  if [[ "$ip" == *:* ]]; then
    last="${ip##*:}"
    [[ "$last" =~ ^[0-9a-fA-F]{1,4}$ ]] && (( 16#$last > 0 )) || return 1
    printf '%s:%x\n' "${ip%:*}" $(( 16#$last - 1 ))
  else
    last="${ip##*.}"
    [[ "$last" =~ ^[0-9]{1,3}$ ]] && (( last > 0 )) || return 1
    printf '%s.%d\n' "${ip%.*}" $(( last - 1 ))
  fi
}

# reuse_verdicts prints "<packets> <evaluated as the Pod> <denied>" for the
# egress packets from the IP to the destination IP:port in the agent logs. The
# packet line follows the "Evaluating packet" line in the klog text format:
#   "Evaluating packet" id=9 direction="Egress" srcPod="dev/b" dstPod="prod/s" packet=<
#           [9] 10.244.1.5:40243 10.244.2.9:8080 TCP
reuse_verdicts() {
  local logs="$1" pod="$2" src="$3" dst="$4"
  awk -v pod="$pod" -v src="$src" -v dst="$dst" '
    /"Evaluating packet" id=[0-9]+ direction="Egress"/ {
      match($0, /id=[0-9]+/); id = substr($0, RSTART + 3, RLENGTH - 3)
      match($0, /srcPod="[^"]*"/); srcpod = substr($0, RSTART + 8, RLENGTH - 9)
      pending = 1
      next
    }
    pending {
      pending = 0
      if ($1 == "[" id "]") {
        ip = $2; sub(/:[0-9]+$/, "", ip)
        if (ip == src && $3 == dst && $4 == "TCP") packets[id] = srcpod
        next
      }
    }
    /"Packet denied by egress policy" id=[0-9]+/ {
      match($0, /id=[0-9]+/); denied[substr($0, RSTART + 3, RLENGTH - 3)] = 1
    }
    END {
      for (id in packets) {
        total++
        if (packets[id] == pod) { own++; if (id in denied) deny++ }
      }
      printf "%d %d %d\n", total, own, deny
    }
  ' <<<"$logs"
}

@test "new pod reusing the IPs of a completed pod is denied from its first packets" {
  REUSE_ID=$RANDOM
  REUSE_A="reuse-old-$REUSE_ID"
  REUSE_B="reuse-blocked-$REUSE_ID"
  REUSE_CONTROL="reuse-control-$REUSE_ID"
  REUSE_SERVER="reuse-server-$REUSE_ID"
  local image="registry.k8s.io/e2e-test-images/agnhost:2.39"
  for tool in docker jq; do
    if ! command -v "$tool" >/dev/null; then
      reuse_fail "$tool is required to inspect the IPAM state of the kind node"
    fi
  done

  # A and B run on one worker, the server on the other one.
  mapfile -t workers < <(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
  if [ "${#workers[@]}" -lt 2 ]; then
    reuse_fail "two worker nodes are required, found: ${workers[*]}"
  fi
  REUSE_NODE="${workers[0]}"
  local server_node="${workers[1]}"
  REUSE_AGENT=$(kubectl -n kube-system get pods -l k8s-app=kube-network-policies --field-selector "spec.nodeName=$REUSE_NODE" -o jsonpath='{.items[*].metadata.name}')
  REUSE_AGENT="${REUSE_AGENT%% *}"
  if [ -z "$REUSE_AGENT" ]; then
    reuse_fail "no kube-network-policies agent runs on $REUSE_NODE"
  fi

  # Only NRI knows that B owns the IPs before the API server reports them.
  if ! kubectl -n kube-system logs "$REUSE_AGENT" | grep -q "Synchronized state with the runtime"; then
    reuse_fail "NRI unavailable: agent $REUSE_AGENT did not synchronize with the runtime"
  fi

  # The host-local IPAM configuration of the kind node.
  if [ "$(docker exec "$REUSE_NODE" hostname)" != "$REUSE_NODE" ]; then
    reuse_fail "the docker container $REUSE_NODE is not the node $REUSE_NODE"
  fi
  local conflist ipam data_dir range4 range6 pod_cidrs
  if ! conflist=$(docker exec "$REUSE_NODE" cat /etc/cni/net.d/10-kindnet.conflist); then
    reuse_fail "the kindnet CNI configuration is missing on $REUSE_NODE"
  fi
  # host-local numbers the cursor files by range set: .0 is IPv4, .1 is IPv6.
  ipam=$(jq -c '[.plugins[] | select(.ipam.type == "host-local") | .ipam][0]' <<<"$conflist")
  data_dir=$(jq -r '.dataDir // "/var/lib/cni/networks"' <<<"$ipam")
  range4=$(jq -r '.ranges[0][0].subnet' <<<"$ipam")
  range6=$(jq -r '.ranges[1][0].subnet' <<<"$ipam")
  pod_cidrs=$(kubectl get node "$REUSE_NODE" -o jsonpath='{.spec.podCIDRs[*]}')
  echo "host-local IPAM in $data_dir, ranges $range4 $range6, node podCIDRs $pod_cidrs"
  if [ "$(jq -r .name <<<"$conflist")" != kindnet ] || [ "$ipam" = null ] ||
     [[ "$range4" == *:* ]] || [[ "$range6" != *:* ]] || [ "$pod_cidrs" != "$range4 $range6" ]; then
    reuse_fail "unexpected CNI configuration on $REUSE_NODE: $conflist"
  fi
  REUSE_IPAM_DIR="$data_dir/kindnet"
  # host-local creates the IPAM state directory on first allocation.
  # Verify both actual allocation files after Pod A becomes Ready.
  if ! docker exec "$REUSE_NODE" sh -c 'command -v flock >/dev/null'; then
    reuse_fail "flock is missing on $REUSE_NODE"
  fi

  # The test scripts, so the Pod specs do not need escaping.
  local scripts="$BATS_TEST_TMPDIR/reuse-scripts"
  mkdir -p "$scripts"
  # Pod A runs until the test tells it to complete.
  cat > "$scripts/wait.sh" <<'EOF'
for _ in $(seq 1 180); do
  [ -e /tmp/exit ] && exit 0
  sleep 1
done
exit 1
EOF
  # The unprotected client checks that the server is reachable.
  cat > "$scripts/control.sh" <<'EOF'
rc=0
for url in "http://${SERVER_IPV4}:8080/" "http://[${SERVER_IPV6}]:8080/"; do
  if curl -g -s -o /dev/null --connect-timeout 5 --max-time 10 "$url"; then
    echo "CONTROL ok $url"
  else
    echo "CONTROL fail $url"
    rc=1
  fi
done
exit "$rc"
EOF
  # Pod B connects from the start of its container, every attempt is a new
  # TCP connection that sends a single SYN. A dropped SYN times out, curl exits
  # with 28, and any completed handshake counts as a connection.
  cat > "$scripts/probe.sh" <<'EOF'
probe() {
  local family="$1" url="$2" attempts=0 connected=0 refused=0 timedout=0 other=0 rc connect
  local end=$((SECONDS + DURATION))
  while [ "$SECONDS" -lt "$end" ]; do
    attempts=$((attempts + 1))
    rc=0
    connect=$(curl -g -s -o /dev/null -w '%{time_connect}' --connect-timeout 0.5 --max-time 1 "$url") || rc=$?
    if [ "$rc" -eq 0 ] || ! [[ "$connect" =~ ^0([.,]0*)?$ ]]; then
      connected=$((connected + 1))
      echo "CONNECTED family=$family attempt=$attempts rc=$rc time_connect=$connect"
      continue
    fi
    case "$rc" in
      7) refused=$((refused + 1)) ;;
      28) timedout=$((timedout + 1)) ;;
      *) other=$((other + 1)); echo "ERROR family=$family attempt=$attempts rc=$rc" ;;
    esac
  done
  echo "SUMMARY family=$family attempts=$attempts connected=$connected refused=$refused timeout=$timedout other=$other"
}
echo "START $(date -u +%H:%M:%S) hosts=$(hostname -i)"
probe ipv4 "http://${SERVER_IPV4}:8080/" &
probe ipv6 "http://[${SERVER_IPV6}]:8080/" &
wait
EOF
  kubectl -n dev create configmap reuse-scripts --from-file="$scripts"

  # A is allowed all egress, the policy keeps the IPs of A in the managed IPs
  # after it completes, so the packets from those IPs are still intercepted.
  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-old
  namespace: dev
spec:
  podSelector:
    matchLabels:
      app: old
  policyTypes:
  - Egress
  egress:
  - {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress-blocked
  namespace: dev
spec:
  podSelector:
    matchLabels:
      app: blocked
  policyTypes:
  - Egress
---
apiVersion: v1
kind: Pod
metadata:
  name: $REUSE_SERVER
  namespace: prod
spec:
  nodeName: $server_node
  terminationGracePeriodSeconds: 1
  containers:
  - name: server
    image: $image
    args: ["netexec", "--http-port=8080"]
    readinessProbe:
      tcpSocket:
        port: 8080
      periodSeconds: 1
---
apiVersion: v1
kind: Pod
metadata:
  name: $REUSE_A
  namespace: dev
  labels:
    app: old
spec:
  nodeName: $REUSE_NODE
  restartPolicy: Never
  containers:
  - name: old
    image: $image
    command: ["bash", "/scripts/wait.sh"]
    volumeMounts:
    - name: scripts
      mountPath: /scripts
  volumes:
  - name: scripts
    configMap:
      name: reuse-scripts
EOF

  if ! kubectl -n prod wait --for=condition=ready "pod/$REUSE_SERVER" --timeout=60s; then
    reuse_fail "server unavailable: $REUSE_SERVER is not ready"
  fi
  REUSE_S4=$(reuse_pod_ip prod "$REUSE_SERVER" ipv4)
  REUSE_S6=$(reuse_pod_ip prod "$REUSE_SERVER" ipv6)
  if ! kubectl -n dev wait --for=condition=ready "pod/$REUSE_A" --timeout=30s; then
    reuse_fail "$REUSE_A is not running"
  fi
  REUSE_A4=$(reuse_pod_ip dev "$REUSE_A" ipv4)
  REUSE_A6=$(reuse_pod_ip dev "$REUSE_A" ipv6)
  echo "pod A $REUSE_A: $REUSE_A4 $REUSE_A6, server $REUSE_SERVER: $REUSE_S4 $REUSE_S6"
  if [ -z "$REUSE_A4" ] || [ -z "$REUSE_A6" ] || [ -z "$REUSE_S4" ] || [ -z "$REUSE_S6" ]; then
    reuse_fail "the Pods do not have IPv4 and IPv6 addresses"
  fi
  # The IPs of A are allocated by the host-local IPAM in this directory.
  if ! docker exec "$REUSE_NODE" test -e "$REUSE_IPAM_DIR/$REUSE_A4" ||
     ! docker exec "$REUSE_NODE" test -e "$REUSE_IPAM_DIR/$REUSE_A6"; then
    reuse_fail "the IPs of $REUSE_A are not allocated in $REUSE_IPAM_DIR"
  fi

  # Positive control: an unprotected client reaches the server Pod IPs.
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $REUSE_CONTROL
  namespace: dev
  labels:
    app: control
spec:
  nodeName: $REUSE_NODE
  restartPolicy: Never
  containers:
  - name: control
    image: $image
    command: ["bash", "/scripts/control.sh"]
    env:
    - name: SERVER_IPV4
      value: "$REUSE_S4"
    - name: SERVER_IPV6
      value: "$REUSE_S6"
    volumeMounts:
    - name: scripts
      mountPath: /scripts
  volumes:
  - name: scripts
    configMap:
      name: reuse-scripts
EOF
  local phase
  phase=$(reuse_wait_finished dev "$REUSE_CONTROL" 20)
  kubectl -n dev logs "$REUSE_CONTROL"
  if [ "$phase" != Succeeded ]; then
    reuse_fail "server unavailable: the unprotected client $REUSE_CONTROL is $phase"
  fi

  # A completes, its object keeps both IPs and its sandbox releases them.
  if ! kubectl -n dev exec "$REUSE_A" -- touch /tmp/exit; then
    reuse_fail "can not tell $REUSE_A to complete"
  fi
  phase=$(reuse_wait_finished dev "$REUSE_A" 10)
  if [ "$phase" != Succeeded ]; then
    reuse_fail "$REUSE_A did not complete successfully: $phase"
  fi
  if [ "$(reuse_pod_ip dev "$REUSE_A" ipv4)" != "$REUSE_A4" ] || [ "$(reuse_pod_ip dev "$REUSE_A" ipv6)" != "$REUSE_A6" ]; then
    reuse_fail "the completed $REUSE_A does not keep its IPs in its status"
  fi
  local released=false
  for _ in $(seq 1 40); do
    if ! docker exec "$REUSE_NODE" test -e "$REUSE_IPAM_DIR/$REUSE_A4" &&
       ! docker exec "$REUSE_NODE" test -e "$REUSE_IPAM_DIR/$REUSE_A6"; then
      released=true
      break
    fi
    sleep 0.5
  done
  # The allocations are never deleted by the test, they belong to the sandbox.
  if [ "$released" != true ]; then
    reuse_fail "CNI did not release the IPs of the completed $REUSE_A while its object exists"
  fi
  echo "The IPs of the completed $REUSE_A were released, its object keeps them."

  # Move the allocation cursors to the addresses before the IPs of A, so the
  # next allocation on the node is A's. Nothing else may start on the node.
  local pending
  pending=$(kubectl get pods -A --field-selector "spec.nodeName=$REUSE_NODE,status.phase=Pending" -o name)
  if [ -n "$pending" ]; then
    reuse_fail "other Pods are starting on $REUSE_NODE: $pending"
  fi
  local cursor4 cursor6 previous4 previous6
  cursor4=$(docker exec "$REUSE_NODE" cat "$REUSE_IPAM_DIR/last_reserved_ip.0")
  cursor6=$(docker exec "$REUSE_NODE" cat "$REUSE_IPAM_DIR/last_reserved_ip.1")
  if [[ "$cursor4" == *:* ]] || [[ "$cursor4" != *.* ]] || [[ "$cursor6" != *:* ]]; then
    reuse_fail "unexpected allocation cursors: IPv4 '$cursor4', IPv6 '$cursor6'"
  fi
  if ! previous4=$(reuse_previous_ip "$REUSE_A4") || ! previous6=$(reuse_previous_ip "$REUSE_A6"); then
    reuse_fail "can not compute the addresses before $REUSE_A4 and $REUSE_A6"
  fi
  echo "Moving the allocation cursors from $cursor4 and $cursor6 to $previous4 and $previous6"
  # host-local holds the same lock while it allocates. The cursors are not
  # restored afterwards, the allocation of B updates them.
  docker exec "$REUSE_NODE" flock "$REUSE_IPAM_DIR/lock" sh -c \
    'printf "%s" "$2" > "$1/last_reserved_ip.0" && printf "%s" "$3" > "$1/last_reserved_ip.1"' \
    _ "$REUSE_IPAM_DIR" "$previous4" "$previous6"
  if [ "$(docker exec "$REUSE_NODE" cat "$REUSE_IPAM_DIR/last_reserved_ip.0" "$REUSE_IPAM_DIR/last_reserved_ip.1")" != "$previous4$previous6" ]; then
    reuse_fail "can not move the allocation cursors in $REUSE_IPAM_DIR"
  fi

  # B is denied all egress before it starts, and connects as soon as its
  # container starts, before the API server may report its IPs.
  local start_time
  start_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $REUSE_B
  namespace: dev
  labels:
    app: blocked
spec:
  nodeName: $REUSE_NODE
  restartPolicy: Never
  containers:
  - name: blocked
    image: $image
    command: ["bash", "/scripts/probe.sh"]
    env:
    - name: SERVER_IPV4
      value: "$REUSE_S4"
    - name: SERVER_IPV6
      value: "$REUSE_S6"
    - name: DURATION
      value: "10"
    volumeMounts:
    - name: scripts
      mountPath: /scripts
  volumes:
  - name: scripts
    configMap:
      name: reuse-scripts
EOF
  phase=$(reuse_wait_finished dev "$REUSE_B" 30)
  local b_logs
  b_logs=$(kubectl -n dev logs "$REUSE_B")
  echo "$b_logs"
  if [ "$phase" != Succeeded ]; then
    reuse_fail "$REUSE_B did not complete successfully: $phase"
  fi

  # B got exactly the IPs of A.
  local b4 b6
  b4=$(reuse_pod_ip dev "$REUSE_B" ipv4)
  b6=$(reuse_pod_ip dev "$REUSE_B" ipv6)
  echo "pod B $REUSE_B: $b4 $b6"
  if [ "$b4" != "$REUSE_A4" ] || [ "$b6" != "$REUSE_A6" ]; then
    reuse_fail "forced reuse failed: $REUSE_B got $b4 $b6 instead of $REUSE_A4 $REUSE_A6"
  fi

  # B tried to connect, no connection was accepted and every SYN was dropped.
  local family summary attempts
  declare -A attempts_by_family
  for family in ipv4 ipv6; do
    summary=$(grep "^SUMMARY family=$family " <<<"$b_logs" || true)
    attempts=$(sed -n 's/.* attempts=\([0-9]*\) .*/\1/p' <<<"$summary")
    if [ -z "$summary" ] || [ "${attempts:-0}" -eq 0 ]; then
      reuse_fail "$REUSE_B made no $family connection attempts"
    fi
    attempts_by_family[$family]=$attempts
    if [[ "$summary" != *" connected=0 "* ]]; then
      reuse_fail "forbidden connection accepted: $summary"
    fi
    if [[ "$summary" != *" refused=0 timeout=$attempts other=0" ]]; then
      reuse_fail "$family SYNs from $REUSE_B were not all dropped: $summary"
    fi
  done

  # The agent learned about B from NRI, with the IPs of A.
  local agent_logs nri_ips
  agent_logs=$(kubectl -n kube-system logs "$REUSE_AGENT" --since-time="$start_time")
  nri_ips=$(grep -F "Starting Pod dev/$REUSE_B " <<<"$agent_logs" | sed -n 's/.* ips=\[\(.*\)\]$/\1/p' | head -n 1)
  echo "NRI reported $REUSE_B with IPs: $nri_ips"
  if [[ " $nri_ips " != *" $REUSE_A4 "* ]] || [[ " $nri_ips " != *" $REUSE_A6 "* ]]; then
    reuse_fail "NRI unavailable: the agent did not see the sandbox of $REUSE_B with $REUSE_A4 and $REUSE_A6"
  fi

  # Every packet from the reused IPs was evaluated as B and denied.
  local src dst verdicts total own denied
  for family in ipv4 ipv6; do
    if [ "$family" = ipv4 ]; then src="$REUSE_A4" dst="$REUSE_S4:8080"; else src="$REUSE_A6" dst="$REUSE_S6:8080"; fi
    verdicts=$(reuse_verdicts "$agent_logs" "dev/$REUSE_B" "$src" "$dst")
    read -r total own denied <<<"$verdicts"
    echo "$family packets from $src to $dst: evaluated=$total as $REUSE_B=$own denied=$denied"
    if [ "$total" -eq 0 ]; then
      reuse_fail "no $family packet from $REUSE_B reached the policy engine"
    fi
    # Each attempt sends one SYN, a SYN that bypassed the policy engine could
    # have reached the server.
    if [ "$total" -lt "${attempts_by_family[$family]}" ]; then
      reuse_fail "only $total of ${attempts_by_family[$family]} $family attempts of $REUSE_B reached the policy engine"
    fi
    if [ "$own" -ne "$total" ]; then
      reuse_fail "$((total - own)) $family packets from $src were evaluated as another Pod or as external"
    fi
    if [ "$denied" -ne "$total" ]; then
      reuse_fail "only $denied of $total $family packets from $REUSE_B were denied by the egress policy"
    fi
  done

  # The server was still available while B was denied.
  if [ "$(kubectl -n prod get pod "$REUSE_SERVER" -o jsonpath='{.status.containerStatuses[0].ready} {.status.containerStatuses[0].restartCount}')" != "true 0" ]; then
    reuse_fail "server unavailable: $REUSE_SERVER restarted or is not ready"
  fi

  # cleanup, the namespaces are deleted by teardown
  kubectl -n dev delete pod "$REUSE_A" "$REUSE_B" "$REUSE_CONTROL" --ignore-not-found
  kubectl -n prod delete pod "$REUSE_SERVER" --ignore-not-found
  kubectl -n dev delete networkpolicy allow-egress-old deny-egress-blocked --ignore-not-found
  kubectl -n dev delete configmap reuse-scripts --ignore-not-found
}
