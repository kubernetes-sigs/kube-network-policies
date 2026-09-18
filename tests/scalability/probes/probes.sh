#!/usr/bin/env bash
# Real-traffic probes on the real workers. Source or execute:
#
#   probes.sh install                 create namespace, gateway, clients
#   probes.sh uninstall
#   probes.sh allowed                 one connection from the sandbox-labeled client; exit 0 if admitted
#   probes.sh denied                  one connection from the unlabeled client; exit 0 if blocked
#   probes.sh until allowed|denied    poll until the expected outcome; prints elapsed ms
#   probes.sh latency [n]             n sequential fresh connections; fortio JSON on stdout
#   probes.sh connrate <out-dir>      connection-rate load, allowed and denied mixes; fortio JSON files
#
# All probes use the gateway Pod IP, not DNS, so resolver latency is not
# folded into the measurement.

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

export PROBE_NAMESPACE="${PROBE_NAMESPACE:-scale-probes}"
export GATEWAY_PORT="${GATEWAY_PORT:-8080}"
export FORTIO_IMAGE="${FORTIO_IMAGE:-fortio/fortio:1.69.5}"
export CONNRATE_DURATION="${CONNRATE_DURATION:-30s}"
export CONNRATE_CONCURRENCY="${CONNRATE_CONCURRENCY:-64}"
export CONNRATE_DENIED_CONCURRENCY="${CONNRATE_DENIED_CONCURRENCY:-16}"

probes_install() {
  require kubectl envsubst
  local workers
  read -r -a workers <<< "$(real_workers)"
  [[ ${#workers[@]} -ge 1 ]] || die "no real workers found"
  export GATEWAY_NODE="${workers[0]}"
  export CLIENT_NODE="${workers[${#workers[@]}-1]}"
  [[ "${GATEWAY_NODE}" != "${CLIENT_NODE}" ]] || warn "single worker: probes will not cross nodes"
  # A previous run's cleanup deletes the namespace without waiting; creating
  # Pods in a Terminating namespace is forbidden.
  if kubectl get ns "${PROBE_NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Terminating; then
    log "waiting for namespace ${PROBE_NAMESPACE} to finish terminating"
    kubectl wait --for=delete ns "${PROBE_NAMESPACE}" --timeout=180s
  fi
  render "${SCALE_ROOT}/probes/probes.yaml" PROBE_NAMESPACE GATEWAY_PORT FORTIO_IMAGE GATEWAY_NODE CLIENT_NODE \
    | kubectl apply -f -
  wait_for_pods "${PROBE_NAMESPACE}" "app in (gateway,client-allowed,client-denied)" 180s
}

probes_uninstall() {
  kubectl delete namespace "${PROBE_NAMESPACE}" --ignore-not-found --wait=false
}

gateway_ip() {
  kubectl -n "${PROBE_NAMESPACE}" get pod gateway -o jsonpath='{.status.podIP}'
}

# curl_from <client-pod> [timeout]  -> exit 0 on HTTP success
curl_from() {
  local pod="$1" timeout="${2:-3s}"
  kubectl -n "${PROBE_NAMESPACE}" exec "$pod" -- \
    fortio curl -timeout "$timeout" "http://$(gateway_ip):${GATEWAY_PORT}/" >/dev/null 2>&1
}

probe_allowed() { curl_from client-allowed; }
probe_denied()  { ! curl_from client-denied 2s; }

# probe_until allowed|denied [max-seconds] -> prints elapsed milliseconds
probe_until() {
  local want="$1" max="${2:-120}" start now
  start=$(date +%s%3N)
  while :; do
    case "$want" in
      allowed) probe_allowed && break ;;
      denied)  probe_denied  && break ;;
      *) die "probe_until: unknown outcome $want" ;;
    esac
    now=$(date +%s%3N)
    (( (now - start) / 1000 < max )) || { echo "timeout"; return 1; }
    sleep 0.1
  done
  echo $(( $(date +%s%3N) - start ))
}

# Sequential fresh connections (no keep-alive): each one traverses the
# queue on both nodes, so the distribution is per-connection admission cost
# plus the network path.
probe_latency() {
  local n="${1:-100}"
  kubectl -n "${PROBE_NAMESPACE}" exec client-allowed -- \
    fortio load -c 1 -n "$n" -qps 0 -H "Connection: close" -json - -quiet \
    "http://$(gateway_ip):${GATEWAY_PORT}/"
}

# Connection-rate load. Runs the allowed mix and, concurrently, a denied mix
# from the outsider client so the agent sees uncached denied packets while
# it serves accepted ones. Denied requests are expected to time out.
probe_connrate() {
  local out="$1" url
  mkdir -p "$out"
  url="http://$(gateway_ip):${GATEWAY_PORT}/"
  # Every request here is expected to fail; without -allow-initial-errors
  # fortio aborts on the first warm-up failure and emits no JSON.
  kubectl -n "${PROBE_NAMESPACE}" exec client-denied -- \
    fortio load -c "${CONNRATE_DENIED_CONCURRENCY}" -qps 0 -t "${CONNRATE_DURATION}" -timeout 500ms \
      -allow-initial-errors -H "Connection: close" -json - -quiet "$url" > "${out}/connrate-denied.json" 2>/dev/null &
  local denied_pid=$!
  kubectl -n "${PROBE_NAMESPACE}" exec client-allowed -- \
    fortio load -c "${CONNRATE_CONCURRENCY}" -qps 0 -t "${CONNRATE_DURATION}" \
      -H "Connection: close" -json - -quiet "$url" > "${out}/connrate-allowed.json"
  wait "$denied_pid" || true
  log "connection-rate results in ${out}"
}

# Dispatch only when executed, not when sourced by run.sh.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    install) probes_install ;;
    uninstall) probes_uninstall ;;
    allowed) probe_allowed ;;
    denied) probe_denied ;;
    until) probe_until "$2" "${3:-120}" ;;
    latency) probe_latency "${2:-100}" ;;
    connrate) probe_connrate "${2:?out-dir}" ;;
    *) echo "usage: $0 {install|uninstall|allowed|denied|until <allowed|denied>|latency [n]|connrate <out-dir>}" >&2; exit 2 ;;
  esac
fi
