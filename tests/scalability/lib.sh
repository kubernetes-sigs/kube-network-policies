#!/usr/bin/env bash
# Shared helpers for the scalability framework. Source, do not execute.

set -euo pipefail

SCALE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCALE_ROOT}/../.." && pwd)"
TEMPLATES="${SCALE_ROOT}/templates"
export SCALE_ROOT REPO_ROOT TEMPLATES

# Cluster
export CLUSTER_NAME="${CLUSTER_NAME:-knp-scale}"
export KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-}"
export REAL_WORKERS="${REAL_WORKERS:-2}"
# Known-good kindnetd that does not enforce NetworkPolicy; the bundled
# kube-network-policies in newer kindnetd would conflict with the DUT.
export KINDNET_PASSIVE_IMAGE="${KINDNET_PASSIVE_IMAGE:-docker.io/kindest/kindnetd:v20230809-80a64d96}"

# kwok
export KWOK_VERSION="${KWOK_VERSION:-v0.8.0}"
# Fake Pod addresses must not overlap kind's Pod (10.244.0.0/16) or Service
# (10.96.0.0/16) ranges so real probe Pods are never confused with fake ones.
export KWOK_POD_CIDR="${KWOK_POD_CIDR:-10.64.0.0/12}"

# Monitoring
export MONITORING_NS="${MONITORING_NS:-monitoring}"
export PROMETHEUS_NODEPORT="${PROMETHEUS_NODEPORT:-30090}"

# Images
export REGISTRY="${REGISTRY:-registry.k8s.io/networking}"
export IMAGE_NAME="${IMAGE_NAME:-kube-network-policies}"
export TAG="${TAG:-scale}"

# Artifacts
export ARTIFACTS="${ARTIFACTS:-${SCALE_ROOT}/_artifacts}"

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[1;31m[%s] ERROR:\033[0m %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; exit 1; }

require() {
  local missing=()
  for bin in "$@"; do command -v "$bin" >/dev/null 2>&1 || missing+=("$bin"); done
  [[ ${#missing[@]} -eq 0 ]] || die "missing required tools: ${missing[*]}"
}

# render <template> VAR...
# Substitute only the listed variables so literal ${1}-style placeholders in
# Prometheus relabel rules and Go templates pass through untouched.
render() {
  local tmpl="$1"; shift
  local spec=""
  for v in "$@"; do spec+="\${$v} "; done
  envsubst "${spec}" < "${tmpl}"
}

cluster_exists() { kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; }

# Every kubectl call in the framework targets this cluster explicitly; the
# user's current context can change underneath a long run.
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-${CLUSTER_NAME}}"
kubectl() { command kubectl --context "${KUBE_CONTEXT}" "$@"; }

# Real (non-kwok) worker node names.
real_workers() {
  kubectl get nodes -l '!type,!node-role.kubernetes.io/control-plane' \
    -o jsonpath='{.items[*].metadata.name}'
}

# Every real node, control plane included (DaemonSets tolerate its taint).
real_nodes() {
  kubectl get nodes -l '!type' -o jsonpath='{.items[*].metadata.name}'
}

# Docker container name of a kind node (same as node name).
node_exec() { local node="$1"; shift; docker exec "$node" "$@"; }

# Epoch seconds, used to bound Prometheus range queries.
now_ts() { date -u +%s; }

# Prometheus base URL reachable from the host (kind maps the NodePort onto
# the control-plane container IP).
prometheus_url() {
  local cp_ip
  cp_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CLUSTER_NAME}-control-plane")
  echo "http://${cp_ip}:${PROMETHEUS_NODEPORT}"
}

wait_for_pods() {
  # wait_for_pods <namespace> <label-selector> [timeout]
  local ns="$1" sel="$2" timeout="${3:-300s}"
  kubectl -n "$ns" wait --for=condition=ready pod -l "$sel" --timeout="$timeout"
}
