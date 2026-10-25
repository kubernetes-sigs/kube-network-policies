#!/usr/bin/env bash
# Create the kind cluster used by the scalability framework, neutralize the
# bundled kindnet NetworkPolicy enforcement, and deploy kwok.
#
#   cluster.sh up      create cluster, kwok controller, stages
#   cluster.sh down    delete cluster
#   cluster.sh status  print node summary

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

export KIND_POD_SUBNET="${KIND_POD_SUBNET:-10.244.0.0/16}"
export KIND_SERVICE_SUBNET="${KIND_SERVICE_SUBNET:-10.96.0.0/16}"
# Set to true for a DUT that provides the CNI itself (cilium, calico, ovn-k).
export KIND_DISABLE_DEFAULT_CNI="${KIND_DISABLE_DEFAULT_CNI:-false}"

kind_config() {
  render "${TEMPLATES}/kind-cluster.yaml" KIND_POD_SUBNET KIND_SERVICE_SUBNET KIND_DISABLE_DEFAULT_CNI PROMETHEUS_NODEPORT
  for _ in $(seq 1 "${REAL_WORKERS}"); do
    cat "${TEMPLATES}/kind-worker.yaml"
  done
}

# systemd inside each kind node needs inotify instances; the kernel default
# of 128-256 is exhausted by a couple of clusters and the node then fails
# with "Failed to allocate manager object: Too many open files".
preflight() {
  local inst watches
  inst=$(cat /proc/sys/fs/inotify/max_user_instances 2>/dev/null || echo 0)
  watches=$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo 0)
  if (( inst < 1024 || watches < 1048576 )); then
    warn "fs.inotify.max_user_instances=${inst} max_user_watches=${watches} are low for kind + kwok at scale"
    warn "raise them with: sudo sysctl fs.inotify.max_user_instances=8192 fs.inotify.max_user_watches=1048576"
  fi
}

cluster_up() {
  require kind kubectl docker curl envsubst
  preflight
  if cluster_exists; then
    log "cluster ${CLUSTER_NAME} already exists"
  else
    log "creating kind cluster ${CLUSTER_NAME} with ${REAL_WORKERS} real workers"
    local image_arg=() wait="2m"
    [[ -n "${KIND_NODE_IMAGE}" ]] && image_arg=(--image "${KIND_NODE_IMAGE}")
    # Nodes cannot become Ready without a CNI; let the DUT install one first.
    [[ "${KIND_DISABLE_DEFAULT_CNI}" == "true" ]] && wait="0s"
    kind_config | kind create cluster --name "${CLUSTER_NAME}" --wait "${wait}" --config=- "${image_arg[@]}"
  fi

  if [[ "${KIND_DISABLE_DEFAULT_CNI}" == "true" ]]; then
    log "default CNI disabled; the DUT must install networking before nodes become Ready"
  else
    log "replacing kindnet with a passive image (no bundled NetworkPolicy enforcement)"
    kubectl -n kube-system set image ds kindnet "kindnet-cni=${KINDNET_PASSIVE_IMAGE}"
    kubectl -n kube-system rollout status ds kindnet --timeout=120s
    # The original kindnetd programmed its enforcement table before the swap
    # and nothing removes it; its queue rules and unconditional ct-label set
    # would sit next to the DUT's chains at the same hook priority.
    for node in $(real_nodes); do
      node_exec "$node" nft delete table inet kindnet-network-policies 2>/dev/null || true
    done
  fi

  for node in $(real_workers); do
    if node_exec "$node" test -S /var/run/nri/nri.sock; then
      log "NRI socket present on ${node}"
    else
      warn "no NRI socket on ${node}; the knp-nri DUTs will fall back to API-only metadata"
    fi
  done

  install_kwok
  cluster_status
}

install_kwok() {
  local base="https://github.com/kubernetes-sigs/kwok/releases/download/${KWOK_VERSION}"
  log "installing kwok ${KWOK_VERSION} (fake Pod CIDR ${KWOK_POD_CIDR})"
  # Upstream manifest; only the fake-Pod CIDR is overridden so it cannot
  # collide with kind's Pod or Service ranges.
  curl -fsSL "${base}/kwok.yaml" \
    | sed "s#cidr: 10.0.0.0/24#cidr: ${KWOK_POD_CIDR}#" \
    | kubectl apply --server-side -f -
  kubectl -n kube-system rollout status deploy kwok-controller --timeout=120s
  kubectl wait --for=condition=established crd/stages.kwok.x-k8s.io --timeout=60s
  curl -fsSL "${base}/stage-fast.yaml" | kubectl apply --server-side -f -
}

cluster_down() {
  require kind
  if cluster_exists; then
    mkdir -p "${ARTIFACTS}"
    kind export logs "${ARTIFACTS}/kind-logs" --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    kind delete cluster --name "${CLUSTER_NAME}"
  else
    log "cluster ${CLUSTER_NAME} does not exist"
  fi
}

cluster_status() {
  kubectl get nodes -L type,scale.knp.x-k8s.io/real -o wide
  kubectl -n kube-system get pods -l app=kwok-controller -o wide
}

case "${1:-}" in
  up) cluster_up ;;
  down) cluster_down ;;
  status) cluster_status ;;
  *) echo "usage: $0 {up|down|status}" >&2; exit 2 ;;
esac
