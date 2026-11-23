#!/usr/bin/env bash
# Shared implementation for the three kube-network-policies DUT flavors.
# Each dut/knp*/install.sh sets the KNP_* variables and calls knp_install.
#
# Required by the caller:
#   DUT               dut directory name (label value)
#   KNP_FLAVOR        standard | iptracker  (selects Makefile target and image tag suffix)
#   KNP_DISABLE_NRI   true | false
#   KNP_WITH_IPTRACKER true | false

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

export KNP_VERBOSITY="${KNP_VERBOSITY:-2}"
export KNP_NFQUEUE_ID="${KNP_NFQUEUE_ID:-98}"
export KNP_METRICS_PORT="${KNP_METRICS_PORT:-9080}"
export KNP_FAIL_OPEN="${KNP_FAIL_OPEN:-true}"
export KNP_STRICT_MODE="${KNP_STRICT_MODE:-true}"
export IPTRACKER_PORT="${IPTRACKER_PORT:-10999}"
export IPTRACKER_REPLICAS="${IPTRACKER_REPLICAS:-1}"
export KNP_BUILD="${KNP_BUILD:-true}"

knp_images() {
  if [[ "${KNP_FLAVOR}" == "standard" ]]; then
    export KNP_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"
  else
    export KNP_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}-${KNP_FLAVOR}"
  fi
  export IPTRACKER_IMAGE="${REGISTRY}/kube-ip-tracker:${TAG}"
}

knp_build_and_load() {
  [[ "${KNP_BUILD}" == "true" ]] || { log "KNP_BUILD=false, using existing images"; return; }
  log "building ${KNP_IMAGE}"
  (cd "${REPO_ROOT}" && TAG="${TAG}" make "image-build-${KNP_FLAVOR}")
  kind load docker-image "${KNP_IMAGE}" --name "${CLUSTER_NAME}"
  if [[ "${KNP_WITH_IPTRACKER}" == "true" ]]; then
    log "building ${IPTRACKER_IMAGE}"
    (cd "${REPO_ROOT}" && TAG="${TAG}" make image-build-kube-ip-tracker-standard)
    kind load docker-image "${IPTRACKER_IMAGE}" --name "${CLUSTER_NAME}"
  fi
}

knp_install() {
  require kubectl kind docker make envsubst
  knp_images
  knp_build_and_load

  export KNP_EXTRA_ARGS=""
  if [[ "${KNP_WITH_IPTRACKER}" == "true" ]]; then
    render "${TEMPLATES}/kube-ip-tracker.yaml" DUT IPTRACKER_IMAGE IPTRACKER_PORT IPTRACKER_REPLICAS KNP_VERBOSITY \
      | kubectl apply -f -
    kubectl -n kube-system rollout status deploy kube-ip-tracker --timeout=120s
    # Indented to sit inside the container args list of the template.
    KNP_EXTRA_ARGS="        - --ip-tracker-address=kube-ip-tracker.kube-system.svc.cluster.local:${IPTRACKER_PORT}"
  fi

  render "${TEMPLATES}/knp-daemonset.yaml" \
      DUT KNP_IMAGE KNP_VERBOSITY KNP_NFQUEUE_ID KNP_METRICS_PORT KNP_DISABLE_NRI KNP_FAIL_OPEN KNP_STRICT_MODE KNP_EXTRA_ARGS \
    | kubectl apply -f -
  kubectl -n kube-system rollout status ds kube-network-policies --timeout=180s
  kubectl -n kube-system get pods -l k8s-app=kube-network-policies -o wide
}

knp_uninstall() {
  require kubectl
  kubectl -n kube-system delete ds kube-network-policies --ignore-not-found --wait
  kubectl delete clusterrolebinding kube-network-policies --ignore-not-found
  kubectl delete clusterrole kube-network-policies --ignore-not-found
  kubectl -n kube-system delete sa kube-network-policies --ignore-not-found
  if [[ "${KNP_WITH_IPTRACKER}" == "true" ]]; then
    kubectl -n kube-system delete deploy,svc kube-ip-tracker --ignore-not-found --wait
    kubectl delete clusterrolebinding,clusterrole kube-ip-tracker --ignore-not-found
    kubectl -n kube-system delete sa kube-ip-tracker --ignore-not-found
  fi
  # The agent removes its nftables table on graceful shutdown only when
  # fail-open is false; clean up unconditionally so the next DUT starts clean.
  for node in $(real_nodes); do
    node_exec "$node" nft delete table inet kube-network-policies 2>/dev/null || true
  done
}

# Kernel state on one real node: rule count, set cardinalities, conntrack
# entries carrying a label. Emits one JSON object. nft JSON is parsed on the
# host because kind nodes ship no jq. The iptracker flavor diverts all
# traffic and programs no podips sets; those report as -1 with
# "divert_all": true.
knp_kernel_state() {
  local node="$1"
  local rules v4 v6 ct divert=false
  rules=$(node_exec "$node" nft -j list table inet kube-network-policies 2>/dev/null \
    | jq '[.nftables[] | select(.rule)] | length' 2>/dev/null || true)
  v4=$(nft_set_size "$node" podips-v4) || { v4=-1; divert=true; }
  v6=$(nft_set_size "$node" podips-v6) || v6=-1
  ct=$(node_exec "$node" sh -c 'conntrack -L -o labels 2>/dev/null | grep -c "labels=" || true')
  printf '{"node":"%s","dut":"%s","nft_rules":%s,"podips_v4":%s,"podips_v6":%s,"conntrack_labeled":%s,"divert_all":%s}\n' \
    "$node" "${DUT}" "${rules:-0}" "${v4}" "${v6}" "${ct:-0}" "${divert}"
}

# nft_set_size <node> <set>: element count, non-zero exit if the set is absent
nft_set_size() {
  local out
  out=$(node_exec "$1" nft -j list set inet kube-network-policies "$2" 2>/dev/null) || return 1
  jq '[.nftables[] | select(.set) | .set.elem // [] | length] | add // 0' <<< "$out"
}
