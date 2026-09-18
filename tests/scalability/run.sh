#!/usr/bin/env bash
# Run one scalability experiment against one DUT.
#
#   run.sh --dut knp|knp-nri|knp-nri-iptracker|<dut-dir> [options]
#
# Phases (each is timestamped in <run-dir>/phases.json):
#   install    DUT and Prometheus scrape config
#   baseline   idle agents, no fake objects
#   nodes      create fake nodes
#   policies   apply scenario to every managed namespace + probe namespace
#   fill       create fake Pods at --rate
#   steady     idle with all Pods Running (materialization cost at rest)
#   probes     allowed/denied checks, revocation and re-enforcement latency,
#              sequential fresh-connection latency
#   churn      replace Pods at --churn-rate (reused or fresh identities)
#   connrate   connection-rate load, allowed + denied mix
#   collect    Prometheus range queries, kernel state, object counts
#
# Options (env var in brackets):
#   --nodes N          fake nodes                         [NODES=100]
#   --pods N           fake Pods                          [PODS=10000]
#   --identities N     distinct identity labels           [IDENTITIES=7]
#   --namespaces N     managed namespaces                 [NAMESPACES=1]
#   --rate R           Pod creations per second           [RATE=100]
#   --scenario S       default-deny|gateway|mesh          [SCENARIO=mesh]
#   --churn-rate R     replacements per second (0 skips)  [CHURN_RATE=20]
#   --churn-duration D e.g. 120s                          [CHURN_DURATION=120s]
#   --fresh-identities replacements use new identities    [FRESH_IDENTITIES=false]
#   --steady D         steady-state dwell                 [STEADY=60s]
#   --skip-install     DUT already installed
#   --keep             leave DUT, nodes and Pods in place after the run
#   --run-id ID        artifact directory name            [RUN_ID=<dut>-<scenario>-i<I>-p<P>-<ts>]

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
source "${SCALE_ROOT}/probes/probes.sh"

DUT="${DUT:-}"
NODES="${NODES:-100}"
PODS="${PODS:-10000}"
IDENTITIES="${IDENTITIES:-7}"
NAMESPACES="${NAMESPACES:-1}"
RATE="${RATE:-100}"
SCENARIO="${SCENARIO:-mesh}"
CHURN_RATE="${CHURN_RATE:-20}"
CHURN_DURATION="${CHURN_DURATION:-120s}"
FRESH_IDENTITIES="${FRESH_IDENTITIES:-false}"
STEADY="${STEADY:-60s}"
SKIP_INSTALL=false
KEEP=false
RUN_ID="${RUN_ID:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dut) DUT="$2"; shift 2 ;;
    --nodes) NODES="$2"; shift 2 ;;
    --pods) PODS="$2"; shift 2 ;;
    --identities) IDENTITIES="$2"; shift 2 ;;
    --namespaces) NAMESPACES="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --churn-rate) CHURN_RATE="$2"; shift 2 ;;
    --churn-duration) CHURN_DURATION="$2"; shift 2 ;;
    --fresh-identities) FRESH_IDENTITIES=true; shift ;;
    --steady) STEADY="$2"; shift 2 ;;
    --skip-install) SKIP_INSTALL=true; shift ;;
    --keep) KEEP=true; shift ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[[ -n "$DUT" ]] || die "--dut is required"
DUT_SH="${SCALE_ROOT}/dut/${DUT}/dut.sh"
[[ -x "$DUT_SH" ]] || die "no executable ${DUT_SH}"
[[ -f "${SCALE_ROOT}/scenarios/${SCENARIO}.yaml" ]] || die "unknown scenario ${SCENARIO}"
require kubectl kind docker curl envsubst go jq
cluster_exists || die "cluster ${CLUSTER_NAME} not found; run cluster.sh up"

RUN_ID="${RUN_ID:-${DUT}-${SCENARIO}-i${IDENTITIES}-p${PODS}-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_DIR="${ARTIFACTS}/${RUN_ID}"
mkdir -p "${RUN_DIR}"
LOADGEN_BIN="${RUN_DIR}/loadgen"
(cd "${REPO_ROOT}" && go build -o "${LOADGEN_BIN}" ./tests/scalability/loadgen) || die "loadgen build failed"
# loadgen <subcommand> [flags]: same context pinning as the kubectl wrapper in
# lib.sh; flags are per subcommand, so --context goes after the command.
loadgen() { local cmd="$1"; shift; "${LOADGEN_BIN}" "$cmd" --context "${KUBE_CONTEXT}" "$@"; }

# ---- phase bookkeeping --------------------------------------------------------
PHASES_FILE="${RUN_DIR}/phases.json"
RESULTS="${RUN_DIR}/results.json"
echo '[]' > "${PHASES_FILE}"
echo '{}' > "${RESULTS}"
phase_start_ts=0
phase() {
  # phase <name>: closes the previous phase and opens a new one
  local now; now=$(now_ts)
  if [[ -n "${current_phase:-}" ]]; then
    jq --arg n "$current_phase" --argjson t0 "$phase_start_ts" --argjson t1 "$now" \
      '. + [{phase:$n,t0:$t0,t1:$t1,seconds:($t1-$t0)}]' "${PHASES_FILE}" > "${PHASES_FILE}.tmp" \
      && mv "${PHASES_FILE}.tmp" "${PHASES_FILE}"
  fi
  current_phase="$1"; phase_start_ts="$now"
  if [[ -n "$1" ]]; then log "=== phase: $1"; fi
}

result() { # result <key> <value>; numbers and booleans are stored typed
  jq --arg k "$1" --arg v "$2" '.[$k] = ($v | try fromjson catch $v)' "${RESULTS}" > "${RESULTS}.tmp" \
    && mv "${RESULTS}.tmp" "${RESULTS}"
}

check() { # check <key> <command...>: records true/false without aborting the run
  local key="$1"; shift
  if "$@"; then result "$key" true; else result "$key" false; fi
}

cleanup() {
  local rc=$?
  set +e
  phase ""
  (( rc == 0 )) || warn "run aborted (exit ${rc}); see ${RUN_DIR}"
  if [[ "$KEEP" == "false" ]]; then
    log "cleaning up fake objects"
    loadgen pods --delete --namespaces "${NAMESPACES}" >/dev/null 2>&1
    kubectl delete networkpolicies -A -l scale.knp.x-k8s.io/managed=true --ignore-not-found >/dev/null 2>&1
    loadgen nodes --delete >/dev/null 2>&1
    probes_uninstall
    kubectl delete namespaces -l scale.knp.x-k8s.io/managed=true --ignore-not-found --wait=false >/dev/null 2>&1
    "${DUT_SH}" uninstall || warn "dut uninstall failed"
  fi
  exit "$rc"
}
trap cleanup EXIT

export RUN_ID DUT NODES PODS IDENTITIES NAMESPACES RATE SCENARIO CHURN_RATE CHURN_DURATION FRESH_IDENTITIES STEADY
REAL_WORKER_LIST="$(real_workers | tr ' ' ',')"
KIND_VERSION="$(kind version 2>/dev/null | head -1)"
STARTED="$(date -u +%FT%TZ)"
export REAL_WORKER_LIST KIND_VERSION STARTED
render "${TEMPLATES}/params.json" RUN_ID DUT NODES PODS IDENTITIES NAMESPACES RATE SCENARIO CHURN_RATE \
    CHURN_DURATION FRESH_IDENTITIES STEADY REAL_WORKER_LIST KWOK_VERSION KIND_VERSION STARTED \
  > "${RUN_DIR}/params.json"

T_RUN0=$(now_ts)

# ---- install ---------------------------------------------------------------------
phase install
if [[ "$SKIP_INSTALL" == "false" ]]; then
  "${DUT_SH}" install
fi
"${SCALE_ROOT}/monitoring/install.sh" "${DUT}"
probes_install
kubectl -n kube-system get pods -l k8s-app=kube-network-policies -o jsonpath='{range .items[*]}{.spec.nodeName}{" "}{.spec.containers[0].image}{" "}{.spec.containers[0].args}{"\n"}{end}' \
  > "${RUN_DIR}/dut-pods.txt" 2>/dev/null || true

# ---- baseline ------------------------------------------------------------------------
phase baseline
sleep 30

# ---- nodes -----------------------------------------------------------------------------
phase nodes
loadgen nodes --count "${NODES}"

# ---- policies ----------------------------------------------------------------------------
phase policies
# Namespaces first so policies have a target; loadgen recreates them idempotently.
loadgen pods --count 0 --namespaces "${NAMESPACES}" >/dev/null
apply_scenario() {
  local ns
  for ns in $(kubectl get ns -l scale.knp.x-k8s.io/managed=true -o jsonpath='{.items[*].metadata.name}'); do
    NAMESPACE="$ns" render "${SCALE_ROOT}/scenarios/default-deny.yaml" NAMESPACE | kubectl apply -f - >/dev/null
    if [[ "${SCENARIO}" != "default-deny" ]]; then
      NAMESPACE="$ns" render "${SCALE_ROOT}/scenarios/${SCENARIO}.yaml" NAMESPACE PROBE_NAMESPACE GATEWAY_PORT \
        | kubectl apply -f - >/dev/null
    fi
  done
}
apply_scenario
# Time until the allowed probe passes after policies land: enforcement latency
# on an otherwise idle cluster.
result enforce_ms_idle "$(probe_until allowed 120 || echo -1)"
check denied_ok_idle probe_denied

# ---- fill ------------------------------------------------------------------------------------
phase fill
loadgen pods --count "${PODS}" --identities "${IDENTITIES}" --namespaces "${NAMESPACES}" --rate "${RATE}" \
  2>&1 | tee "${RUN_DIR}/fill.log"
loadgen wait --count "${PODS}" --timeout 15m 2>&1 | tee -a "${RUN_DIR}/fill.log"
result fill_achieved_rate "$(grep -o 'achieved_rate="[0-9.]*' "${RUN_DIR}/fill.log" | tail -1 | cut -d'"' -f2)"

# ---- steady ----------------------------------------------------------------------------------
phase steady
sleep "${STEADY}"
# Materialized state at rest, before probes and churn disturb it.
: > "${RUN_DIR}/kernel-state-steady.jsonl"
for node in $(real_workers); do
  "${DUT_SH}" kernel-state "$node" >> "${RUN_DIR}/kernel-state-steady.jsonl" || warn "kernel-state failed on ${node}"
done

# ---- probes ------------------------------------------------------------------------------------
phase probes
check allowed_ok_loaded probe_allowed
check denied_ok_loaded probe_denied
probe_latency 200 > "${RUN_DIR}/latency-fresh-connections.json" || warn "latency probe failed"
# Revocation: drop the allow policy in the probe namespace, time until denied.
kubectl -n "${PROBE_NAMESPACE}" delete networkpolicy -l scale.knp.x-k8s.io/managed=true --ignore-not-found >/dev/null
result revoke_ms "$(probe_until denied 120 || echo -1)"
# Re-enforcement: reapply, time until allowed.
NAMESPACE="${PROBE_NAMESPACE}" render "${SCALE_ROOT}/scenarios/default-deny.yaml" NAMESPACE | kubectl apply -f - >/dev/null
[[ "${SCENARIO}" != "default-deny" ]] && NAMESPACE="${PROBE_NAMESPACE}" render "${SCALE_ROOT}/scenarios/${SCENARIO}.yaml" NAMESPACE PROBE_NAMESPACE GATEWAY_PORT | kubectl apply -f - >/dev/null
result enforce_ms_loaded "$(probe_until allowed 120 || echo -1)"

# ---- churn -----------------------------------------------------------------------------------------
if [[ "${CHURN_RATE}" != "0" ]]; then
  phase churn
  fresh_flag=()
  [[ "${FRESH_IDENTITIES}" == "true" ]] && fresh_flag=(--fresh-identities)
  loadgen churn --rate "${CHURN_RATE}" --duration "${CHURN_DURATION}" --identities "${IDENTITIES}" "${fresh_flag[@]}" \
    2>&1 | tee "${RUN_DIR}/churn.log"
  result churn_replaced "$(grep -o 'replaced=[0-9]*' "${RUN_DIR}/churn.log" | tail -1 | cut -d= -f2)"
  result churn_failed "$(grep -o 'failed=[0-9]*' "${RUN_DIR}/churn.log" | tail -1 | cut -d= -f2)"
  check allowed_ok_after_churn probe_allowed
  check denied_ok_after_churn probe_denied
fi

# ---- connrate ----------------------------------------------------------------------------------------
phase connrate
probe_connrate "${RUN_DIR}"

# ---- collect --------------------------------------------------------------------------------------------
phase collect
T_RUN1=$(now_ts)
"${SCALE_ROOT}/collect.sh" "${RUN_DIR}" "${T_RUN0}" "${T_RUN1}" "${DUT}"
kubectl -n kube-system logs -l k8s-app=kube-network-policies --tail=2000 --prefix > "${RUN_DIR}/agent.log" 2>/dev/null || true
phase ""
log "run ${RUN_ID} complete: ${RUN_DIR}"
