#!/usr/bin/env bash
# Pull the metrics for one run window out of Prometheus and snapshot
# per-node kernel state.
#
#   collect.sh <run-dir> <t0-epoch> <t1-epoch> [dut]
#
# Writes:
#   <run-dir>/prom/<query-name>.json   range-query results (matrix)
#   <run-dir>/prom/queries.txt         the exact expressions used
#   <run-dir>/kernel-state.jsonl       one line per real worker from dut.sh kernel-state
#   <run-dir>/objects.json             counts of Pods, Nodes, NetworkPolicies at t1

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

run_dir="${1:?run-dir}"; t0="${2:?t0}"; t1="${3:?t1}"; dut="${4:-}"
require curl kubectl
mkdir -p "${run_dir}/prom"

url="$(prometheus_url)"
# One sample per 5 s scrape; range windows longer than an hour get thinned.
span=$(( t1 - t0 )); step=5
(( span / step <= 11000 )) || step=$(( span / 11000 + 1 ))

queries() {
  cat "${SCALE_ROOT}/monitoring/queries.txt"
  [[ -n "$dut" && -f "${SCALE_ROOT}/dut/${dut}/queries.txt" ]] && cat "${SCALE_ROOT}/dut/${dut}/queries.txt"
  return 0
}
queries > "${run_dir}/prom/queries.txt"

ok=0; empty=0
while IFS='|' read -r name expr; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  out="${run_dir}/prom/${name}.json"
  if curl -fsS "${url}/api/v1/query_range" \
      --data-urlencode "query=${expr}" \
      --data-urlencode "start=${t0}" --data-urlencode "end=${t1}" --data-urlencode "step=${step}" \
      -o "$out"; then
    if grep -q '"result":\[\]' "$out"; then empty=$((empty+1)); else ok=$((ok+1)); fi
  else
    warn "query failed: ${name}"
  fi
done < "${run_dir}/prom/queries.txt"
log "prometheus: ${ok} queries with data, ${empty} empty (step ${step}s over ${span}s)"

if [[ -n "$dut" && -x "${SCALE_ROOT}/dut/${dut}/dut.sh" ]]; then
  : > "${run_dir}/kernel-state.jsonl"
  for node in $(real_workers); do
    "${SCALE_ROOT}/dut/${dut}/dut.sh" kernel-state "$node" >> "${run_dir}/kernel-state.jsonl" || warn "kernel-state failed on ${node}"
  done
fi

kubectl get --raw /metrics 2>/dev/null | grep '^apiserver_storage_objects' > "${run_dir}/storage-objects.prom" || true
printf '{"pods":%s,"nodes":%s,"networkpolicies":%s,"namespaces":%s,"t1":%s}\n' \
  "$(kubectl get pods -A --no-headers 2>/dev/null | wc -l)" \
  "$(kubectl get nodes --no-headers 2>/dev/null | wc -l)" \
  "$(kubectl get networkpolicies -A --no-headers 2>/dev/null | wc -l)" \
  "$(kubectl get namespaces --no-headers 2>/dev/null | wc -l)" \
  "$t1" > "${run_dir}/objects.json"
log "collected into ${run_dir}"
