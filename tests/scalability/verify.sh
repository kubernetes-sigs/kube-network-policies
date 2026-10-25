#!/usr/bin/env bash
# Assert that a run produced a complete, sane set of artifacts. Used by the
# CI smoke job to catch framework regressions; it checks plumbing and
# enforcement correctness, not performance thresholds.
#
#   verify.sh <run-dir>

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require jq

d="${1:?run-dir}"
fail=0
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=$((fail+1)); }
check() { # check <description> <command...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
jq_true() { [[ "$(jq -r "$1" "$2" 2>/dev/null)" == "true" ]]; }
jq_num_gt() { jq -e "($1) > $3" "$2" >/dev/null 2>&1; }

log "verifying ${d}"

# ---- files ---------------------------------------------------------------
for f in params.json phases.json results.json fill.log latency-fresh-connections.json \
         connrate-allowed.json connrate-denied.json kernel-state-steady.jsonl kernel-state.jsonl \
         objects.json dut-pods.txt agent.log prom/queries.txt; do
  check "artifact ${f}" test -s "${d}/${f}"
done

# ---- phases --------------------------------------------------------------
for p in install baseline nodes policies fill steady probes connrate collect; do
  # shellcheck disable=SC2016  # $p is a jq variable
  check "phase ${p} recorded" jq -e --arg p "$p" '.[] | select(.phase==$p)' "${d}/phases.json"
done

# ---- fill ----------------------------------------------------------------
pods=$(jq -r .pods "${d}/params.json")
check "all ${pods} fake Pods reached Running" grep -q "\"pods running\" running=${pods} " "${d}/fill.log"
check "fill achieved rate recorded" jq_num_gt .fill_achieved_rate "${d}/results.json" 0

# ---- enforcement -------------------------------------------------------------
for k in denied_ok_idle denied_ok_loaded allowed_ok_loaded; do
  check "results.${k} is true" jq_true ".${k}" "${d}/results.json"
done
if [[ "$(jq -r .churn_rate "${d}/params.json")" != "0" ]]; then
  check "results.denied_ok_after_churn is true" jq_true .denied_ok_after_churn "${d}/results.json"
  check "results.allowed_ok_after_churn is true" jq_true .allowed_ok_after_churn "${d}/results.json"
  check "churn replaced > 0" jq_num_gt .churn_replaced "${d}/results.json" 0
fi
for k in enforce_ms_idle enforce_ms_loaded revoke_ms; do
  check "results.${k} measured (not timed out)" jq_num_gt ".${k}" "${d}/results.json" 0
done

# ---- probes ------------------------------------------------------------------
check "fresh connections all 200" jq -e '.DurationHistogram.Count > 0 and .RetCodes["200"] == .DurationHistogram.Count' "${d}/latency-fresh-connections.json"
check "connrate allowed all 200" jq -e '.DurationHistogram.Count > 0 and .RetCodes["200"] == .DurationHistogram.Count' "${d}/connrate-allowed.json"
check "connrate denied: zero successes" jq -e '.DurationHistogram.Count > 0 and ((.RetCodes["200"] // 0) == 0)' "${d}/connrate-denied.json"

# ---- metrics -------------------------------------------------------------------
for q in agent_cpu_cores agent_memory_wss_bytes agent_verdicts_per_s agent_queue_depth \
         agent_process_p99_us apiserver_cpu_cores apiserver_watch_events_per_s kwok_cpu_cores; do
  check "prometheus ${q} has samples" jq -e '.data.result | length > 0' "${d}/prom/${q}.json"
done
check "agent accept verdicts observed" jq -e '[.data.result[] | select(.metric.verdict=="accept") | .values[][1] | tonumber] | max > 0' "${d}/prom/agent_verdicts_per_s.json"
check "agent drop verdicts observed" jq -e '[.data.result[] | select(.metric.verdict=="drop") | .values[][1] | tonumber] | max > 0' "${d}/prom/agent_verdicts_per_s.json"
check "no NFQUEUE kernel drops" jq -e '[.data.result[] | .values[][1] | tonumber] | (max // 0) == 0' "${d}/prom/agent_queue_dropped.json"

# ---- kernel state ----------------------------------------------------------------
check "kernel state covers every real worker" bash -c "[[ \$(wc -l < '${d}/kernel-state-steady.jsonl') -eq \$(echo '$(real_workers)' | wc -w) ]]"
check "nftables rules present on workers" jq -e '.nft_rules > 0' "${d}/kernel-state-steady.jsonl"
if jq -es 'all(.[]; .divert_all == true)' "${d}/kernel-state-steady.jsonl" >/dev/null 2>&1; then
  ok "divert-all flavor: no managed-IP sets expected"
else
  check "managed local IPs programmed" jq -es '[.[].podips_v4] | add > 0' "${d}/kernel-state-steady.jsonl"
fi

if (( fail > 0 )); then
  die "${fail} check(s) failed"
fi
log "all checks passed"
