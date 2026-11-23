#!/usr/bin/env bash
# Summarize one or more runs into a Markdown report and a compact JSON file.
#
#   report.sh <run-dir>... [--out <dir>]
#
# Per run:  <out>/<run-id>.json      one flat summary object
# Overall:  <out>/<name>.md          tables comparing every run given
#           where <name> is the run id for a single run, otherwise
#           compare-<dut list>-<timestamp>.
#
# Default <out> is reports/. Prometheus series are reduced to max and mean
# over the whole run window; phase slicing is left to notebooks, the raw
# range results stay under _artifacts/.

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require jq

OUT="${SCALE_ROOT}/reports"
runs=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) runs+=("${1%/}"); shift ;;
  esac
done
[[ ${#runs[@]} -gt 0 ]] || die "usage: report.sh <run-dir>... [--out <dir>]"
mkdir -p "${OUT}"

# prom_stat <run-dir> <query-name> <max|mean> [label-filter-jq]
# Reduces a Prometheus range result to one number across all series.
prom_stat() {
  local f="$1/prom/$2.json" fn="$3" filter="${4:-true}"
  [[ -s "$f" ]] || { echo null; return; }
  jq --arg fn "$fn" --argjson _ 0 \
    "[.data.result[] | select(${filter}) | .values[][1] | tonumber | select(isnan|not)]
     | if length == 0 then null
       elif \$fn == \"max\" then max
       else (add / length) end" "$f" 2>/dev/null || echo null
}

# fortio_pct <file> <percentile> -> milliseconds
fortio_pct() {
  local f="$1" p="$2"
  [[ -s "$f" ]] || { echo null; return; }
  jq "[.DurationHistogram.Percentiles[] | select(.Percentile == $p)][0].Value * 1000" "$f" 2>/dev/null || echo null
}
fortio_field() { [[ -s "$1" ]] && jq "$2" "$1" 2>/dev/null || echo null; }

# mb <run-dir> <query-name>: max of a byte series in MiB, null if absent
mb() { jq -n "$(prom_stat "$1" "$2" max) | if . == null then null else . / 1048576 end"; }

summarize() {
  local d="$1"
  [[ -f "$d/params.json" ]] || die "no params.json in $d"
  local lat="$d/latency-fresh-connections.json" allowed="$d/connrate-allowed.json" denied="$d/connrate-denied.json"
  local ks="$d/kernel-state-steady.jsonl"
  jq -n \
    --slurpfile params "$d/params.json" \
    --slurpfile results "$d/results.json" \
    --slurpfile phases "$d/phases.json" \
    --argjson fresh_p50_ms "$(fortio_pct "$lat" 50)" \
    --argjson fresh_p99_ms "$(fortio_pct "$lat" 99)" \
    --argjson fresh_count "$(fortio_field "$lat" '.DurationHistogram.Count')" \
    --argjson fresh_ok "$(fortio_field "$lat" '(.RetCodes["200"] // 0)')" \
    --argjson conn_qps "$(fortio_field "$allowed" '.ActualQPS')" \
    --argjson conn_count "$(fortio_field "$allowed" '.DurationHistogram.Count')" \
    --argjson conn_ok "$(fortio_field "$allowed" '(.RetCodes["200"] // 0)')" \
    --argjson conn_p50_ms "$(fortio_pct "$allowed" 50)" \
    --argjson conn_p99_ms "$(fortio_pct "$allowed" 99)" \
    --argjson denied_attempts "$(fortio_field "$denied" '.DurationHistogram.Count')" \
    --argjson denied_ok "$(fortio_field "$denied" '(.RetCodes["200"] // 0)')" \
    --argjson agent_cpu_max "$(prom_stat "$d" agent_cpu_cores max)" \
    --argjson agent_cpu_mean "$(prom_stat "$d" agent_cpu_cores mean)" \
    --argjson agent_wss_max_mb "$(mb "$d" agent_memory_wss_bytes)" \
    --argjson agent_heap_max_mb "$(mb "$d" agent_go_heap_bytes)" \
    --argjson accept_per_s_max "$(prom_stat "$d" agent_verdicts_per_s max '.metric.verdict=="accept"')" \
    --argjson drop_per_s_max "$(prom_stat "$d" agent_verdicts_per_s max '.metric.verdict=="drop"')" \
    --argjson process_p99_us_max "$(prom_stat "$d" agent_process_p99_us max)" \
    --argjson queue_depth_max "$(prom_stat "$d" agent_queue_depth max)" \
    --argjson queue_dropped_max "$(prom_stat "$d" agent_queue_dropped max)" \
    --argjson iptracker_cpu_max "$(prom_stat "$d" iptracker_cpu_cores max)" \
    --argjson iptracker_wss_max_mb "$(mb "$d" iptracker_memory_wss_bytes)" \
    --argjson apiserver_cpu_max "$(prom_stat "$d" apiserver_cpu_cores max)" \
    --argjson apiserver_wss_max_mb "$(mb "$d" apiserver_memory_wss_bytes)" \
    --argjson watch_events_per_s_max "$(prom_stat "$d" apiserver_watch_events_per_s max)" \
    --argjson kwok_cpu_max "$(prom_stat "$d" kwok_cpu_cores max)" \
    --argjson kernel "$( [[ -s "$ks" ]] && jq -s . "$ks" || echo '[]')" \
    '{
      run_id: $params[0].run_id, dut: $params[0].dut, scenario: $params[0].scenario,
      nodes: $params[0].nodes, pods: $params[0].pods, identities: $params[0].identities,
      namespaces: $params[0].namespaces, rate: $params[0].rate,
      churn_rate: $params[0].churn_rate, churn_duration: $params[0].churn_duration,
      fresh_identities: $params[0].fresh_identities, started: $params[0].started,
      kind_version: $params[0].kind_version, kwok_version: $params[0].kwok_version,
      total_seconds: ([$phases[0][].seconds] | add),
      fill_seconds: ([$phases[0][] | select(.phase=="fill") | .seconds] | add),
      results: $results[0],
      probes: {
        fresh_conn_count: $fresh_count, fresh_conn_ok: $fresh_ok,
        fresh_conn_p50_ms: $fresh_p50_ms, fresh_conn_p99_ms: $fresh_p99_ms,
        connrate_qps: $conn_qps, connrate_count: $conn_count, connrate_ok: $conn_ok,
        connrate_p50_ms: $conn_p50_ms, connrate_p99_ms: $conn_p99_ms,
        denied_attempts: $denied_attempts, denied_succeeded: $denied_ok
      },
      agent: {
        cpu_cores_max: $agent_cpu_max, cpu_cores_mean: $agent_cpu_mean,
        memory_wss_mb_max: $agent_wss_max_mb, go_heap_mb_max: $agent_heap_max_mb,
        accept_per_s_max: $accept_per_s_max, drop_per_s_max: $drop_per_s_max,
        process_p99_us_max: $process_p99_us_max,
        queue_depth_max: $queue_depth_max, queue_dropped_max: $queue_dropped_max
      },
      iptracker: { cpu_cores_max: $iptracker_cpu_max, memory_wss_mb_max: $iptracker_wss_max_mb },
      control_plane: {
        apiserver_cpu_cores_max: $apiserver_cpu_max, apiserver_memory_wss_mb_max: $apiserver_wss_max_mb,
        watch_events_per_s_max: $watch_events_per_s_max, kwok_cpu_cores_max: $kwok_cpu_max
      },
      kernel_state_steady: $kernel
    }'
}

# fmt <jq-expr> [digits]: prints a number rounded, or "-" for null
fmt() {
  jq -r --argjson dg "${2:-2}" "$1 | if . == null then \"-\" else (. * pow(10;\$dg) | round / pow(10;\$dg)) end" "$SUMMARY"
}
flag() { jq -r "$1 | if . == null then \"-\" elif . then \"yes\" else \"**no**\" end" "$SUMMARY"; }

summaries=()
for d in "${runs[@]}"; do
  id=$(jq -r .run_id "$d/params.json")
  SUMMARY="${OUT}/${id}.json"
  summarize "$d" > "$SUMMARY"
  summaries+=("$SUMMARY")
  log "wrote ${SUMMARY}"
done

if [[ ${#summaries[@]} -eq 1 ]]; then
  name=$(jq -r .run_id "${summaries[0]}")
else
  duts=$(for s in "${summaries[@]}"; do jq -r .dut "$s"; done | sort -u | tr '\n' '-' | sed 's/-$//')
  name="compare-${duts}-$(date -u +%Y%m%dT%H%M%SZ)"
fi
MD="${OUT}/${name}.md"

{
  echo "# Scalability report: ${name}"
  echo
  echo "Generated $(date -u +%FT%TZ) by \`tests/scalability/report.sh\` from ${#summaries[@]} run(s)."
  echo "Every value below is read from the run's artifacts; Prometheus series are reduced over the"
  echo "whole run window (install through connrate), so agent maxima include the connection-rate phase."
  echo
  echo "## Runs"
  echo
  echo "| run | DUT | scenario | fake nodes | Pods | identities | ns | rate/s | churn/s × dur | fresh ids | started |"
  echo "|---|---|---|---:|---:|---:|---:|---:|---|---|---|"
  for SUMMARY in "${summaries[@]}"; do
    jq -r '"| \(.run_id) | \(.dut) | \(.scenario) | \(.nodes) | \(.pods) | \(.identities) | \(.namespaces) | \(.rate) | \(.churn_rate) × \(.churn_duration) | \(.fresh_identities) | \(.started) |"' "$SUMMARY"
  done
  echo
  echo "## Enforcement and admission"
  echo
  echo "Latencies are measured on real Pods across two real workers. Enforcement: policy apply → first"
  echo "permitted connection. Revocation: policy delete → first refused connection. \"denied blocked\" is"
  echo "the unlabeled client failing to connect; a **no** is an enforcement failure."
  echo
  echo "| run | achieved fill Pods/s | enforce idle (ms) | enforce loaded (ms) | revoke (ms) | denied blocked idle/loaded/after churn | allowed ok loaded/after churn | churn replaced/failed |"
  echo "|---|---:|---:|---:|---:|---|---|---|"
  for SUMMARY in "${summaries[@]}"; do
    printf '| %s | %s | %s | %s | %s | %s/%s/%s | %s/%s | %s/%s |\n' \
      "$(jq -r .run_id "$SUMMARY")" "$(fmt .results.fill_achieved_rate 1)" \
      "$(fmt .results.enforce_ms_idle 0)" "$(fmt .results.enforce_ms_loaded 0)" "$(fmt .results.revoke_ms 0)" \
      "$(flag .results.denied_ok_idle)" "$(flag .results.denied_ok_loaded)" "$(flag .results.denied_ok_after_churn)" \
      "$(flag .results.allowed_ok_loaded)" "$(flag .results.allowed_ok_after_churn)" \
      "$(fmt .results.churn_replaced 0)" "$(fmt .results.churn_failed 0)"
  done
  echo
  echo "## Connection path (fortio, no keep-alive, client → gateway across nodes)"
  echo
  echo "| run | fresh conns (ok/total) | fresh p50 / p99 (ms) | conn rate (conn/s) | conns ok/total | rate p50 / p99 (ms) | denied attempts / succeeded |"
  echo "|---|---|---|---:|---|---|---|"
  for SUMMARY in "${summaries[@]}"; do
    printf '| %s | %s/%s | %s / %s | %s | %s/%s | %s / %s | %s / %s |\n' \
      "$(jq -r .run_id "$SUMMARY")" \
      "$(fmt .probes.fresh_conn_ok 0)" "$(fmt .probes.fresh_conn_count 0)" \
      "$(fmt .probes.fresh_conn_p50_ms)" "$(fmt .probes.fresh_conn_p99_ms)" \
      "$(fmt .probes.connrate_qps 0)" "$(fmt .probes.connrate_ok 0)" "$(fmt .probes.connrate_count 0)" \
      "$(fmt .probes.connrate_p50_ms)" "$(fmt .probes.connrate_p99_ms)" \
      "$(fmt .probes.denied_attempts 0)" "$(fmt .probes.denied_succeeded 0)"
  done
  echo
  echo "## Agent resources and queue (max over run, summed across real nodes where applicable)"
  echo
  echo "| run | CPU max / mean (cores) | WSS max (MB) | Go heap max (MB) | accept/s max | drop/s max | process p99 max (µs) | queue depth max | queue drops |"
  echo "|---|---|---:|---:|---:|---:|---:|---:|---:|"
  for SUMMARY in "${summaries[@]}"; do
    printf '| %s | %s / %s | %s | %s | %s | %s | %s | %s | %s |\n' \
      "$(jq -r .run_id "$SUMMARY")" \
      "$(fmt .agent.cpu_cores_max 3)" "$(fmt .agent.cpu_cores_mean 3)" \
      "$(fmt .agent.memory_wss_mb_max 1)" "$(fmt .agent.go_heap_mb_max 1)" \
      "$(fmt .agent.accept_per_s_max 0)" "$(fmt .agent.drop_per_s_max 0)" \
      "$(fmt .agent.process_p99_us_max 0)" "$(fmt .agent.queue_depth_max 0)" "$(fmt .agent.queue_dropped_max 0)"
  done
  echo
  echo "## Control plane and distributor"
  echo
  echo "| run | apiserver CPU max (cores) | apiserver WSS max (MB) | watch events/s max | kwok CPU max | ip-tracker CPU max | ip-tracker WSS max (MB) |"
  echo "|---|---:|---:|---:|---:|---:|---:|"
  for SUMMARY in "${summaries[@]}"; do
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
      "$(jq -r .run_id "$SUMMARY")" \
      "$(fmt .control_plane.apiserver_cpu_cores_max 3)" "$(fmt .control_plane.apiserver_memory_wss_mb_max 0)" \
      "$(fmt .control_plane.watch_events_per_s_max 0)" "$(fmt .control_plane.kwok_cpu_cores_max 3)" \
      "$(fmt .iptracker.cpu_cores_max 3)" "$(fmt .iptracker.memory_wss_mb_max 1)"
  done
  echo
  echo "## Kernel state at steady state (per real worker)"
  echo
  echo "\`-1\` means the set does not exist: the iptracker flavor diverts all traffic and programs no managed-IP sets."
  echo
  echo "| run | node | nft rules | podips-v4 | podips-v6 | conntrack labeled | divert-all |"
  echo "|---|---|---:|---:|---:|---:|---|"
  for SUMMARY in "${summaries[@]}"; do
    jq -r '.run_id as $r | .kernel_state_steady[] | "| \($r) | \(.node) | \(.nft_rules) | \(.podips_v4) | \(.podips_v6) | \(.conntrack_labeled) | \(.divert_all // false) |"' "$SUMMARY"
  done
  echo
  echo "## Reading the numbers"
  echo
  echo "- kwok Pods have addresses but no network namespace: the agents ingest and index them, and the"
  echo "  nftables sets hold only *local* managed addresses (the probe Pods), so \`podips-v4\` stays small"
  echo "  by design for KNP. Agent CPU, memory and API-server load are where the fake objects show up."
  echo "- One run per configuration; treat differences below ~20% as noise until repeated."
  echo "- Raw artifacts (Prometheus range results, fortio JSON, phases, logs) are under"
  echo "  \`tests/scalability/_artifacts/<run-id>/\` on the machine that ran the experiment."
} > "$MD"
log "wrote ${MD}"
