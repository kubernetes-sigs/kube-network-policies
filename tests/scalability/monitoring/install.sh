#!/usr/bin/env bash
# Deploy (or reconfigure) the Prometheus collector.
#
#   monitoring/install.sh [dut-name]
#
# The scrape configuration is scrape-base.yaml plus, when a DUT name is
# given and dut/<name>/scrape.yaml exists, that file's scrape_configs list
# items appended verbatim. Re-running with a different DUT reloads Prometheus.

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

export PROMETHEUS_IMAGE="${PROMETHEUS_IMAGE:-quay.io/prometheus/prometheus:v3.5.0}"

dut="${1:-}"
require kubectl envsubst curl

scrape_config() {
  cat "${SCALE_ROOT}/monitoring/scrape-base.yaml"
  if [[ -n "$dut" && -f "${SCALE_ROOT}/dut/${dut}/scrape.yaml" ]]; then
    log "adding scrape jobs from dut/${dut}/scrape.yaml"
    cat "${SCALE_ROOT}/dut/${dut}/scrape.yaml"
  fi
}

render "${SCALE_ROOT}/monitoring/prometheus.yaml" MONITORING_NS PROMETHEUS_NODEPORT PROMETHEUS_IMAGE \
  | kubectl apply -f -

kubectl -n "${MONITORING_NS}" create configmap prometheus \
  --from-file=prometheus.yaml=<(scrape_config) \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "${MONITORING_NS}" rollout status deploy prometheus --timeout=120s

# The ConfigMap volume refreshes asynchronously; force a reload once it lands.
url="$(prometheus_url)"
for _ in $(seq 1 30); do
  if curl -fsS -X POST "${url}/-/reload" >/dev/null 2>&1; then
    log "prometheus reloaded at ${url}"
    exit 0
  fi
  sleep 2
done
warn "prometheus did not accept reload at ${url}; it will pick the config up on its own"
