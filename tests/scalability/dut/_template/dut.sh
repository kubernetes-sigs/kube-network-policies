#!/usr/bin/env bash
# Template for an external DUT (e.g. cilium, calico, ovn-kubernetes, antrea).
# Copy this directory to dut/<name>/ and fill in the three entry points.
# run.sh invokes:  dut.sh install | dut.sh uninstall | dut.sh kernel-state <node>
#
# Contract:
#  - install must return only when the enforcer is ready on every real
#    worker ($(real_workers) from lib.sh) and must NOT schedule onto kwok
#    nodes (nodeAffinity: type NotIn [kwok]).
#  - the enforcer must implement Kubernetes NetworkPolicy so the shared
#    scenarios in scenarios/ apply unchanged.
#  - if the DUT exposes Prometheus metrics, add scrape.yaml next to this file
#    (a list of scrape_configs items); monitoring/install.sh appends it.
#  - kernel-state must print one JSON object describing per-node enforcement
#    state (map/set/flow cardinalities) so materialization can be compared
#    across representations.
#
# The DUT is expected to coexist with kindnet acting as a plain CNI
# (cluster.sh replaces kindnetd with an image that does not enforce policy).
# A DUT that is itself a CNI should create the cluster with
# KIND_DISABLE_DEFAULT_CNI=true and install networking here.

DUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUT="$(basename "${DUT_DIR}")"
export DUT
source "${DUT_DIR}/../../lib.sh"

install() {
  die "dut/${DUT}: install not implemented"
}

uninstall() {
  die "dut/${DUT}: uninstall not implemented"
}

kernel_state() {
  local node="$1"
  printf '{"node":"%s","dut":"%s"}\n' "$node" "${DUT}"
}

case "${1:-install}" in
  install) install ;;
  uninstall) uninstall ;;
  kernel-state) kernel_state "$2" ;;
  *) echo "usage: $0 {install|uninstall|kernel-state <node>}" >&2; exit 2 ;;
esac
