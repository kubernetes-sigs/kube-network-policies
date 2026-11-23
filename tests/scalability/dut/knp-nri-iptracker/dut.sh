#!/usr/bin/env bash
# DUT: kube-network-policies iptracker flavor with NRI enabled.
# Agents take remote Pod metadata from the kube-ip-tracker distributor
# instead of watching Pods directly; local addresses come from NRI.
# Note: this flavor queues all forwarded traffic (ManagedIPs divert-all).

DUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUT="$(basename "${DUT_DIR}")"
export DUT
export KNP_FLAVOR="iptracker"
export KNP_DISABLE_NRI="false"
export KNP_WITH_IPTRACKER="true"
# Avoid the standard flavor's queue id so a stale agent cannot steal packets.
export KNP_NFQUEUE_ID="${KNP_NFQUEUE_ID:-198}"

source "${DUT_DIR}/../knp-lib.sh"

case "${1:-install}" in
  install) knp_install ;;
  uninstall) knp_uninstall ;;
  kernel-state) knp_kernel_state "$2" ;;
  *) echo "usage: $0 {install|uninstall|kernel-state <node>}" >&2; exit 2 ;;
esac
