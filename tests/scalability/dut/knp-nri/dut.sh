#!/usr/bin/env bash
# DUT: kube-network-policies standard flavor with NRI enabled.
# Local Pod addresses come from the container runtime at sandbox creation;
# remote addresses still arrive through informer watches.

DUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUT="$(basename "${DUT_DIR}")"
export DUT
export KNP_FLAVOR="standard"
export KNP_DISABLE_NRI="false"
export KNP_WITH_IPTRACKER="false"

source "${DUT_DIR}/../knp-lib.sh"

case "${1:-install}" in
  install) knp_install ;;
  uninstall) knp_uninstall ;;
  kernel-state) knp_kernel_state "$2" ;;
  *) echo "usage: $0 {install|uninstall|kernel-state <node>}" >&2; exit 2 ;;
esac
