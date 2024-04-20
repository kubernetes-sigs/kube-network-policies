
#!/bin/bash

set -o errexit -o nounset -o pipefail

# cd to the repo root
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "${REPO_ROOT}"

docker build . -t aojea/kube-netpol:"${1:-test}"
