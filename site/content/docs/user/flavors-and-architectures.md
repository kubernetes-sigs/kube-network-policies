---
title: "Flavors & Architectures"
weight: 2
---

`kube-network-policies` is distributed in different image flavors to optimize resource consumption and support different use-cases. It also natively supports multi-platform architectures.

## Supported Architectures

Images are built and published for the following hardware architectures:
- `linux/amd64`
- `linux/arm64`
- `linux/s390x`

Multi-platform images are pushed automatically to the staging registry during releases, allowing Kubernetes to pull the correct architecture for your nodes.

---

## Image Flavors

Depending on your cluster size, requirements, and policy choices, you can select one of the following image flavors:

### 1. `standard`
* **Target Image:** `registry.k8s.io/networking/kube-network-policies:<tag>`
* **Description:** This is the default flavor. It runs an in-cluster agent on every node that watches the Kubernetes API for standard namespace-scoped `NetworkPolicy` objects, `Pods`, and `Namespaces`.
* **Resource Cost:** Higher on large clusters since every node maintains an active informer cache for all pods and namespaces.
* **Deployment Manifest:** `install.yaml`

### 2. `npa-v1alpha2` (Admin Network Policy)
* **Target Image:** `registry.k8s.io/networking/kube-network-policies:<tag>-npa-v1alpha2`
* **Description:** Extends the standard agent to add support for the newer Kubernetes `ClusterNetworkPolicy` APIs (v1alpha2 spec). It evaluates Admin Network Policies and Baseline Admin Network Policies using a userspace pipeline. It also runs a built-in DNS/Domain cache to resolve egress domain-name rules.
* **Resource Cost:** Similar to standard, but intercepts all traffic (`divertAll = true`) because baseline policies can apply globally across the cluster.
* **Deployment Manifest:** `install-cnp.yaml`

### 3. `iptracker`
* **Target Image:** `registry.k8s.io/networking/kube-network-policies:<tag>-iptracker`
* **Description:** Optimized for large-scale clusters. Instead of having every node run heavy API informers for all pods, namespaces, and nodes, it connects over gRPC to a centralized helper daemon (`kube-ip-tracker`) to retrieve IP-to-pod mappings.
* **Resource Cost:** Very low memory footprint per node.
* **Deployment Manifest:** `install-iptracker.yaml`

### 4. `kube-ip-tracker` (Standalone Daemon)
* **Target Image:** `registry.k8s.io/networking/kube-ip-tracker:<tag>`
* **Description:** A standalone control-plane helper daemon that runs centrally in your cluster. It watches pods, namespaces, and nodes, aggregates their labels, and runs an embedded etcd store to serve IP-to-PodInfo mappings to the node agents running in `iptracker` mode.
* **Deployment Manifest:** Included as a Deployment in `install-iptracker.yaml`

---

## Configuration Options & Flags

When deploying `kube-network-policies` or `kube-ip-tracker`, you can pass the following command-line flags to customize behavior:

### Agent Flags (`kube-network-policies`)

| Flag | Default | Description |
|---|---|---|
| `--kubeconfig` | `""` | Path to a kubeconfig file. If empty, the agent uses in-cluster service account credentials. |
| `--fail-open` | `true` | If true, do not drop packets if the agent is not running or crashes. |
| `--nfqueue-id` | `100` | The NFQUEUE ID to use for intercepting network packets. |
| `--metrics-bind-address` | `:9080` | The port/address to expose Prometheus metrics. |
| `--hostname-override` | `""` | Node name to use. If unset, uses the hostname of the OS. |
| `--netfilter-bug-1766-fix` | `true` | Processes DNS packets on `PREROUTING` to prevent a conntrack race bug in Linux kernels before v6.12. |
| `--disable-nri` | `false` | Disables NRI integration. NRI avoids race conditions by retrieving pod container setup events early. |
| `--strict-mode` | `true` | If true, updates to policies will immediately evaluate and affect established connections in addition to new ones. |

### Standalone IP Tracker Flags (`kube-ip-tracker`)

| Flag | Default | Description |
|---|---|---|
| `--listen-address` | `http://0.0.0.0:19090` | The address the gRPC cache server listens on. |
| `--etcd-dir` | `./ipcache.etcd` | Directory where the embedded etcd server stores its state database. |
| `--tls-ca-file` | `""` | TLS CA file for client validation. |
| `--tls-cert-file` | `""` | TLS certificate file. |
| `--tls-key-file` | `""` | TLS key file. |

---

## Building and Releasing Images

The `Makefile` in the repository root provides targets to build and release images:

```bash
# Build all binary variants locally
make build

# Build and load all image variants into your local Docker daemon
make images-build

# Build multi-platform images and push them to the registry
make images-push
```
