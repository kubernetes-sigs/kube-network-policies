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

### 2. `npa-v1beta1` (ClusterNetworkPolicy)
* **Target Image:** `registry.k8s.io/networking/kube-network-policies:<tag>-npa-v1beta1`
* **Description:** Extends the standard agent to support the Kubernetes `ClusterNetworkPolicy` API (`v1beta1`, the storage version). It evaluates `ClusterNetworkPolicy` rules at the `Admin` and `Baseline` tiers using a userspace pipeline, and runs a built-in DNS/Domain cache to resolve egress domain-name rules.
* **Resource Cost:** Similar to standard, but intercepts all traffic (`divertAll = true`) because baseline-tier policies can apply globally across the cluster.
* **Deployment Manifest:** `install-cnp.yaml`

### 3. `npa-v1alpha2` (ClusterNetworkPolicy — serving version)
* **Target Image:** `registry.k8s.io/networking/kube-network-policies:<tag>-npa-v1alpha2`
* **Description:** Same as `npa-v1beta1`, but built against the `v1alpha2` serving version of `ClusterNetworkPolicy` for backward compatibility.
* **Resource Cost:** Same as `npa-v1beta1`.
* **Deployment Manifest:** `install-cnp.yaml`

### 4. `iptracker`
* **Target Image:** `registry.k8s.io/networking/kube-network-policies:<tag>-iptracker`
* **Description:** Optimized for large-scale clusters. Instead of having every node run heavy API informers for all pods, namespaces, and nodes, it connects over gRPC to a centralized helper daemon (`kube-ip-tracker`) to retrieve IP-to-pod mappings.
* **Resource Cost:** Very low memory footprint per node.
* **Deployment Manifest:** `install-iptracker.yaml`

### 5. `kube-ip-tracker` (Standalone Daemon)
* **Target Image:** `registry.k8s.io/networking/kube-ip-tracker:<tag>`
* **Description:** A standalone control-plane helper daemon that runs centrally in your cluster. It watches pods, namespaces, and nodes, aggregates their labels, and runs an embedded etcd store to serve IP-to-PodInfo mappings to the node agents running in `iptracker` mode.
* **Deployment Manifest:** Included as a Deployment in `install-iptracker.yaml`

### 6. `dht` (1-Hop Agent DHT)
* **Target Image:** `registry.k8s.io/networking/kube-network-policies:<tag>-dht`
* **Description:** Self-contained large-scale flavor with no central stateful helper daemon. Each node watches only its own local pods (`spec.nodeName=<node>` + NRI), `Namespaces`, `NetworkPolicies`, and the DaemonSet headless Service `EndpointSlice`s, sharing IP-to-PodInfo mappings in a 1-hop Rendezvous-Hashing DHT over stdlib HTTP/2 with async `NFQUEUE` dispatch.
* **Resource Cost:** Very low memory footprint per node ($O(\text{local pods} + \text{active peers} + k \cdot P/N)$), and keeps `divertAll = false` so unmanaged local pods stay in the kernel fast path.
* **Deployment Manifest:** `install-dht.yaml`
* **Design & Comparison:** See [1-Hop Agent DHT Design](../../concepts/dht-design/) and [Scaling Approaches Comparison](../../concepts/scaling-approaches/).

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
| `--log-verdicts` | `deny` | Logs the verdict of the evaluated packets at any verbosity: `deny` logs the denied packets, `all` also the accepted ones and `none` disables it. The verdicts are written by a dedicated goroutine, so they do not delay the packets, and dropped when the log destination falls behind (see the `kube_network_policies_verdict_log_dropped` metric). |

### Standalone IP Tracker Flags (`kube-ip-tracker`)

| Flag | Default | Description |
|---|---|---|
| `--listen-address` | `http://0.0.0.0:19090` | The address the gRPC cache server listens on. |
| `--etcd-dir` | `./ipcache.etcd` | Directory where the embedded etcd server stores its state database. |
| `--tls-ca-file` | `""` | TLS CA file for client validation. |
| `--tls-cert-file` | `""` | TLS certificate file. |
| `--tls-key-file` | `""` | TLS key file. |

### 1-Hop Agent DHT Flags (`kube-network-policies` `dht` flavor)

| Flag | Default | Description |
|---|---|---|
| `--dht-listen-address` | `:19091` | Address and port for the 1-hop DHT HTTP/2 server. |
| `--dht-service-name` | `kube-network-policies-dht` | Headless Service name whose `EndpointSlice`s define the DHT ring. |
| `--dht-service-namespace` | `kube-system` | Namespace of the DHT headless Service. |
| `--dht-ca-file` | `""` | CA certificate file for mutual TLS between DHT agents. |
| `--dht-cert-file` | `""` | Certificate file for mutual TLS between DHT agents. |
| `--dht-key-file` | `""` | Private key file for mutual TLS between DHT agents. |

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
