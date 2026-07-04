---
title: "Modularity and Extensibility"
weight: 2
---

The `PolicyEvaluator` interface is the core abstraction of the packet filtering pipeline in `kube-network-policies`. Each evaluator is responsible for processing a packet and deciding its outcome based on its policy implementation.

## The PolicyEvaluator Interface

The interface is defined in `pkg/api/interfaces.go` (or `pkg/networkpolicy/engine.go`) as follows:

```go
type PolicyEvaluator interface {  
    Name() string  
    EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)  
    EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error)  
}
```

The `Verdict` returned by each evaluator can be one of the following:

- `VerdictAccept`: The packet is allowed, and no further evaluators in the pipeline are consulted.
- `VerdictDeny`: The packet is denied, and no further evaluators are consulted.
- `VerdictNext`: The packet does not match this policy (or is passed through), and the engine continues to the next evaluator in the pipeline.

## The Pipeline Order

When a packet is evaluated, it is processed sequentially by a pipeline of policy evaluators. The order is crucial, especially for Admin Network Policies:

1. **Logging Evaluator** (if `-v=2` is enabled): Emits a structured log of the packet being evaluated.
2. **Admin Network Policy (ANP)** (`ClusterNetworkPolicy` at `AdminTier`): Enforces administrator-defined policies that take precedence over user-defined rules.
3. **Standard Network Policy** (`StandardNetworkPolicy`): Enforces normal Kubernetes `NetworkPolicies` defined by namespace owners.
4. **Baseline Admin Network Policy (BANP)** (`ClusterNetworkPolicy` at `BaselineTier`): Enforces baseline default rules that only take effect if no prior policy accepted or denied the traffic.

If a packet runs through the entire pipeline and receives a `VerdictNext` from all evaluators, the default behavior of the cluster (typically to allow) is applied.

---

## Embedding & Extensibility

A key design goal of `kube-network-policies` is modularity. Rather than being a monolithic CNI or controller, the project is structured as a Go library. The core components (the dataplane controller, the policy engine, and the individual evaluators) can be imported and composed into other projects.

This modular architecture allows third-party projects to build custom packet-filtering solutions, CNI plugins, or multi-cluster network policies by implementing the `PolicyEvaluator` interface and plugging custom evaluators into the engine pipeline.

### Real-World Examples

Several Kubernetes projects embed `kube-network-policies` as a library:

1. **[GKE Labs Multicluster Network Policy](https://github.com/gke-labs/multicluster-network-policy):**
   Uses the engine and extends it with a custom `PolicyEvaluator` plugin to evaluate and enforce network security policies across multiple Kubernetes clusters.

2. **[Kindnet](https://github.com/kubernetes-sigs/kindnet):**
   The default, lightweight CNI provider for [KIND (Kubernetes in Docker)](https://kind.sigs.k8s.io/). Kindnet embeds this package directly in its CNI daemon to provide userspace NetworkPolicy enforcement:
   - See [kindnetd cmd/main.go in Kubernetes-sigs/kind](https://github.com/kubernetes-sigs/kind/blob/2947cc25da536264eaed186033189ee89a1820a9/images/kindnetd/cmd/kindnetd/main.go#L33-L36) for how the package is imported.
   - See [kindnetd cmd/main.go in Kubernetes-sigs/kindnet](https://github.com/kubernetes-sigs/kindnet/blob/57aff7ece2f69da64b4551683c4de996689d9b81/cmd/kindnetd/main.go#L42-L46) for the initialization process.

---

## Additive & Safe Coexistence

`kube-network-policies` is fully **additive** and designed to safely coexist alongside any other CNI provider (such as **Cilium**, **Calico**, or **Flannel**) and their respective network policy implementations.

When deployed alongside another CNI with network policy support, the cluster will run **two policy engines** in parallel. This configuration is entirely safe due to how the Linux network stack and firewalling layers function:

- **Logical AND Enforcement:** A packet must pass both policy engines to be allowed through. If either the primary CNI's engine (via eBPF, iptables, etc.) or the `kube-network-policies` userspace engine (via `nftables` + `NFQUEUE`) decides to drop a packet, the packet is discarded.
- **Double-Sided Verification:** For a connection to succeed, both policy engines must individually evaluate and accept the traffic.

This coexistence enables several operational advantages:
- **Incremental Migration:** You can introduce `kube-network-policies` to an existing cluster to gradually transition policies without turning off the current implementation.
- **Separation of Concerns:** Administrators can use `kube-network-policies` specifically to enforce cluster-wide Admin Network Policies (ANPs) and Baseline Admin Network Policies (BANPs) at the host layer, while leaving application developers to manage standard namespaces policies through the primary CNI.
- **Non-Disruptive Auditing:** You can run the agent alongside your main CNI with logging enabled (`-v=2`) to audit traffic decisions and collect rich userspace JSON logs without altering the primary CNI's data path.

