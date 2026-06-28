---
title: "Policy Evaluators"
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
