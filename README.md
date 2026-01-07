# Kubernetes network policies

Implementation of Kubernetes Network Policies:
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Admin Network Policies and Baseline Admin Network Policies](https://network-policy-api.sigs.k8s.io/)


## Architecture Overview

The kube-network-policies project is designed to enforce Kubernetes network policies by intercepting and evaluating network packets in userspace. This is achieved by using NFQUEUE to redirect packets to the controller, which then decides whether to allow or deny them based on a set of policy evaluators.

### Packet Flow

The following diagram illustrates the flow of a network packet from the kernel to the userspace controller and back:

[![](https://mermaid.ink/img/pako:eNp1UlFvmzAQ_iuWnzaJsEADATpVSgppp25dljZ7GPDg4EuC6tjImHVZlP8-Y6KgpZsfwHz3fXf3HXfAhaCAI7yRpNqi5zjjSJ-6WXXAA0gODD1VpIAu1B5aSihUKTj6vOjRSfoI6lXIFzQnxQso9HElb9BcUDTJ0WBwg6YHvlZkxaBGi6Z9GkJMFKkY4YBuBVdSMAbyeN2nnWotgroVlvUW6AcJjCigJmWcThgTr28qTvNTBuA04xemljXI-n-Onqc92o-hWcHg5G4wF6wsSt1-328vaU-SGsoeJXxTcujMz87gT8IaooRETn79t3BmmHdvme4l884w71PbtvM-YsxeuDbje5x9WybLxIiSU6r7NvAdJC0LFaFJUUClupn-kxAD35vwp3dpvPg6z99rGrbwDuSOlFSv0KGVZVhtYQcZjvSVwpo0TGU440dNJY0ST3te4EjJBizcVFT_yLgkesg7HK0Jq89oQktt_AyC-fzS7apZWQtXhOPogH_hyPFCOwxG-hW4fnjl-p6F9zhyg6Htjv3A930ndN3x1dHCv4XQpYa27wzdcOQFw5EXeuFobGEpms32XFAn_2GoXasb2Vrs7lJPF-StaLjCke8c_wB98vpd?type=png)](https://mermaid.live/edit#pako:eNp1UlFvmzAQ_iuWnzaJsEADATpVSgppp25dljZ7GPDg4EuC6tjImHVZlP8-Y6KgpZsfwHz3fXf3HXfAhaCAI7yRpNqi5zjjSJ-6WXXAA0gODD1VpIAu1B5aSihUKTj6vOjRSfoI6lXIFzQnxQso9HElb9BcUDTJ0WBwg6YHvlZkxaBGi6Z9GkJMFKkY4YBuBVdSMAbyeN2nnWotgroVlvUW6AcJjCigJmWcThgTr28qTvNTBuA04xemljXI-n-Onqc92o-hWcHg5G4wF6wsSt1-328vaU-SGsoeJXxTcujMz87gT8IaooRETn79t3BmmHdvme4l884w71PbtvM-YsxeuDbje5x9WybLxIiSU6r7NvAdJC0LFaFJUUClupn-kxAD35vwp3dpvPg6z99rGrbwDuSOlFSv0KGVZVhtYQcZjvSVwpo0TGU440dNJY0ST3te4EjJBizcVFT_yLgkesg7HK0Jq89oQktt_AyC-fzS7apZWQtXhOPogH_hyPFCOwxG-hW4fnjl-p6F9zhyg6Htjv3A930ndN3x1dHCv4XQpYa27wzdcOQFw5EXeuFobGEpms32XFAn_2GoXasb2Vrs7lJPF-StaLjCke8c_wB98vpd)

### Key Components

The key components of the architecture are:

* **Dataplane Controller**: The `dataplane/controller.go` file contains the main controller that sets up NFQUEUE, intercepts packets, and orchestrates the policy evaluation process. It is responsible for creating the necessary nftables rules to redirect traffic. To avoid the performance penalty of sending all packets to userspace, the controller includes logic to only capture packets for pods that are targeted by at least one network policy.
* **Policy Engine**: The `networkpolicy/engine.go` file defines the `PolicyEngine`, which manages a pipeline of `PolicyEvaluator` plugins. The engine is responsible for running each packet through the pipeline and making a final decision based on the verdicts returned by the evaluators.
* **Pod Info Provider**: The `podinfo/podinfo.go` file provides an interface for retrieving pod information. It resolves a packet's IP address to a PodInfo protobuf type (`pkg/api/kubenetworkpolicies.proto`). This `PodInfo` object contains all the necessary information for evaluators to match policies, including the pod's name, labels, namespace, and associated node information.  
* **Policy Evaluators**: These are plugins that implement the PolicyEvaluator interface and contain the logic for a specific type of network policy. The project currently includes evaluators for AdminNetworkPolicy, BaselineAdminNetworkPolicy, and the standard Kubernetes NetworkPolicy.

Here is a diagram illustrating the interaction between these components:

[![](https://mermaid.ink/img/pako:eNpNkdtum0AQhl9lNFeNhB2bGAykipTYVLKqVDSHXiTkYgtjjIp30bJYcS2_e4eFkO7Nzs7OfP8cTpipnDDCQot6B0_rVAKf29cU18KIuhKSYKWk0aqqSH_9rS9vJvBIpoG2hh_ffj7Hz_HgfaCMygM1UIvsD0ek-AaTCST2xdYN3DE2UVWZHSGWRSlpyLwXUhScSAdRtcKoXgegLmuqOIxJ131hdx2RIZbpQKLyjdyqFC1-9R_-g_SluRhEBhfBRhaamuYyttdYvGm1hF-k8zIzn4IrS15bcg6dGCRaHcp8HMYDNarq2t4kYNRHScPnbZaxBn9-Dxqbrfeku8lco4Ns7kWZ8_RPnViKZkd7bjZiM6etaCsuJJVnDhWtUY9HmWFkdEsOtnXOraxLwXvbY7QVVTN647zkxkcn2ed9v2a7bQdrITE64TtGcy-chsGCr8D1wyvX9xw8YuQGs6m79APf9-eh6y6vzg7-VYqlZlN_PnPDhRfMFl7ohYulg1q1xW4UZPiLDe1LLXTXYm9rkjy4lWqlwcj3zv8A6-vK3A?type=png)](https://mermaid.live/edit#pako:eNpNkdtum0AQhl9lNFeNhB2bGAykipTYVLKqVDSHXiTkYgtjjIp30bJYcS2_e4eFkO7Nzs7OfP8cTpipnDDCQot6B0_rVAKf29cU18KIuhKSYKWk0aqqSH_9rS9vJvBIpoG2hh_ffj7Hz_HgfaCMygM1UIvsD0ek-AaTCST2xdYN3DE2UVWZHSGWRSlpyLwXUhScSAdRtcKoXgegLmuqOIxJ131hdx2RIZbpQKLyjdyqFC1-9R_-g_SluRhEBhfBRhaamuYyttdYvGm1hF-k8zIzn4IrS15bcg6dGCRaHcp8HMYDNarq2t4kYNRHScPnbZaxBn9-Dxqbrfeku8lco4Ns7kWZ8_RPnViKZkd7bjZiM6etaCsuJJVnDhWtUY9HmWFkdEsOtnXOraxLwXvbY7QVVTN647zkxkcn2ed9v2a7bQdrITE64TtGcy-chsGCr8D1wyvX9xw8YuQGs6m79APf9-eh6y6vzg7-VYqlZlN_PnPDhRfMFl7ohYulg1q1xW4UZPiLDe1LLXTXYm9rkjy4lWqlwcj3zv8A6-vK3A)

### The PolicyEvaluator Interface

The PolicyEvaluator interface is the core of the policy evaluation pipeline. Each evaluator is responsible for determining whether a packet should be allowed, denied, or passed to the next evaluator in the pipeline.

The interface is defined in `pkg/networkpolicy/engine.go` as follows:

```go
type PolicyEvaluator interface {  
    Name() string  
    EvaluateIngress(ctx context.Context, p \*network.Packet, srcPod, dstPod \*api.PodInfo) (Verdict, error)  
    EvaluateEgress(ctx context.Context, p \*network.Packet, srcPod, dstPod \*api.PodInfo) (Verdict, error)  
}
```

The Verdict returned by each evaluator can be one of the following:

* `VerdictAccept`: The packet is allowed, and no further evaluators are consulted.
* `VerdictDeny`: The packet is denied, and no further evaluators are consulted.
* `VerdictNext`: The packet is passed to the next evaluator in the pipeline.

### How to Add a New PolicyEvaluator

Adding a new `PolicyEvaluator` is straightforward and involves the following steps:

1. **Create a new file** for your evaluator in the `pkg/networkpolicy` directory.
2. **Define a struct** for your evaluator that implements the `PolicyEvaluator` interface.
3. **Implement the Name method** to return a unique name for your evaluator.
4. **Implement the EvaluateIngress and EvaluateEgress methods** to define the logic for your policy.
5. **Register your new evaluator** in the PolicyEngine in `cmd/main.go`.

#### Example: Creating an AllowListPolicy

Let's create a simple `AllowListPolicy` that only allows traffic from a predefined list of IP addresses.

1. **Create the file** pkg/networkpolicy/allowlistpolicy.go:

```go
   package networkpolicy

   import (  
       "context"  
       "net"  
       "sigs.k8s.io/kube-network-policies/pkg/api"  
       "sigs.k8s.io/kube-network-policies/pkg/network"  
   )

   // AllowListPolicy is a simple policy that allows traffic only from a predefined list of IP addresses.  
   type AllowListPolicy struct {  
       allowedIPs []net.IP
   }

   // NewAllowListPolicy creates a new AllowListPolicy.  
   func NewAllowListPolicy(allowedIPs []net.IP) *AllowListPolicy {
       return &AllowListPolicy{
           allowedIPs: allowedIPs,  
       }  
   }

   func (a *AllowListPolicy) Name() string {
       return "AllowListPolicy"
   }

   func (a *AllowListPolicy) EvaluateIngress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
       for \_, ip := range a.allowedIPs {
           if ip.Equal(p.SrcIP) {  
               return VerdictAccept, nil  
           }  
       }  
       return VerdictDeny, nil  
   }

   func (a *AllowListPolicy) EvaluateEgress(ctx context.Context, p *network.Packet, srcPod, dstPod *api.PodInfo) (Verdict, error) {
       // This policy only applies to ingress traffic.
       return VerdictNext, nil
   }
```

2. **Register the new evaluator** in `cmd/main.go`:

```go
   // ... (imports)

   func main() {  
       // ... (existing setup)

       // Create the evaluators for the Pipeline to process the packets  
       // and take a network policy action. The evaluators are processed  
       // by the order in the array.  
       evaluators := []networkpolicy.PolicyEvaluator{}

       // Add the new AllowListPolicy evaluator
       allowedIPs := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
       evaluators = append(evaluators, networkpolicy.NewAllowListPolicy(allowedIPs))

       // ... (rest of the evaluators)

       // Create the controller that enforces the network policies on the data plane  
       networkPolicyController, err := dataplane.NewController(  
           clientset,  
           networkPolicyInfomer,  
           nsInformer,  
           podInformer,  
           networkpolicy.NewPolicyEngine(podInfoProvider, evaluators),  
           cfg,  
       )  
       // ... (rest of the main function)  
   }
```

By following these steps, you can easily extend the functionality of kube-network-policies with your own custom policy evaluators.

### Future Improvements

* **Programmable Traffic Capture**: Currently, the controller decides which traffic to send to userspace based on whether a pod is selected by any network policy. A potential improvement is to make this more programmable, allowing individual PolicyEvaluator plugins to specify the exact traffic they are interested in. This would further optimize performance by reducing the amount of traffic sent to userspace.

## Install

### Manual Installation

There are two manifest in the current repository:

1. For "traditional" Kubernetes Network policies just do:

```sh
kubectl apply -f install.yaml
```

2. For the Admin Network Policies and Baseline Admin Network Policies the CRDs has to be installed first:

```sh
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml

kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml
```

and then install the daemonset enabling the features with the corresponding flags:

```sh
kubectl apply -f install-anp.yaml
```

### Helm

To install kube-network-policies via Helm run:

```sh
helm install kube-network-policies -n kube-system charts/kube-network-policies
```

Admin Network Policies and Baseline Admin Network Policies features are controlled by `Values.adminNetworkPolicy` and
they are enabled by default. Disable them if needed in values.yaml or use `--set adminNetworkPolicy=false` when running
`helm install` command.

NOTE: the corresponding CRDs must be installed first.

## Uninstall

### Manual Uninstallation

To uninstall the components installed manually:

1. Remove the "traditional" Kubernetes Network Policies:

```sh
kubectl delete -f install.yaml
```

2. For the Admin Network Policies and Baseline Admin Network Policies, remove the CRDs and the daemonset:
```sh
kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml

kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml
```

### Helm Uninstallation
To uninstall kube-network-policies if installed via Helm:
```sh
helm uninstall kube-network-policies -n kube-system
```

## Metrics

Prometheus metrics are exposed on the address defined by the flag

```
  -metrics-bind-address string
        The IP address and port for the metrics server to serve on (default ":9080")
```

Current implemented metrics are:

* packet_process_time: Time it has taken to process each packet (microseconds)
* packet_process_duration_microseconds: A summary of the packet processing durations in microseconds
* packet_count: Number of packets
* nfqueue_queue_total: The number of packets currently queued and waiting to be processed by the application
* nfqueue_queue_dropped: Number of packets that had to be dropped by the kernel because too many packets are already waiting for user space to send back the mandatory accept/drop verdicts
* nfqueue_user_dropped: Number of packets that were dropped within the netlink subsystem. Such drops usually happen when the corresponding socket buffer is full; that is, user space is not able to read messages fast enough
* nfqueue_packet_id: ID of the most recent packet queued

## Testing

See [TESTING](docs/testing/README.md)

There are two github workflows that runs e2e tests aginst the Kubernetes/Kubernetes Network Policy tests and the Network Policy API Working Group conformance tests.

## Project Scope

This project was created to fill the gap on testing coverage in the area of Network Policies.
There are limited existing solutions, but those are specific to individual network providers
that require to install additional functionality, adding complexity and debugging difficulty,
and not allowing to iterate fast during the development of new features.

Ref: https://github.com/kubernetes/org/issues/4856

This is an Open Source project maintained by the community with a best-effort support model, contributions
aligned with the current project scope, feedback and bugs reports are very welcome.

### Goals

P0: Support Testing Kubernetes

Stakeholders: SIG Network, SIG Testing, SIG Scalability, SIG Release, Network Policy API Working Group
Covered Work: e2e testing, scalability, performance and reliability

P0: Provide Early Feedback

Stakeholders: SIG Network, Network Policy API Working Group
Covered: New features implemented under feature gates for fast iteraton

### Non Goals

Implementing functionality that is not part of an official or proposed Kubernetes network policy API

## References

* https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
* https://netfilter.org/projects/libnetfilter_queue/doxygen/html/


## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack](https://kubernetes.slack.com/messages/sig-network)
- [Mailing List](https://groups.google.com/a/kubernetes.io/g/sig-network)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).

[owners]: https://git.k8s.io/community/contributors/guide/owners.md
[Creative Commons 4.0]: https://git.k8s.io/website/LICENSE
