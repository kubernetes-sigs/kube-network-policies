# Kubernetes network policies

Implementation of Kubernetes Network Policies:
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Admin Network Policies and Baseline Admin Network Policies](https://network-policy-api.sigs.k8s.io/)

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

## Development

Network policies are hard to implement efficiently and in large clusters this is translated to performance and scalability problems.

Most of the existing implementations use the same approach of processing the APIs and transforming them in the corresponding dataplane implementation: iptables, nftables, ebpf or ovs, ...

This project takes a different approach. It uses the NFQUEUE functionality implemented in netfilter to process the first packet of each connection (or udp flows) in userspace and emit a verdict. The advantage is that the dataplane implementation does not need to represent all the complex logic, allowing it to scale better. The disadvantage is that we need to pass each new connection packet through userspace. Subsequent packets are accepted via a  "ct state established,related accept" rule.

For performance only the Pods selected by network policies will be queued to user space and thus absorb the first packet perf hit. 

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
- [Mailing List](https://groups.google.com/g/kubernetes-sig-network)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).

[owners]: https://git.k8s.io/community/contributors/guide/owners.md
[Creative Commons 4.0]: https://git.k8s.io/website/LICENSE
