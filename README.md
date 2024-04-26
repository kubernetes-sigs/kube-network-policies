# Kubernetes network policies

Implementation of Kubernetes Network Policies:
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Admin Network Policies and Baseline Admint Network Policies](https://network-policy-api.sigs.k8s.io/)

## Install

There are two manifest in the current repository:

1. For "traditional" Kubernetes Network policies just do:

```
kubectl apply -f install.yaml
```

2. For the Admin Network Policies and Baseline Admint Network Policies the CRDs has to be installed first:
```
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml

kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml
```

and then install the daemonset enabling the features with the corresponding flags:

```
kubectl apply -f install-anp.yaml
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

This project takes a different approach. It uses the NFQUEUE functionality implemented in netfilter to process the first packet of each connection in userspace and emit a verdict. The advantage is that the dataplane implementation does not need to represent all the complex logic, allowing it to scale better. The disadvantage is that we need to pass each new connection packet through userspace.

There are some performance improvements that can be applied, such as to restrict in the dataplane the packets that are sent to userspace to the ones that have network policies only, so only
the Pods affected by network policies will hit the first byte performance.

## Testing

See [TESTING](docs/testing/README.md) 

There are two github workflows that runs e2e tests aginst the Kubernetes/Kubernetes Network Policy tests and the Network Policy API Working Group conformance tests.

## Project Scope

This project was created to fill the gap on testing coverage in the area of Network Policies.
There are limited existing solutions, but those are specific to individual network providers that require to install additional functionality, adding complexity and debugging difficulty, and not allowing to iterate fast during the development of new features.

Ref: https://github.com/kubernetes/org/issues/4856

### Goals

P0: Support Testing Kubernetes

Stakeholders: SIG Network, SIG Testing, SIG Scalability, SIG Release, Network Policy API Working Group
Covered Work: e2e testing, scalability, performance and reliability

P0: Provide Early Feedback

Stakeholders: SIG Network, Network Policy API Working Group
Covered: New features implemented under feature gates for fast iteraton

### Non Goals

Implementing additional functionalities unrelated to Network Policies

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
