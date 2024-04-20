# Kubernetes network policies

Network policies are hard to implement efficiently and in large clusters this is translated to performance and scalability problems.

Most of the existing implementations use the same approach of processing the APIs and transforming them in the corresponding dataplane implementation: iptables, nftables, ebpf or ovs, ...

This project takes a different approach. It uses the NFQUEUE functionality implemented in netfilter to process the first packet of each connection in userspace and emit a verdict. The advantage is that the dataplane implementation does not need to represent all the complex logic, allowing it to scale better. The disadvantage is that we need to pass each new connection packet through userspace.

There are some performance improvements that can be applied, such as to restrict in the dataplane the packets that are sent to userspace to the ones that have network policies only, so only
the Pods affected by network policies will hit the first byte performance.

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

See [.docs/testing/README.md] 

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
