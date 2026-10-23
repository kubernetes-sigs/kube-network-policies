# Using JSON logging for troubleshooting network policies

The controller supports structured JSON logging via klog's `--logging-format=json` flag.
It produces machine-readable log entries for the packets evaluated against network
policies, making it straightforward to filter and analyze traffic decisions with tools
like [`jq`](https://jqlang.github.io/jq/).

There are two kinds of per-packet entries:

- The **verdict entry**, one per packet, with the 5-tuple, the pods and the evaluator
  that decided. It is written at any verbosity, controlled by `--log-verdicts`, and the
  denied packets are logged by default. This is the entry to use for auditing, alerting
  and most troubleshooting.
- The **evaluation trace**, several entries per packet, written at `-v=2`. It shows each
  step of the pipeline and is meant for debugging the policy evaluation itself.

## Enabling JSON logging

Pass the following flag to the controller binary (or set it in the DaemonSet args):

```
--logging-format=json
```

Add `-v=2` to also get the evaluation trace. The trace costs several log lines per
connection written in the packet processing path, so keep it for debugging sessions.

## Verdict entries

The `--log-verdicts` flag selects the verdicts that are logged:

```
--log-verdicts=deny   # the denied packets (default)
--log-verdicts=all    # the denied and the accepted packets
--log-verdicts=none   # disabled
```

One entry is emitted per packet after the pipeline completes:

```json
{
  "ts": 1720777151838.4001,
  "caller": "networkpolicy/verdictlog.go:150",
  "msg": "Packet verdict",
  "id": 9,
  "verdict": "deny",
  "family": "IPv4",
  "protocol": "TCP",
  "src": "10.0.1.3:40243",
  "dst": "10.0.2.2:8080",
  "srcPod": "default/frontend",
  "dstPod": "default/backend",
  "direction": "ingress",
  "evaluator": "StandardNetworkPolicy"
}
```

Key fields:
- `msg`: always `"Packet verdict"`
- `verdict`: `"deny"` or `"accept"`
- `id`: packet ID; links this entry to the evaluation trace of the same packet
- `family` / `protocol`: `"IPv4"` or `"IPv6"`, and `"TCP"`, `"UDP"` or `"SCTP"`
- `src` / `dst`: the IP and port of the packet
- `srcPod` / `dstPod`: `"namespace/name"`, or `"external"` for traffic outside the cluster
- `direction`: the pipeline that produced the verdict, `"egress"` or `"ingress"`
- `evaluator`: the evaluator that produced the verdict, for example `"StandardNetworkPolicy"`,
  `"ClusterNetworkPolicyAdmin"` or `"ClusterNetworkPolicyBaseline"`. Both `direction` and
  `evaluator` are empty when the packet is accepted because no policy applies to it.

The verdicts are written by a dedicated goroutine, so a slow log destination does not
delay the packets. When the destination falls behind, the verdicts that do not fit in
the buffer are dropped and counted in the `kube_network_policies_verdict_log_dropped`
metric.

## Evaluation trace at `-v=2`

At `-v=2`, two things happen:
- The `LoggingPolicy` evaluator is activated and emits one log entry per packet and
  direction with its 5-tuple and the source/destination pod names.
- The policy engine emits a trace entry for each packet indicating whether it was
  accepted or denied.

Without `-v=2`, the `LoggingPolicy` evaluator is not added to the pipeline and these
entries are not produced.

### Packet evaluation entry

Emitted once per direction (Egress then Ingress) for each packet:

```json
{
  "ts": 1720777151838.3552,
  "caller": "networkpolicy/logging.go:67",
  "msg": "Evaluating packet",
  "id": 9,
  "direction": "Egress",
  "srcPod": "default/frontend",
  "dstPod": "default/backend",
  "packet": {
    "ID": 9,
    "Family": "IPv4",
    "SrcIP": "10.0.1.3",
    "DstIP": "10.0.2.2",
    "Proto": "TCP",
    "SrcPort": 40243,
    "DstPort": 8080
  }
}
```

Key fields:
- `id`: packet ID; links this entry to the other entries of the same packet
- `direction`: `"Egress"` or `"Ingress"`
- `srcPod` / `dstPod`: `"namespace/name"`, or `"external"` for traffic outside the cluster
- `packet`: the 5-tuple without the raw payload (payload is omitted in JSON mode)

### Pipeline result entry

Emitted once per packet after the pipeline completes:

```json
{
  "ts": 1720777151838.4001,
  "caller": "networkpolicy/engine.go:57",
  "msg": "Packet denied by egress policy",
  "v": 2,
  "id": 9
}
```

Possible `msg` values:
- `"Packet denied by egress policy"`
- `"Packet denied by ingress policy"`
- `"Packet accepted by policy"`

The `id` field matches the packet evaluation entries above and the verdict entry, which
also carries the evaluator that decided.

## Text vs JSON format

In the default text format, the verdict entry is a single line with the same keys:

```
I0712 09:53:52.257809       1 verdictlog.go:150] "Packet verdict" id=9 verdict="deny" family="IPv4" protocol="TCP" src="10.0.1.3:40243" dst="10.0.2.2:8080" srcPod="default/frontend" dstPod="default/backend" direction="ingress" evaluator="StandardNetworkPolicy"
```

and the trace entries are logged with a raw hex dump of the payload:

```
I0712 09:53:52.257809       1 logging.go:67] "Evaluating packet" id=9 direction="Egress" srcPod="default/frontend" dstPod="default/backend" packet=<
        [9] 10.0.1.3:40243 10.0.2.2:8080 TCP
        00000000  00 00 a0 02 fa f0 19 33  00 00 02 04 05 b4 04 02  |.......3........|
        00000010  08 0a c1 d9 c1 bd 00 00  00 00 01 03 03 07        |..............|
 >
```

In JSON mode, the payload is omitted and the packet is rendered as a structured object,
making it easy to filter with `jq`.

## Troubleshooting examples with jq

The examples below assume log lines are streamed from `kubectl logs`:

```sh
kubectl logs -n kube-system -l k8s-app=kube-network-policies --follow
```

The verdict entries are enough for all of them at the default verbosity. The last
section uses the evaluation trace and needs `-v=2`.

### Show all denied packets

```sh
kubectl logs ... | jq -c 'select(.verdict == "deny")'
```

### Show only egress denials

```sh
kubectl logs ... | jq -c 'select(.verdict == "deny" and .direction == "egress")'
```

### Show the denials decided by one evaluator

```sh
kubectl logs ... | jq -c 'select(.verdict == "deny" and .evaluator == "ClusterNetworkPolicyAdmin")'
```

### Filter packets from a specific pod

```sh
kubectl logs ... | jq -c 'select(.srcPod == "default/frontend")'
```

### Show all traffic to external destinations

```sh
kubectl logs ... | jq -c 'select(.dstPod == "external")'
```

### Filter packets by destination port

The port is the last element of `dst`, also for IPv6 addresses:

```sh
kubectl logs ... | jq -c 'select(.verdict != null and (.dst | split(":") | last) == "8080")'
```

### Count denials per destination pod

```sh
kubectl logs ... | jq -r 'select(.verdict == "deny") | .dstPod' | sort | uniq -c | sort -rn
```

### Count denials per direction and evaluator

```sh
kubectl logs ... | jq -r 'select(.verdict == "deny") | "\(.direction) \(.evaluator)"' | sort | uniq -c
```

### Summarize denied destination ports

```sh
kubectl logs ... | jq -r 'select(.verdict == "deny") | .dst | split(":") | last' | sort -n | uniq -c | sort -rn
```

### Follow the evaluation of a denied packet (`-v=2`)

Take the `id` of a verdict entry (e.g. `id=42`) and show every entry of that packet,
the evaluation of each direction and the pipeline result:

```sh
kubectl logs ... | jq -c 'select(.id == 42)'
```
