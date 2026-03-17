# Using JSON logging for troubleshooting network policies

The controller supports structured JSON logging via klog's `--logging-format=json` flag.
When combined with `-v=2`, it produces machine-readable log entries for every packet
evaluated against network policies, making it straightforward to filter and analyze
traffic decisions with tools like [`jq`](https://jqlang.github.io/jq/).

## Enabling JSON logging

Pass the following flags to the controller binary (or set them in the DaemonSet args):

```
--logging-format=json -v=2
```

At `-v=2`, two things happen:
- The `LoggingPolicy` evaluator is activated and emits one log entry per packet with
  its 5-tuple and the source/destination pod names.
- The policy engine emits a verdict entry for each packet indicating whether it was
  accepted or denied.

Without `-v=2`, the `LoggingPolicy` evaluator is not added to the pipeline and packet-level
logs are not produced.

## Log entry structure

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
- `id`: packet ID; links this entry to the corresponding verdict entry
- `direction`: `"Egress"` or `"Ingress"`
- `srcPod` / `dstPod`: `"namespace/name"`, or `"external"` for traffic outside the cluster
- `packet`: the 5-tuple without the raw payload (payload is omitted in JSON mode)

### Verdict entry

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

The `id` field matches the packet evaluation entries above.

## Text vs JSON format

In the default text format, packets are logged with a raw hex dump of the payload:

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
kubectl logs -n kube-system -l app=kube-network-policies --follow
```

### Show all denied packets

```sh
kubectl logs ... | jq -c 'select(.msg | test("Packet denied"))'
```

### Show only egress denials

```sh
kubectl logs ... | jq -c 'select(.msg == "Packet denied by egress policy")'
```

### Show packet details for denied connections

Correlate the verdict entry back to its packet evaluation entry using the `id` field.
Collect all denied IDs, then filter the packet entries:

```sh
kubectl logs ... | jq -c '
  . as $entry |
  select(.msg | test("Packet denied")) |
  {id: .id, msg: .msg}
'
```

Then look up the full packet info for a specific ID (e.g. `id=42`):

```sh
kubectl logs ... | jq -c 'select(.id == 42 and .packet != null)'
```

### Filter packets by destination port

```sh
kubectl logs ... | jq -c 'select(.packet.DstPort == 8080)'
```

### Filter packets from a specific pod

```sh
kubectl logs ... | jq -c 'select(.srcPod == "default/frontend")'
```

### Show all traffic to external destinations

```sh
kubectl logs ... | jq -c 'select(.dstPod == "external")'
```

### Count denials per direction

```sh
kubectl logs ... | jq -r 'select(.msg | test("Packet denied")) | .msg' | sort | uniq -c
```

### Summarize denied destination ports

```sh
kubectl logs ... | jq -r 'select(.packet != null) | .packet.DstPort' | sort -n | uniq -c | sort -rn
```
