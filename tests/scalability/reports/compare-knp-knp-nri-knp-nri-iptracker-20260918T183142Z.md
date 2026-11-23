# Scalability report: compare-knp-knp-nri-knp-nri-iptracker-20260918T183142Z

Generated 2026-09-18T18:31:42Z by `tests/scalability/report.sh` from 3 run(s).
Every value below is read from the run's artifacts; Prometheus series are reduced over the
whole run window (install through connrate), so agent maxima include the connection-rate phase.

## Runs

| run | DUT | scenario | fake nodes | Pods | identities | ns | rate/s | churn/s × dur | fresh ids | started |
|---|---|---|---:|---:|---:|---:|---:|---|---|---|
| knp-mesh-i200-p1000-20260918T182310Z | knp | mesh | 20 | 1000 | 200 | 5 | 100 | 10 × 30s | false | 2026-09-18T18:23:12Z |
| knp-nri-mesh-i200-p1000-20260918T182310Z | knp-nri | mesh | 20 | 1000 | 200 | 5 | 100 | 10 × 30s | false | 2026-09-18T18:25:54Z |
| knp-nri-iptracker-mesh-i200-p1000-20260918T182310Z | knp-nri-iptracker | mesh | 20 | 1000 | 200 | 5 | 100 | 10 × 30s | false | 2026-09-18T18:28:40Z |

## Enforcement and admission

Latencies are measured on real Pods across two real workers. Enforcement: policy apply → first
permitted connection. Revocation: policy delete → first refused connection. "denied blocked" is
the unlabeled client failing to connect; a **no** is an enforcement failure.

| run | achieved fill Pods/s | enforce idle (ms) | enforce loaded (ms) | revoke (ms) | denied blocked idle/loaded/after churn | allowed ok loaded/after churn | churn replaced/failed |
|---|---:|---:|---:|---:|---|---|---|
| knp-mesh-i200-p1000-20260918T182310Z | 100 | 322 | 333 | 2320 | yes/yes/yes | yes/yes | 301/0 |
| knp-nri-mesh-i200-p1000-20260918T182310Z | 100 | 308 | 312 | 2320 | yes/yes/yes | yes/yes | 301/0 |
| knp-nri-iptracker-mesh-i200-p1000-20260918T182310Z | 99.9 | 316 | 307 | 2328 | yes/yes/yes | yes/yes | 301/0 |

## Connection path (fortio, no keep-alive, client → gateway across nodes)

| run | fresh conns (ok/total) | fresh p50 / p99 (ms) | conn rate (conn/s) | conns ok/total | rate p50 / p99 (ms) | denied attempts / succeeded |
|---|---|---|---:|---|---|---|
| knp-mesh-i200-p1000-20260918T182310Z | 200/200 | 0.74 / 1 | 8464 | 253999/253999 | 9.46 / 13.8 | 960 / 0 |
| knp-nri-mesh-i200-p1000-20260918T182310Z | 200/200 | 0.72 / 1 | 8462 | 253953/253953 | 9.51 / 13.77 | 960 / 0 |
| knp-nri-iptracker-mesh-i200-p1000-20260918T182310Z | 200/200 | 0.71 / 1 | 10281 | 308483/308483 | 8.01 / 11.44 | 960 / 0 |

## Agent resources and queue (max over run, summed across real nodes where applicable)

| run | CPU max / mean (cores) | WSS max (MB) | Go heap max (MB) | accept/s max | drop/s max | process p99 max (µs) | queue depth max | queue drops |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| knp-mesh-i200-p1000-20260918T182310Z | 1.477 / 0.112 | 137.7 | 30.5 | 5936 | 31 | 392 | 31 | 0 |
| knp-nri-mesh-i200-p1000-20260918T182310Z | 1.203 / 0.119 | 99.2 | 27.5 | 6045 | 32 | 462 | 0 | 0 |
| knp-nri-iptracker-mesh-i200-p1000-20260918T182310Z | 1.505 / 0.169 | 131.8 | 23.9 | 6830 | 31 | 811 | 44 | 0 |

## Control plane and distributor

| run | apiserver CPU max (cores) | apiserver WSS max (MB) | watch events/s max | kwok CPU max | ip-tracker CPU max | ip-tracker WSS max (MB) |
|---|---:|---:|---:|---:|---:|---:|
| knp-mesh-i200-p1000-20260918T182310Z | 0.842 | 943 | 869 | 0.182 | - | - |
| knp-nri-mesh-i200-p1000-20260918T182310Z | 0.81 | 822 | 830 | 0.153 | - | - |
| knp-nri-iptracker-mesh-i200-p1000-20260918T182310Z | 0.666 | 783 | 629 | 0.152 | 0.09 | 58 |

## Kernel state at steady state (per real worker)

`-1` means the set does not exist: the iptracker flavor diverts all traffic and programs no managed-IP sets.

| run | node | nft rules | podips-v4 | podips-v6 | conntrack labeled | divert-all |
|---|---|---:|---:|---:|---:|---|
| knp-mesh-i200-p1000-20260918T182310Z | knp-scale-worker | 22 | 1 | 0 | 0 | false |
| knp-mesh-i200-p1000-20260918T182310Z | knp-scale-worker2 | 22 | 2 | 0 | 0 | false |
| knp-nri-mesh-i200-p1000-20260918T182310Z | knp-scale-worker | 22 | 1 | 0 | 0 | false |
| knp-nri-mesh-i200-p1000-20260918T182310Z | knp-scale-worker2 | 22 | 2 | 0 | 0 | false |
| knp-nri-iptracker-mesh-i200-p1000-20260918T182310Z | knp-scale-worker | 15 | -1 | -1 | 0 | true |
| knp-nri-iptracker-mesh-i200-p1000-20260918T182310Z | knp-scale-worker2 | 15 | -1 | -1 | 0 | true |

## Reading the numbers

- kwok Pods have addresses but no network namespace: the agents ingest and index them, and the
  nftables sets hold only *local* managed addresses (the probe Pods), so `podips-v4` stays small
  by design for KNP. Agent CPU, memory and API-server load are where the fake objects show up.
- One run per configuration; treat differences below ~20% as noise until repeated.
- Raw artifacts (Prometheus range results, fortio JSON, phases, logs) are under
  `tests/scalability/_artifacts/<run-id>/` on the machine that ran the experiment.
