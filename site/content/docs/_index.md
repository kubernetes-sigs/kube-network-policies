---
title: Kubernetes Network Policies
weight: 1150

---

`kube-network-policies` is a Kubernetes network policy implementation that enforces rules in userspace. It leverages Linux NFQUEUE to intercept network packets and evaluate them against various policy formats.

## Key Features

- **Userspace Packet Filtering:** Uses NFQUEUE and nftables to selectively redirect and evaluate network traffic in userspace.
- **Multiple Policy Engines:** Fully supports standard Kubernetes `NetworkPolicy`, `AdminNetworkPolicy` (ANP), and `BaselineAdminNetworkPolicy` (BANP).
- **High Efficiency Selective Capture:** Avoids intercepting all traffic by dynamically identifying and capturing only packets belonging to pods targeted by active policies.
- **Structured JSON Logging:** Offers rich diagnostics, allowing deep troubleshooting of network policy decisions using tools like `jq`.
- **Flexible Extensibility:** Built on a pipeline of `PolicyEvaluator` plugins, making it simple to add custom validation logic.

## Disclaimer

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
