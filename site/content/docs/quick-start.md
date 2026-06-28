---
title: "Quick Start"
date: 2026-06-28T13:20:00Z
weight: 1
---

This guide gets you up and running with `kube-network-policies` in a local development cluster using **KIND** (Kubernetes in Docker).

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running.
- [KIND](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) CLI installed.
- [kubectl](https://kubernetes.io/docs/tasks/tools/) installed.

## Step 1: Create a KIND cluster

Create a simple local Kubernetes cluster with KIND:

```sh
kind create cluster --name kube-net-pol
```

## Step 2: Install kube-network-policies

You can install `kube-network-policies` either manually using raw manifests or via Helm.

### Option A: Manual Installation

#### 1. Traditional Network Policies
To support traditional Kubernetes `NetworkPolicies`, apply the core manifest:

```sh
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/kube-network-policies/main/install.yaml
```

#### 2. Admin Network Policies (ANP) and Baseline Admin Network Policies (BANP)
If you want to use the newer ANP/BANP policies, you must first install the experimental Network Policy API CRDs, then deploy the ANP-configured daemonset:

```sh
# Install CRDs
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml

# Deploy the ANP daemonset
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/kube-network-policies/main/install-anp.yaml
```

---

### Option B: Helm Installation

Alternatively, you can install the project using Helm:

```sh
helm install kube-network-policies -n kube-system charts/kube-network-policies
```

> [!NOTE]
> If you are using Helm and want to enable Admin Network Policies (enabled by default), you **must** install the CRDs listed in Step 2.2 first.

## Step 3: Verify the Installation

Check that the daemonset pods are running in the `kube-system` namespace:

```sh
kubectl get pods -n kube-system -l app=kube-network-policies
```

You should see one or more agent pods running:

```
NAME                          READY   STATUS    RESTARTS   AGE
kube-network-policies-xxxxx   1/1     Running   0          30s
```

## Next Steps

Now that the controller is running, you can:
- Read the [User Guide](/docs/user/) to learn how to create policies and see packet interception in action.
- Learn how to use [JSON Logging](/docs/user/json-logging/) to troubleshoot traffic decisions.
- Learn about the internal components in [Concepts](/docs/concepts/).
