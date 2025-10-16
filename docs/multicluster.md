# Multi-Cluster Network Policies User Guide

This guide provides instructions on how to install and use the multi-cluster
feature of `kube-network-policies`. This feature allows you to enforce network
policies across multiple Kubernetes clusters.

### Overview

The multi-cluster feature is composed of two main components:

*   **`kube-ip-tracker`**: A central component that runs as a **Deployment** in
    each cluster. It watches for `Pods`, `Namespaces`, and `Nodes` in all
    clusters and stores the necessary information for applying
    `NetworkPolicies`: IPs and Labels. This component requires a `kubeconfig`
    file with access to all clusters in the mesh.

*   **`kube-network-policies` agent**: A **DaemonSet** that runs on each node of
    each cluster. This agent enforces the network policies and connects to the
    `kube-ip-tracker` service to get the necessary information to apply the
    `NetworkPolicies`.

### Prerequisites

*   Two or more Kubernetes clusters.
*   `kubectl` installed and configured with contexts for all your clusters.
*   Full network connectivity between the pods of all clusters. This means that
    a pod in one cluster must be able to reach the IP of a pod in any of the
    other clusters, and vice-versa. This guide does not cover how to set up this
    inter-cluster networking.

### 1. RBAC Requirements

Proper functioning of the multi-cluster feature requires specific RBAC
permissions for each component.

The `install-multicluster.yaml` manifest provided in this repository includes
the necessary `ServiceAccounts`, `ClusterRoles`, and `ClusterRoleBindings`.

### 2. Prepare the kubeconfig secret

The `kube-ip-tracker` needs access to all clusters in the mesh. We will provide
this access via a secret containing the kubeconfig files for each cluster.

For each cluster, you need to have a kubeconfig file. You will then create a
secret named `remote-kubeconfigs` in the `kube-system` namespace of **each**
cluster. This secret will contain the kubeconfig files for all clusters in your
mesh.

For example, if you have two clusters, `cluster-a` and `cluster-b`, and you have
their kubeconfig files at `/path/to/cluster-a.conf` and
`/path/to/cluster-b.conf`, you would run the following commands for **each** of
your clusters:

```bash
# Replace <context-for-cluster-a> with the kubectl context for your first cluster
kubectl --context <context-for-cluster-a> -n kube-system create secret generic remote-kubeconfigs \
  --from-file=cluster-a.yaml=/path/to/cluster-a.conf \
  --from-file=cluster-b.yaml=/path/to/cluster-b.conf

# Replace <context-for-cluster-b> with the kubectl context for your second cluster
kubectl --context <context-for-cluster-b> -n kube-system create secret generic remote-kubeconfigs \
  --from-file=cluster-a.yaml=/path/to/cluster-a.conf \
  --from-file=cluster-b.yaml=/path/to/cluster-b.conf
```

### 3. Deploy the multi-cluster components

Now we will deploy the `kube-ip-tracker` and the `kube-network-policies` agent
to both clusters using the `install-multicluster.yaml` manifest.

Make sure the container images specified in the manifest are available in your
clusters. You may need to push them to a registry that your clusters can access
and update the image paths in the `install-multicluster.yaml` file.

Apply the manifest to each cluster:

```bash
# Replace <context-for-cluster-a> with the kubectl context for your first cluster
kubectl --context <context-for-cluster-a> apply -f install-multicluster.yaml

# Replace <context-for-cluster-b> with the kubectl context for your second cluster
kubectl --context <context-for-cluster-b> apply -f install-multicluster.yaml
```


### 4. Example: Enforcing Cross-Cluster Security Boundaries

This example demonstrates how to enforce a network policy that allows traffic from a specific application in one cluster to a database in another cluster, while denying traffic from other applications.

First, let's label the `default` namespace in each cluster with the cluster's name. This will allow us to create policies that are scoped to a specific cluster.

```bash
# Replace <context-for-cluster-a> and <context-for-cluster-b> with your contexts
kubectl --context <context-for-cluster-a> label namespace default cluster.clusterset.k8s.io=clustera
kubectl --context <context-for-cluster-b> label namespace default cluster.clusterset.k8s.io=clusterb
```

Now, let's deploy a `database` service in `cluster-a`:

```bash
# Replace <context-for-cluster-a> with your context
kubectl --context <context-for-cluster-a> run database --image=httpd:2 --labels="app=database" --expose --port=80
kubectl --context <context-for-cluster-a> wait --for=condition=ready pod -l app=database --timeout=2m
```

Next, apply a network policy to the `database` pod that allows ingress traffic only from pods with the label `app=billing` in `cluster-b`.

```bash
# Replace <context-for-cluster-a> with your context
DB_POD_IP=$(kubectl --context <context-for-cluster-a> get pod -l app=database -o jsonpath='{.items[0].status.podIP}')

kubectl --context <context-for-cluster-a> apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-billing-from-clusterb
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: billing
      namespaceSelector:
        matchLabels:
          clusterset.k8s.io/cluster-name: clusterb
EOF
```

### 5. Verification

Let's test our setup by trying to connect from different pods in `cluster-b`.

This connection from the `billing` app should **SUCCEED**:

```bash
# Replace <context-for-cluster-b> with your context
kubectl --context <context-for-cluster-b> run billing-client --image=busybox --labels="app=billing" --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${DB_POD_IP}
```

This connection from the `analytics` app should **FAIL**:

```bash
# Replace <context-for-cluster-b> with your context
kubectl --context <context-for-cluster-b> run analytics-client --image=busybox --labels="app=analytics" --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${DB_POD_IP}
```

This demonstrates that the policy correctly allows traffic from the intended application in the remote cluster while blocking traffic from others.

### 7. Cleanup

To remove the resources created in this guide, you can run:

```bash
# Replace <context-for-cluster-a> with your context
kubectl --context <context-for-cluster-a> delete -f install-multicluster.yaml
kubectl --context <context-for-cluster-a> delete secret -n kube-system remote-kubeconfigs
kubectl --context <context-for-cluster-a> delete networkpolicy allow-from-cluster-b
kubectl --context <context-for-cluster-a> delete service web
kubectl --context <context-for-cluster-a> delete pod web

# Replace <context-for-cluster-b> with your context
kubectl --context <context-for-cluster-b> delete -f install-multicluster.yaml
kubectl --context <context-for-cluster-b> delete secret -n kube-system remote-kubeconfigs
```
