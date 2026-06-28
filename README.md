# Kubernetes Network Policies

An implementation of Kubernetes Network Policies.

For comprehensive documentation, architecture details, user guides, and troubleshooting, visit the website:

👉 **[kube-network-policies.sigs.k8s.io](https://kube-network-policies.sigs.k8s.io)**

## Quick Start

### Installation

For traditional Kubernetes Network Policies:

```sh
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/kube-network-policies/main/install.yaml
```

For Admin Network Policies (ANP) and Baseline Admin Network Policies (BANP):

```sh
# Install CRDs
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_adminnetworkpolicies.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/v0.1.5/config/crd/experimental/policy.networking.k8s.io_baselineadminnetworkpolicies.yaml

# Deploy the ANP daemonset
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/kube-network-policies/main/install-anp.yaml
```

For Helm:

```sh
helm install kube-network-policies -n kube-system charts/kube-network-policies
```

## Community & Support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- **Slack:** [#sig-network](https://kubernetes.slack.com/messages/sig-network) on Kubernetes Slack
- **Mailing List:** [sig-network](https://groups.google.com/a/kubernetes.io/g/sig-network)

### Code of Conduct

Participation in the Kubernetes community is governed by the [CNCF Code of Conduct](code-of-conduct.md).
