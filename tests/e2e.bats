#!/usr/bin/env bats

setup() {
  kubectl create namespace dev
  kubectl label namespace/dev purpose=testing

  kubectl create namespace prod
  kubectl label namespace/prod purpose=production

}

teardown() {
  kubectl delete namespace prod
  kubectl delete namespace dev
}


@test "allow traffic from a namespace" {
  # https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/06-allow-traffic-from-a-namespace.md

  kubectl apply -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-allow-prods
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          purpose: production
EOF
  # propagation delay
  sleep 1
  # query should be blocked
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://web.default && echo ok || echo fail")
  echo "Connect to webserver should fail: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "fail"

  # query should work
  output=$(kubectl run test-$RANDOM --namespace=prod --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://web.default && echo ok || echo fail")
  echo "Connect to webserver should work: $output"
  kubectl --namespace=prod get pods -o wide
  test "$output" = "ok"

  # cleanup
  kubectl delete networkpolicy web-allow-prods
}


@test "Maintaining an allowlist of domains" {
  # https://network-policy-api.sigs.k8s.io/npeps/npep-133-fqdn-egress-selector/#maintaining-an-allowlist-of-domains

  kubectl apply -f - <<EOF
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-private-egress
spec:
  priority: 45
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-cluster"
    action: "Allow"
    to:
    - networks:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
---
apiVersion: policy.networking.k8s.io/v1alpha1
kind: AdminNetworkPolicy
metadata:
  name: allow-my-service-egress
spec:
  priority: 55
  subject:
    namespaces:
      matchLabels:
        kubernetes.io/metadata.name: "dev"
  egress:
  - name: "allow-to-my-service"
    action: "Allow"
    to:
    - domainNames:
      - "blog.kubernetes.io"
      - "*.k8s.io"
    ports:
    - portNumber:
        protocol: TCP
        port: 80
    - portNumber:
        protocol: TCP
        port: 443
  - name: "default-deny"
    action: "Deny"
    to:
    - networks:
      - "0.0.0.0/0"
EOF
  # propagation delay
  sleep 2
  # query should be blocked
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://go.dev/ && echo ok || echo fail")
  echo "Connect to webserver should fail: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "fail"

  # query should work
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://blog.kubernetes.io && echo ok || echo fail")
  echo "Connect to webserver should work: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "ok"

 # query should work
  output=$(kubectl run test-$RANDOM --namespace=dev --image=registry.k8s.io/e2e-test-images/agnhost:2.39 --restart=Never -i --command -- bash -c "curl -q -s --connect-timeout 5 --output /dev/null http://network-policy-api.sigs.k8s.io && echo ok || echo fail")
  echo "Connect to webserver should work: $output"
  kubectl --namespace=dev get pods -o wide
  test "$output" = "ok"

  # cleanup
  kubectl delete adminnetworkpolicy allow-private-egress
  kubectl delete adminnetworkpolicy allow-to-my-service
}
