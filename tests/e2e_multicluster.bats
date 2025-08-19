#!/usr/bin/env bats

#
# setup_file: This function is executed once before all tests.
# It sets up a two-cluster kind environment, deploys the necessary controllers,
# and establishes network connectivity between the clusters.
#
function setup_file {
  export BATS_TEST_TIMEOUT=300 # Increased timeout for multi-cluster setup

  # Define image variables
  export REGISTRY=${REGISTRY:-"registry.k8s.io/networking"}
  export IMAGE_NAME=${IMAGE_NAME:-"kube-network-policies"}
  export TAG=${TAG:-"test"}

  # Build the images for the specific binaries and architecture
  (
    cd "$BATS_TEST_DIRNAME"/..
    TAG="$TAG" make image-build-multicluster image-build-kube-ip-tracker-multicluster
  )

  # Define cluster names and network subnets
  export CLUSTER_NAME_A="clustera"
  export CLUSTER_NAME_B="clusterb"
  export POD_SUBNET_A="10.110.0.0/16"
  export SERVICE_SUBNET_A="10.115.0.0/16"
  export POD_SUBNET_B="10.220.0.0/16"
  export SERVICE_SUBNET_B="10.225.0.0/16"

  # --- Create Cluster A ---
  kind delete cluster --name $CLUSTER_NAME_A || true

  cat <<EOF | kind create cluster \
    --name $CLUSTER_NAME_A \
    -v1 --wait 1m --retain --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "$POD_SUBNET_A"
  serviceSubnet: "$SERVICE_SUBNET_A"
nodes:
- role: control-plane
- role: worker
EOF

  # --- Create Cluster B ---
  kind delete cluster --name $CLUSTER_NAME_B || true

  cat <<EOF | kind create cluster \
    --name $CLUSTER_NAME_B \
    -v1 --wait 1m --retain --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "$POD_SUBNET_B"
  serviceSubnet: "$SERVICE_SUBNET_B"
nodes:
- role: control-plane
- role: worker
EOF

  # Load the Docker images into the kind clusters
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG-multicluster" --name "$CLUSTER_NAME_A"
  kind load docker-image "$REGISTRY/kube-ip-tracker:$TAG-multicluster" --name "$CLUSTER_NAME_A"
  kind load docker-image "$REGISTRY/$IMAGE_NAME:$TAG-multicluster" --name "$CLUSTER_NAME_B"
  kind load docker-image "$REGISTRY/kube-ip-tracker:$TAG-multicluster" --name "$CLUSTER_NAME_B"

  # Configure Cluster A
  kubectl --context kind-clustera -n kube-system set image ds kindnet kindnet-cni=docker.io/kindest/kindnetd:v20230809-80a64d96
  kubectl --context kind-clustera run web --image=httpd:2 --labels="app=web" --expose --port=80
  
  kubectl --context kind-clustera wait --for=condition=ready pod -l app=web --timeout=2m

  # Configure Cluster B
  kubectl --context kind-clusterb -n kube-system set image ds kindnet kindnet-cni=docker.io/kindest/kindnetd:v20230809-80a64d96
  kubectl --context kind-clusterb run web --image=httpd:2 --labels="app=web" --expose --port=80
  kubectl --context kind-clusterb wait --for=condition=ready pod -l app=web --timeout=2m

  # --- Configure Networking and Deploy Services ---
  kind get kubeconfig --name $CLUSTER_NAME_A > /tmp/kubeconfig-a
  kind get kubeconfig --name $CLUSTER_NAME_B > /tmp/kubeconfig-b

  # Merge kubeconfigs to be used by the tests
  KUBECONFIG=/tmp/kubeconfig-a:/tmp/kubeconfig-b kubectl config view --flatten > /tmp/kubeconfig
  export KUBECONFIG=/tmp/kubeconfig

  # --- Establish Cross-Cluster Routes ---
  ROUTES_B=$(kubectl --context kind-clusterb get nodes -o=jsonpath='{range .items[*]}{"ip route add "}{.spec.podCIDR}{" via "}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
  for n in $(kind get nodes --name ${CLUSTER_NAME_A}); do
    echo "$ROUTES_B" | while read -r route; do docker exec ${n} $route; done
    docker exec ${n} ip route add $SERVICE_SUBNET_B via $(kubectl --context kind-clusterb get nodes -o=jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    # avoid cross cluster traffic to be masqueraded
    docker exec ${n} iptables -t nat -I KIND-MASQ-AGENT 1 -d $POD_SUBNET_B -j ACCEPT
    docker exec ${n} iptables -t nat -I KIND-MASQ-AGENT 1 -d $SERVICE_SUBNET_B -j ACCEPT
  done

  ROUTES_A=$(kubectl --context kind-clustera get nodes -o=jsonpath='{range .items[*]}{"ip route add "}{.spec.podCIDR}{" via "}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
  for n in $(kind get nodes --name ${CLUSTER_NAME_B}); do
    echo "$ROUTES_A" | while read -r route; do docker exec ${n} $route; done
    docker exec ${n} ip route add $SERVICE_SUBNET_A via $(kubectl --context kind-clustera get nodes -o=jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    # avoid cross cluster traffic to be masqueraded
    docker exec ${n} iptables -t nat -I KIND-MASQ-AGENT 1 -d $POD_SUBNET_A -j ACCEPT
    docker exec ${n} iptables -t nat -I KIND-MASQ-AGENT 1 -d $SERVICE_SUBNET_A -j ACCEPT
  done

  # --- Deploy Multi-Cluster Controllers ---
  # Prepare the installation manifest by replacing image placeholders
  _install_manifest=$(cat "$BATS_TEST_DIRNAME"/../install-multicluster.yaml | \
    sed "s#registry.k8s.io/networking/kube-ip-tracker:.*#$REGISTRY/kube-ip-tracker:$TAG-multicluster#" | \
    sed "s#registry.k8s.io/networking/kube-network-policies:.*#$REGISTRY/$IMAGE_NAME:$TAG-multicluster#")

  # Deploy controllers to both clusters
  kind get kubeconfig --name $CLUSTER_NAME_A --internal > /tmp/kubeconfig-internal-a
  kind get kubeconfig --name $CLUSTER_NAME_B --internal > /tmp/kubeconfig-internal-b
  for cluster_context in "kind-clustera" "kind-clusterb"; do
    # Create the shared kubeconfig secret with separate files
    kubectl --context $cluster_context -n kube-system create secret generic remote-kubeconfigs \
      --from-file=clustera.yaml=/tmp/kubeconfig-internal-a \
      --from-file=clusterb.yaml=/tmp/kubeconfig-internal-b
    
    # Apply the installation manifest
    printf '%s' "${_install_manifest}" | kubectl --context $cluster_context apply -f -
  done

  # Wait for all controllers to be ready
  kubectl --context kind-clustera -n kube-system wait --for=condition=ready pod -l app=kube-ip-tracker --timeout=2m
  kubectl --context kind-clustera -n kube-system wait --for=condition=ready pod -l k8s-app=kube-network-policies
  kubectl --context kind-clusterb -n kube-system wait --for=condition=ready pod -l app=kube-ip-tracker --timeout=2m
  kubectl --context kind-clusterb -n kube-system wait --for=condition=ready pod -l k8s-app=kube-network-policies

}

#
# teardown: This function is executed after each test.
# It cleans up network policies to ensure tests are isolated.
#
function teardown {
  # Clean up network policies in both clusters
  kubectl --context kind-clustera delete networkpolicy --all --namespace default
  kubectl --context kind-clusterb delete networkpolicy --all --namespace default
}

#
# teardown_file: This function is executed once after all tests.
# It exports logs and deletes the kind clusters.
#
function teardown_file {
    kind export logs "$BATS_TEST_DIRNAME"/../_artifacts --name "$CLUSTER_NAME_A"
    kind delete cluster --name "$CLUSTER_NAME_A"
    kind export logs "$BATS_TEST_DIRNAME"/../_artifacts --name "$CLUSTER_NAME_B"
    kind delete cluster --name "$CLUSTER_NAME_B"
}

@test "multicluster: deny all ingress traffic between clusters" {
  # Get the pod IP of the web service in cluster A
  POD_IP_A=$(kubectl --context kind-clustera get pod -l app=web -o jsonpath='{.items[0].status.podIP}')

  # Apply a default deny policy to the web server in cluster A
  kubectl --context kind-clustera apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress: []
EOF

  # Give the controller a moment to enforce the policy
  sleep 5

  # Attempt to connect from a pod in cluster B to the pod in cluster A. This should fail.
  run kubectl --context kind-clusterb run busybox --image=busybox --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_A}
  [ "$status" -ne 0 ]
}

@test "multicluster: allow traffic based on pod and cluster label" {
  # Get the pod IP of the web service in cluster A
  POD_IP_A=$(kubectl --context kind-clustera get pod -l app=web -o jsonpath='{.items[0].status.podIP}')

  # Apply a policy to allow traffic from pods labeled 'app=allowed' in 'clusterb'
  kubectl --context kind-clustera apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-clusterb
  annotations:
    networking.x-k8s.io/scope: cross-cluster
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: allowed
          networking.k8s.io/multicluster-name: ${CLUSTER_NAME_B}
EOF

  # Give the controller a moment to enforce the policy
  sleep 5

  # This connection should SUCCEED
  run kubectl --context kind-clusterb run busybox-allowed --image=busybox --labels="app=allowed" --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_A}
  [ "$status" -eq 0 ]

  # This connection should FAIL
  run kubectl --context kind-clusterb run busybox-denied --image=busybox --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_A}
  [ "$status" -ne 0 ]
}

@test "multicluster: allow all traffic from a specific cluster" {
  # Get the pod IPs of the web services in cluster A
  POD_IP_A_WEB1=$(kubectl --context kind-clustera get pod -l app=web -o jsonpath='{.items[0].status.podIP}')
  kubectl --context kind-clustera run web2 --image=httpd:2 --labels="app=web2" --expose --port=80
  kubectl --context kind-clustera wait --for=condition=ready pod -l app=web2 --timeout=2m
  POD_IP_A_WEB2=$(kubectl --context kind-clustera get pod -l app=web2 -o jsonpath='{.items[0].status.podIP}')

  # Apply a default deny policy to web2
  kubectl --context kind-clustera apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web2-deny-all
spec:
  podSelector:
    matchLabels:
      app: web2
  policyTypes:
  - Ingress
  ingress: []
EOF

  # Apply a policy to allow all traffic from any pod in 'clusterb' to the 'web' service
  kubectl --context kind-clustera apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-from-clusterb
  annotations:
    networking.x-k8s.io/scope: cross-cluster
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
           networking.k8s.io/multicluster-name: ${CLUSTER_NAME_B}
EOF

  # Give the controller a moment to enforce the policies
  sleep 5

  # This connection to 'web' should SUCCEED
  run kubectl --context kind-clusterb run busybox --image=busybox --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_A_WEB1}
  [ "$status" -eq 0 ]

  # This connection to 'web2' should FAIL
  run kubectl --context kind-clusterb run busybox --image=busybox --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_A_WEB2}
  [ "$status" -ne 0 ]
}

@test "multicluster: allow egress traffic only within the local cluster" {
  # Get the pod IP of a pod in the same cluster (cluster A)
  POD_IP_A_WEB=$(kubectl --context kind-clustera get pod -l app=web -o jsonpath='{.items[0].status.podIP}')
  # Get the pod IP of a pod in the other cluster (cluster B)
  POD_IP_B_WEB=$(kubectl --context kind-clusterb get pod -l app=web -o jsonpath='{.items[0].status.podIP}')

  # Apply an egress policy with cluster-local scope
  kubectl --context kind-clustera apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-local-egress
  annotations:
    networking.x-k8s.io/scope: cluster-local
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
EOF

  # Give the controller a moment to enforce the policy
  sleep 5

  # This connection should SUCCEED because it is within the same cluster
  run kubectl --context kind-clustera run busybox --image=busybox --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_A_WEB}
  [ "$status" -eq 0 ]

  # This connection should FAIL because it is to another cluster
  run kubectl --context kind-clustera run busybox --image=busybox --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_B_WEB}
  [ "$status" -ne 0 ]
}

@test "multicluster: ipBlock policy should still work" {
  # Get the pod IP of the web service in cluster A
  POD_IP_A=$(kubectl --context kind-clustera get pod -l app=web -o jsonpath='{.items[0].status.podIP}')

  # Apply a policy to allow traffic from a specific IP block
  kubectl --context kind-clustera apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ip-block
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 10.220.0.0/16 # Cluster B's pod subnet
EOF

  # Give the controller a moment to enforce the policy
  sleep 5

  # This connection should SUCCEED
  run kubectl --context kind-clusterb run busybox --image=busybox --rm -it --restart=Never --command -- wget -O- --timeout=2 http://${POD_IP_A}
  [ "$status" -eq 0 ]
}