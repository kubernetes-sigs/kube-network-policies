# Integration tests


1. Install `bats` https://bats-core.readthedocs.io/en/stable/installation.html

2. Install `kind` https://kind.sigs.k8s.io/

3. Run `bats tests/`

## Troubleshooting test failures

`bats -x -o _artifacts --print-output-on-failure --filter "network policy drops established connections" tests/e2e_standard.bats`

You can modify or comment the `tests/setup_suite.bash` hooks to avoid creating and recreating the cluster.

```diff
diff --git a/tests/setup_suite.bash b/tests/setup_suite.bash
index f34cc39..8006903 100644
--- a/tests/setup_suite.bash
+++ b/tests/setup_suite.bash
@@ -29,5 +29,5 @@ EOF

 function teardown_suite {
     kind export logs "$BATS_TEST_DIRNAME"/../_artifacts --name "$CLUSTER_NAME"
-    kind delete cluster --name "$CLUSTER_NAME"
+    # kind delete cluster --name "$CLUSTER_NAME"
 }
 ```