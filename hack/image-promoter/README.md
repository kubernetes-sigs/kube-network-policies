# Kubernetes Image Promotion Script

This directory contains a portable tool to automate the promotion of staging images to the official `kubernetes/k8s.io` repository.

## Files

- [promote-images.py](file:///usr/local/google/home/aojea/src/kube-network-policies/hack/image-promoter/promote-images.py): The promotion script itself.
- [.image-promoter.json](file:///usr/local/google/home/aojea/src/kube-network-policies/hack/image-promoter/.image-promoter.json) (located in the same directory): Staging registry configuration and image mapping for this project.

## Configuration

To use this tool in a project, place a `.image-promoter.json` file in the same directory as the script (or in the project root). Below is the configuration structure for this repository:

```json
{
  "staging_registry": "gcr.io/k8s-staging-networking",
  "manifest_path": "registry.k8s.io/images/k8s-staging-networking/images.yaml",
  "staging_tag_format": "v{date}-{commit_hash}",
  "promotions": [
    {
      "name": "kube-network-policies",
      "staging_image": "kube-network-policies",
      "tags": [
        {
          "promoted": "{tag}",
          "staging_suffix": ""
        },
        {
          "promoted": "{tag}-npa-v1alpha2",
          "staging_suffix": "-npa-v1alpha2"
        },
        {
          "promoted": "{tag}-iptracker",
          "staging_suffix": "-iptracker"
        }
      ]
    },
    {
      "name": "kube-ip-tracker",
      "staging_image": "kube-ip-tracker",
      "tags": [
        {
          "promoted": "{tag}",
          "staging_suffix": ""
        }
      ]
    }
  ]
}
```

### Configuration Fields
- `staging_registry`: Staging container registry for this project.
- `manifest_path`: The manifest file path inside `kubernetes/k8s.io` (e.g. `registry.k8s.io/images/k8s-staging-networking/images.yaml`).
- `staging_tag_format`: String format to resolve the staging image tag from the git release tag. Supported keys: `{date}` (`YYYYMMDD` in UTC) and `{commit_hash}` (7-character short commit hash).
- `promotions`: Array of image names mapping staging images and their suffixes to the target image blocks and tags in the manifest.
- `repository_manifests`: (Optional) Array of local project files (e.g. installer YAML files, Helm charts) to be updated to use the new release image tags. Each file entry specifies a list of regex replacement patterns to run.

## Release PR Workflows

When you run the tool:
1. **Image Promotion PR**: It updates `registry.k8s.io` manifests inside `kubernetes/k8s.io` to map staging image digests to your release tag and opens a promotion PR.
2. **Local Repository Manifests PR**: If `repository_manifests` is configured, it checks out a new branch (`update-manifests-{tag}`) from the release tag, applies the regex updates to your installer manifests/Helm charts, commits/pushes the branch, and opens a secondary pull request to your project's upstream repository with a `/hold` instruction. The PR will only be unheld/merged after the first Image Promotion PR is merged.

## Usage

Ensure you are authenticated with the GitHub CLI before running:
```bash
gh auth login
```

### Dry Run (Recommended)
Verify the staging image resolution and check the generated PR body description without pushing any changes:
```bash
python3 hack/image-promoter/promote-images.py --dry-run
```

### Run Promotion
To run the full promotion process (resolving tags, editing the manifest in `kubernetes/k8s.io`, committing/pushing, and submitting the PR):
```bash
# Promotes for the latest git tag (auto-detected)
python3 hack/image-promoter/promote-images.py

# Promotes for a specific git tag
python3 hack/image-promoter/promote-images.py --tag v1.1.0
```
