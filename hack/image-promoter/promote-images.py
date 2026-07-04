#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

def run_cmd(args, cwd=None, env=None):
    res = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        raise Exception(f"Command {' '.join(args)} failed in {cwd or '.'} (exit code {res.returncode}):\nStdout: {res.stdout.decode()}\nStderr: {res.stderr.decode()}")
    return res.stdout.decode().strip()

def get_staging_tag(tag, format_str):
    env = os.environ.copy()
    env["TZ"] = "UTC"
    
    commit_hash = run_cmd(["git", "rev-parse", "--short=7", tag], env=env)
    date_str = run_cmd(["git", "show", "-s", "--format=%cd", "--date=format-local:%Y%m%d", tag], env=env)
    
    return format_str.format(date=date_str, commit_hash=commit_hash)

def parse_registry(registry):
    parts = registry.split("/", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "gcr.io", registry

def get_upstream_repo():
    try:
        url = run_cmd(["git", "remote", "get-url", "upstream"])
    except Exception:
        url = run_cmd(["git", "remote", "get-url", "origin"])
        
    url = url.replace(".git", "")
    if "github.com:" in url:
        return url.split("github.com:")[-1]
    elif "github.com/" in url:
        return url.split("github.com/")[-1]
    return url

def get_image_digest(registry_host, repository, reference):
    url = f"https://{registry_host}/v2/{repository}/manifests/{reference}"
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json")
    try:
        with urllib.request.urlopen(req) as resp:
            headers = resp.info()
            return headers.get("Docker-Content-Digest")
    except Exception as e:
        print(f"Error fetching digest for {url}: {e}", file=sys.stderr)
        return None

def insert_digests_into_file(file_path, image_name, digest_tag_mappings):
    with open(file_path, 'r') as f:
        content = f.read()
        
    lines = content.splitlines()
    output = []
    in_target_image = False
    
    i = 0
    while i < len(lines):
        line = lines[i]
        output.append(line)
        
        if line.strip() == f"- name: {image_name}":
            in_target_image = True
            i += 1
            continue
            
        if in_target_image and line.strip() == "dmap:":
            existing_digests = set()
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                if next_line.strip().startswith("- name:") or next_line.strip() == "" or (next_line.strip() and not next_line.startswith(" ")):
                    break
                match = re.search(r'"([^"]+)"', next_line)
                if match:
                    digest_key = match.group(1)
                    existing_digests.add(digest_key)
                j += 1
            
            for digest, promoted_tag in digest_tag_mappings:
                if digest not in existing_digests:
                    output.append(f'    "{digest}": ["{promoted_tag}"]')
                    print(f"Added manifest mapping: {image_name} -> {digest}: ['{promoted_tag}']")
                else:
                    print(f"Manifest mapping already exists for {image_name} -> {digest}")
            in_target_image = False
            
        i += 1
        
    with open(file_path, 'w') as f:
        f.write("\n".join(output) + "\n")

def update_local_manifests(tag, manifests_config, dry_run=False):
    if not manifests_config:
        return False
        
    modified_any = False
    for entry in manifests_config:
        file_path = entry["file"]
        if not os.path.exists(file_path):
            print(f"Warning: Local repository manifest {file_path} not found. Skipping.", file=sys.stderr)
            continue
            
        with open(file_path, 'r') as f:
            content = f.read()
            
        modified = content
        for replacement in entry["replacements"]:
            pattern = replacement["pattern"]
            value_template = replacement["value"]
            value = value_template.replace("{tag}", tag)
            modified = re.sub(pattern, value, modified, flags=re.MULTILINE)
            
        if modified != content:
            modified_any = True
            if dry_run:
                print(f"[DRY RUN] Would update local repository manifest: {file_path}")
                for line in modified.splitlines():
                    if tag in line:
                        print(f"  [DRY RUN] New line: {line.strip()}")
            else:
                with open(file_path, 'w') as f:
                    f.write(modified)
                print(f"Updated local repository manifest: {file_path}")
        else:
            print(f"No changes needed for local repository manifest: {file_path}")
            
    return modified_any

def parse_image_ref(image_ref):
    parts = image_ref.split("/", 1)
    if len(parts) == 2:
        host = parts[0]
        rest = parts[1]
    else:
        host = "index.docker.io"
        rest = parts[0]
        
    repo_parts = rest.split(":")
    if len(repo_parts) == 2:
        repo = repo_parts[0]
        tag = repo_parts[1]
    else:
        repo = rest
        tag = "latest"
        
    return host, repo, tag

def extract_images_from_file(file_path):
    images = []
    with open(file_path, 'r') as f:
        content = f.read()
        
    if "repository:" in content and "tag:" in content:
        repo_match = re.search(r'repository:\s*["\']?([^"\'\s]+)["\']?', content)
        tag_match = re.search(r'tag:\s*["\']?([^"\'\s]+)["\']?', content)
        if repo_match and tag_match:
            repo = repo_match.group(1).strip()
            tag = tag_match.group(1).strip()
            images.append(f"{repo}:{tag}")
            
    inline_matches = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[a-zA-Z0-9_./-]+:[a-zA-Z0-9_.-]+)', content)
    for img in inline_matches:
        images.append(img)
        
    return list(set(images))

def main():
    parser = argparse.ArgumentParser(description="Promote Kubernetes staging images to registry manifests")
    parser.add_argument("--config", default=".image-promoter.json", help="Path to promoter config file")
    parser.add_argument("--tag", help="Git release tag to promote (defaults to latest tag)")
    parser.add_argument("--dry-run", action="store_true", help="Print actions instead of making git branch pushes/PRs")
    parser.add_argument("--check", action="store_true", help="Validate that all image references in local repository manifests exist on the registry")
    parser.add_argument("--promotion-pr", help="URL of already submitted image promotion PR (skips k8s.io fork/PR creation steps)")
    args = parser.parse_args()
    
    config_path = args.config
    if not os.path.exists(config_path) and config_path == ".image-promoter.json":
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_dir_config = os.path.join(script_dir, ".image-promoter.json")
        if os.path.exists(script_dir_config):
            config_path = script_dir_config
            
    if not os.path.exists(config_path):
        print(f"Config file {config_path} not found.", file=sys.stderr)
        sys.exit(1)
        
    with open(config_path, 'r') as f:
        config = json.load(f)
        
    if args.check:
        local_manifests = config.get("repository_manifests", [])
        if not local_manifests:
            print("No local repository manifests configured to check.")
            sys.exit(0)
            
        all_images = []
        for entry in local_manifests:
            file_path = entry["file"]
            if os.path.exists(file_path):
                all_images.extend(extract_images_from_file(file_path))
                
        all_images = list(set(all_images))
        
        print(f"Checking {len(all_images)} image references from manifests...")
        failed = False
        for img in all_images:
            host, repo, ref = parse_image_ref(img)
            print(f"Validating image: {img} ...")
            digest = get_image_digest(host, repo, ref)
            if digest:
                print(f"  ✓ Valid: {digest}")
            else:
                print(f"  ✗ Invalid: Image {img} not found on registry!", file=sys.stderr)
                failed = True
                
        if failed:
            print("\nValidation failed: One or more manifest images are invalid/missing.", file=sys.stderr)
            sys.exit(1)
        else:
            print("\nValidation succeeded: All manifest images exist on the registry.")
            sys.exit(0)
        
    tag = args.tag
    if not tag:
        try:
            tag = run_cmd(["git", "describe", "--tags", "--abbrev=0"])
        except Exception as e:
            print("Failed to auto-detect latest git tag. Please specify --tag option.", file=sys.stderr)
            sys.exit(1)
            
    print(f"Promoting for git tag: {tag}")
    
    staging_tag_format = config.get("staging_tag_format", "v{date}-{commit_hash}")
    staging_tag = get_staging_tag(tag, staging_tag_format)
    print(f"Resolved staging image tag: {staging_tag}")
    
    staging_registry = config["staging_registry"]
    reg_host, reg_repo = parse_registry(staging_registry)
    
    # 1. Fetch digests
    promotions = config["promotions"]
    resolved_promotions = {}
    evidence_lines = []
    
    for promo in promotions:
        manifest_name = promo["name"]
        staging_image = promo["staging_image"]
        resolved_promotions[manifest_name] = []
        
        for tag_map in promo["tags"]:
            promoted_template = tag_map["promoted"]
            promoted_tag = promoted_template.replace("{tag}", tag)
            
            suffix = tag_map.get("staging_suffix", "")
            staging_ref = f"{staging_tag}{suffix}"
            
            repo_path = f"{reg_repo}/{staging_image}"
            print(f"Fetching digest for {reg_host}/{repo_path}:{staging_ref} ...")
            digest = get_image_digest(reg_host, repo_path, staging_ref)
            if not digest:
                print(f"Failed to find digest for staging image: {reg_host}/{repo_path}:{staging_ref}", file=sys.stderr)
                sys.exit(1)
                
            resolved_promotions[manifest_name].append((digest, promoted_tag))
            evidence_lines.append(f"$ crane digest {staging_registry}/{staging_image}:{staging_ref} {digest}")
            
    commit_info = run_cmd(["git", "show", "--quiet", "--format=commit %H (tag: %d)%n%n%s%n%b", tag])
    pr_body = "\n".join(evidence_lines) + "\n\n" + commit_info
    
    print("\nResolved promotions and digests:")
    for manifest_name, mappings in resolved_promotions.items():
        print(f"  {manifest_name}:")
        for digest, p_tag in mappings:
            print(f"    {digest} -> {p_tag}")
    # 2. Update local manifests (Dry-run simulation)
    local_manifests = config.get("repository_manifests", [])
    if args.dry_run:
        update_local_manifests(tag, local_manifests, dry_run=True)
        print("\n--- DRY RUN: PR Body ---")
        print(pr_body)
        print("-----------------------")
        return
        
    try:
        github_user = run_cmd(["gh", "api", "user", "-q", ".login"])
    except Exception as e:
        print("Failed to get GitHub username. Make sure you are authenticated with 'gh auth login'.", file=sys.stderr)
        sys.exit(1)
        
    pr_url = args.promotion_pr
    if not pr_url:
        temp_dir = ".k8s.io-temp"
        
        print(f"\nCloning/updating fork of kubernetes/k8s.io to {temp_dir} ...")
        if not os.path.exists(temp_dir):
            try:
                print(f"Cloning {github_user}/k8s.io fork...")
                run_cmd(["gh", "repo", "clone", f"{github_user}/k8s.io", temp_dir, "--", "--depth=1"])
            except Exception:
                print("Fork not found or clone failed. Forking kubernetes/k8s.io...")
                run_cmd(["gh", "repo", "fork", "kubernetes/k8s.io", "--clone=false"])
                print("Cloning fork...")
                run_cmd(["gh", "repo", "clone", f"{github_user}/k8s.io", temp_dir, "--", "--depth=1"])
                
        # Ensure upstream remote exists and points to correct URL
        remotes = run_cmd(["git", "remote"], cwd=temp_dir).split()
        if "upstream" in remotes:
            run_cmd(["git", "remote", "remove", "upstream"], cwd=temp_dir)
        run_cmd(["git", "remote", "add", "upstream", "https://github.com/kubernetes/k8s.io.git"], cwd=temp_dir)
        
        print("Fetching and checking out upstream main...")
        run_cmd(["git", "fetch", "upstream", "main"], cwd=temp_dir)
        
        branch_name = f"promote-{github_user}-{tag}"
        
        # Try checking out a clean branch based on upstream/main
        # If the local branch already exists, delete it first.
        try:
            # Check current branch in temp_dir. If it is branch_name, switch away to avoid self-deletion error.
            current_branch = run_cmd(["git", "branch", "--show-current"], cwd=temp_dir)
            if current_branch == branch_name:
                run_cmd(["git", "checkout", "--detach"], cwd=temp_dir)
            run_cmd(["git", "branch", "-D", branch_name], cwd=temp_dir)
        except Exception:
            pass
            
        run_cmd(["git", "checkout", "-b", branch_name, "upstream/main"], cwd=temp_dir)
            
        manifest_file = os.path.join(temp_dir, config["manifest_path"])
        if not os.path.exists(manifest_file):
            print(f"Manifest file {manifest_file} not found in cloned repository.", file=sys.stderr)
            sys.exit(1)
            
        for manifest_name, mappings in resolved_promotions.items():
            insert_digests_into_file(manifest_file, manifest_name, mappings)
            
        print("Committing and pushing changes...")
        run_cmd(["git", "add", config["manifest_path"]], cwd=temp_dir)
        run_cmd(["git", "commit", "-m", f"promote {tag}"], cwd=temp_dir)
        run_cmd(["git", "push", "-u", "origin", branch_name, "--force"], cwd=temp_dir)
        
        print("Creating Pull Request...")
        pr_title = f"promote {tag} by {github_user}"
        pr_url = run_cmd([
            "gh", "pr", "create",
            "--repo", "kubernetes/k8s.io",
            "--title", pr_title,
            "--body", pr_body,
            "--head", f"{github_user}:{branch_name}",
            "--base", "main"
        ], cwd=temp_dir)
        
        print(f"\nPull request created successfully: {pr_url}")
    
    if local_manifests:
        print("\nUpdating repository manifests and creating pull request...")
        original_branch = run_cmd(["git", "branch", "--show-current"])
        original_head = run_cmd(["git", "rev-parse", "HEAD"])
        
        manifests_branch = f"update-manifests-{tag}"
        
        run_cmd(["git", "checkout", "--detach"])
        try:
            run_cmd(["git", "branch", "-D", manifests_branch])
        except Exception:
            pass
            
        print(f"Creating local branch {manifests_branch} from tag {tag}...")
        run_cmd(["git", "checkout", "-b", manifests_branch, tag])
        
        modified = update_local_manifests(tag, local_manifests, dry_run=False)
        if modified:
            print("Committing and pushing local manifest changes...")
            for entry in local_manifests:
                run_cmd(["git", "add", entry["file"]])
                
            run_cmd(["git", "commit", "-m", f"Update repository manifests to {tag}"])
            run_cmd(["git", "push", "-u", "origin", manifests_branch, "--force"])
            
            print("Creating second Pull Request to update repository manifests...")
            second_pr_title = f"Update repository manifests to {tag}"
            second_pr_body = f"/hold\n\nThis PR updates the repository manifests to use the new release images.\n\nDepends on image promotion PR: {pr_url}\n\nInstructions: Please do not unhold/merge this PR until the image promotion PR is merged and the promoted images are live."
            upstream_repo = get_upstream_repo()
            
            second_pr_url = run_cmd([
                "gh", "pr", "create",
                "--repo", upstream_repo,
                "--title", second_pr_title,
                "--body", second_pr_body,
                "--head", f"{github_user}:{manifests_branch}",
                "--base", "main"
            ])
            print(f"Repository manifests PR created successfully: {second_pr_url}")
        else:
            print("No local manifest modifications were made.")
            
        print("Restoring workspace to original branch...")
        if original_branch:
            run_cmd(["git", "checkout", original_branch])
        else:
            run_cmd(["git", "checkout", original_head])

if __name__ == "__main__":
    main()
