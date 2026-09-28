# Synchronizing OpenTelemetry Python Contrib

Run all commands from the repository root. `main` is the primary Beacon downstream branch; the official upstream branch is used only to discover updates and must not directly replace Beacon-specific commits. The legacy repository used for the initial import and the adopted official Contrib and Core tags are recorded in the [baseline file](upstream.lock.json). Keep the import record unchanged, and update the `upstream` and `core` fields only after merging and validating a new version.

The primary Beacon downstream CI entry point is [ci.yml](../.github/workflows/ci.yml), which validates only the two Beacon packages. Upstream-generated reusable test workflows are retained for synchronization or targeted validation and are not part of the routine Beacon release gate. Preserve this downstream entry point during upstream synchronization; do not overwrite it with generated scripts.

## Remote Configuration

After cloning the Beacon repository, first confirm that `origin` points to `https://github.com/beacon-observability/beacon-python.git`. If `upstream` does not exist, add it:

```bash
git remote add upstream https://github.com/open-telemetry/opentelemetry-python-contrib.git
git config remote.upstream.tagOpt --no-tags
git config --replace-all remote.upstream.fetch '+refs/heads/main:refs/remotes/upstream/main'
git config remote.pushDefault origin
```

If a remote already exists, verify its URL and do not overwrite it. The initial-import source is recorded in [upstream.lock.json](upstream.lock.json) for provenance and is not a source for future releases.

Remotes, refspecs, and remote-tracking references are local configuration and are not included in Git commits. Creating a remote repository or pushing for the first time requires separate authorization. Do not push to the official `upstream` remote.

## Pinning and Merging an Official Baseline

1. Review the official release and independently verify the tag and its full commit SHA. A Python Contrib release tag may be on a release branch and does not have to be an ancestor of the official `main` branch.
2. Fetch the tag with the [single-tag verification script](scripts/fetch-upstream-tag.sh). If an upstream reference with the same name already exists, the script rejects any change to the tag object. For example, using the recorded baseline:

   ```bash
   bash beacon/scripts/fetch-upstream-tag.sh v0.65b0 a5470c666947acddc24fd4064ec7c1b169dfe8b6
   ```

3. Create a synchronization branch from a clean `main` and merge the verified commit. Preserve the merge commit rather than squashing the entire upstream synchronization. Resolve conflicts and adapt first-party packages as needed. Do not replace the entire downstream worktree with the new upstream tree.
4. Verify the Python Core tag in the root [pyproject.toml](../pyproject.toml), then regenerate and inspect [uv.lock](../uv.lock). Review the upstream Contrib tag, Python Core tag, and dependency versions together as a compatible baseline; do not blindly switch them to `main` or the latest versions.
5. Run regressions for first-party packages and affected upstream tests, and validate runtime environments and backends within the intended release scope. Then update the `upstream` and `core` fields in the [baseline file](upstream.lock.json), and run `python beacon/scripts/check-version.py` to compare actual dependencies with the recorded values. Confirm that the target commit is an ancestor of the product's primary branch:

   ```bash
   git merge-base --is-ancestor <verified-upstream-commit-sha> HEAD
   ```

Fetching, merging, testing, and releasing are distinct states. `uv.lock` pins development dependencies but does not replace package release validation. Preserve upstream licenses, history, and package names, and maintain first-party features in their corresponding packages. Inherited upstream release and maintenance-bot workflows are not Beacon entry points and have been removed from this repository. Review new or changed workflows after every synchronization to avoid reintroducing them.
