# Contributing

## Branches and pull requests

- `dev` is the default branch. Open pull requests against `dev`.
- Every push to a PR runs the fast CI tier (`.github/workflows/ci.yml`):
  rustfmt, clippy, unit tests for the main feature sets, MSRV, docs,
  cargo-deny, gitleaks, an advisory semver check and a SQL Server 2022 smoke
  test. The required check is `ci-ok`.
- Approved PRs land through the merge queue (squash or rebase). The queue
  runs the heavy tier (`.github/workflows/qa.yml`) on the exact commit that
  will land: the full Linux SQL Server matrix, macOS, Windows integrated
  auth, and a strict semver check against the latest crates.io release. A
  red run removes the PR from the queue. The required check is `qa-ok`.
- A breaking API change must bump the version on `dev` in the same PR (for
  0.x, a minor bump), otherwise the strict semver check fails.

## Releasing

`main` always equals the latest crates.io release, and every PR into `main`
is a release from `dev`. Everything else, including CI and docs changes,
goes to `dev` and reaches `main` with the next release. `main` only ever
receives merges of `dev`.

1. On `dev`, land a PR that bumps `version` in `Cargo.toml` (and in
   `tiberius-macros/Cargo.toml` if the macros changed) and adds a
   `## Version X.Y.Z` section to `CHANGELOG.md`. Wait for the merge queue
   to finish; that QA run is what the release is checked against.
2. Open a PR from `dev` into `main`. The `release gate` check verifies:
   - the version bump (a PR without one fails) and the changelog heading;
   - that the tag is free;
   - that the PR head is `dev`;
   - that the merged tree is identical to a `dev` commit that passed QA,
     including its strict semver check;
   - that `tiberius-macros`, if not bumped, is unchanged since its last
     release.
3. Merge it with **Create a merge commit** (the only method allowed on
   `main`). `dev` keeps its history and `main` records each release as a
   merge of `dev`, so the next release PR is again conflict-free.
   Publishing is automatic: `.github/workflows/release.yml` publishes to
   crates.io with Trusted Publishing, verifies the index, then tags
   `vX.Y.Z` and creates the GitHub Release.

If a release fails part-way, re-run the failed jobs, or use the Release
workflow's "Run workflow" button on `main` with dry run off. Crates already
published from that commit are skipped.
