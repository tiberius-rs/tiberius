#!/usr/bin/env python3
"""Release gate and publish helpers for .github/workflows/release.yml.

Subcommands:

  gate    Decide whether a commit on (or headed for) `main` is a release, and
          fail with an actionable message when it must not land. Writes the
          release plan to $GITHUB_OUTPUT.
  verify  After `cargo publish`, poll the registry index (bounded) for the new
          version and check its `cksum` against the local .crate file.

Pull request into main (strict; every PR into main is a release):

  * bootstrap: if the target branch tip has no .github/workflows/release.yml,
    the PR introduces the release workflow; it passes with a notice and
    publishes nothing (one-time, cannot recur once release.yml is on main);
  * every publishable crate's version is valid semver and not lower than
    the registry's latest, and at least one is above it;
  * CHANGELOG.md has a `## Version X.Y.Z` heading for the primary crate;
  * the release tags do not already exist on a different commit;
  * a released crate's workspace dependencies are published or released
    in the same run;
  * a crate NOT being released is unchanged against its published .crate
    (cargo-generated files ignored);
  * the PR head is the QA branch (dev) or a commit reachable from it;
  * the tree of the merge result (GitHub's test merge commit, i.e. exactly
    what "Create a merge commit" lands on main) equals the tree of a commit
    on the QA branch whose QA workflow run succeeded. That run includes the
    strict semver check. Because main only ever receives merges of dev, the
    merge result's tree is dev's tree; any change that reached main another
    way makes it differ, and the gate fails.

Push to main (simple): a crate whose version is above the registry's latest
is published (after the changelog, tag and dependency sanity checks); if no
version is above it, the push is a no-op. Lower or invalid versions fail. A
crate already published from this exact commit (per its
.cargo_vcs_info.json) is resumed, so a failed release can be re-run.

Only the Python standard library is used, so it runs on any runner.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Optional

NO_BUMP_MSG = "PRs into main are releases: bump the version"
NOOP_MSG = "no version is above crates.io; nothing to release"
BOOTSTRAP_MSG = "bootstrap: release workflow introduced by this change"
RELEASE_WORKFLOW = ".github/workflows/release.yml"

REGISTRIES = {
    "crates-io": "https://index.crates.io/",
    "staging": "https://index.staging.crates.io/",
}

# Files cargo generates into every .crate; they differ between builds even
# when the sources are identical, so they never count as a content change.
# `Cargo.toml.orig` (the manifest as written) IS compared.
GENERATED_FILES = {"Cargo.toml", "Cargo.lock", ".cargo_vcs_info.json"}


# Only these events run the real QA jobs. qa.yml also runs on pull_request
# purely to report a (skipped) `qa-ok` status, so those runs prove nothing.
QA_EVENTS = {"merge_group", "workflow_dispatch", "push"}

USER_AGENT = "tiberius-release-gate (https://github.com/tiberius-rs/tiberius)"


class GateError(Exception):
    pass


# --------------------------------------------------------------------------
# Semver


SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@dataclasses.dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    pre: tuple = ()
    text: str = dataclasses.field(default="", compare=False)

    @classmethod
    def parse(cls, text: str) -> "Version":
        m = SEMVER_RE.match(text)
        if not m:
            raise ValueError(f"invalid semver version {text!r}")
        pre = tuple(m.group(4).split(".")) if m.group(4) else ()
        return cls(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre, text)

    def _pre_key(self):
        # A release sorts after all of its pre-releases.
        if not self.pre:
            return (1,)
        return (0,) + tuple(
            (0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pre
        )

    def key(self):
        return (self.major, self.minor, self.patch, self._pre_key())

    def __lt__(self, other):
        return self.key() < other.key()

    def __le__(self, other):
        return self.key() <= other.key()

    def __gt__(self, other):
        return self.key() > other.key()

    def __ge__(self, other):
        return self.key() >= other.key()

    def __str__(self):
        return self.text or f"{self.major}.{self.minor}.{self.patch}"


def _partial(text: str):
    parts = text.split("+", 1)[0].split(".") if text else []
    nums = []
    pre = ()
    for i, p in enumerate(parts):
        if p in ("*", "x", "X"):
            break
        if "-" in p:
            num, _, rest = p.partition("-")
            nums.append(int(num))
            pre = tuple(".".join([rest] + parts[i + 1 :]).split("."))
            break
        nums.append(int(p))
    return nums, pre


def _cmp_matches(op: str, spec: str, v: Version) -> bool:
    nums, pre = _partial(spec)
    n = len(nums)
    major = nums[0] if n > 0 else 0
    minor = nums[1] if n > 1 else 0
    patch = nums[2] if n > 2 else 0
    lo = Version(major, minor, patch, pre)
    base = (v.major, v.minor, v.patch)

    def upper(kind):
        if kind == "caret":
            if n == 0:
                return None
            if major > 0 or n == 1:
                return (major + 1, 0, 0)
            if minor > 0 or n == 2:
                return (major, minor + 1, 0)
            return (major, minor, patch + 1)
        if kind == "tilde":
            if n <= 1:
                return (major + 1, 0, 0)
            return (major, minor + 1, 0)
        # wildcard / exact partial
        if n == 0:
            return None
        if n == 1:
            return (major + 1, 0, 0)
        if n == 2:
            return (major, minor + 1, 0)
        return None

    if op == "^":
        up = upper("caret")
        return v >= lo and (up is None or base < up)
    if op == "~":
        return v >= lo and base < upper("tilde")
    if op == "=":
        if n == 3:
            return v == lo
        up = upper("wild")
        return v >= lo and (up is None or base < up)
    if op == ">":
        if n == 3:
            return v > lo
        up = upper("wild")
        return up is None or base >= up
    if op == ">=":
        return v >= lo
    if op == "<":
        return v < lo
    if op == "<=":
        if n == 3:
            return v <= lo
        up = upper("wild")
        return up is None or base < up
    raise ValueError(f"unsupported operator {op!r}")


def req_matches(req: str, version: Version) -> bool:
    """Cargo-style version requirement matching (caret default)."""
    comparators = [c.strip() for c in req.split(",") if c.strip()]
    if not comparators:
        comparators = ["*"]
    parsed = []
    for c in comparators:
        m = re.match(r"^(\^|~|=|>=|<=|>|<)?\s*(.+)$", c)
        op, spec = m.group(1), m.group(2)
        if op is None:
            op = "=" if any(ch in spec for ch in "*xX") else "^"
        if spec in ("*", "x", "X"):
            spec = ""
        parsed.append((op, spec))
    # Pre-release versions only match a comparator naming the same
    # major.minor.patch with a pre-release (cargo semantics).
    if version.pre:
        ok = False
        for _, spec in parsed:
            nums, pre = _partial(spec) if spec else ([], ())
            if pre and len(nums) == 3 and tuple(nums) == (
                version.major,
                version.minor,
                version.patch,
            ):
                ok = True
        if not ok:
            return False
    return all(_cmp_matches(op, spec, version) for op, spec in parsed)


# --------------------------------------------------------------------------
# Registry access


def _http_get(url: str) -> Optional[bytes]:
    """GET a URL; None on 404 / missing file."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (403, 404, 410):
            return None
        raise
    except urllib.error.URLError as e:
        if isinstance(e.reason, FileNotFoundError) or "No such file" in str(e):
            return None
        raise
    except FileNotFoundError:
        return None


def index_path(name: str) -> str:
    n = name.lower()
    if len(n) == 1:
        return f"1/{n}"
    if len(n) == 2:
        return f"2/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[0:2]}/{n[2:4]}/{n}"


class Registry:
    def __init__(self, index_url: str, fetch: Callable[[str], Optional[bytes]] = _http_get):
        self.index_url = index_url if index_url.endswith("/") else index_url + "/"
        self.fetch = fetch
        self._config = None

    @property
    def dl(self) -> str:
        if self._config is None:
            raw = self.fetch(self.index_url + "config.json")
            if raw is None:
                raise GateError(f"registry index {self.index_url} has no config.json")
            self._config = json.loads(raw)
        return self._config["dl"]

    def entries(self, name: str, bust: bool = False) -> list:
        url = self.index_url + index_path(name)
        if bust and url.startswith("http"):
            url += f"?cache-bust={time.time_ns()}"
        raw = self.fetch(url)
        if raw is None:
            return []
        return [json.loads(line) for line in raw.decode().splitlines() if line.strip()]

    def crate_url(self, name: str, version: str) -> str:
        dl = self.dl
        markers = ("{crate}", "{version}", "{prefix}", "{lowerprefix}", "{sha256-checksum}")
        if any(m in dl for m in markers):
            return dl.replace("{crate}", name).replace("{version}", version).replace(
                "{prefix}", index_path(name).rsplit("/", 1)[0]
            ).replace("{lowerprefix}", index_path(name).rsplit("/", 1)[0].lower())
        return f"{dl.rstrip('/')}/{name}/{version}/download"

    def download(self, name: str, version: str) -> bytes:
        raw = self.fetch(self.crate_url(name, version))
        if raw is None:
            raise GateError(f"could not download {name} {version} from the registry")
        return raw


# --------------------------------------------------------------------------
# Git / cargo helpers


def run(cmd: list, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, check=check, text=True, capture_output=True)


def git(root: Path, *args: str, check: bool = True) -> str:
    return run(["git", *args], root, check=check).stdout.strip()


def git_ok(root: Path, *args: str) -> bool:
    return run(["git", *args], root, check=False).returncode == 0


@dataclasses.dataclass
class Package:
    name: str
    version_text: str
    manifest: Path
    # (dependency name, requirement) for path dependencies on workspace crates
    workspace_deps: list

    @property
    def dir(self) -> Path:
        return self.manifest.parent


def workspace_packages(root: Path) -> list:
    meta = json.loads(
        run(["cargo", "metadata", "--no-deps", "--format-version", "1"], root).stdout
    )
    members = {p["name"] for p in meta["packages"]}
    pkgs = []
    for p in meta["packages"]:
        # publish == [] means `publish = false`
        if p.get("publish") == []:
            continue
        deps = [
            (d["name"], d["req"])
            for d in p["dependencies"]
            if d["name"] in members and d.get("path") and d.get("kind") in (None, "build")
        ]
        pkgs.append(Package(p["name"], p["version"], Path(p["manifest_path"]).resolve(), deps))
    return pkgs


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def local_contents(root: Path, pkg: Package) -> dict:
    out = run(
        ["cargo", "package", "--list", "--allow-dirty", "-p", pkg.name], root
    ).stdout
    files = {}
    for rel in out.splitlines():
        rel = rel.strip()
        if not rel or rel in GENERATED_FILES:
            continue
        src = pkg.manifest if rel == "Cargo.toml.orig" else pkg.dir / rel
        files[rel] = sha256(src.read_bytes())
    return files


def crate_contents(data: bytes) -> tuple:
    """(files -> sha256, .cargo_vcs_info.json sha1 or None)"""
    files = {}
    vcs_sha = None
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            rel = member.name.split("/", 1)[1] if "/" in member.name else member.name
            content = tar.extractfile(member).read()
            if rel == ".cargo_vcs_info.json":
                try:
                    vcs_sha = json.loads(content)["git"]["sha1"]
                except (KeyError, ValueError):
                    pass
            if rel in GENERATED_FILES:
                continue
            files[rel] = sha256(content)
    return files, vcs_sha


def diff_contents(local: dict, published: dict, limit: int = 10) -> list:
    changed = []
    for rel in sorted(set(local) | set(published)):
        if rel not in published:
            changed.append(f"added {rel}")
        elif rel not in local:
            changed.append(f"removed {rel}")
        elif local[rel] != published[rel]:
            changed.append(f"modified {rel}")
    if len(changed) > limit:
        changed = changed[:limit] + [f"... and {len(changed) - limit} more"]
    return changed


# --------------------------------------------------------------------------
# QA provenance


def github_qa_runs(repo: str, workflow: str, token: Optional[str], pages: int = 5) -> list:
    runs = []
    for page in range(1, pages + 1):
        url = (
            f"https://api.github.com/repos/{repo}/actions/workflows/{workflow}/runs"
            f"?status=success&per_page=100&page={page}"
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                batch = json.load(r).get("workflow_runs", [])
        except urllib.error.HTTPError as e:
            if e.code == 404:  # the QA workflow does not exist (yet): no runs
                return runs
            raise
        runs.extend(
            {
                "head_sha": w["head_sha"],
                "html_url": w["html_url"],
                "event": w["event"],
                "conclusion": w.get("conclusion"),
            }
            for w in batch
        )
        if len(batch) < 100:
            break
    return runs


def find_qa_match(root: Path, sha: str, qa_ref: str, runs: Iterable[dict]) -> tuple:
    """Return (matching run or None, the commit's tree)."""
    tree = git(root, "rev-parse", f"{sha}^{{tree}}")
    for r in runs:
        if r.get("conclusion", "success") != "success" or r.get("event") not in QA_EVENTS:
            continue
        head = r["head_sha"]
        if not git_ok(root, "cat-file", "-e", f"{head}^{{commit}}"):
            continue
        if git(root, "rev-parse", f"{head}^{{tree}}") != tree:
            continue
        if not git_ok(root, "merge-base", "--is-ancestor", head, qa_ref):
            continue
        return r, tree
    return None, tree


# --------------------------------------------------------------------------
# The gate


@dataclasses.dataclass
class CrateStatus:
    name: str
    version: str
    action: str  # "release" | "resume" | "unchanged" | "error"
    tag: str = ""
    detail: str = ""


@dataclasses.dataclass
class GateResult:
    crates: list
    errors: list
    notes: list
    qa_run: Optional[dict] = None
    release: bool = False

    @property
    def publish(self) -> list:
        return [c for c in self.crates if c.action == "release"]

    @property
    def resume(self) -> list:
        return [c for c in self.crates if c.action == "resume"]


def tag_commit(root: Path, tag: str, remote: Optional[str]) -> Optional[str]:
    """Commit a tag points at: local refs (CI checkout fetches all tags), or
    `git ls-remote` against `remote` when given."""
    ref = f"refs/tags/{tag}"
    if remote:
        out = git(root, "ls-remote", remote, ref, f"{ref}^{{}}")
        found = dict(reversed(line.split("\t")) for line in out.splitlines() if line)
        return found.get(f"{ref}^{{}}") or found.get(ref)
    if git_ok(root, "rev-parse", "-q", "--verify", ref):
        return git(root, "rev-parse", f"{ref}^{{commit}}")
    return None


def tag_name(pkg_name: str, version: str, primary: str) -> str:
    return f"v{version}" if pkg_name == primary else f"{pkg_name}-v{version}"


def topo_order(pkgs: list) -> list:
    names = {p.name for p in pkgs}
    done, out = set(), []

    def visit(p, stack=()):
        if p.name in done:
            return
        for dep, _ in p.workspace_deps:
            if dep in names and dep not in stack:
                visit(next(q for q in pkgs if q.name == dep), stack + (p.name,))
        done.add(p.name)
        out.append(p)

    for p in sorted(pkgs, key=lambda p: p.name):
        visit(p)
    return out


def evaluate(
    root: Path,
    sha: str,
    registry: Registry,
    primary: str,
    qa_runs,
    qa_ref: str,
    changelog: str = "CHANGELOG.md",
    tag_remote: Optional[str] = None,
    mode: str = "push",
    target_tip: Optional[str] = None,
    head: Optional[str] = None,
) -> GateResult:
    """`mode`: "pr" (strict release gate) or "push" (publish if bumped).
    `sha`: the commit whose contents are judged (for a PR, GitHub's test
    merge commit). `target_tip`: for "pr", the target branch tip. `head`:
    for "pr", the PR head commit (defaults to `sha`). `qa_runs`: a list of
    runs, a callable returning one (fetched only when needed), or None to
    skip the tree-identity check."""
    root = root.resolve()
    errors, notes, statuses = [], [], []
    result = GateResult(statuses, errors, notes)

    if mode == "pr":
        if target_tip is None:
            raise GateError("pr mode needs the target branch tip")
        if not git_ok(root, "cat-file", "-e", f"{target_tip}:{RELEASE_WORKFLOW}"):
            notes.append(f"{BOOTSTRAP_MSG} ({RELEASE_WORKFLOW} is absent at the target tip "
                         f"{target_tip[:12]}); nothing is released")
            return result

    pkgs = topo_order(workspace_packages(root))
    published_versions = {}

    for pkg in pkgs:
        entries = registry.entries(pkg.name)
        published_versions[pkg.name] = [
            (Version.parse(e["vers"]), bool(e.get("yanked"))) for e in entries
        ]
        tag = tag_name(pkg.name, pkg.version_text, primary)
        try:
            local = Version.parse(pkg.version_text)
        except ValueError:
            errors.append(
                f"{pkg.name}: version {pkg.version_text!r} in {pkg.manifest.relative_to(root)} "
                "is not valid semver (expected MAJOR.MINOR.PATCH[-PRE][+BUILD])"
            )
            statuses.append(CrateStatus(pkg.name, pkg.version_text, "error", tag))
            continue

        all_versions = [v for v, _ in published_versions[pkg.name]]
        latest = max(all_versions) if all_versions else None
        same = next((v for v in all_versions if v.key() == local.key()), None)

        if latest is None:
            statuses.append(CrateStatus(pkg.name, str(local), "release", tag, "first release"))
        elif local > latest:
            statuses.append(CrateStatus(pkg.name, str(local), "release", tag, f"{latest} -> {local}"))
        elif local < latest and same is None:
            errors.append(
                f"{pkg.name}: version {local} is lower than the latest published {latest}; "
                f"set it above {latest}"
            )
            statuses.append(CrateStatus(pkg.name, str(local), "error", tag))
        else:
            # Equal to a published version. On push, a crate published from
            # this very commit is a retry of an interrupted release.
            action, detail = "unchanged", f"version equals published {same}"
            if mode == "push":
                _, vcs_sha = crate_contents(registry.download(pkg.name, same.text or str(same)))
                if vcs_sha == sha:
                    action, detail = "resume", "already published from this commit (retry)"
            statuses.append(CrateStatus(pkg.name, str(local), action, tag, detail))
            if same != latest:
                notes.append(f"{pkg.name}: {local} is published but older than latest {latest}")

    releasing = {s.name for s in statuses if s.action in ("release", "resume")}
    result.release = bool(releasing) and mode == "push"

    if not releasing:
        if mode == "pr":
            errors.append(
                f"{NO_BUMP_MSG}: land a version bump above crates.io latest (Cargo.toml, and "
                "tiberius-macros/Cargo.toml if it changed) on dev, then open the PR from dev"
            )
        elif not errors:
            notes.append(NOOP_MSG)
        return result

    by_name = {s.name: s for s in statuses}

    # Changelog heading for the primary crate.
    prim = next((p for p in pkgs if p.name == primary), None)
    if prim is None:
        errors.append(f"primary crate {primary!r} not found in the workspace")
    else:
        text = (root / changelog).read_text() if (root / changelog).exists() else ""
        if not re.search(rf"^## Version {re.escape(prim.version_text)}\s*$", text, re.M):
            errors.append(
                f"{changelog}: missing a `## Version {prim.version_text}` heading for "
                f"{primary} {prim.version_text}; add the release notes under that heading"
            )

    # Tags must not already point at another commit.
    for s in statuses:
        if s.action not in ("release", "resume"):
            continue
        target = tag_commit(root, s.tag, tag_remote)
        if target is not None and target != sha:
            errors.append(
                f"tag {s.tag} already exists on {target[:12]}, not on this commit "
                f"{sha[:12]}; {s.name} {s.version} was already tagged. Bump the version"
            )

    # Workspace dependencies of released crates must be available.
    for pkg in pkgs:
        if pkg.name not in releasing:
            continue
        for dep, req in pkg.workspace_deps:
            if dep not in published_versions:
                published_versions[dep] = [
                    (Version.parse(e["vers"]), bool(e.get("yanked"))) for e in registry.entries(dep)
                ]
            candidates = [v for v, yanked in published_versions[dep] if not yanked]
            dep_status = by_name.get(dep)
            if dep_status and dep in releasing:
                try:
                    candidates.append(Version.parse(dep_status.version))
                except ValueError:
                    pass
            if not any(req_matches(req, v) for v in candidates):
                local_dep = dep_status.version if dep_status else "unknown"
                errors.append(
                    f"{pkg.name} requires {dep} {req}, which is not published and is not "
                    f"being released now (local {dep} is {local_dep}). Release {dep} in "
                    "the same PR (bump its version) or depend on a published version"
                )

    if mode != "pr":
        return result

    # A crate that is not being released must be byte-identical (ignoring
    # cargo-generated files) to its published .crate, or it needs a bump.
    for s in statuses:
        if s.action != "unchanged":
            continue
        pkg = next(p for p in pkgs if p.name == s.name)
        pub_files, _ = crate_contents(registry.download(pkg.name, s.version))
        changed = diff_contents(local_contents(root, pkg), pub_files)
        if changed:
            errors.append(
                f"bump {pkg.name}: its package differs from the published {pkg.name} "
                f"{s.version} but it is not being released. Bump `version` in "
                f"{pkg.manifest.relative_to(root)}. Changed files: " + ", ".join(changed)
            )

    # Releases come from dev: the PR head is dev itself or a commit on it.
    head = head or sha
    if git_ok(root, "rev-parse", "-q", "--verify", f"{qa_ref}^{{commit}}") and not git_ok(
        root, "merge-base", "--is-ancestor", head, qa_ref
    ):
        errors.append(
            f"release PRs must come from dev: head {head[:12]} is not on {qa_ref}. Open the "
            "PR from `dev` into `main`"
        )

    # Tree identity with a green QA run on the QA branch.
    if callable(qa_runs):
        qa_runs = qa_runs()
    if qa_runs is not None and not git_ok(root, "rev-parse", "-q", "--verify", f"{qa_ref}^{{commit}}"):
        errors.append(f"QA branch ref {qa_ref} not found; cannot prove this tree passed QA")
    elif qa_runs is not None:
        qa_match, tree = find_qa_match(root, sha, qa_ref, qa_runs)
        result.qa_run = qa_match
        if qa_match is None:
            errors.append(
                f"tree {tree[:12]} of {sha[:12]} does not match any commit on {qa_ref} with a "
                "successful QA run. Land the change on dev through the merge queue (or run "
                "qa.yml on dev), then open the dev→main PR from that exact state. If main "
                "received a change that is not on dev, the merge result differs from every "
                "dev tree: bring that change to dev first"
            )
        else:
            notes.append(
                f"tree {tree[:12]} matches QA-verified {qa_match['head_sha'][:12]} "
                f"({qa_match['event']}): {qa_match['html_url']}"
            )

    return result


def write_outputs(result: GateResult, path: Optional[str]) -> None:
    plan = {
        "publish": [s.name for s in result.publish],
        "resume": [s.name for s in result.resume],
        "releases": [
            {"crate": s.name, "version": s.version, "tag": s.tag}
            for s in result.crates
            if s.action in ("release", "resume")
        ],
    }
    lines = [
        f"release={'true' if result.release else 'false'}",
        f"publish={' '.join(plan['publish'])}",
        f"plan={json.dumps(plan, separators=(',', ':'))}",
    ]
    if path:
        with open(path, "a") as f:
            f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def cmd_gate(args) -> int:
    root = Path(args.root).resolve()
    sha = git(root, "rev-parse", args.sha)
    registry = Registry(args.index_url or REGISTRIES[args.registry])

    mode = "pr" if args.target else "push"
    target_tip = git(root, "rev-parse", f"{args.target}^{{commit}}") if args.target else None

    # Tree identity is enforced on the PR only.
    qa_runs = None
    if mode == "pr" and args.qa_runs_file:
        qa_runs = json.loads(Path(args.qa_runs_file).read_text())
    elif mode == "pr" and not args.skip_qa_check:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        qa_runs = lambda: github_qa_runs(args.repo, args.qa_workflow, token)  # noqa: E731

    head = git(root, "rev-parse", args.head) if args.head else None
    result = evaluate(
        root, sha, registry, args.primary, qa_runs, args.qa_ref, tag_remote=args.tag_remote,
        mode=mode, target_tip=target_tip, head=head,
    )

    print(f"Release gate ({mode}) for {sha} ({registry.index_url})")
    for s in result.crates:
        print(f"  {s.name} {s.version}: {s.action}{' - ' + s.detail if s.detail else ''}")
    for n in result.notes:
        print(f"  note: {n}")
    if result.errors:
        for e in result.errors:
            print(f"::error title=release gate::{e}")
        return 1
    write_outputs(result, os.environ.get("GITHUB_OUTPUT") if not args.no_output else None)
    return 0


def cmd_verify(args) -> int:
    registry = Registry(args.index_url or REGISTRIES[args.registry])
    expected = sha256(Path(args.crate_file).read_bytes())
    deadline = time.monotonic() + args.timeout
    while True:
        for e in registry.entries(args.crate, bust=True):
            if e["vers"] == args.version:
                if e["cksum"] != expected:
                    print(
                        f"::error::{args.crate} {args.version}: index cksum {e['cksum']} != "
                        f"sha256 of {args.crate_file} {expected}"
                    )
                    return 1
                print(f"{args.crate} {args.version} is in the index, cksum {expected} matches")
                return 0
        if time.monotonic() >= deadline:
            print(f"::error::{args.crate} {args.version} did not appear in the index "
                  f"within {args.timeout}s")
            return 1
        time.sleep(args.interval)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gate")
    g.add_argument("--root", default=".")
    g.add_argument("--sha", default="HEAD")
    g.add_argument("--registry", choices=sorted(REGISTRIES), default="crates-io")
    g.add_argument("--index-url", help="override the sparse index URL (tests)")
    g.add_argument("--primary", default="tiberius", help="crate tagged vX.Y.Z")
    g.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "tiberius-rs/tiberius"))
    g.add_argument("--qa-workflow", default="qa.yml")
    g.add_argument("--qa-ref", default="origin/dev", help="QA'd commits must be reachable from this")
    g.add_argument("--qa-runs-file", help="JSON list of runs instead of the GitHub API (tests)")
    g.add_argument("--target", help="PR mode: the target branch ref (e.g. origin/main). "
                   "Without it the gate runs in push mode")
    g.add_argument("--head", help="PR mode: the PR head commit (must be on --qa-ref); "
                   "--sha is then the test merge commit")
    g.add_argument("--tag-remote", help="look tags up on this remote instead of local refs")
    g.add_argument("--skip-qa-check", action="store_true", help="skip tree identity (local use)")
    g.add_argument("--no-output", action="store_true")
    g.set_defaults(func=cmd_gate)

    v = sub.add_parser("verify")
    v.add_argument("--crate", required=True)
    v.add_argument("--version", required=True)
    v.add_argument("--crate-file", required=True)
    v.add_argument("--registry", choices=sorted(REGISTRIES), default="crates-io")
    v.add_argument("--index-url")
    v.add_argument("--timeout", type=int, default=600)
    v.add_argument("--interval", type=int, default=10)
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except GateError as e:
        print(f"::error title=release gate::{e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
