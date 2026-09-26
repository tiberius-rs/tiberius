#!/usr/bin/env python3
"""Tests for release_gate.py. Offline: a throwaway git repo holds a two-crate
workspace shaped like tiberius (tiberius -> tiberius-macros, path + version),
and a file:// sparse index plays the registry.

Run: python3 .github/scripts/test_release_gate.py -v
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_gate as rg  # noqa: E402

ENV = dict(os.environ, CARGO_NET_OFFLINE="true", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")


def sh(cwd, *cmd):
    return subprocess.run(cmd, cwd=cwd, env=ENV, check=True, text=True, capture_output=True).stdout.strip()


class Fixture:
    """Workspace repo + fake registry."""

    def __init__(self, tmp: Path):
        self.repo = tmp / "repo"
        self.index = tmp / "index"
        self.dl = tmp / "dl"
        for d in (self.repo, self.index, self.dl):
            d.mkdir()
        (self.index / "config.json").write_text(
            json.dumps({"dl": f"file://{self.dl}/{{crate}}-{{version}}.crate", "api": "x"})
        )
        sh(self.repo, "git", "init", "-q", "-b", "dev")
        self.write_ws("0.13.0", "0.1.0", macros_req="0.1.0", changelog=["0.13.0"])
        # The pipeline is already on main (not a bootstrap) unless a test
        # says otherwise.
        wf = self.repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "release.yml").write_text("name: Release\n")
        self.base = self.commit("base")

    # -- workspace --------------------------------------------------------

    def write_ws(self, tib, mac, macros_req=None, changelog=(), macros_body="// macros\n"):
        r = self.repo
        (r / "src").mkdir(exist_ok=True)
        (r / "tiberius-macros" / "src").mkdir(parents=True, exist_ok=True)
        req = macros_req or mac
        (r / "Cargo.toml").write_text(
            f'[package]\nname = "tiberius"\nversion = "{tib}"\nedition = "2021"\n'
            'license = "MIT"\ndescription = "t"\n\n[workspace]\nmembers = ["tiberius-macros"]\n\n'
            f'[dependencies]\ntiberius-macros = {{ path = "tiberius-macros", version = "{req}" }}\n'
        )
        (r / "src" / "lib.rs").write_text("pub fn f() {}\n")
        (r / "tiberius-macros" / "Cargo.toml").write_text(
            f'[package]\nname = "tiberius-macros"\nversion = "{mac}"\nedition = "2021"\n'
            'license = "MIT"\ndescription = "t"\n'
        )
        (r / "tiberius-macros" / "src" / "lib.rs").write_text(macros_body)
        (r / "CHANGELOG.md").write_text(
            "# Changes\n\n" + "".join(f"## Version {v}\n\n- x\n\n" for v in changelog)
        )
        (r / ".gitignore").write_text("target\nCargo.lock\n")

    def commit(self, msg):
        sh(self.repo, "git", "add", "-A")
        # Isolate from the developer's global hooks / signing config.
        sh(self.repo, "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
           "commit", "-q", "-m", msg)
        return sh(self.repo, "git", "rev-parse", "HEAD")

    # -- registry ---------------------------------------------------------

    def publish(self, name, version, vcs_sha="0" * 40, yanked=False):
        """Package the current working tree state of `name` into the fake registry."""
        pkg = next(p for p in rg.workspace_packages(self.repo) if p.name == name)
        files = sh(self.repo, "cargo", "package", "--list", "--allow-dirty", "-p", name).splitlines()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            def add(rel, data):
                info = tarfile.TarInfo(f"{name}-{version}/{rel}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            for rel in files:
                if rel == "Cargo.toml.orig":
                    add(rel, pkg.manifest.read_bytes())
                elif rel == ".cargo_vcs_info.json":
                    add(rel, json.dumps({"git": {"sha1": vcs_sha}}).encode())
                elif rel in ("Cargo.toml", "Cargo.lock"):
                    add(rel, b"# generated, differs every build\n" + os.urandom(8).hex().encode())
                else:
                    add(rel, (pkg.dir / rel).read_bytes())
        data = buf.getvalue()
        (self.dl / f"{name}-{version}.crate").write_bytes(data)
        path = self.index / rg.index_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"name": name, "vers": version, "cksum": hashlib.sha256(data).hexdigest(),
                 "yanked": yanked, "deps": [], "features": {}}
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return data

    def registry(self):
        return rg.Registry(f"file://{self.index}/")

    def gate(self, sha="HEAD", qa_runs=None, qa_ref="dev", mode="pr", target_tip="BASE",
             head=None):
        """PR mode by default, targeting the fixture's base commit (as if
        main were at the last release and dev branched from it)."""
        sha = sh(self.repo, "git", "rev-parse", sha)
        if target_tip == "BASE":
            target_tip = self.base
        head = sh(self.repo, "git", "rev-parse", head) if head else None
        return rg.evaluate(self.repo, sha, self.registry(), "tiberius", qa_runs, qa_ref,
                           mode=mode, target_tip=target_tip if mode == "pr" else None,
                           head=head)


def run_for(sha, event="merge_group", conclusion="success"):
    return {"head_sha": sha, "html_url": f"https://example/runs/{sha[:7]}", "event": event,
            "conclusion": conclusion}


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.fx = Fixture(self.tmp)
        # Published state == the base commit, like tiberius 0.13.0 / macros 0.1.0.
        self.fx.publish("tiberius-macros", "0.1.0")
        self.fx.publish("tiberius", "0.13.0")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def assertError(self, result, needle):
        self.assertTrue(any(needle in e for e in result.errors),
                        f"expected an error containing {needle!r}, got {result.errors}")

    def bump(self, tib="0.13.1", mac="0.1.0", changelog=("0.13.1", "0.13.0"), **kw):
        self.fx.write_ws(tib, mac, changelog=changelog, **kw)
        return self.fx.commit(f"release {tib}")

    def touch(self, path, text="x\n", msg="change"):
        f = self.fx.repo / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        return self.fx.commit(msg)

    def rev(self, ref="HEAD"):
        return sh(self.fx.repo, "git", "rev-parse", ref)

    # -- PR: every PR into main is a release -----------------------------------

    def test_pr_without_bump_fails(self):
        for label, path in {"ci only": ".github/workflows/ci.yml", "src": "src/lib.rs",
                            "tests": "tests/query.rs"}.items():
            with self.subTest(label):
                self.touch(path, f"// {label}\n")
                r = self.fx.gate()
                self.assertError(r, rg.NO_BUMP_MSG)
                self.assertFalse(r.release)

    def test_pr_release_tiberius_only_passes(self):
        # Mirrors fixes/stacked: tiberius 0.13.1, macros unchanged.
        sha = self.bump()
        r = self.fx.gate(qa_runs=[run_for(sha)])
        self.assertEqual(r.errors, [])
        self.assertEqual([c.name for c in r.publish], ["tiberius"])
        self.assertEqual(r.publish[0].tag, "v0.13.1")
        self.assertEqual(r.qa_run["head_sha"], sha)
        self.assertFalse(r.release)  # a PR never publishes

    def test_pr_release_both_crates_in_dependency_order(self):
        sha = self.bump(mac="0.1.1", macros_req="0.1.1", macros_body="// new\n")
        r = self.fx.gate(qa_runs=[run_for(sha)])
        self.assertEqual(r.errors, [])
        self.assertEqual([c.name for c in r.publish], ["tiberius-macros", "tiberius"])
        self.assertEqual(r.publish[0].tag, "tiberius-macros-v0.1.1")

    def test_pr_prerelease_bump_passes(self):
        sha = self.bump(tib="0.13.1-proof.1", changelog=("0.13.1-proof.1",))
        self.assertEqual(self.fx.gate(qa_runs=[run_for(sha)]).errors, [])

    def test_pr_repo_wide_changes_do_not_need_a_macros_bump(self):
        # CI/docs/src changes outside tiberius-macros/ ride along with a
        # tiberius release; only the macros package is compared.
        self.touch(".github/workflows/ci.yml", "on: push\n")
        self.touch("README.md", "# readme\n")
        sha = self.bump()
        self.assertEqual(self.fx.gate(qa_runs=[run_for(sha)]).errors, [])

    # -- synthetic failures ----------------------------------------------------

    def test_lower_version_fails(self):
        self.bump(tib="0.12.9", changelog=("0.12.9",))
        for mode in ("pr", "push"):
            with self.subTest(mode):
                self.assertError(self.fx.gate(mode=mode),
                                 "tiberius: version 0.12.9 is lower than the latest published 0.13.0")

    def test_invalid_semver_fails(self):
        # cargo itself rejects most invalid versions, so inject one.
        real = rg.workspace_packages

        def patched(root):
            pkgs = real(root)
            for p in pkgs:
                if p.name == "tiberius":
                    p.version_text = "0.13"
            return pkgs

        self.bump()
        with mock.patch.object(rg, "workspace_packages", patched):
            for mode in ("pr", "push"):
                with self.subTest(mode):
                    self.assertError(self.fx.gate(mode=mode),
                                     "tiberius: version '0.13' in Cargo.toml is not valid semver")

    def test_macros_changed_without_bump_fails(self):
        self.bump(macros_body="// changed\n")
        r = self.fx.gate()
        self.assertError(r, "bump tiberius-macros: its package differs from the published tiberius-macros 0.1.0")
        self.assertError(r, "modified src/lib.rs")

    def test_missing_changelog_heading_fails(self):
        self.bump(changelog=("0.13.0",))
        for mode in ("pr", "push"):
            with self.subTest(mode):
                self.assertError(self.fx.gate(mode=mode), "missing a `## Version 0.13.1` heading")

    def test_tag_on_other_commit_fails(self):
        sh(self.fx.repo, "git", "tag", "v0.13.1", self.fx.base)
        self.bump()
        for mode in ("pr", "push"):
            with self.subTest(mode):
                self.assertError(self.fx.gate(mode=mode), "tag v0.13.1 already exists on")

    def test_tag_on_same_commit_is_ok(self):
        sha = self.bump()
        sh(self.fx.repo, "git", "tag", "v0.13.1", sha)
        self.assertEqual(self.fx.gate(qa_runs=[run_for(sha)]).errors, [])

    def test_unpublished_macros_dependency_fails(self):
        # macros 0.0.9 cannot be released (lower than 0.1.0), yet tiberius needs it.
        self.bump(mac="0.0.9", macros_req="=0.0.9")
        r = self.fx.gate()
        self.assertError(r, "tiberius requires tiberius-macros =0.0.9, which is not published "
                            "and is not being released now")

    def test_tree_matching_no_green_qa_run_fails(self):
        sha = self.bump()
        cases = {
            "no runs": [],
            "only an older tree": [run_for(self.fx.base)],
            "failed run": [run_for(sha, conclusion="failure")],
            "pull_request shim run": [run_for(sha, event="pull_request")],
        }
        for label, runs in cases.items():
            with self.subTest(label):
                self.assertError(self.fx.gate(qa_runs=runs),
                                 "does not match any commit on dev with a successful QA run")

    def test_qa_run_not_on_dev_fails(self):
        sh(self.fx.repo, "git", "checkout", "-q", "-b", "side")
        sha = self.bump()
        r = self.fx.gate(sha=sha, qa_runs=[run_for(sha, event="workflow_dispatch")])
        self.assertError(r, "does not match any commit on dev")

    # -- merge-commit releases: dev -> main ------------------------------------

    def merge_into_main(self, dev_sha, msg):
        """What GitHub's "Create a merge commit" does (also its PR test merge)."""
        sh(self.fx.repo, "git", "checkout", "-q", "main")
        sh(self.fx.repo, "git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
           "merge", "-q", "--no-ff", "-m", msg, dev_sha)
        m = self.rev()
        sh(self.fx.repo, "git", "checkout", "-q", "dev")
        return m

    def test_two_merge_commit_release_cycles(self):
        sh(self.fx.repo, "git", "branch", "main", self.fx.base)
        # Cycle 1: dev work + bump, QA'd, merged into main with a merge commit.
        self.touch("src/lib.rs", "pub fn one() {}\n", "feature one")
        d1 = self.bump()
        m1 = self.merge_into_main(d1, "Merge dev (0.13.1)")
        self.assertEqual(self.rev(f"{m1}^{{tree}}"), self.rev(f"{d1}^{{tree}}"))
        r = self.fx.gate(sha=m1, head=d1, target_tip=self.fx.base, qa_runs=[run_for(d1)])
        self.assertEqual(r.errors, [])
        self.fx.publish("tiberius", "0.13.1")
        # Cycle 2: dev never received main's merge commit, yet the next
        # merge is clean and lands dev's tree exactly.
        self.touch("src/lib.rs", "pub fn two() {}\n", "feature two")
        d2 = self.bump(tib="0.13.2", changelog=("0.13.2", "0.13.1", "0.13.0"))
        # `git merge-tree` exits non-zero on conflicts (sh() would raise).
        sh(self.fx.repo, "git", "merge-tree", "--write-tree", m1, d2)
        m2 = self.merge_into_main(d2, "Merge dev (0.13.2)")
        self.assertEqual(self.rev(f"{m2}^{{tree}}"), self.rev(f"{d2}^{{tree}}"))
        r = self.fx.gate(sha=m2, head=d2, target_tip=m1, qa_runs=[run_for(d2)])
        self.assertEqual(r.errors, [])
        self.assertEqual([c.version for c in r.publish], ["0.13.2"])
        # main's history contains dev's original commits (same SHAs).
        for c in (d1, d2):
            self.assertTrue(rg.git_ok(self.fx.repo, "merge-base", "--is-ancestor", c, m2))

    def test_change_that_bypassed_dev_fails_tree_identity(self):
        sh(self.fx.repo, "git", "checkout", "-q", "-b", "main", self.fx.base)
        stray = self.touch("docs/hotfix.md", "only on main\n", "direct commit to main")
        sh(self.fx.repo, "git", "checkout", "-q", "dev")
        d = self.bump()
        m = self.merge_into_main(d, "Merge dev")
        r = self.fx.gate(sha=m, head=d, target_tip=stray, qa_runs=[run_for(d)])
        self.assertError(r, "does not match any commit on dev with a successful QA run")

    def test_pr_head_not_on_dev_fails(self):
        sh(self.fx.repo, "git", "checkout", "-q", "-b", "feature")
        f = self.bump()
        sh(self.fx.repo, "git", "checkout", "-q", "dev")
        # Even with a QA'd identical tree on dev, the head itself must be on dev.
        sh(self.fx.repo, "git", "merge", "-q", "--squash", "feature")
        d = self.fx.commit("same tree on dev")
        self.assertEqual(self.rev(f"{f}^{{tree}}"), self.rev(f"{d}^{{tree}}"))
        r = self.fx.gate(sha=f, head=f, qa_runs=[run_for(d)])
        self.assertError(r, "release PRs must come from dev")
        self.assertEqual(self.fx.gate(sha=d, head=d, qa_runs=[run_for(d)]).errors, [])

    # -- bootstrap: keyed strictly on release.yml at the target tip -----------

    def _strip_release_yml(self):
        (self.fx.repo / ".github" / "workflows" / "release.yml").unlink()
        return self.fx.commit("no release workflow yet")

    def test_bootstrap_passes_when_target_lacks_release_yml(self):
        tip = self._strip_release_yml()
        # This change re-adds it (the CI PR) and also touches crate code
        # without a bump; bootstrap passes anyway and releases nothing.
        self.touch(".github/workflows/release.yml", "name: Release\n")
        self.touch("src/lib.rs", "pub fn unreleased() {}\n")
        r = self.fx.gate(target_tip=tip)
        self.assertEqual(r.errors, [])
        self.assertTrue(any(rg.BOOTSTRAP_MSG in n for n in r.notes), r.notes)
        self.assertEqual(r.crates, [])
        self.assertFalse(r.release)

    def test_bootstrap_never_queries_qa_runs(self):
        # Upstream has no qa.yml before the bootstrap PR lands, so the runs
        # API would 404; bootstrap must not need it.
        tip = self._strip_release_yml()

        def boom():
            raise AssertionError("QA runs fetched during bootstrap")

        self.assertEqual(self.fx.gate(target_tip=tip, qa_runs=boom).errors, [])

    def test_missing_qa_workflow_means_no_runs(self):
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with mock.patch.object(rg.urllib.request, "urlopen", side_effect=err):
            self.assertEqual(rg.github_qa_runs("o/r", "qa.yml", None), [])

    def test_bootstrap_is_keyed_on_the_target_tip_only(self):
        # Head lacks release.yml but the target has it: not a bootstrap.
        tip = self.fx.base
        self._strip_release_yml()
        self.assertError(self.fx.gate(target_tip=tip), rg.NO_BUMP_MSG)
        # Other workflow files at the target don't matter; only release.yml.
        (self.fx.repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\n")
        tip2 = self.fx.commit("ci.yml but no release.yml")
        self.assertTrue(any(rg.BOOTSTRAP_MSG in n for n in self.fx.gate(target_tip=tip2).notes))
        # A stale branch whose merge base predates release.yml is NOT a
        # bootstrap once the target tip has it.
        sh(self.fx.repo, "git", "checkout", "-q", "-b", "main")
        tip3 = self.touch(".github/workflows/release.yml", "name: Release\n", "pipeline lands")
        sh(self.fx.repo, "git", "checkout", "-q", "dev")
        self.touch("src/lib.rs", "pub fn stale() {}\n")
        r = self.fx.gate(target_tip=tip3)
        self.assertError(r, rg.NO_BUMP_MSG)
        self.assertFalse(any(rg.BOOTSTRAP_MSG in n for n in r.notes))

    # -- push to main -----------------------------------------------------------

    def test_push_without_bump_is_a_noop(self):
        # Even with crate code that differs from the published .crate (like
        # upstream main today): no content comparison on push.
        self.touch("src/lib.rs", "pub fn unreleased() {}\n")
        self.touch("tiberius-macros/src/lib.rs", "// unreleased\n")
        r = self.fx.gate(mode="push")
        self.assertEqual(r.errors, [])
        self.assertFalse(r.release)
        self.assertIn(rg.NOOP_MSG, r.notes)

    def test_push_with_bump_releases(self):
        self.bump()
        r = self.fx.gate(mode="push")
        self.assertEqual(r.errors, [])
        self.assertTrue(r.release)
        self.assertEqual([c.name for c in r.publish], ["tiberius"])

    def test_push_does_not_need_qa_or_a_macros_bump(self):
        self.bump(macros_body="// changed\n")
        self.assertEqual(self.fx.gate(mode="push", qa_runs=[]).errors, [])

    def test_push_retry_after_partial_publish_resumes(self):
        sha = self.bump()
        self.fx.publish("tiberius", "0.13.1", vcs_sha=sha)
        r = self.fx.gate(mode="push")
        self.assertEqual(r.errors, [])
        self.assertTrue(r.release)
        self.assertEqual([c.name for c in r.resume], ["tiberius"])
        self.assertEqual(r.publish, [])


class VerifyTests(unittest.TestCase):
    def test_verify_cksum(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            fx = Fixture(tmp)
            data = fx.publish("tiberius", "0.13.0")
            crate = tmp / "t.crate"
            crate.write_bytes(data)
            base = ["verify", "--crate", "tiberius", "--version", "0.13.0",
                    "--index-url", f"file://{fx.index}/", "--timeout", "0"]
            self.assertEqual(rg.main(base + ["--crate-file", str(crate)]), 0)
            crate.write_bytes(data + b"x")
            self.assertEqual(rg.main(base + ["--crate-file", str(crate)]), 1)
            missing = [a if a != "0.13.0" else "9.9.9" for a in base]
            self.assertEqual(rg.main(missing + ["--crate-file", str(crate), "--interval", "0"]), 1)
        finally:
            shutil.rmtree(tmp)


class SemverTests(unittest.TestCase):
    def test_ordering(self):
        v = rg.Version.parse
        self.assertLess(v("0.13.0"), v("0.13.1-proof.1"))
        self.assertLess(v("0.13.1-proof.1"), v("0.13.1"))
        self.assertLess(v("1.0.0-alpha.2"), v("1.0.0-alpha.10"))
        self.assertLess(v("1.0.0-alpha"), v("1.0.0-alpha.1"))
        self.assertLess(v("1.0.0-9"), v("1.0.0-a"))

    def test_invalid(self):
        for bad in ("0.13", "01.2.3", "1.2.3-", "v1.2.3", "1.2.3.4", ""):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    rg.Version.parse(bad)

    def test_req(self):
        v = rg.Version.parse
        cases = [
            ("^0.1.0", "0.1.5", True), ("0.1.0", "0.2.0", False), ("^0.0.3", "0.0.4", False),
            ("^1.2", "1.9.0", True), ("^1.2", "2.0.0", False), ("~0.1.2", "0.1.9", True),
            ("~0.1.2", "0.2.0", False), ("=0.1.0", "0.1.1", False), (">=0.1, <0.3", "0.2.9", True),
            (">=0.1, <0.3", "0.3.0", False), ("0.1.*", "0.1.7", True), ("*", "3.0.0", True),
            ("^0.1.0", "0.1.1-rc.1", False), ("^0.1.1-rc.1", "0.1.1-rc.2", True),
            ("<0.2", "0.1.9", True), ("<=0.2", "0.2.5", True), (">0.2", "0.2.5", False),
        ]
        for req, ver, want in cases:
            with self.subTest(req=req, ver=ver):
                self.assertEqual(rg.req_matches(req, v(ver)), want)


if __name__ == "__main__":
    unittest.main()
