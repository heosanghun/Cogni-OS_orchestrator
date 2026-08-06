from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from cogni_os.retained_git import (
    RETAINED_GIT_API_ASSURANCE,
    RETAINED_GIT_CONTRACT_ID,
    RETAINED_GIT_SCHEMA_VERSION,
    GitCommand,
    GitCommandResult,
    RetainedGitError,
    RetainedGitLimits,
    TrustedGitBinding,
    _verify_retained_git_artifact,
    retained_git_api_assurance,
    validate_retained_git_manifest,
    verify_retained_git_artifact,
)
from cogni_os.retained_source import retain_source_artifact


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _readdress_manifest(manifest: dict[str, object]) -> dict[str, object]:
    document = deepcopy(manifest)
    without_id = {
        key: value for key, value in document.items() if key != "manifest_sha256"
    }
    canonical = (
        json.dumps(
            without_id,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    document["manifest_sha256"] = _sha256_bytes(canonical)
    return document


class _FakeGit:
    def __init__(
        self,
        *,
        commit_oid: str,
        tree_oid: str,
        listed_heads: bytes | None = None,
        exact_commit: str | None = None,
        exact_tree: str | None = None,
        object_inventory: bytes | None = None,
        forbidden_feature: str | None = None,
        pack_files: tuple[bytes, ...] = (b"PACKDATA",),
    ) -> None:
        self.commit_oid = commit_oid
        self.tree_oid = tree_oid
        self.listed_heads = listed_heads or (
            f"{commit_oid} refs/heads/main\n".encode("ascii")
        )
        self.exact_commit = exact_commit or commit_oid
        self.exact_tree = exact_tree or tree_oid
        self.object_inventory = object_inventory or (
            f"{commit_oid} commit 10 8\n{tree_oid} tree 6 5\n{'3' * 40} blob 4 4\n"
        ).encode("ascii")
        self.forbidden_feature = forbidden_feature
        self.pack_files = pack_files
        self.commands: list[GitCommand] = []

    def __call__(self, command: GitCommand) -> GitCommandResult:
        self.commands.append(command)
        if command.phase == "init":
            git_dir = Path(command.argv[-1])
            (git_dir / "objects" / "pack").mkdir(parents=True)
            (git_dir / "objects" / "info").mkdir()
            (git_dir / "info").mkdir()
            for index, content in enumerate(self.pack_files):
                suffix = ".pack" if index % 2 == 0 else ".idx"
                (git_dir / "objects" / "pack" / f"pack-{index}{suffix}").write_bytes(
                    content
                )
            return GitCommandResult(0, b"", b"")
        git_dir_text = next(
            value.removeprefix("--git-dir=")
            for value in command.argv
            if value.startswith("--git-dir=")
        )
        git_dir = Path(git_dir_text)
        if command.phase in {"object-format-before", "object-format-after"}:
            return GitCommandResult(0, b"sha1\n", b"")
        if command.phase == "bundle-verify":
            return GitCommandResult(0, b"verified\n", b"")
        if command.phase == "bundle-list-heads":
            return GitCommandResult(0, self.listed_heads, b"")
        if command.phase == "bundle-import":
            if self.forbidden_feature == "alternates":
                (git_dir / "objects" / "info" / "alternates").write_text(
                    "C:/actor/objects\n", encoding="utf-8"
                )
            elif self.forbidden_feature == "grafts":
                (git_dir / "info" / "grafts").write_text("bad\n", encoding="utf-8")
            elif self.forbidden_feature == "shallow":
                (git_dir / "shallow").write_text("bad\n", encoding="utf-8")
            elif self.forbidden_feature == "promisor":
                (git_dir / "objects" / "pack" / "pack-bad.promisor").write_text(
                    "bad\n", encoding="utf-8"
                )
            return GitCommandResult(0, self.listed_heads, b"")
        if command.phase == "forbidden-config":
            if self.forbidden_feature == "config":
                return GitCommandResult(0, b"extensions.partialclone origin\n", b"")
            return GitCommandResult(1, b"", b"")
        if command.phase == "replace-refs":
            if self.forbidden_feature == "replace":
                return GitCommandResult(0, b"refs/replace/deadbeef\n", b"")
            return GitCommandResult(0, b"", b"")
        if command.phase == "exact-commit":
            return GitCommandResult(0, f"{self.exact_commit}\n".encode("ascii"), b"")
        if command.phase == "exact-tree":
            return GitCommandResult(0, f"{self.exact_tree}\n".encode("ascii"), b"")
        if command.phase == "fsck":
            return GitCommandResult(0, b"", b"")
        if command.phase == "object-inventory":
            return GitCommandResult(0, self.object_inventory, b"")
        raise AssertionError(f"unexpected phase: {command.phase}")


class RetainedGitTests(unittest.TestCase):
    commit_oid = "a" * 40
    tree_oid = "b" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.store = self.base / "immutable-store"
        self.actor_tree = self.base / "actor-working-tree"
        self.inbox = self.base / "admin-inbox"
        self.quarantine = self.base / "verifier-quarantine"
        for path in (self.store, self.actor_tree, self.inbox, self.quarantine):
            path.mkdir()
        self.git_executable = self.base / (
            "trusted-git.exe" if os.name == "nt" else "trusted-git"
        )
        self.git_executable.write_bytes(b"fixed-trusted-git-binary\n")
        if os.name == "posix":
            self.git_executable.chmod(0o700)
        self.binding = TrustedGitBinding(
            policy_id="test-fixed-git-v1",
            executable=self.git_executable.resolve(),
            sha256=_sha256_file(self.git_executable),
            provenance="test-injected-fixed-path-and-sha256",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _retain(
        self,
        *,
        bundle: bytes | None = None,
        commit_oid: str | None = None,
        tree_oid: str | None = None,
    ):
        commit = commit_oid or self.commit_oid
        tree = tree_oid or self.tree_oid
        bundle_bytes = bundle or (
            b"# v2 git bundle\n"
            + f"{commit} refs/heads/main\n\n".encode("ascii")
            + b"PACKfake"
        )
        bundle_path = self.inbox / "source.bundle"
        manifest_path = self.inbox / "verifier.json"
        contract_path = self.inbox / "contract.json"
        bundle_path.write_bytes(bundle_bytes)
        manifest_path.write_bytes(b'{"schema_version":1}\n')
        contract_path.write_bytes(b'{"network":false,"gpu":false}\n')
        return retain_source_artifact(
            immutable_root=self.store.resolve(),
            forbidden_actor_working_tree=self.actor_tree.resolve(),
            repository_id="heosanghun/Cogni-OS_orchestrator",
            workspace_id="portable-contract-test",
            task_id="P01-RETAINED-GIT",
            attempt=1,
            run_id="1" * 32,
            git_bundle_path=bundle_path.resolve(),
            git_bundle_sha256=_sha256_bytes(bundle_bytes),
            git_bundle_size_bytes=len(bundle_bytes),
            commit_oid=commit,
            tree_oid=tree,
            verifier_manifest_path=manifest_path.resolve(),
            verifier_manifest_sha256=_sha256_file(manifest_path),
            validation_contract_path=contract_path.resolve(),
            validation_contract_sha256=_sha256_file(contract_path),
        )

    def _verify(self, artifact, fake: _FakeGit, *, limits=None):
        return _verify_retained_git_artifact(
            immutable_root=self.store.resolve(),
            artifact_id=artifact.artifact_id,
            quarantine_root=self.quarantine.resolve(),
            git_binding=self.binding,
            command_runner=fake,
            limits=limits or RetainedGitLimits(),
        )

    def test_exact_command_plan_and_content_addressed_manifest(self) -> None:
        artifact = self._retain()
        fake = _FakeGit(commit_oid=self.commit_oid, tree_oid=self.tree_oid)

        verified = self._verify(artifact, fake)

        self.assertEqual(
            [command.phase for command in verified.command_plan],
            [
                "init",
                "object-format-before",
                "bundle-verify",
                "bundle-list-heads",
                "bundle-import",
                "object-format-after",
                "forbidden-config",
                "replace-refs",
                "exact-commit",
                "exact-tree",
                "fsck",
                "object-inventory",
            ],
        )
        for command in verified.command_plan:
            self.assertEqual(command.argv[0], str(self.binding.executable))
            self.assertNotIn(str(self.actor_tree.resolve()), " ".join(command.argv))
            self.assertFalse(
                command.environment.get("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            )
        self.assertIn("bundle", fake.commands[2].argv)
        self.assertIn("verify", fake.commands[2].argv)
        self.assertIn("list-heads", fake.commands[3].argv)
        self.assertIn("unbundle", fake.commands[4].argv)
        self.assertIn("fsck", fake.commands[10].argv)

        manifest = verified.manifest
        self.assertEqual(manifest["schema_version"], RETAINED_GIT_SCHEMA_VERSION)
        self.assertEqual(manifest["contract_id"], RETAINED_GIT_CONTRACT_ID)
        self.assertEqual(
            set(manifest),
            {
                "manifest_sha256",
                "schema_version",
                "contract_id",
                "policy_id",
                "retained_source",
                "git",
                "bundle",
                "source",
                "object_graph",
                "verification",
                "limits",
                "assurance",
            },
        )
        self.assertEqual(manifest["manifest_sha256"], verified.manifest_sha256)
        without_id = {
            key: value for key, value in manifest.items() if key != "manifest_sha256"
        }
        canonical_without_id = (
            __import__("json")
            .dumps(
                without_id,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            .encode("utf-8")
            + b"\n"
        )
        self.assertEqual(_sha256_bytes(canonical_without_id), verified.manifest_sha256)
        self.assertEqual(manifest["source"]["commit_oid"], self.commit_oid)
        self.assertEqual(manifest["source"]["tree_oid"], self.tree_oid)
        self.assertEqual(manifest["object_graph"]["object_count"], 3)
        self.assertFalse(manifest["assurance"]["release_ready"])
        self.assertEqual(validate_retained_git_manifest(manifest), manifest)
        widened = deepcopy(manifest)
        widened["unexpected"] = True
        with self.assertRaisesRegex(RetainedGitError, "schema is not exact"):
            validate_retained_git_manifest(widened)
        tampered = deepcopy(manifest)
        tampered["object_graph"]["object_count"] += 1
        with self.assertRaisesRegex(RetainedGitError, "content address does not match"):
            validate_retained_git_manifest(tampered)

        excessive = deepcopy(manifest)
        excessive["object_graph"]["object_count"] = (
            excessive["limits"]["max_object_count"] + 1
        )
        with self.assertRaisesRegex(RetainedGitError, "exceeds its limit"):
            validate_retained_git_manifest(_readdress_manifest(excessive))

        inconsistent = deepcopy(manifest)
        inconsistent["object_graph"]["max_object_bytes"] = 5
        inconsistent["object_graph"]["total_inflated_bytes"] = 4
        with self.assertRaisesRegex(RetainedGitError, "metrics are inconsistent"):
            validate_retained_git_manifest(_readdress_manifest(inconsistent))

        bad_returncode = deepcopy(manifest)
        bad_returncode["verification"]["command_results"]["fsck"]["returncode"] = 2
        with self.assertRaisesRegex(RetainedGitError, "return code"):
            validate_retained_git_manifest(_readdress_manifest(bad_returncode))

        bad_capability = deepcopy(manifest)
        bad_capability["bundle"]["capabilities"] = ["object-format=sha256"]
        with self.assertRaisesRegex(RetainedGitError, "capabilities violate"):
            validate_retained_git_manifest(_readdress_manifest(bad_capability))
        self.assertFalse(any(self.quarantine.iterdir()))

    def test_rejects_prerequisites_extra_heads_and_sha256_repository(self) -> None:
        prerequisite_bundle = (
            b"# v2 git bundle\n"
            + f"-{'9' * 40} prerequisite\n".encode("ascii")
            + f"{self.commit_oid} refs/heads/main\n\n".encode("ascii")
            + b"PACKfake"
        )
        artifact = self._retain(bundle=prerequisite_bundle)
        with self.assertRaisesRegex(RetainedGitError, "prerequisites are forbidden"):
            self._verify(
                artifact, _FakeGit(commit_oid=self.commit_oid, tree_oid=self.tree_oid)
            )

        extra_heads_bundle = (
            b"# v2 git bundle\n"
            + f"{self.commit_oid} refs/heads/main\n".encode("ascii")
            + f"{'c' * 40} refs/heads/extra\n\n".encode("ascii")
            + b"PACKfake"
        )
        artifact = self._retain(bundle=extra_heads_bundle)
        with self.assertRaisesRegex(RetainedGitError, "extra heads"):
            self._verify(
                artifact, _FakeGit(commit_oid=self.commit_oid, tree_oid=self.tree_oid)
            )

        sha256_oid = "d" * 64
        sha256_bundle = (
            b"# v3 git bundle\n@object-format=sha256\n"
            + f"{sha256_oid} refs/heads/main\n\n".encode("ascii")
            + b"PACKfake"
        )
        artifact = self._retain(
            bundle=sha256_bundle, commit_oid=sha256_oid, tree_oid="e" * 64
        )
        with self.assertRaisesRegex(RetainedGitError, "SHA-256"):
            self._verify(artifact, _FakeGit(commit_oid=sha256_oid, tree_oid="e" * 64))

    def test_rejects_header_and_list_heads_mismatch(self) -> None:
        artifact = self._retain()
        fake = _FakeGit(
            commit_oid=self.commit_oid,
            tree_oid=self.tree_oid,
            listed_heads=f"{'c' * 40} refs/heads/main\n".encode("ascii"),
        )
        with self.assertRaisesRegex(RetainedGitError, "does not match retained header"):
            self._verify(artifact, fake)

    def test_rejects_alternates_replace_grafts_shallow_promisor_and_partial_clone(
        self,
    ) -> None:
        artifact = self._retain()
        expectations = {
            "alternates": "Forbidden Git repository feature",
            "grafts": "Forbidden Git repository feature",
            "shallow": "Forbidden Git repository feature",
            "promisor": "Promisor object stores",
            "replace": "replace refs",
            "config": "Partial-clone or promisor",
        }
        for feature, message in expectations.items():
            with self.subTest(feature=feature):
                fake = _FakeGit(
                    commit_oid=self.commit_oid,
                    tree_oid=self.tree_oid,
                    forbidden_feature=feature,
                )
                with self.assertRaisesRegex(RetainedGitError, message):
                    self._verify(artifact, fake)

    def test_rejects_exact_commit_and_tree_mismatch(self) -> None:
        artifact = self._retain()
        with self.assertRaisesRegex(RetainedGitError, "Imported commit"):
            self._verify(
                artifact,
                _FakeGit(
                    commit_oid=self.commit_oid,
                    tree_oid=self.tree_oid,
                    exact_commit="c" * 40,
                ),
            )
        with self.assertRaisesRegex(RetainedGitError, "Imported tree"):
            self._verify(
                artifact,
                _FakeGit(
                    commit_oid=self.commit_oid,
                    tree_oid=self.tree_oid,
                    exact_tree="c" * 40,
                ),
            )

    def test_enforces_object_count_total_single_and_pack_bounds(self) -> None:
        artifact = self._retain()
        three_objects = (
            f"{self.commit_oid} commit 4 4\n"
            f"{self.tree_oid} tree 4 4\n"
            f"{'3' * 40} blob 4 4\n"
        ).encode("ascii")
        base_limits = RetainedGitLimits(
            max_object_count=10,
            max_total_object_bytes=100,
            max_single_object_bytes=100,
            max_total_object_disk_bytes=100,
            max_single_object_disk_bytes=100,
            max_pack_file_count=10,
            max_pack_total_bytes=100,
            max_single_pack_file_bytes=100,
        )
        cases = (
            (
                replace(base_limits, max_object_count=2),
                _FakeGit(
                    commit_oid=self.commit_oid,
                    tree_oid=self.tree_oid,
                    object_inventory=three_objects,
                ),
                "object count",
            ),
            (
                replace(
                    base_limits, max_total_object_bytes=10, max_single_object_bytes=10
                ),
                _FakeGit(
                    commit_oid=self.commit_oid,
                    tree_oid=self.tree_oid,
                    object_inventory=three_objects,
                ),
                "total inflated-byte",
            ),
            (
                replace(base_limits, max_single_object_bytes=3),
                _FakeGit(
                    commit_oid=self.commit_oid,
                    tree_oid=self.tree_oid,
                    object_inventory=three_objects,
                ),
                "single-object",
            ),
            (
                replace(base_limits, max_single_pack_file_bytes=7),
                _FakeGit(commit_oid=self.commit_oid, tree_oid=self.tree_oid),
                "pack file exceeds",
            ),
            (
                replace(
                    base_limits,
                    max_pack_total_bytes=7,
                    max_single_pack_file_bytes=7,
                ),
                _FakeGit(commit_oid=self.commit_oid, tree_oid=self.tree_oid),
                "pre-import pack/disk ceiling",
            ),
        )
        for limits, fake, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(RetainedGitError, message),
            ):
                self._verify(artifact, fake, limits=limits)

    def test_fixed_git_digest_is_checked_before_execution(self) -> None:
        artifact = self._retain()
        bad_binding = replace(self.binding, sha256="f" * 64)
        with self.assertRaisesRegex(RetainedGitError, "digest does not match"):
            verify_retained_git_artifact(
                immutable_root=self.store.resolve(),
                artifact_id=artifact.artifact_id,
                quarantine_root=self.quarantine.resolve(),
                git_binding=bad_binding,
            )

    def test_assurance_keeps_ubuntu_release_blockers(self) -> None:
        assurance = retained_git_api_assurance()
        self.assertEqual(assurance, RETAINED_GIT_API_ASSURANCE)
        self.assertFalse(assurance["actor_working_tree_execution_input"])
        self.assertFalse(assurance["linux_root_owned_quarantine_e2e"])
        self.assertFalse(assurance["git_object_graph_bounded"])
        self.assertTrue(assurance["portable_post_import_object_graph_bounds_enforced"])
        self.assertFalse(assurance["snapshot_broker_handoff_e2e"])
        self.assertFalse(assurance["bwrap_network_gpu_isolation_e2e"])
        self.assertFalse(assurance["release_ready"])
        self.assertIn(
            "linux-root-owned-quarantine-and-retained-store-e2e",
            assurance["remaining_blockers"],
        )
        assurance["remaining_blockers"].append("does-not-mutate-constant")
        self.assertNotEqual(assurance, RETAINED_GIT_API_ASSURANCE)

    def test_public_entrypoint_has_no_runner_or_limit_override(self) -> None:
        parameters = inspect.signature(verify_retained_git_artifact).parameters
        self.assertNotIn("command_runner", parameters)
        self.assertNotIn("limits", parameters)

        artifact = self._retain()
        excessive = replace(
            RetainedGitLimits(),
            max_object_count=RetainedGitLimits().max_object_count + 1,
        )
        with self.assertRaisesRegex(RetainedGitError, "fixed policy ceiling"):
            self._verify(
                artifact,
                _FakeGit(commit_oid=self.commit_oid, tree_oid=self.tree_oid),
                limits=excessive,
            )


class RetainedGitRealPortableIntegrationTests(unittest.TestCase):
    def test_real_self_contained_bundle_round_trip_when_git_is_available(self) -> None:
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source_repo = base / "source-repo"
            store = base / "immutable-store"
            actor = base / "actor-tree-never-used"
            inbox = base / "admin-inbox"
            quarantine = base / "quarantine"
            for path in (source_repo, store, actor, inbox, quarantine):
                path.mkdir()

            def run(*arguments: str) -> str:
                return (
                    subprocess.check_output(
                        [git, *arguments], cwd=source_repo, stderr=subprocess.STDOUT
                    )
                    .decode("utf-8")
                    .strip()
                )

            run("init", "--object-format=sha1")
            run("config", "user.name", "Cogni Test")
            run("config", "user.email", "cogni@example.invalid")
            source_repo.joinpath("proof.txt").write_text(
                "retained proof\n", encoding="utf-8"
            )
            run("add", "proof.txt")
            run("commit", "-m", "portable retained bundle")
            commit = run("rev-parse", "HEAD^{commit}").lower()
            tree = run("rev-parse", "HEAD^{tree}").lower()
            bundle_path = inbox / "source.bundle"
            run("bundle", "create", str(bundle_path), "HEAD")
            manifest_path = inbox / "manifest.json"
            contract_path = inbox / "contract.json"
            manifest_path.write_bytes(b'{"schema_version":1}\n')
            contract_path.write_bytes(b'{"network":false,"gpu":false}\n')
            artifact = retain_source_artifact(
                immutable_root=store.resolve(),
                forbidden_actor_working_tree=actor.resolve(),
                repository_id="portable/real-git",
                workspace_id="portable-real-git",
                task_id="P01-REAL-GIT",
                attempt=1,
                run_id="2" * 32,
                git_bundle_path=bundle_path.resolve(),
                git_bundle_sha256=_sha256_file(bundle_path),
                git_bundle_size_bytes=bundle_path.stat().st_size,
                commit_oid=commit,
                tree_oid=tree,
                verifier_manifest_path=manifest_path.resolve(),
                verifier_manifest_sha256=_sha256_file(manifest_path),
                validation_contract_path=contract_path.resolve(),
                validation_contract_sha256=_sha256_file(contract_path),
            )
            git_path = Path(git).resolve()
            binding = TrustedGitBinding(
                policy_id="portable-real-git-test-v1",
                executable=git_path,
                sha256=_sha256_file(git_path),
                provenance="test-only-path-selected-by-test-harness",
            )

            verified = verify_retained_git_artifact(
                immutable_root=store.resolve(),
                artifact_id=artifact.artifact_id,
                quarantine_root=quarantine.resolve(),
                git_binding=binding,
            )

            self.assertEqual(verified.manifest["source"]["commit_oid"], commit)
            self.assertEqual(verified.manifest["source"]["tree_oid"], tree)
            self.assertGreaterEqual(
                verified.manifest["object_graph"]["object_count"], 3
            )
            self.assertFalse(verified.manifest["assurance"]["release_ready"])
            self.assertFalse(any(quarantine.iterdir()))


if __name__ == "__main__":
    unittest.main()
