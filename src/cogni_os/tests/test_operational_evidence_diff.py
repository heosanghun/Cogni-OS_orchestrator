from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_operational_evidence_diff import (  # noqa: E402
    EvidenceDiffError,
    validate_operational_evidence_diff,
)


class OperationalEvidenceDiffTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _repository(self, root: Path) -> str:
        self._git(root, "init", "-q")
        self._git(root, "config", "user.email", "evidence-test@cogni.invalid")
        self._git(root, "config", "user.name", "Evidence Test")
        for directory in (
            "ledger",
            "tasks",
            "reports",
            "submissions",
            "runs",
            "archive",
        ):
            (root / directory).mkdir()
        (root / "ledger" / "events.jsonl").write_text(
            '{"event_hash":"a","sequence":1,"signature":"local"}\n',
            encoding="utf-8",
        )
        (root / "tasks" / "T-001.json").write_text(
            '{"state":"verified"}\n', encoding="utf-8"
        )
        (root / "reports" / "T-001.md").write_text(
            "original report\n", encoding="utf-8"
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-q", "-m", "base evidence")
        return self._git(root, "rev-parse", "HEAD")

    def test_new_non_executable_evidence_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            (root / "reports" / "T-002.md").write_text(
                "new report\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "append evidence")
            result = validate_operational_evidence_diff(root, base=base)
            self.assertEqual(result["additions"], 1)
            self.assertEqual(result["addition_bytes"], len("new report\n"))
            self.assertEqual(result["transitions"], 1)

    def test_legacy_hmac_ledger_append_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            ledger = root / "ledger" / "events.jsonl"
            with ledger.open("a", encoding="utf-8", newline="") as stream:
                stream.write('{"forged":"event"}\n')
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "append legacy ledger")
            with self.assertRaisesRegex(EvidenceDiffError, "offline trusted verifier"):
                validate_operational_evidence_diff(root, base=base)

    def test_existing_report_modification_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            (root / "reports" / "T-001.md").write_text(
                "rewritten report\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "rewrite evidence")
            with self.assertRaisesRegex(EvidenceDiffError, "immutable"):
                validate_operational_evidence_diff(root, base=base)

    def test_existing_task_deletion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            (root / "tasks" / "T-001.json").unlink()
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "delete evidence")
            with self.assertRaisesRegex(EvidenceDiffError, "immutable"):
                validate_operational_evidence_diff(root, base=base)

    def test_transient_rewrite_then_restore_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            report = root / "reports" / "T-001.md"
            report.write_text("temporary rewrite\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "temporary rewrite")
            report.write_text("original report\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "restore bytes")
            with self.assertRaisesRegex(EvidenceDiffError, "immutable"):
                validate_operational_evidence_diff(root, base=base)

    def test_executable_evidence_blob_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            artifact = root / "reports" / "T-002.md"
            artifact.write_text("new report\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "update-index", "--chmod=+x", "reports/T-002.md")
            self._git(root, "commit", "-q", "-m", "executable evidence")
            with self.assertRaisesRegex(EvidenceDiffError, "non-executable"):
                validate_operational_evidence_diff(root, base=base)

    def test_executable_source_suffix_in_evidence_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            (root / "reports" / "payload.py").write_text(
                "raise SystemExit(0)\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "hidden executable source")
            with self.assertRaisesRegex(EvidenceDiffError, "not allowlisted"):
                validate_operational_evidence_diff(root, base=base)

    def test_pathspec_metacharacter_cannot_hide_symlink_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            (root / "reports" / "ZA.md").write_text(
                "regular decoy\n", encoding="utf-8"
            )
            link_target = root / "link-target.txt"
            link_target.write_text("ZA.md", encoding="utf-8")
            blob = self._git(root, "hash-object", "-w", "link-target.txt")
            self._git(root, "add", "reports/ZA.md")
            self._git(
                root,
                "update-index",
                "--add",
                "--cacheinfo",
                f"120000,{blob},reports/Z[A].md",
            )
            self._git(root, "commit", "-q", "-m", "pathspec symlink attack")
            with self.assertRaisesRegex(EvidenceDiffError, "non-executable"):
                validate_operational_evidence_diff(root, base=base)

    def test_safe_merge_with_addition_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            main_branch = self._git(root, "branch", "--show-current")
            self._git(root, "checkout", "-q", "-b", "safe-side")
            (root / "reports" / "T-002.md").write_text(
                "side evidence\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "safe side evidence")
            self._git(root, "checkout", "-q", main_branch)
            self._git(
                root, "merge", "-q", "--no-ff", "-m", "safe merge", "safe-side"
            )
            result = validate_operational_evidence_diff(root, base=base)
            self.assertGreaterEqual(result["additions"], 1)

    def test_side_branch_delete_restore_before_merge_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            main_branch = self._git(root, "branch", "--show-current")
            self._git(root, "checkout", "-q", "-b", "rewrite-side")
            report = root / "reports" / "T-001.md"
            report.unlink()
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "delete evidence")
            report.write_text("original report\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "restore evidence")
            self._git(root, "checkout", "-q", main_branch)
            self._git(
                root,
                "merge",
                "-q",
                "--no-ff",
                "-m",
                "merge restored side",
                "rewrite-side",
            )
            with self.assertRaisesRegex(EvidenceDiffError, "immutable"):
                validate_operational_evidence_diff(root, base=base)

    def test_merge_resolution_rewrite_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            main_branch = self._git(root, "branch", "--show-current")
            self._git(root, "checkout", "-q", "-b", "merge-side")
            (root / "reports" / "T-002.md").write_text(
                "side evidence\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "side evidence")
            self._git(root, "checkout", "-q", main_branch)
            (root / "reports" / "T-003.md").write_text(
                "main evidence\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "main evidence")
            self._git(root, "merge", "-q", "--no-ff", "--no-commit", "merge-side")
            (root / "reports" / "T-001.md").write_text(
                "merge rewrite\n", encoding="utf-8"
            )
            self._git(root, "add", ".")
            self._git(root, "commit", "-q", "-m", "unsafe merge resolution")
            with self.assertRaisesRegex(EvidenceDiffError, "immutable"):
                validate_operational_evidence_diff(root, base=base)

    def test_non_ancestor_base_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._repository(root)
            self._git(root, "checkout", "-q", "--orphan", "unrelated")
            (root / "reports").mkdir(exist_ok=True)
            (root / "reports" / "unrelated.md").write_text(
                "unrelated history\n", encoding="utf-8"
            )
            self._git(root, "add", "reports/unrelated.md")
            self._git(root, "commit", "-q", "-m", "unrelated root")
            with self.assertRaises(EvidenceDiffError):
                validate_operational_evidence_diff(root, base=base)


if __name__ == "__main__":
    unittest.main()
