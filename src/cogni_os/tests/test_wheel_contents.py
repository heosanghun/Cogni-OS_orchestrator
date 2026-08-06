"""Regression tests for the production wheel boundary."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from setuptools import build_meta


class TestWheelContents(unittest.TestCase):
    def test_wheel_excludes_tests_and_release_evidence_unsafe_seams(self) -> None:
        repository = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            project = temporary_root / "project"
            wheelhouse = temporary_root / "wheelhouse"
            project.mkdir()
            wheelhouse.mkdir()
            shutil.copy2(repository / "pyproject.toml", project / "pyproject.toml")
            shutil.copy2(repository / "README.md", project / "README.md")
            shutil.copytree(repository / "src", project / "src")

            previous = Path.cwd()
            try:
                os.chdir(project)
                wheel_name = build_meta.build_wheel(str(wheelhouse))
            finally:
                os.chdir(previous)

            wheel_path = wheelhouse / wheel_name
            self.assertTrue(wheel_path.is_file())
            with zipfile.ZipFile(wheel_path) as wheel:
                names = set(wheel.namelist())
                self.assertIn("cogni_os/release_evidence.py", names)
                self.assertFalse(
                    any(
                        name.startswith("cogni_os/tests/")
                        or name.endswith("_test_support.py")
                        for name in names
                    ),
                    sorted(names),
                )
                release_source = wheel.read("cogni_os/release_evidence.py")
                for forbidden in (
                    b"allow_unsafe_test_archive",
                    b"cloudflare_fetcher",
                    b"fetcher: Callable",
                    b"_collect_p01_production_evidence_test_only",
                ):
                    self.assertNotIn(forbidden, release_source)


if __name__ == "__main__":
    unittest.main()
