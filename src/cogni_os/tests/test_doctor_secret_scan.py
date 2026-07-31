from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cogni_os.doctor import _scan_secrets


class DoctorSecretScanTests(unittest.TestCase):
    def test_prose_with_secret_and_pass_words_is_not_a_credential(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "task.json"
            path.write_text(
                "Connected deployment and secret provisioning are conductor-only. "
                "Customer replay drills all pass before release.\n",
                encoding="utf-8",
            )

            self.assertEqual(_scan_secrets(path), [])

    def test_explicit_assignments_and_tables_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "settings.txt"
            path.write_text(
                '"secret": "sensitive-value-123"\n'
                "TOKEN=another-sensitive-value\n"
                "| api_key | third-sensitive-value |\n",
                encoding="utf-8",
            )

            findings = _scan_secrets(path)

            self.assertEqual([item["key"] for item in findings], [
                "secret",
                "token",
                "api_key",
            ])
            self.assertTrue(all(item["value"] == "[REDACTED]" for item in findings))


if __name__ == "__main__":
    unittest.main()
