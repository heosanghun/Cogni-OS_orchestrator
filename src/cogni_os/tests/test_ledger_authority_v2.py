from __future__ import annotations

import base64
import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cogni_os.ledger_authority_v2 import (
    LEDGER_V2_DOMAIN,
    LEDGER_V2_GENESIS_HASH,
    LEDGER_V2_PROTOCOL_ID,
    MIGRATION_ACTION,
    SIGNATURE_PREIMAGE_KEYS,
    LedgerAuthorityV2Error,
    _openssl_ed25519,
    _public_key_spki_sha256,
    _signature_payload,
    build_v1_migration_anchor_payload,
    canonical_json_bytes,
    canonical_json_sha256,
    decode_canonical_v2_envelope,
    ledger_authority_v2_assurance,
    sign_v2_event,
    trusted_ledger_signing_binding,
    trusted_ledger_verification_binding,
    verify_signed_dispatch,
    verify_v1_migration_anchor,
    verify_v2_chain,
    verify_v2_event,
)
from cogni_os.util import sha256_file
from cogni_os.verifier_protocol import (
    VERIFIER_PROTOCOL_ID,
    VERIFIER_SCHEMA_VERSION,
)

NOW = 1_800_000_000


def _openssl_path() -> Path:
    discovered = shutil.which("openssl")
    candidates = (
        Path(discovered) if discovered else None,
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
    )
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise AssertionError("OpenSSL is required for Ledger Authority v2 tests")


def _pem_bytes(label: str, der: bytes, *, newline: bytes = b"\n") -> bytes:
    encoded = base64.b64encode(der)
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (
        f"-----BEGIN {label}-----".encode("ascii")
        + newline
        + newline.join(lines)
        + newline
        + f"-----END {label}-----".encode("ascii")
        + newline
    )


def _event(
    *,
    sequence: int = 1,
    ledger_id: str = "workspace-p01",
    previous_hash: str = LEDGER_V2_GENESIS_HASH,
    action: str = "task.created",
    task_id: str | None = "P01-TRUTH",
    actor: str = "codex",
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "ledger_id": ledger_id,
        "timestamp": "2027-01-15T08:00:00Z",
        "actor": actor,
        "action": action,
        "task_id": task_id,
        "payload": {"state": "requested"} if payload is None else payload,
        "previous_hash": previous_hash,
    }


def _dispatch_payload() -> dict[str, object]:
    return {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "protocol_id": VERIFIER_PROTOCOL_ID,
        "kind": "verification-dispatch",
        "ledger_domain": LEDGER_V2_DOMAIN,
        "ledger_head_hash": LEDGER_V2_GENESIS_HASH,
        "workspace_id": "workspace-p01",
        "task_id": "P01-TRUTH",
        "attempt": 1,
        "actor": "codex",
        "run_id": "1" * 32,
        "source": {
            "artifact_id": "retained-source-p01",
            "bundle_sha256": "2" * 64,
            "size_bytes": 4096,
            "commit_oid": "3" * 40,
            "tree_oid": "4" * 40,
        },
        "verifier_manifest_sha256": "5" * 64,
        "validation_contract_sha256": "6" * 64,
        "capability_receipt_sha256": "7" * 64,
        "network_allowed": False,
        "gpu_allowed": False,
        "nonce": "dispatch-nonce-p01",
        "issued_at": NOW - 10,
        "expires_at": NOW + 300,
    }


class LedgerAuthorityV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root = Path(self.temporary.name)
        self.openssl = _openssl_path()
        self.private_keys: dict[str, Path] = {}
        self.public_keys: dict[str, Path] = {}
        for name in ("ledger", "broker", "verifier"):
            private = self.root / f"{name}-private.pem"
            public = self.root / f"{name}-public.pem"
            subprocess.run(
                [
                    str(self.openssl),
                    "genpkey",
                    "-algorithm",
                    "ED25519",
                    "-out",
                    str(private),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    str(self.openssl),
                    "pkey",
                    "-in",
                    str(private),
                    "-pubout",
                    "-out",
                    str(public),
                ],
                check=True,
                capture_output=True,
            )
            self.private_keys[name] = private
            self.public_keys[name] = public
        self.signing_binding = {
            "private_key_path": str(self.private_keys["ledger"]),
            "public_key_path": str(self.public_keys["ledger"]),
            "key_id": _public_key_spki_sha256(
                public_key_path=self.public_keys["ledger"],
                openssl_path=self.openssl,
            ),
            "openssl_path": str(self.openssl),
            "openssl_sha256": sha256_file(self.openssl),
        }
        self.verification_binding = {
            key: value
            for key, value in self.signing_binding.items()
            if key != "private_key_path"
        }
        self.patchers = (
            patch(
                "cogni_os.ledger_authority_v2.trusted_ledger_signing_binding",
                return_value=self.signing_binding,
            ),
            patch(
                "cogni_os.ledger_authority_v2.trusted_ledger_verification_binding",
                return_value=self.verification_binding,
            ),
        )
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def test_rfc8032_known_answer(self) -> None:
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f"
            "5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        public = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc"
            "9c982ccf2ec4968cc0cd55f12af4660c"
        )
        expected = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00"
        )
        private_path = self.root / "rfc8032-private.pem"
        public_path = self.root / "rfc8032-public.pem"
        private_path.write_bytes(
            _pem_bytes(
                "PRIVATE KEY",
                bytes.fromhex("302e020100300506032b657004220420") + seed,
            )
        )
        public_path.write_bytes(
            _pem_bytes(
                "PUBLIC KEY",
                bytes.fromhex("302a300506032b6570032100") + public,
            )
        )
        observed = _openssl_ed25519(
            b"\x72",
            openssl_path=self.openssl,
            key_path=private_path,
            signature=None,
        )
        self.assertEqual(observed, expected)
        self.assertIs(
            _openssl_ed25519(
                b"\x72",
                openssl_path=self.openssl,
                key_path=public_path,
                signature=expected,
            ),
            True,
        )

    def test_exact_event_roundtrip_tamper_and_unknown_fields(self) -> None:
        envelope = sign_v2_event(_event())
        verified = verify_v2_event(envelope)
        self.assertEqual(verified["domain"], "cogni-os.ledger-event.v2")
        self.assertEqual(verified["protocol_id"], LEDGER_V2_PROTOCOL_ID)
        self.assertNotIn("public_key_sha256", verified)
        signature_preimage = _signature_payload(
            verified["event"], verified["event_hash"], verified["key_id"]
        )
        self.assertEqual(set(signature_preimage), SIGNATURE_PREIMAGE_KEYS)
        self.assertEqual(signature_preimage["ledger_id"], "workspace-p01")
        self.assertEqual(signature_preimage["key_id"], verified["key_id"])
        encoded = canonical_json_bytes(envelope)
        self.assertEqual(decode_canonical_v2_envelope(encoded), envelope)
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "not canonical"):
            decode_canonical_v2_envelope(
                json.dumps(envelope, indent=2, ensure_ascii=False).encode("utf-8")
            )

        unknown_envelope = copy.deepcopy(envelope)
        unknown_envelope["legacy_signature"] = "not-authority"
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "schema is not exact"):
            verify_v2_event(unknown_envelope)
        unknown_event = copy.deepcopy(envelope)
        unknown_event["event"]["authority"] = True
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "schema is not exact"):
            verify_v2_event(unknown_event)

        tampered = copy.deepcopy(envelope)
        tampered["event"]["payload"]["state"] = "verified"
        tampered["event_hash"] = canonical_json_sha256(tampered["event"])
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "signature is invalid"):
            verify_v2_event(tampered)

    def test_signed_dispatch_binds_event_hash_position_and_exact_payload(self) -> None:
        payload = _dispatch_payload()
        envelope = sign_v2_event(
            _event(
                action="verification.requested",
                payload=payload,
            )
        )
        dispatch = verify_signed_dispatch(
            [envelope],
            dispatch_event_hash=envelope["event_hash"],
            now=NOW,
        )
        self.assertEqual(dispatch["dispatch_event_hash"], envelope["event_hash"])
        self.assertEqual(dispatch["ledger_head_hash"], LEDGER_V2_GENESIS_HASH)

        with self.assertRaisesRegex(LedgerAuthorityV2Error, "full-chain head"):
            verify_signed_dispatch(
                [envelope],
                dispatch_event_hash="8" * 64,
                now=NOW,
            )
        unknown_payload = copy.deepcopy(envelope)
        unknown_payload["event"]["payload"]["legacy_hmac"] = "9" * 64
        unknown_payload["event_hash"] = canonical_json_sha256(unknown_payload["event"])
        unknown_payload = sign_v2_event(unknown_payload["event"])
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "schema is not exact"):
            verify_signed_dispatch(
                [unknown_payload],
                dispatch_event_hash=unknown_payload["event_hash"],
                now=NOW,
            )

        stale_dispatch = envelope
        later = sign_v2_event(
            _event(
                sequence=2,
                previous_hash=stale_dispatch["event_hash"],
                action="verification.superseded",
            )
        )
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "full-chain head"):
            verify_signed_dispatch(
                [stale_dispatch, later],
                dispatch_event_hash=stale_dispatch["event_hash"],
                now=NOW,
            )

        standalone_nonmember = sign_v2_event(
            _event(
                sequence=2,
                previous_hash="8" * 64,
                action="verification.requested",
                payload=_dispatch_payload(),
            )
        )
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "chain sequence"):
            verify_signed_dispatch(
                [standalone_nonmember],
                dispatch_event_hash=standalone_nonmember["event_hash"],
                now=NOW,
            )

        other_ledger = sign_v2_event(
            _event(
                ledger_id="other-workspace",
                action="verification.requested",
                payload=_dispatch_payload(),
            )
        )
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "event binding"):
            verify_signed_dispatch(
                [other_ledger],
                dispatch_event_hash=other_ledger["event_hash"],
                now=NOW,
            )

    def test_hmac_v1_never_mixes_and_migration_is_audit_only(self) -> None:
        legacy_core = _event()
        legacy_core.pop("ledger_id")
        legacy_event = {
            **legacy_core,
            "event_hash": "a" * 64,
            "signature": "b" * 64,
        }
        normal_v2 = sign_v2_event(_event())
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "must not be mixed"):
            verify_v2_chain([normal_v2, legacy_event])

        migration_payload = build_v1_migration_anchor_payload(
            legacy_head_hash="a" * 64,
            legacy_event_count=17,
            legacy_snapshot_sha256="c" * 64,
            legacy_snapshot_size_bytes=4096,
        )
        migration = sign_v2_event(
            _event(
                action=MIGRATION_ACTION,
                task_id=None,
                actor="ledger-authority",
                payload=migration_payload,
            )
        )
        self.assertFalse(verify_v1_migration_anchor(migration)["legacy_authoritative"])
        result = verify_v2_chain([migration])
        self.assertTrue(result["migrated_from_v1_audit_only"])
        self.assertFalse(result["release_ready"])

        cross_ledger = sign_v2_event(
            _event(
                sequence=2,
                ledger_id="other-ledger",
                previous_hash=migration["event_hash"],
            )
        )
        with self.assertRaisesRegex(LedgerAuthorityV2Error, "ledger_id changed"):
            verify_v2_chain([migration, cross_ledger])
        zero_size = build_v1_migration_anchor_payload(
            legacy_head_hash="a" * 64,
            legacy_event_count=0,
            legacy_snapshot_sha256="c" * 64,
            legacy_snapshot_size_bytes=0,
        )
        self.assertEqual(zero_size["legacy_snapshot_size_bytes"], 0)
        with self.assertRaisesRegex(
            LedgerAuthorityV2Error, "legacy_snapshot_size_bytes"
        ):
            build_v1_migration_anchor_payload(
                legacy_head_hash="a" * 64,
                legacy_event_count=0,
                legacy_snapshot_sha256="c" * 64,
                legacy_snapshot_size_bytes=(512 * 1024 * 1024) + 1,
            )

    def test_spki_key_reuse_fails_for_signing_and_verification_bindings(self) -> None:
        ledger_der = subprocess.run(
            [
                str(self.openssl),
                "pkey",
                "-pubin",
                "-in",
                str(self.public_keys["ledger"]),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        broker_same_spki = self.root / "broker-same-spki-different-pem.pem"
        broker_same_spki.write_bytes(
            _pem_bytes("PUBLIC KEY", ledger_der, newline=b"\r\n") + b"\r\n"
        )
        self.assertNotEqual(
            sha256_file(self.public_keys["ledger"]), sha256_file(broker_same_spki)
        )
        openssl_binding = {
            "path": str(self.openssl),
            "sha256": sha256_file(self.openssl),
        }
        with (
            patch(
                "cogni_os.ledger_authority_v2._require_root_owned_file",
                side_effect=lambda path, **_kwargs: Path(path),
            ),
            patch(
                "cogni_os.ledger_authority_v2._trusted_openssl_binding",
                return_value=openssl_binding,
            ),
        ):
            with self.assertRaisesRegex(
                LedgerAuthorityV2Error, "distinct Ed25519 SPKI keys"
            ):
                trusted_ledger_signing_binding(
                    private_key_path=self.private_keys["ledger"],
                    public_key_path=self.public_keys["ledger"],
                    broker_public_key_path=broker_same_spki,
                    verifier_public_key_path=self.public_keys["verifier"],
                    openssl_path=self.openssl,
                    openssl_sha256_path=self.root / "unused.sha256",
                )
            with self.assertRaisesRegex(
                LedgerAuthorityV2Error, "distinct Ed25519 SPKI keys"
            ):
                trusted_ledger_verification_binding(
                    public_key_path=self.public_keys["ledger"],
                    broker_public_key_path=broker_same_spki,
                    verifier_public_key_path=self.public_keys["verifier"],
                    openssl_path=self.openssl,
                    openssl_sha256_path=self.root / "unused.sha256",
                )

            broker_der = subprocess.run(
                [
                    str(self.openssl),
                    "pkey",
                    "-pubin",
                    "-in",
                    str(self.public_keys["broker"]),
                    "-outform",
                    "DER",
                ],
                check=True,
                capture_output=True,
            ).stdout
            verifier_same_spki = self.root / "verifier-same-as-broker.pem"
            verifier_same_spki.write_bytes(
                _pem_bytes("PUBLIC KEY", broker_der) + b"\n"
            )
            with self.assertRaisesRegex(
                LedgerAuthorityV2Error, "distinct Ed25519 SPKI keys"
            ):
                trusted_ledger_verification_binding(
                    public_key_path=self.public_keys["ledger"],
                    broker_public_key_path=self.public_keys["broker"],
                    verifier_public_key_path=verifier_same_spki,
                    openssl_path=self.openssl,
                    openssl_sha256_path=self.root / "unused.sha256",
                )

    def test_same_spki_pem_rewrap_keeps_key_id_and_existing_signature_valid(self) -> None:
        envelope = sign_v2_event(_event())
        original_bytes_sha = sha256_file(self.public_keys["ledger"])
        original_key_id = self.signing_binding["key_id"]
        ledger_der = subprocess.run(
            [
                str(self.openssl),
                "pkey",
                "-pubin",
                "-in",
                str(self.public_keys["ledger"]),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        self.public_keys["ledger"].write_bytes(
            _pem_bytes("PUBLIC KEY", ledger_der, newline=b"\r\n") + b"\r\n"
        )
        self.assertNotEqual(original_bytes_sha, sha256_file(self.public_keys["ledger"]))
        rewrapped_key_id = _public_key_spki_sha256(
            public_key_path=self.public_keys["ledger"],
            openssl_path=self.openssl,
        )
        self.assertEqual(rewrapped_key_id, original_key_id)
        rewrapped_binding = {
            **self.verification_binding,
            "key_id": rewrapped_key_id,
        }
        with patch(
            "cogni_os.ledger_authority_v2.trusted_ledger_verification_binding",
            return_value=rewrapped_binding,
        ):
            verified = verify_v2_event(envelope)
        self.assertEqual(verified["event_hash"], envelope["event_hash"])
        self.assertEqual(verified["signature_b64"], envelope["signature_b64"])

    def test_assurance_never_upgrades_legacy_ledger_or_release(self) -> None:
        assurance = ledger_authority_v2_assurance()
        self.assertFalse(assurance["release_ready"])
        self.assertEqual(
            assurance["legacy_ledger"], "hmac-sha256-v1-separate-unmodified"
        )
        self.assertIn(
            "workspace_projection_release_gate_not_v2_integrated",
            assurance["release_blockers"],
        )
        for blocker in (
            "ledger_authority_key_rotation_registry_not_implemented",
            "durable_bounded_v2_log_checkpoint_not_implemented",
            "current_task_terminal_supersession_projection_not_integrated",
            "legacy_bounded_byte_validation_not_implemented",
        ):
            self.assertIn(blocker, assurance["release_blockers"])


if __name__ == "__main__":
    unittest.main()
