"""Hash-chained, HMAC-signed append-only event ledger for Cogni-OS."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from .errors import IntegrityError
from .lock import FileLock
from .util import canonical_json, utc_now

GENESIS_HASH = "0" * 64


class Ledger:
    """Append and validate immutable workspace events."""

    def __init__(self, path: Path, lock_path: Path, key_path: Path) -> None:
        self.path = path
        self.lock_path = lock_path
        self.key_path = key_path

    def initialize(self) -> None:
        """Create an empty ledger and a private local signing key."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        if not self.key_path.exists():
            self.key_path.write_bytes(os.urandom(32))
            try:
                self.key_path.chmod(0o600)
            except OSError:
                pass

    def _key(self) -> bytes:
        try:
            return self.key_path.read_bytes()
        except FileNotFoundError as exc:
            raise IntegrityError(f"Ledger signing key is missing: {self.key_path}") from exc

    def read(self) -> list[dict[str, Any]]:
        """Read all events, failing on malformed lines."""
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line_number, line in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IntegrityError(
                    f"Malformed ledger JSON at line {line_number}: {exc}"
                ) from exc
            if not isinstance(event, dict):
                raise IntegrityError(f"Ledger line {line_number} is not an object")
            events.append(event)
        return events

    def append(
        self,
        *,
        actor: str,
        action: str,
        task_id: str | None,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Append one signed event while holding the ledger lock."""
        with FileLock(self.lock_path):
            events = self.read()
            self._verify_events(events)
            previous_hash = events[-1]["event_hash"] if events else GENESIS_HASH
            core = {
                "sequence": len(events) + 1,
                "timestamp": utc_now(),
                "actor": actor,
                "action": action,
                "task_id": task_id,
                "payload": payload,
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(canonical_json(core)).hexdigest()
            signature = hmac.new(
                self._key(), event_hash.encode("ascii"), hashlib.sha256
            ).hexdigest()
            event = {**core, "event_hash": event_hash, "signature": signature}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            return event

    def _verify_events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        previous_hash = GENESIS_HASH
        key = self._key()
        for expected_sequence, event in enumerate(events, start=1):
            if event.get("sequence") != expected_sequence:
                raise IntegrityError(
                    f"Ledger sequence mismatch at event {expected_sequence}"
                )
            if event.get("previous_hash") != previous_hash:
                raise IntegrityError(
                    f"Ledger chain mismatch at event {expected_sequence}"
                )
            core = {
                key_name: event.get(key_name)
                for key_name in (
                    "sequence",
                    "timestamp",
                    "actor",
                    "action",
                    "task_id",
                    "payload",
                    "previous_hash",
                )
            }
            calculated_hash = hashlib.sha256(canonical_json(core)).hexdigest()
            if not hmac.compare_digest(calculated_hash, str(event.get("event_hash", ""))):
                raise IntegrityError(
                    f"Ledger event hash mismatch at event {expected_sequence}"
                )
            calculated_signature = hmac.new(
                key, calculated_hash.encode("ascii"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(
                calculated_signature, str(event.get("signature", ""))
            ):
                raise IntegrityError(
                    f"Ledger signature mismatch at event {expected_sequence}"
                )
            previous_hash = calculated_hash
        return {
            "valid": True,
            "events": len(events),
            "head": previous_hash,
            "signed": True,
        }

    def verify(self) -> dict[str, Any]:
        """Verify sequence, hash links, event hashes, and HMAC signatures."""
        return self._verify_events(self.read())

    def read_verified(self) -> list[dict[str, Any]]:
        """Return one in-memory ledger snapshot after signature verification.

        Consumers that project security-sensitive state must not call
        :meth:`verify` and :meth:`read` separately: the ledger could change
        between those two reads.  This method validates and returns the exact
        event objects from one read instead.
        """

        events = self.read()
        self._verify_events(events)
        return events

    def projected_tasks(self) -> dict[str, dict[str, Any]]:
        """Reconstruct the latest task snapshots from the event stream."""
        tasks: dict[str, dict[str, Any]] = {}
        for event in self.read():
            snapshot = event.get("payload", {}).get("task")
            task_id = event.get("task_id")
            if task_id and isinstance(snapshot, dict):
                tasks[task_id] = snapshot
        return tasks
