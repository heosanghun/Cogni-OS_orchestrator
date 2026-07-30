"""Portable lock files for short workspace transactions."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .errors import LockTimeout
from .util import utc_now


class FileLock:
    """Acquire a lock with atomic create and recover abandoned lock files."""

    def __init__(
        self,
        path: Path,
        *,
        timeout_seconds: float = 10.0,
        stale_seconds: float = 120.0,
        poll_seconds: float = 0.05,
    ) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.stale_seconds = stale_seconds
        self.poll_seconds = poll_seconds
        self._held = False

    def acquire(self) -> None:
        """Acquire the lock or raise after the configured timeout."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout_seconds
        payload = json.dumps({"pid": os.getpid(), "created_at": utc_now()}).encode("utf-8")
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                self._remove_if_stale()
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"Timed out waiting for lock {self.path}")
                time.sleep(self.poll_seconds)
                continue
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._held = True
            return

    def _remove_if_stale(self) -> None:
        try:
            age = time.time() - self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if age <= self.stale_seconds:
            return
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def release(self) -> None:
        """Release a lock held by this instance."""
        if not self._held:
            return
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self._held = False

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()
