"""Encrypted local session state with transactional, revision-checked writes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from ..client import CrystalClient


class SessionJournal:
    """One local session per database in a caller-owned private directory.

    SQLite owns transaction recovery; the client encrypts the state before it
    reaches SQLite. An older database remains replayable unless the caller
    retains a separate current commitment. This is not a remote-history check.
    """

    def __init__(self, path: str | os.PathLike[str], client: CrystalClient, session_id: str):
        self.path = Path(path).absolute()
        self.client = client
        self.context = {
            "schema": "wm.crystal-session/1",
            "session_id": session_id,
            "tenant_id": client.tenant_id,
            "tenant_hash": client.tenant_hash,
            "api_url": client.api_url,
        }
        parent = self.path.parent
        if parent.resolve() != parent:
            raise ValueError("session state directory must not use symlinks")
        self._check_private(parent, directory=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._check_private(self.path, directory=False)
        db = self._connect()
        try:
            db.execute("CREATE TABLE IF NOT EXISTS session_state "
                       "(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, envelope TEXT NOT NULL)")
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _check_private(path: Path, *, directory: bool) -> None:
        info = path.lstat()
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(info.st_mode):
            raise ValueError("session state requires a regular file in a private directory")
        if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("session state file and directory must be owned by you and private (0700/0600)")

    def _connect(self) -> sqlite3.Connection:
        # No connection is held over a network request. CAS below prevents a
        # second manager from overwriting state loaded by an earlier manager.
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def load(self) -> tuple[int, dict[str, Any] | None]:
        db = self._connect()
        try:
            row = db.execute("SELECT revision, envelope FROM session_state WHERE id=1").fetchone()
        finally:
            db.close()
        if row is None:
            return 0, None
        envelope = json.loads(row[1])
        state = json.loads(self.client.unseal(envelope))
        if not isinstance(state, dict) or state.get("context") != self.context:
            raise ValueError("session state belongs to a different session or client context")
        return row[0], state

    def save(self, state: dict[str, Any], *, revision: int) -> int:
        envelope = self.client.seal({"context": self.context, **state})
        encoded = json.dumps(envelope, separators=(",", ":"), allow_nan=False)
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT revision FROM session_state WHERE id=1").fetchone()
            current = row[0] if row else 0
            if current != revision:
                raise RuntimeError("session state changed in another manager; reopen before continuing")
            next_revision = revision + 1
            db.execute("INSERT OR REPLACE INTO session_state VALUES (1, ?, ?)", (next_revision, encoded))
            db.commit()
            return next_revision
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
