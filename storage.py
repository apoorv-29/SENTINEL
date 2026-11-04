"""Small Phase 1 persistence layer.

SQLite is an interim local persistence boundary for Phase 1. Phase 2 will
replace this module with PostgreSQL/SQLAlchemy/Alembic without changing the
service-level authorization contracts.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


ACCESS_TTL = timedelta(minutes=15)
REFRESH_TTL = timedelta(days=7)


def _db_path() -> str:
    return os.getenv("SENTINEL_DB_PATH", "/tmp/sentinel.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    path = _db_path()
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS memberships (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, organization_id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                token_type TEXT NOT NULL CHECK (token_type IN ('access', 'refresh')),
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL REFERENCES users(id),
                organization_id TEXT NOT NULL REFERENCES organizations(id),
                target TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
                request_json TEXT NOT NULL,
                results_json TEXT,
                error_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                read_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_memberships_org ON memberships(organization_id);
            CREATE INDEX IF NOT EXISTS idx_scans_org_created ON scans(organization_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_owner_created ON scans(owner_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, token_type);
            CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id, created_at);
            """
        )


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = encoded.split("$", 2)
        if algorithm != "scrypt":
            return False
        candidate = _hash_password(password, bytes.fromhex(salt_hex)).split("$", 2)[2]
        return hmac.compare_digest(candidate, digest_hex)
    except (ValueError, TypeError):
        return False


def _new_token() -> str:
    return secrets.token_urlsafe(48)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _issue_token(conn: sqlite3.Connection, user_id: str, token_type: str, ttl: timedelta) -> str:
    token = _new_token()
    conn.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, NULL, ?)",
        (str(uuid4()), user_id, _token_hash(token), token_type, (datetime.now(timezone.utc) + ttl).isoformat(), _now()),
    )
    return token


def _public_user(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "email": row["email"], "organization_id": row["organization_id"], "role": row["role"]}


def register_user(email: str, password: str, organization_name: str) -> tuple[dict[str, Any], str, str]:
    user_id, organization_id, now = str(uuid4()), str(uuid4()), _now()
    with _connect() as conn:
        try:
            conn.execute("INSERT INTO organizations VALUES (?, ?, ?)", (organization_id, organization_name, now))
            conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, 0)", (user_id, email, _hash_password(password), now))
            conn.execute("INSERT INTO memberships VALUES (?, ?, 'owner', ?)", (user_id, organization_id, now))
            access, refresh = _issue_token(conn, user_id, "access", ACCESS_TTL), _issue_token(conn, user_id, "refresh", REFRESH_TTL)
        except sqlite3.IntegrityError as exc:
            raise ValueError("email already registered") from exc
    return {"id": user_id, "email": email, "organization_id": organization_id, "role": "owner"}, access, refresh


def authenticate(email: str, password: str) -> tuple[dict[str, Any], str, str] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT u.*, m.organization_id, m.role FROM users u JOIN memberships m ON m.user_id=u.id WHERE u.email=? AND u.disabled=0",
            (email,),
        ).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return None
        access, refresh = _issue_token(conn, row["id"], "access", ACCESS_TTL), _issue_token(conn, row["id"], "refresh", REFRESH_TTL)
        return _public_user(row), access, refresh


def user_from_token(token: str, token_type: str = "access") -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT u.*, m.organization_id, m.role FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON m.user_id=u.id WHERE s.token_hash=? AND s.token_type=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.disabled=0",
            (_token_hash(token), token_type, _now()),
        ).fetchone()
        return _public_user(row) if row else None


def rotate_refresh_token(token: str) -> tuple[dict[str, Any], str, str] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT s.*, u.*, m.organization_id, m.role FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON m.user_id=u.id WHERE s.token_hash=? AND s.token_type='refresh' AND s.revoked_at IS NULL AND s.expires_at>? AND u.disabled=0",
            (_token_hash(token), _now()),
        ).fetchone()
        if not row:
            return None
        conn.execute("UPDATE sessions SET revoked_at=? WHERE id=?", (_now(), row["id"]))
        access, refresh = _issue_token(conn, row["user_id"], "access", ACCESS_TTL), _issue_token(conn, row["user_id"], "refresh", REFRESH_TTL)
        return _public_user(row), access, refresh


def revoke_token(token: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (_now(), _token_hash(token)))


def create_scan(scan_id: str, owner_id: str, organization_id: str, target: str, request_json: str) -> None:
    now = _now()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, 'queued', ?, NULL, NULL, ?, ?)",
            (scan_id, owner_id, organization_id, target, request_json, now, now),
        )


def get_scan(scan_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id=? AND owner_id=? AND organization_id=?",
            (scan_id, user["id"], user["organization_id"]),
        ).fetchone()
        return dict(row) if row else None


def list_scans(user: dict[str, Any]) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE organization_id=? ORDER BY created_at DESC",
            (user["organization_id"],),
        ).fetchall()
        return [dict(row) for row in rows]


def update_scan(scan_id: str, **fields: Any) -> None:
    if not fields:
        return
    fields["updated_at"] = _now()
    assignments = ", ".join(f"{key}=?" for key in fields)
    with _connect() as conn:
        conn.execute(f"UPDATE scans SET {assignments} WHERE id=?", (*fields.values(), scan_id))


def find_users(query: str, current_user_id: str) -> list[dict[str, Any]]:
    pattern = f"%{query.strip().lower()}%"
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, email FROM users WHERE disabled=0 AND id<>? AND lower(email) LIKE ? ORDER BY email LIMIT 25",
            (current_user_id, pattern),
        ).fetchall()
        return [{"id": row["id"], "email": row["email"]} for row in rows]


def user_exists(user_id: str) -> bool:
    with _connect() as conn:
        return conn.execute("SELECT 1 FROM users WHERE id=? AND disabled=0", (user_id,)).fetchone() is not None


def create_message(sender_id: str, recipient_id: str, body: str) -> dict[str, Any]:
    message = {"id": str(uuid4()), "sender_id": sender_id, "recipient_id": recipient_id, "body": body, "created_at": _now()}
    with _connect() as conn:
        conn.execute(
            "INSERT INTO messages (id, sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
            (message["id"], sender_id, recipient_id, body, message["created_at"]),
        )
    return message


def list_messages(user_id: str, other_user_id: str, limit: int = 100) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, sender_id, recipient_id, body, created_at FROM messages WHERE ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) ORDER BY created_at DESC LIMIT ?",
            (user_id, other_user_id, other_user_id, user_id, limit),
        ).fetchall()
        return [dict(row) for row in reversed(rows)]


def search_scan_rows(user: dict[str, Any], query: str = "", severity: str = "", category: str = "", status: str = "") -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM scans WHERE organization_id=? ORDER BY created_at DESC", (user["organization_id"],)).fetchall()
    query = query.strip().lower()
    output: list[dict[str, Any]] = []
    import json
    for row in rows:
        if status and row["status"] != status:
            continue
        results = json.loads(row["results_json"]) if row["results_json"] else {"findings": []}
        findings = [f for f in results.get("findings", []) if (not severity or f.get("severity") == severity) and (not category or f.get("category") == category)]
        haystack = (row["target"] + " " + json.dumps(findings)).lower()
        if query and query not in haystack:
            continue
        output.append({"scan_id": row["id"], "target": row["target"], "status": row["status"], "findings": findings, "created_at": row["created_at"]})
    return output
