"""Authentication, session management and RBAC.

Passwords are hashed with scrypt (stdlib) using per-user salts. Tokens are
short-lived HS256 JWTs with a server-side session record so they can be revoked.
No credentials are ever logged.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt

from sentinel.config import Settings
from sentinel.errors import AuthenticationError, ConfigError
from sentinel.models.common import Role, ensure_utc, iso, utcnow
from sentinel.observability.logging import get_logger
from sentinel.persistence.audit import AuditRepository
from sentinel.persistence.db import Database

_log = get_logger(__name__)

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ConfigError(f"password must be at least {_MIN_PASSWORD_LENGTH} characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n_raw, r_raw, p_raw, salt_hex, hash_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n_raw), int(r_raw), int(p_raw)
        if n > 2**16 or r > 32 or p > 8:
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=n,
            r=r,
            p=p,
            dklen=len(bytes.fromhex(hash_hex)),
        )
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


@dataclass(frozen=True)
class User:
    user_id: str
    username: str
    role: Role
    active: bool
    failed_attempts: int
    locked_until: datetime | None


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    role: Role
    jti: str
    expires_at: datetime


class UserRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(
        self, conn: sqlite3.Connection, *, username: str, password: str, role: Role
    ) -> User:
        user_id = f"usr-{uuid.uuid4().hex}"
        conn.execute(
            """
            INSERT INTO users (user_id, username, password_hash, role, active, failed_attempts, created_at)
            VALUES (?, ?, ?, ?, 1, 0, ?)
            """,
            (user_id, username.lower(), hash_password(password), role.value, iso(utcnow())),
        )
        return User(user_id, username.lower(), role, True, 0, None)

    def get_by_username(self, username: str) -> tuple[User, str] | None:
        row = self.db.query_one("SELECT * FROM users WHERE username = ?", (username.lower(),))
        if row is None:
            return None
        return self._row(row), str(row["password_hash"])

    def get_by_id(self, user_id: str) -> User | None:
        row = self.db.query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return self._row(row) if row else None

    def record_failure(self, username: str, *, lock_after: int, lock_minutes: int) -> None:
        with self.db.tx() as conn:
            row = conn.execute("SELECT failed_attempts FROM users WHERE username = ?", (username.lower(),)).fetchone()
            if row is None:
                return
            attempts = int(row["failed_attempts"]) + 1
            locked_until = None
            if attempts >= lock_after:
                locked_until = iso(utcnow() + timedelta(minutes=lock_minutes))
                attempts = 0
            conn.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                (attempts, locked_until, username.lower()),
            )

    def reset_failures(self, user_id: str) -> None:
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE user_id=?",
                (user_id,),
            )

    def list(self) -> list[User]:
        return [self._row(row) for row in self.db.query("SELECT * FROM users ORDER BY username")]

    @staticmethod
    def _row(row: sqlite3.Row) -> User:
        locked = row["locked_until"]
        return User(
            user_id=row["user_id"],
            username=row["username"],
            role=Role(row["role"]),
            active=bool(row["active"]),
            failed_attempts=int(row["failed_attempts"]),
            locked_until=datetime.fromisoformat(str(locked).replace("Z", "+00:00")) if locked else None,
        )


class SessionRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, conn: sqlite3.Connection, *, jti: str, user_id: str, expires_at: datetime) -> None:
        conn.execute(
            "INSERT INTO sessions (jti, user_id, issued_at, expires_at, revoked) VALUES (?, ?, ?, ?, 0)",
            (jti, user_id, iso(utcnow()), iso(expires_at)),
        )

    def is_valid(self, jti: str) -> bool:
        row = self.db.query_one("SELECT revoked, expires_at FROM sessions WHERE jti = ?", (jti,))
        if row is None or bool(row["revoked"]):
            return False
        expires = ensure_utc(datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00")))
        return expires > utcnow()

    def revoke(self, jti: str) -> None:
        with self.db.tx() as conn:
            conn.execute("UPDATE sessions SET revoked=1 WHERE jti=?", (jti,))

    def revoke_all_for_user(self, user_id: str) -> int:
        with self.db.tx() as conn:
            cursor = conn.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0", (user_id,))
            return cursor.rowcount


class AuthService:
    def __init__(
        self,
        *,
        settings: Settings,
        users: UserRepository,
        sessions: SessionRepository,
        audit: AuditRepository,
    ) -> None:
        self.settings = settings
        self.users = users
        self.sessions = sessions
        self.audit = audit
        self._secret = settings.resolved_jwt_secret()

    def bootstrap_user(
        self,
        username: str,
        password: str,
        role: Role = Role.ADMIN,
        *,
        actor: str = "bootstrap",
    ) -> User:
        existing = self.users.get_by_username(username)
        if existing is not None:
            return existing[0]
        with self.users.db.tx() as conn:
            user = self.users.create(conn, username=username, password=password, role=role)
            self.audit.append(
                conn,
                actor=actor,
                action="USER_CREATED",
                result="success",
                correlation_id="bootstrap",
                details={"username": user.username, "role": role.value},
            )
        _log.info("bootstrap user created", extra={"extra_fields": {"username": username, "role": role.value}})
        return user

    def login(self, username: str, password: str, *, ip_address: str = "unknown") -> dict[str, object]:
        normalized = username.strip().lower()
        record = self.users.get_by_username(normalized)
        if record is None:
            # Constant-cost dummy verification to reduce user enumeration timing.
            verify_password(password, _DUMMY_HASH)
            self._audit_login_failure(normalized, ip_address, "unknown_user")
            raise AuthenticationError("invalid username or password")

        user, encoded = record
        if not user.active:
            verify_password(password, _DUMMY_HASH)
            self._audit_login_failure(normalized, ip_address, "inactive_user")
            raise AuthenticationError("invalid username or password")
        if user.locked_until is not None and ensure_utc(user.locked_until) > utcnow():
            self._audit_login_failure(normalized, ip_address, "locked")
            raise AuthenticationError("invalid username or password")

        if not verify_password(password, encoded):
            self.users.record_failure(
                normalized,
                lock_after=self.settings.login_rate_limit_per_minute,
                lock_minutes=self.settings.login_lockout_minutes,
            )
            self._audit_login_failure(normalized, ip_address, "bad_password")
            raise AuthenticationError("invalid username or password")

        self.users.reset_failures(user.user_id)
        jti = uuid.uuid4().hex
        expires_at = utcnow() + timedelta(minutes=self.settings.session_ttl_minutes)
        token = jwt.encode(
            {
                "sub": user.user_id,
                "username": user.username,
                "role": user.role.value,
                "jti": jti,
                "iat": int(utcnow().timestamp()),
                "exp": int(expires_at.timestamp()),
                "iss": self.settings.jwt_issuer,
                "aud": self.settings.jwt_audience,
            },
            self._secret,
            algorithm="HS256",
        )
        with self.users.db.tx() as conn:
            self.sessions.create(conn, jti=jti, user_id=user.user_id, expires_at=expires_at)
            self.audit.append(
                conn,
                actor=user.username,
                action="AUTH_LOGIN_SUCCEEDED",
                result="success",
                correlation_id=jti,
                details={"ip_hash": _hash_ip(ip_address), "role": user.role.value},
            )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_at": iso(expires_at),
            "user": {"username": user.username, "role": user.role.value},
        }

    def authenticate(self, token: str) -> Principal:
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                audience=self.settings.jwt_audience,
                issuer=self.settings.jwt_issuer,
                options={"require": ["exp", "iat", "sub", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError("invalid or expired session") from exc
        jti = str(payload["jti"])
        if not self.sessions.is_valid(jti):
            raise AuthenticationError("session is no longer valid")
        user = self.users.get_by_id(str(payload["sub"]))
        if user is None or not user.active:
            raise AuthenticationError("account is not active")
        if user.role.value != payload.get("role"):
            raise AuthenticationError("role changed; re-authenticate")
        return Principal(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            jti=jti,
            expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=utcnow().tzinfo),
        )

    def logout(self, principal: Principal) -> None:
        self.sessions.revoke(principal.jti)
        with self.users.db.tx() as conn:
            self.audit.append(
                conn,
                actor=principal.username,
                action="AUTH_LOGOUT",
                result="success",
                correlation_id=principal.jti,
            )

    def _audit_login_failure(self, username: str, ip_address: str, reason: str) -> None:
        with self.users.db.tx() as conn:
            self.audit.append(
                conn,
                actor=username[:64] or "unknown",
                action="AUTH_LOGIN_FAILED",
                result="failure",
                failure_reason=reason,
                correlation_id=uuid.uuid4().hex,
                details={"ip_hash": _hash_ip(ip_address)},
            )


def _hash_ip(ip_address: str) -> str:
    return hashlib.sha256(ip_address.encode("utf-8")).hexdigest()[:16]
