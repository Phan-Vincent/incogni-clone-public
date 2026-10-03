"""Single-operator password and signed-session authentication."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import BoundedSemaphore, Lock
from typing import Callable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


@dataclass(frozen=True)
class Session:
    expires_at: int
    csrf_token: str
    session_id: str


class LoginThrottle:
    """Small in-memory brute-force guard for the single local operator."""

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_seconds: int = 300,
        clock: Callable[[], float] = time.monotonic,
        max_concurrent_verifications: int = 2,
    ):
        if max_concurrent_verifications < 1:
            raise ValueError("max_concurrent_verifications must be positive")
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.clock = clock
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()
        self._verification_slots = BoundedSemaphore(max_concurrent_verifications)

    def _purge(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        values = self._failures[key]
        while values and values[0] <= cutoff:
            values.popleft()

    def allowed(self, key: str) -> bool:
        with self._lock:
            now = self.clock()
            self._purge(key, now)
            return len(self._failures[key]) < self.max_failures

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self.clock()
            self._purge(key, now)
            self._failures[key].append(now)

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def authenticate(self, key: str, verifier: Callable[[], bool]) -> bool | None:
        """Reserve a rate-limit slot before a bounded password check.

        None means the source is throttled. A reservation remains a failure
        unless the supplied verifier succeeds.
        """
        with self._lock:
            now = self.clock()
            self._purge(key, now)
            if len(self._failures[key]) >= self.max_failures:
                return None
            self._failures[key].append(now)
        with self._verification_slots:
            verified = verifier()
        if verified:
            self.record_success(key)
        return verified


class OperatorAuth:
    def __init__(
        self,
        password_hash: str,
        signing_key: bytes,
        *,
        ttl_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ):
        if len(signing_key) < 32:
            raise ValueError("session signing key must be at least 32 bytes")
        self.password_hash = password_hash
        self.signing_key = hashlib.sha256(b"incogni-session-v1" + signing_key).digest()
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self.hasher = PasswordHasher()

    @staticmethod
    def hash_password(password: str) -> str:
        if len(password) < 12:
            raise ValueError("password must be at least 12 characters")
        return PasswordHasher().hash(password)

    def verify_password(self, password: str) -> bool:
        try:
            return self.hasher.verify(self.password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    @staticmethod
    def _unb64(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    def issue_session(self) -> tuple[str, Session]:
        session = Session(
            expires_at=int(self.clock()) + self.ttl_seconds,
            csrf_token=secrets.token_urlsafe(24),
            session_id=secrets.token_urlsafe(24),
        )
        payload = json.dumps(
            {
                "exp": session.expires_at,
                "csrf": session.csrf_token,
                "sid": session.session_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        encoded = self._b64(payload)
        signature = self._b64(hmac.digest(self.signing_key, encoded.encode(), "sha256"))
        return f"{encoded}.{signature}", session

    def verify_session(self, token: str) -> Session | None:
        try:
            encoded, supplied_signature = token.split(".", 1)
            expected = self._b64(
                hmac.digest(self.signing_key, encoded.encode(), "sha256")
            )
            if not hmac.compare_digest(expected, supplied_signature):
                return None
            payload = json.loads(self._unb64(encoded))
            session = Session(
                expires_at=int(payload["exp"]),
                csrf_token=str(payload["csrf"]),
                session_id=str(payload["sid"]),
            )
            if session.expires_at <= int(self.clock()):
                return None
            return session
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None
