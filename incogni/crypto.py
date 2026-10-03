"""Authenticated encryption for sensitive service payloads."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncryptedEnvelope:
    version: int
    key_id: str
    nonce: str
    ciphertext: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "key_id": self.key_id,
                "nonce": self.nonce,
                "ciphertext": self.ciphertext,
            },
            separators=(",", ":"),
            sort_keys=True,
        )


class EnvelopeCrypto:
    """AES-256-GCM envelope encryption with explicit key rotation support."""

    def __init__(self, keys: Mapping[str, bytes], active_key_id: str):
        self._keys = dict(keys)
        if active_key_id not in self._keys:
            raise ValueError("active key id is not present")
        if not self._keys or any(len(key) != 32 for key in self._keys.values()):
            raise ValueError("all encryption keys must be exactly 32 bytes")
        self.active_key_id = active_key_id

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii")

    @staticmethod
    def _unb64(value: str) -> bytes:
        try:
            return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("invalid encrypted envelope encoding") from exc

    def encrypt_bytes(self, plaintext: bytes, *, aad: bytes) -> str:
        if not isinstance(aad, bytes) or not aad:
            raise ValueError("non-empty AAD is required")
        nonce = os.urandom(12)
        encrypted = AESGCM(self._keys[self.active_key_id]).encrypt(nonce, plaintext, aad)
        return EncryptedEnvelope(
            version=1,
            key_id=self.active_key_id,
            nonce=self._b64(nonce),
            ciphertext=self._b64(encrypted),
        ).to_json()

    def decrypt_bytes(self, envelope_json: str, *, aad: bytes) -> bytes:
        if not isinstance(aad, bytes) or not aad:
            raise ValueError("non-empty AAD is required")
        try:
            raw = json.loads(envelope_json)
            if set(raw) != {"version", "key_id", "nonce", "ciphertext"}:
                raise ValueError
            if raw["version"] != 1 or not isinstance(raw["key_id"], str):
                raise ValueError
            key = self._keys[raw["key_id"]]
            nonce = self._unb64(raw["nonce"])
            ciphertext = self._unb64(raw["ciphertext"])
            if len(nonce) != 12:
                raise ValueError
        except (KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("malformed or unknown encrypted envelope") from exc
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise ValueError("encrypted payload authentication failed") from exc

    def encrypt_json(self, value: Any, *, aad: bytes) -> str:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        return self.encrypt_bytes(encoded, aad=aad)

    def decrypt_json(self, envelope_json: str, *, aad: bytes) -> Any:
        try:
            return json.loads(self.decrypt_bytes(envelope_json, aad=aad).decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("decrypted payload is not valid JSON") from exc
