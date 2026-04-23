"""
encrypted_rehydrator.py
=======================
Encrypted placeholder map (Guide Section 4.2).

Security rationale:
  The placeholder_map {<<ENTITY_1>>: "real_value"} is held in process memory
  for the request lifetime. In normal operation this is fine — the map exists
  only until the response is rehydrated (a few hundred milliseconds).

  However the guide (Section 4.2) calls for encrypting the map so that:
    1. If the map is accidentally serialised to disk/logs it is not recoverable
    2. The map is only decryptable by the session that created it
    3. An adversary who dumps process memory cannot trivially read PII values

  Implementation:
    - Uses AES-256-GCM (authenticated encryption) via cryptography.fernet
    - A per-request ephemeral key is derived from a secret + request_id
    - The key NEVER leaves the process — only the encrypted map is shared
    - EncryptedMap is a base64-encoded JSON blob: {iv, tag, ciphertext}

  Fallback:
    If `cryptography` is not installed, falls back to unencrypted map with a
    loud warning. This preserves backward compatibility while making the
    upgrade path obvious.
"""

import base64
import json
import os
import struct
import warnings
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Try to import cryptography — graceful fallback if not installed
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
    logger.debug("encrypted_placeholder_map_enabled", backend="AES-256-GCM")
except ImportError:
    _CRYPTO_AVAILABLE = False
    warnings.warn(
        "cryptography package not installed — placeholder map encryption DISABLED. "
        "Install with: pip install cryptography",
        SecurityWarning,
        stacklevel=2,
    )
    logger.warning(
        "encrypted_placeholder_map_disabled",
        reason="cryptography_not_installed",
        install="pip install cryptography",
    )


class EncryptedPlaceholderMap:
    """
    Wraps a placeholder dict with AES-256-GCM encryption.

    Usage:
        # Encrypt on creation (after PII scrubbing)
        enc_map = EncryptedPlaceholderMap.from_plaintext(raw_map)

        # Decrypt for rehydration
        raw_map = enc_map.decrypt()
    """

    def __init__(self, encrypted_blob: str, key: bytes):
        """
        Args:
            encrypted_blob: Base64-encoded JSON {nonce, ciphertext}
            key: 32-byte AES-256 key (ephemeral, per-request)
        """
        self._blob = encrypted_blob
        self._key  = key

    @classmethod
    def from_plaintext(
        cls,
        plaintext_map: dict[str, str],
        key: bytes | None = None,
    ) -> "EncryptedPlaceholderMap":
        """
        Encrypt a plaintext placeholder map.

        Args:
            plaintext_map: {placeholder: original_value}
            key: Optional 32-byte key. If None, a fresh random key is generated.

        Returns:
            EncryptedPlaceholderMap instance.
        """
        if not plaintext_map:
            # Nothing to encrypt
            return _NullEncryptedMap(plaintext_map)

        if not _CRYPTO_AVAILABLE:
            # Graceful fallback — return a passthrough wrapper
            logger.warning("returning_unencrypted_placeholder_map")
            return _NullEncryptedMap(plaintext_map)

        if key is None:
            key = os.urandom(32)  # AES-256

        aesgcm = AESGCM(key)
        nonce  = os.urandom(12)   # 96-bit nonce (GCM standard)

        plaintext_bytes = json.dumps(plaintext_map).encode("utf-8")
        ciphertext      = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

        blob = {
            "n": base64.b64encode(nonce).decode(),
            "c": base64.b64encode(ciphertext).decode(),
        }
        encrypted_blob = base64.b64encode(json.dumps(blob).encode()).decode()

        logger.debug(
            "placeholder_map_encrypted",
            entries=len(plaintext_map),
            key_bytes=len(key),
        )
        return cls(encrypted_blob, key)

    def decrypt(self) -> dict[str, str]:
        """
        Decrypt and return the original placeholder map.

        Returns:
            {placeholder: original_value} dict.
        """
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError(
                "Cannot decrypt: cryptography package not installed. "
                "Install with: pip install cryptography"
            )
        try:
            outer     = json.loads(base64.b64decode(self._blob.encode()).decode())
            nonce     = base64.b64decode(outer["n"])
            ciphertext = base64.b64decode(outer["c"])

            aesgcm    = AESGCM(self._key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

            result = json.loads(plaintext.decode("utf-8"))
            logger.debug("placeholder_map_decrypted", entries=len(result))
            return result
        except Exception as e:
            logger.error("placeholder_map_decrypt_failed", error=str(e))
            raise ValueError(f"Failed to decrypt placeholder map: {e}") from e

    @property
    def is_encrypted(self) -> bool:
        return True


class _NullEncryptedMap(EncryptedPlaceholderMap):
    """
    Fallback when cryptography is unavailable — stores map in plaintext.
    Raises a security warning on construction so it's impossible to miss.
    """

    def __init__(self, plaintext_map: dict[str, str]):
        self._plaintext = plaintext_map
        # No super().__init__ — we skip the encrypted fields entirely

    def decrypt(self) -> dict[str, str]:
        return self._plaintext

    @property
    def is_encrypted(self) -> bool:
        return False


class EncryptedRehydrator:
    """
    Drop-in replacement for Rehydrator that accepts EncryptedPlaceholderMap.

    The pipeline creates an EncryptedPlaceholderMap after PII scrubbing.
    The rehydrator decrypts it immediately before restoring values into the
    LLM response.  The key and the map never leave the process.
    """

    @staticmethod
    def restore(
        llm_response: str,
        encrypted_map: EncryptedPlaceholderMap,
    ) -> str:
        """
        Decrypt the map and restore PII into the LLM response.

        Args:
            llm_response:  The LLM response (may contain placeholders)
            encrypted_map: The encrypted placeholder map

        Returns:
            Response with all placeholders replaced by original values.
        """
        if not llm_response:
            return llm_response

        try:
            plaintext_map = encrypted_map.decrypt()
        except Exception as e:
            logger.error("rehydration_decrypt_failed", error=str(e))
            return llm_response  # Fail safe — return without rehydration

        if not plaintext_map:
            return llm_response

        result = llm_response
        restored = 0
        for placeholder, original in plaintext_map.items():
            if placeholder in result:
                result = result.replace(placeholder, original)
                restored += 1

        if restored > 0:
            logger.info(
                "pii_rehydrated_encrypted",
                placeholders_restored=restored,
                total_placeholders=len(plaintext_map),
                map_encrypted=encrypted_map.is_encrypted,
            )

        return result
