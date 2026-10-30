"""Data at rest and backup encryption using AES-256-GCM authenticated encryption."""
import hashlib
import os
from pathlib import Path
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_HEADER = b'VFENC1\x00'
NONCE_LENGTH = 12


class DecryptionError(Exception):
    """Raised when backup or data decryption fails due to invalid key or tampering."""
    pass


class DataEncryptor:
    """Provides authenticated AES-256-GCM symmetric encryption for backups and sensitive artifacts."""

    @staticmethod
    def generate_key() -> str:
        """Generate a cryptographically secure 256-bit key in hex format."""
        return AESGCM.generate_key(bit_length=256).hex()

    @staticmethod
    def _normalize_key(key: Union[bytes, str]) -> bytes:
        if isinstance(key, str):
            key = key.strip()
            # If 64 hex characters, decode to 32 bytes
            if len(key) == 64 and all(c in '0123456789abcdefABCDEF' for c in key):
                return bytes.fromhex(key)
            # Otherwise derive SHA-256 32-byte key
            return hashlib.sha256(key.encode('utf-8')).digest()
        if len(key) != 32:
            return hashlib.sha256(key).digest()
        return key

    @classmethod
    def encrypt(cls, plaintext: bytes, key: Union[bytes, str]) -> bytes:
        norm_key = cls._normalize_key(key)
        aesgcm = AESGCM(norm_key)
        nonce = os.urandom(NONCE_LENGTH)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return MAGIC_HEADER + nonce + ciphertext

    @classmethod
    def decrypt(cls, encrypted_data: bytes, key: Union[bytes, str]) -> bytes:
        if not encrypted_data.startswith(MAGIC_HEADER):
            raise DecryptionError("Invalid encrypted payload: Missing VulnForge magic header")

        header_len = len(MAGIC_HEADER)
        if len(encrypted_data) < header_len + NONCE_LENGTH + 16:
            raise DecryptionError("Encrypted payload too short to contain nonce and authentication tag")

        nonce = encrypted_data[header_len:header_len + NONCE_LENGTH]
        ciphertext = encrypted_data[header_len + NONCE_LENGTH:]
        norm_key = cls._normalize_key(key)

        try:
            aesgcm = AESGCM(norm_key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise DecryptionError("Decryption failed: authentication tag mismatch or invalid key") from exc


def create_encrypted_backup(source_path: Union[str, Path], backup_path: Union[str, Path], key: Union[bytes, str]) -> dict:
    source_p = Path(source_path)
    if not source_p.exists():
        raise FileNotFoundError(f"Source file for backup does not exist: {source_path}")

    plaintext = source_p.read_bytes()
    encrypted = DataEncryptor.encrypt(plaintext, key)

    backup_p = Path(backup_path)
    backup_p.parent.mkdir(parents=True, exist_ok=True)
    backup_p.write_bytes(encrypted)

    return {
        'source_path': str(source_p),
        'backup_path': str(backup_p),
        'source_bytes': len(plaintext),
        'backup_bytes': len(encrypted),
        'source_sha256': hashlib.sha256(plaintext).hexdigest(),
        'backup_sha256': hashlib.sha256(encrypted).hexdigest()
    }


def restore_encrypted_backup(backup_path: Union[str, Path], restore_path: Union[str, Path], key: Union[bytes, str]) -> dict:
    backup_p = Path(backup_path)
    if not backup_p.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    encrypted = backup_p.read_bytes()
    decrypted = DataEncryptor.decrypt(encrypted, key)

    restore_p = Path(restore_path)
    restore_p.parent.mkdir(parents=True, exist_ok=True)
    restore_p.write_bytes(decrypted)

    return {
        'backup_path': str(backup_p),
        'restored_path': str(restore_p),
        'restored_bytes': len(decrypted),
        'restored_sha256': hashlib.sha256(decrypted).hexdigest()
    }

