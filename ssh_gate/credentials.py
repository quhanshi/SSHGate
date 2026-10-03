"""Local encrypted SSH credential storage.

The connection config intentionally remains secret-free. Encrypted credentials and the
random master key live in separate current-user directories, outside the source project. The key-provider boundary is deliberately small so a future
DPAPI/Keychain/Secret Service provider can replace FileKeyProvider without changing
credential records or SSH authentication flow.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


STORE_VERSION = 1
KEY_BYTES = 32
NONCE_BYTES = 12


def user_data_dir() -> Path:
    override = os.environ.get("SSH_GATE_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SSHGate"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "SSHGate"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "SSHGate"



def user_key_dir() -> Path:
    override = os.environ.get("SSH_GATE_KEY_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", str(Path.home()))) / "SSHGate" / "keys"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Preferences" / "SSHGate"
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "SSHGate"


def _private_permissions(path: Path) -> None:
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


class KeyProvider(Protocol):
    def get_key(self) -> bytes: ...


@dataclass
class FileKeyProvider:
    path: Path

    def get_key(self) -> bytes:
        if self.path.exists():
            key = self.path.read_bytes()
            if len(key) != KEY_BYTES:
                raise ValueError("本机凭据主密钥格式无效")
            return key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(KEY_BYTES)
        try:
            with self.path.open("xb") as out:
                out.write(key)
                out.flush()
                os.fsync(out.fileno())
            _private_permissions(self.path)
            return key
        except FileExistsError:
            key = self.path.read_bytes()
            if len(key) != KEY_BYTES:
                raise ValueError("本机凭据主密钥格式无效")
            return key


class CredentialStore:
    """AES-256-GCM credential records backed by a per-install random master key."""

    def __init__(self, root: Path | None = None, key_provider: KeyProvider | None = None):
        self.root = (root or user_data_dir()).resolve()
        self.path = self.root / "credentials.json"
        key_path = self.root / "master.key" if root is not None else user_key_dir() / "master.key"
        self.key_provider = key_provider or FileKeyProvider(key_path)
        self._lock = threading.RLock()

    @staticmethod
    def reference(connection_id: str, username: str, hostname: str, port: int) -> str:
        # Keep endpoint identity out of the encrypted payload so a stored secret can be
        # selected before decryption. This is metadata, not a secret.
        raw = f"ssh-v1\0{connection_id}\0{username}\0{hostname.lower()}\0{port}".encode("utf-8")
        import hashlib
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def secret_reference(name: str) -> str:
        """Stable opaque reference for non-SSH application secrets."""
        if not isinstance(name, str) or not name or any(c in name for c in "\r\n\x00"):
            raise ValueError("凭据名称无效")
        import hashlib
        return hashlib.sha256(f"app-secret-v1\0{name}".encode("utf-8")).hexdigest()

    def _load(self) -> dict:
        if not self.path.exists():
            return {"version": STORE_VERSION, "entries": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("本机凭据存储损坏") from exc
        if data.get("version") != STORE_VERSION or not isinstance(data.get("entries"), dict):
            raise ValueError("本机凭据存储版本不受支持")
        return data

    def _write(self, data: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as out:
                json.dump(data, out, ensure_ascii=False, separators=(",", ":"))
                out.write("\n")
                out.flush()
                os.fsync(out.fileno())
            _private_permissions(tmp)
            os.replace(tmp, self.path)
            _private_permissions(self.path)
        finally:
            tmp.unlink(missing_ok=True)

    def get(self, reference: str) -> dict[str, str] | None:
        with self._lock:
            return self._get(reference)

    def _get(self, reference: str) -> dict[str, str] | None:
        entry = self._load()["entries"].get(reference)
        if not isinstance(entry, dict) or entry.get("v") != STORE_VERSION:
            return None
        try:
            nonce = base64.b64decode(entry["nonce"], validate=True)
            ciphertext = base64.b64decode(entry["ciphertext"], validate=True)
            if len(nonce) != NONCE_BYTES:
                return None
            plaintext = AESGCM(self.key_provider.get_key()).decrypt(nonce, ciphertext, reference.encode("ascii"))
            value = json.loads(plaintext.decode("utf-8"))
            if value.get("mode") not in {"password", "passphrase", "api_key"} or not isinstance(value.get("secret"), str):
                return None
            return {"mode": value["mode"], "secret": value["secret"]}
        except (KeyError, ValueError, InvalidTag, json.JSONDecodeError, UnicodeDecodeError):
            # A moved/corrupt record must never block login. Remove only this unusable entry.
            try:
                self._delete(reference)
            except (OSError, ValueError):
                pass
            return None

    def save(self, reference: str, mode: str, secret: str) -> None:
        with self._lock:
            self._save(reference, mode, secret)

    def _save(self, reference: str, mode: str, secret: str) -> None:
        if mode not in {"password", "passphrase", "api_key"} or not secret:
            raise ValueError("凭据内容无效")
        data = self._load()
        nonce = os.urandom(NONCE_BYTES)
        plaintext = json.dumps({"mode": mode, "secret": secret}, ensure_ascii=False,
                              separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(self.key_provider.get_key()).encrypt(nonce, plaintext, reference.encode("ascii"))
        data["entries"][reference] = {
            "v": STORE_VERSION,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        self._write(data)

    def delete(self, reference: str) -> None:
        with self._lock:
            self._delete(reference)

    def _delete(self, reference: str) -> None:
        data = self._load()
        if reference in data["entries"]:
            del data["entries"][reference]
            self._write(data)

    def has(self, reference: str) -> bool:
        with self._lock:
            return reference in self._load()["entries"]
