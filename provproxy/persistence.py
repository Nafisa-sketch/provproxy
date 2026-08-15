from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import PersistenceConfig


class PersistenceError(RuntimeError):
    """Base class for persistent provenance-state failures."""


class PersistenceCorruptionError(PersistenceError):
    """Authenticated state could not be verified/decrypted."""


class KeyProtectionError(PersistenceError):
    """Master-key protection/recovery failed."""


@dataclass
class _Fragment:
    data: str
    timestamp: float


@dataclass
class _Source:
    text: str
    timestamp: float


class _WindowsDPAPI:
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint32),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    @classmethod
    def _blob_from_bytes(cls, data: bytes):
        buf = ctypes.create_string_buffer(data)
        blob = cls.DATA_BLOB(
            len(data),
            ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
        )
        return blob, buf

    @classmethod
    def protect(cls, data: bytes) -> bytes:
        if os.name != "nt":
            raise KeyProtectionError("Windows DPAPI is only available on Windows.")
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        in_blob, _keepalive = cls._blob_from_bytes(data)
        out_blob = cls.DATA_BLOB()
        ok = crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "ProvProxy provenance-state master key",
            None, None, None,
            cls.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise KeyProtectionError(
                f"CryptProtectData failed with WinError {ctypes.get_last_error()}"
            )
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            if out_blob.pbData:
                kernel32.LocalFree(out_blob.pbData)

    @classmethod
    def unprotect(cls, protected: bytes) -> bytes:
        if os.name != "nt":
            raise KeyProtectionError("Windows DPAPI is only available on Windows.")
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        in_blob, _keepalive = cls._blob_from_bytes(protected)
        out_blob = cls.DATA_BLOB()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None, None, None, None,
            cls.CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        if not ok:
            raise KeyProtectionError(
                f"CryptUnprotectData failed with WinError {ctypes.get_last_error()}"
            )
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            if out_blob.pbData:
                kernel32.LocalFree(out_blob.pbData)


class SecurePersistentStateRegistry:
    """Encrypted append-only provenance persistence for V4.

    Stores BOTH:
      1. registered sensitive sources, and
      2. cross-call outbound evidence.

    Source persistence is required because restoring only the accumulated
    outbound fragments would be useless after a process restart: V4 still
    needs the original registered source text to calculate coverage.

    Records are AES-256-GCM authenticated. On Windows, the AES key is
    protected using DPAPI. Corruption/tampering is fail-closed by default.
    """

    FORMAT_VERSION = 2
    AAD_PREFIX = b"provproxy-p6-runtime-v2:"

    def __init__(self, config: PersistenceConfig, *, ttl_seconds: int):
        self.config = config
        self.ttl_seconds = int(ttl_seconds)
        self.state_dir = Path(config.state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.journal_path = self.state_dir / "state.journal"
        self.snapshot_path = self.state_dir / "state.snapshot"
        self.key_path = self.state_dir / "master.key.dpapi"

        self._lock = threading.RLock()
        self._fragments: dict[tuple[str, str, str], list[_Fragment]] = {}
        self._sources: dict[tuple[str, str], _Source] = {}
        self._seq = 0
        self._snapshot_seq = 0
        self._appends_since_fsync = 0
        self._appends_since_compact = 0

        self._master_key = self._load_or_create_master_key()
        if len(self._master_key) != 32:
            raise KeyProtectionError("Expected a 32-byte AES-256 master key.")
        self._aesgcm = AESGCM(self._master_key)
        self._load_state()

    # ---------------------------- key handling ----------------------------

    def _load_or_create_master_key(self) -> bytes:
        env_key = os.environ.get("PROVPROXY_MASTER_KEY_B64")
        if env_key:
            try:
                key = base64.b64decode(env_key, validate=True)
            except Exception as exc:
                raise KeyProtectionError(
                    "PROVPROXY_MASTER_KEY_B64 is not valid Base64."
                ) from exc
            if len(key) != 32:
                raise KeyProtectionError(
                    "PROVPROXY_MASTER_KEY_B64 must decode to exactly 32 bytes."
                )
            return key

        if os.name == "nt":
            if self.key_path.exists():
                try:
                    return _WindowsDPAPI.unprotect(self.key_path.read_bytes())
                except Exception as exc:
                    raise KeyProtectionError(
                        f"Unable to recover DPAPI-protected key: {exc}"
                    ) from exc
            key = secrets.token_bytes(32)
            self._atomic_write_bytes(self.key_path, _WindowsDPAPI.protect(key))
            return key

        if not self.config.allow_file_key_fallback:
            raise KeyProtectionError(
                "No OS key protector configured on this platform. "
                "Set PROVPROXY_MASTER_KEY_B64 to a securely supplied 32-byte key. "
                "allow_file_key_fallback is for local tests only."
            )

        dev_key = self.state_dir / "master.key.dev"
        if dev_key.exists():
            key = dev_key.read_bytes()
            if len(key) != 32:
                raise KeyProtectionError("Development key file is invalid.")
            return key

        key = secrets.token_bytes(32)
        self._atomic_write_bytes(dev_key, key)
        try:
            os.chmod(dev_key, 0o600)
        except OSError:
            pass
        return key

    # ---------------------------- encryption -----------------------------

    def _encrypt_record(self, kind: str, payload: dict[str, Any]) -> bytes:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        aad = self.AAD_PREFIX + kind.encode("ascii")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        envelope = {
            "v": self.FORMAT_VERSION,
            "kind": kind,
            "n": base64.b64encode(nonce).decode("ascii"),
            "c": base64.b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8") + b"\n"

    def _decrypt_record(self, raw: bytes, expected_kind: str | None = None) -> dict[str, Any]:
        try:
            envelope = json.loads(raw.decode("utf-8"))
            if envelope.get("v") != self.FORMAT_VERSION:
                raise PersistenceCorruptionError("Unsupported persistence format.")
            kind = envelope["kind"]
            if expected_kind is not None and kind != expected_kind:
                raise PersistenceCorruptionError(
                    f"Expected {expected_kind!r}, got {kind!r}."
                )
            nonce = base64.b64decode(envelope["n"], validate=True)
            ciphertext = base64.b64decode(envelope["c"], validate=True)
            plaintext = self._aesgcm.decrypt(
                nonce, ciphertext, self.AAD_PREFIX + kind.encode("ascii")
            )
            payload = json.loads(plaintext.decode("utf-8"))
            payload["_kind"] = kind
            return payload
        except PersistenceCorruptionError:
            raise
        except Exception as exc:
            raise PersistenceCorruptionError(
                "Encrypted persistence record failed authentication/parsing."
            ) from exc

    # ------------------------------- load --------------------------------

    def _load_state(self) -> None:
        with self._lock:
            self._fragments.clear()
            self._sources.clear()
            self._seq = 0
            self._snapshot_seq = 0

            if self.snapshot_path.exists() and self.snapshot_path.stat().st_size:
                try:
                    snap = self._decrypt_record(
                        self.snapshot_path.read_bytes(),
                        expected_kind="snapshot",
                    )
                    self._snapshot_seq = int(snap.get("last_seq", 0))
                    self._seq = self._snapshot_seq
                    self._restore_snapshot(snap)
                except PersistenceCorruptionError:
                    if self.config.fail_closed_on_corruption:
                        raise

            if self.journal_path.exists():
                with self.journal_path.open("rb") as fh:
                    for line_no, line in enumerate(fh, 1):
                        if not line.strip():
                            continue
                        try:
                            payload = self._decrypt_record(line)
                            seq = int(payload["seq"])
                            if seq <= self._snapshot_seq:
                                continue
                            kind = payload["_kind"]
                            if kind == "add":
                                self._apply_add(payload)
                            elif kind == "source":
                                self._apply_source(payload)
                            else:
                                raise PersistenceCorruptionError(
                                    f"Unexpected journal kind {kind!r}."
                                )
                            self._seq = max(self._seq, seq)
                        except PersistenceCorruptionError as exc:
                            if self.config.fail_closed_on_corruption:
                                raise PersistenceCorruptionError(
                                    f"Journal corruption at line {line_no}: {exc}"
                                ) from exc

            self._prune_expired_locked()

    def _restore_snapshot(self, snap: dict[str, Any]) -> None:
        now = time.time()
        for row in snap.get("sources", []):
            ts = float(row["timestamp"])
            if now - ts <= self.ttl_seconds:
                self._sources[(str(row["session_id"]), str(row["source_id"]))] = _Source(
                    text=str(row["source_text"]), timestamp=ts
                )

        for row in snap.get("fragments", []):
            ts = float(row["timestamp"])
            if now - ts <= self.ttl_seconds:
                key = (
                    str(row["session_id"]),
                    str(row["destination"]),
                    str(row["source_id"]),
                )
                self._fragments.setdefault(key, []).append(
                    _Fragment(data=str(row["data"]), timestamp=ts)
                )

    def _apply_source(self, payload: dict[str, Any]) -> None:
        ts = float(payload["timestamp"])
        if time.time() - ts > self.ttl_seconds:
            return
        key = (str(payload["session_id"]), str(payload["source_id"]))
        self._sources[key] = _Source(
            text=str(payload["source_text"]), timestamp=ts
        )

    def _apply_add(self, payload: dict[str, Any]) -> None:
        ts = float(payload["timestamp"])
        if time.time() - ts > self.ttl_seconds:
            return
        key = (
            str(payload["session_id"]),
            str(payload["destination"]),
            str(payload["source_id"]),
        )
        self._fragments.setdefault(key, []).append(
            _Fragment(data=str(payload["data"]), timestamp=ts)
        )

    # ------------------------------ public -------------------------------

    def register_source(self, session_id: str, source_id: str, source_text: str) -> None:
        with self._lock:
            self._prune_expired_locked()
            self._seq += 1
            ts = time.time()
            payload = {
                "seq": self._seq,
                "session_id": session_id,
                "source_id": source_id,
                "source_text": source_text,
                "timestamp": ts,
            }
            self._append_record("source", payload)
            self._sources[(session_id, source_id)] = _Source(source_text, ts)
            self._after_append_locked()

    def add_fragment(
        self,
        session_id: str,
        destination: str,
        source_id: str,
        fragment_data: str,
    ) -> None:
        with self._lock:
            self._prune_expired_locked()
            self._seq += 1
            ts = time.time()
            payload = {
                "seq": self._seq,
                "session_id": session_id,
                "destination": destination,
                "source_id": source_id,
                "data": fragment_data,
                "timestamp": ts,
            }
            self._append_record("add", payload)
            key = (session_id, destination, source_id)
            self._fragments.setdefault(key, []).append(_Fragment(fragment_data, ts))
            self._after_append_locked()

    def get_sources(self, session_id: str) -> list[tuple[str, str]]:
        with self._lock:
            self._prune_expired_locked()
            return [
                (source_id, src.text)
                for (sid, source_id), src in self._sources.items()
                if sid == session_id
            ]

    def get_accumulated_entries(
        self, session_id: str, destination: str, source_id: str
    ) -> list[tuple[str, float]]:
        with self._lock:
            self._prune_expired_locked()
            key = (session_id, destination, source_id)
            return [
                (frag.data, frag.timestamp)
                for frag in self._fragments.get(key, [])
            ]

    def compact(self) -> None:
        with self._lock:
            self._compact_locked()

    def close(self) -> None:
        with self._lock:
            if self.journal_path.exists():
                with self.journal_path.open("ab") as fh:
                    fh.flush()
                    os.fsync(fh.fileno())
            self._appends_since_fsync = 0

    # -------------------------- internal writes --------------------------

    def _append_record(self, kind: str, payload: dict[str, Any]) -> None:
        line = self._encrypt_record(kind, payload)
        with self.journal_path.open("ab") as fh:
            fh.write(line)
            fh.flush()
            self._appends_since_fsync += 1
            if self._appends_since_fsync >= self.config.fsync_every:
                os.fsync(fh.fileno())
                self._appends_since_fsync = 0

    def _after_append_locked(self) -> None:
        self._appends_since_compact += 1
        if self._appends_since_compact >= self.config.compact_every:
            self._compact_locked()

    def _prune_expired_locked(self) -> None:
        now = time.time()

        dead_sources = [
            key for key, src in self._sources.items()
            if now - src.timestamp > self.ttl_seconds
        ]
        for key in dead_sources:
            self._sources.pop(key, None)

        dead_fragment_keys = []
        for key, frags in self._fragments.items():
            kept = [f for f in frags if now - f.timestamp <= self.ttl_seconds]
            if kept:
                self._fragments[key] = kept
            else:
                dead_fragment_keys.append(key)
        for key in dead_fragment_keys:
            self._fragments.pop(key, None)

    def _compact_locked(self) -> None:
        self._prune_expired_locked()

        sources = [
            {
                "session_id": sid,
                "source_id": source_id,
                "source_text": src.text,
                "timestamp": src.timestamp,
            }
            for (sid, source_id), src in self._sources.items()
        ]

        fragments = []
        for (sid, destination, source_id), rows in self._fragments.items():
            for frag in rows:
                fragments.append(
                    {
                        "session_id": sid,
                        "destination": destination,
                        "source_id": source_id,
                        "data": frag.data,
                        "timestamp": frag.timestamp,
                    }
                )

        snapshot = {
            "last_seq": self._seq,
            "created_at": time.time(),
            "sources": sources,
            "fragments": fragments,
        }

        self._atomic_write_bytes(
            self.snapshot_path,
            self._encrypt_record("snapshot", snapshot),
        )
        self._atomic_write_bytes(self.journal_path, b"")
        self._snapshot_seq = self._seq
        self._appends_since_compact = 0
        self._appends_since_fsync = 0

    @staticmethod
    def _atomic_write_bytes(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
        with tmp.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)


_SHARED_LOCK = threading.RLock()
_SHARED: dict[tuple, SecurePersistentStateRegistry] = {}


def get_shared_persistence(
    config: PersistenceConfig, *, ttl_seconds: int
) -> SecurePersistentStateRegistry:
    """One writer/lock domain per state directory inside the process."""
    key = (
        str(Path(config.state_dir).resolve()),
        int(ttl_seconds),
        int(config.fsync_every),
        int(config.compact_every),
        bool(config.fail_closed_on_corruption),
        bool(config.allow_file_key_fallback),
    )
    with _SHARED_LOCK:
        reg = _SHARED.get(key)
        if reg is None:
            reg = SecurePersistentStateRegistry(config, ttl_seconds=ttl_seconds)
            _SHARED[key] = reg
        return reg


def reset_shared_persistence_for_tests() -> None:
    with _SHARED_LOCK:
        for reg in _SHARED.values():
            try:
                reg.close()
            except Exception:
                pass
        _SHARED.clear()
