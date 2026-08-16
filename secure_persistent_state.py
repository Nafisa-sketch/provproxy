from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PersistenceError(RuntimeError):
    """Base persistence failure."""


class PersistenceCorruptionError(PersistenceError):
    """Raised when authenticated state cannot be verified/decrypted."""


class KeyProtectionError(PersistenceError):
    """Raised when the master key cannot be protected or recovered."""


@dataclass
class _Fragment:
    data: str
    timestamp: float


class _WindowsDPAPI:
    """
    Windows DPAPI wrapper.

    The AES-256 master key is protected with CryptProtectData and therefore
    is not written to disk as plaintext. The protected blob is user-bound
    by Windows.
    """

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

        in_blob, in_buf = cls._blob_from_bytes(data)
        out_blob = cls.DATA_BLOB()

        ok = crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            "ProvProxy P6 master key",
            None,
            None,
            None,
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

        in_blob, in_buf = cls._blob_from_bytes(protected)
        out_blob = cls.DATA_BLOB()

        ok = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
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
    """
    Authenticated, append-only persistent state for ProvProxy P6.

    Improvements over the earlier prototype:
      * AES-256-GCM authenticated encryption instead of reversible string masking.
      * Windows DPAPI protects the AES key at rest.
      * Append-only journal: add_fragment() does NOT rewrite the whole state.
      * Atomic encrypted snapshots for periodic compaction.
      * Monotonic record sequence numbers prevent duplicate replay after a crash
        during compaction.
      * Corruption/tampering is fail-closed by default instead of silently
        resetting provenance state.
      * Session + destination + source isolation is preserved.
      * TTL filtering is applied on load and read.

    Durability:
      * Every append is Python-flushed immediately.
      * `fsync_every=1` gives strongest crash/power-loss durability at higher cost.
      * Default `fsync_every=16` is a practical research/prototype trade-off.
        Process restart continuity is retained, while disk sync cost is amortized.
    """

    FORMAT_VERSION = 1
    AAD_PREFIX = b"provproxy-p6-state-v1:"

    def __init__(
        self,
        state_dir: str | os.PathLike[str] = ".provproxy_state",
        *,
        ttl_seconds: int = 300,
        fsync_every: int = 16,
        compact_every: int = 2000,
        fail_closed_on_corruption: bool = True,
        allow_file_key_fallback: bool = False,
    ):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if fsync_every <= 0:
            raise ValueError("fsync_every must be > 0")
        if compact_every <= 0:
            raise ValueError("compact_every must be > 0")

        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.journal_path = self.state_dir / "state.journal"
        self.snapshot_path = self.state_dir / "state.snapshot"
        self.key_path = self.state_dir / "master.key.dpapi"

        self.ttl_seconds = ttl_seconds
        self.fsync_every = fsync_every
        self.compact_every = compact_every
        self.fail_closed_on_corruption = fail_closed_on_corruption
        self.allow_file_key_fallback = allow_file_key_fallback

        self._lock = threading.RLock()
        self._state: dict[tuple[str, str, str], list[_Fragment]] = {}
        self._seq = 0
        self._snapshot_seq = 0
        self._appends_since_fsync = 0
        self._appends_since_compact = 0

        self._master_key = self._load_or_create_master_key()
        if len(self._master_key) != 32:
            raise KeyProtectionError("Expected a 32-byte AES-256 master key.")
        self._aesgcm = AESGCM(self._master_key)

        self._load_state()

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

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
                        f"Unable to recover DPAPI-protected master key: {exc}"
                    ) from exc

            key = secrets.token_bytes(32)
            protected = _WindowsDPAPI.protect(key)
            self._atomic_write_bytes(self.key_path, protected)
            return key

        # Non-Windows fallback is deliberately opt-in so production users
        # do not accidentally store an unprotected key beside ciphertext.
        if not self.allow_file_key_fallback:
            raise KeyProtectionError(
                "No OS key protector configured on this platform. "
                "Set PROVPROXY_MASTER_KEY_B64 to a securely supplied 32-byte key, "
                "or use allow_file_key_fallback=True for local testing only."
            )

        fallback = self.state_dir / "master.key.dev"
        if fallback.exists():
            key = fallback.read_bytes()
            if len(key) != 32:
                raise KeyProtectionError("Development key file is invalid.")
            return key

        key = secrets.token_bytes(32)
        self._atomic_write_bytes(fallback, key)
        try:
            os.chmod(fallback, 0o600)
        except OSError:
            pass
        return key

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    def _encrypt_record(self, kind: str, payload: dict[str, Any]) -> bytes:
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        aad = self.AAD_PREFIX + kind.encode("ascii")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        envelope = {
            "v": self.FORMAT_VERSION,
            "kind": kind,
            "n": base64.b64encode(nonce).decode("ascii"),
            "c": base64.b64encode(ciphertext).decode("ascii"),
        }
        return (
            json.dumps(envelope, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )

    def _decrypt_record(self, raw: bytes, expected_kind: str | None = None) -> dict[str, Any]:
        try:
            envelope = json.loads(raw.decode("utf-8"))
            if envelope.get("v") != self.FORMAT_VERSION:
                raise PersistenceCorruptionError("Unsupported persistence format.")
            kind = envelope["kind"]
            if expected_kind is not None and kind != expected_kind:
                raise PersistenceCorruptionError(
                    f"Expected record kind {expected_kind!r}, got {kind!r}."
                )
            nonce = base64.b64decode(envelope["n"], validate=True)
            ciphertext = base64.b64decode(envelope["c"], validate=True)
            aad = self.AAD_PREFIX + kind.encode("ascii")
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
            payload = json.loads(plaintext.decode("utf-8"))
            payload["_kind"] = kind
            return payload
        except PersistenceCorruptionError:
            raise
        except Exception as exc:
            raise PersistenceCorruptionError(
                "Encrypted persistence record failed authentication or parsing."
            ) from exc

    # ------------------------------------------------------------------
    # Load / replay
    # ------------------------------------------------------------------

    def _load_state(self) -> None:
        with self._lock:
            self._state.clear()
            self._seq = 0
            self._snapshot_seq = 0

            if self.snapshot_path.exists() and self.snapshot_path.stat().st_size:
                try:
                    payload = self._decrypt_record(
                        self.snapshot_path.read_bytes(),
                        expected_kind="snapshot",
                    )
                    self._snapshot_seq = int(payload.get("last_seq", 0))
                    self._seq = self._snapshot_seq
                    self._restore_snapshot_entries(payload.get("entries", []))
                except PersistenceCorruptionError:
                    if self.fail_closed_on_corruption:
                        raise

            if self.journal_path.exists():
                with self.journal_path.open("rb") as fh:
                    for line_no, line in enumerate(fh, 1):
                        if not line.strip():
                            continue
                        try:
                            payload = self._decrypt_record(
                                line,
                                expected_kind="add",
                            )
                            seq = int(payload["seq"])
                            # Old journal records may remain if a crash happened
                            # after snapshot replace but before journal truncation.
                            if seq <= self._snapshot_seq:
                                continue
                            self._apply_add_payload(payload)
                            self._seq = max(self._seq, seq)
                        except PersistenceCorruptionError as exc:
                            if self.fail_closed_on_corruption:
                                raise PersistenceCorruptionError(
                                    f"Journal corruption at line {line_no}: {exc}"
                                ) from exc

            self._prune_expired_locked()

    def _restore_snapshot_entries(self, entries: list[dict[str, Any]]) -> None:
        now = time.time()
        for row in entries:
            ts = float(row["timestamp"])
            if now - ts > self.ttl_seconds:
                continue
            key = (
                str(row["session_id"]),
                str(row["destination"]),
                str(row["source"]),
            )
            self._state.setdefault(key, []).append(
                _Fragment(data=str(row["data"]), timestamp=ts)
            )

    def _apply_add_payload(self, payload: dict[str, Any]) -> None:
        ts = float(payload["timestamp"])
        if time.time() - ts > self.ttl_seconds:
            return
        key = (
            str(payload["session_id"]),
            str(payload["destination"]),
            str(payload["source"]),
        )
        self._state.setdefault(key, []).append(
            _Fragment(data=str(payload["data"]), timestamp=ts)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_fragment(
        self,
        session_id: str,
        destination: str,
        source: str,
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
                "source": source,
                "data": fragment_data,
                "timestamp": ts,
            }

            line = self._encrypt_record("add", payload)

            # Append one authenticated record instead of rewriting all state.
            with self.journal_path.open("ab") as fh:
                fh.write(line)
                fh.flush()
                self._appends_since_fsync += 1
                if self._appends_since_fsync >= self.fsync_every:
                    os.fsync(fh.fileno())
                    self._appends_since_fsync = 0

            key = (session_id, destination, source)
            self._state.setdefault(key, []).append(
                _Fragment(data=fragment_data, timestamp=ts)
            )

            self._appends_since_compact += 1
            if self._appends_since_compact >= self.compact_every:
                self._compact_locked()

    def get_accumulated(
        self,
        session_id: str,
        destination: str,
        source: str,
    ) -> list[str]:
        with self._lock:
            self._prune_expired_locked()
            key = (session_id, destination, source)
            return [frag.data for frag in self._state.get(key, [])]

    def compact(self) -> None:
        with self._lock:
            self._compact_locked()

    def close(self) -> None:
        """
        Force the current journal to disk. Safe to call repeatedly.
        """
        with self._lock:
            if self.journal_path.exists():
                with self.journal_path.open("ab") as fh:
                    fh.flush()
                    os.fsync(fh.fileno())
            self._appends_since_fsync = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # ------------------------------------------------------------------
    # TTL / compaction
    # ------------------------------------------------------------------

    def _prune_expired_locked(self) -> None:
        now = time.time()
        dead = []
        for key, fragments in self._state.items():
            kept = [
                frag
                for frag in fragments
                if now - frag.timestamp <= self.ttl_seconds
            ]
            if kept:
                self._state[key] = kept
            else:
                dead.append(key)
        for key in dead:
            self._state.pop(key, None)

    def _compact_locked(self) -> None:
        self._prune_expired_locked()

        entries: list[dict[str, Any]] = []
        for (session_id, destination, source), fragments in self._state.items():
            for frag in fragments:
                entries.append(
                    {
                        "session_id": session_id,
                        "destination": destination,
                        "source": source,
                        "data": frag.data,
                        "timestamp": frag.timestamp,
                    }
                )

        payload = {
            "last_seq": self._seq,
            "created_at": time.time(),
            "entries": entries,
        }
        encrypted = self._encrypt_record("snapshot", payload)

        # Snapshot first, then journal replacement. Sequence numbers make a
        # crash between these operations replay-safe.
        self._atomic_write_bytes(self.snapshot_path, encrypted)
        self._atomic_write_bytes(self.journal_path, b"")

        self._snapshot_seq = self._seq
        self._appends_since_compact = 0
        self._appends_since_fsync = 0

    # ------------------------------------------------------------------
    # Atomic file helper
    # ------------------------------------------------------------------

    @staticmethod
    def _atomic_write_bytes(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
        with tmp.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
