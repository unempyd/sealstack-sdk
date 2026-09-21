"""Local agent identity: directory ownership, identity file and registration.

SPEC §14 (registration), §16 (fingerprint), §18 (identity file), §20
(versioning), §21 (permissions), §22 (atomic writes), §24 (exclusive owner).

Key rotation execution (§71–§77) is out of scope here; this module only
preserves the documented file shapes and refuses to sign while the identity is
unregistered or holds an unresolved pending key.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any, Final

import httpx

from product.events import AuditFailure, log_error, new_uuid
from product.signing import (
    b64url_decode,
    b64url_encode,
    fingerprint,
    generate_seed,
    public_key_from_seed,
    sign,
    strict_loads,
)

if sys.platform == "win32":  # pragma: no cover - POSIX is the tested platform
    import ctypes
    import msvcrt

    class _Overlapped(ctypes.Structure):
        """The ``OVERLAPPED`` block ``LockFileEx`` requires (zeroed offsets)."""

        _fields_ = (
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", ctypes.c_ulong),
            ("OffsetHigh", ctypes.c_ulong),
            ("hEvent", ctypes.c_void_p),
        )
else:
    import fcntl

IDENTITY_SCHEMA_VERSION: Final[int] = 1
IDENTITY_FILENAME: Final[str] = "identity.json"
LOCK_FILENAME: Final[str] = "identity.lock"
SEED_LENGTH: Final[int] = 32
REGISTRATION_RETRY_SECONDS: Final[float] = 5.0
REGISTRATION_TIMEOUT_SECONDS: Final[float] = 10.0
REQUIRED_IDENTITY_MODE: Final[int] = 0o600
LOCKFILE_FAIL_IMMEDIATELY: Final[int] = 0x0001
LOCKFILE_EXCLUSIVE_LOCK: Final[int] = 0x0002


class DirectoryLock:
    """The single-owner lock on a local state directory (§24).

    The lock is taken on the stable ``identity.lock`` inode before anything is
    read, generated or opened, so a losing owner mutates nothing.
    """

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / LOCK_FILENAME
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _lock_exclusive_nonblocking(fd)
        except OSError as exc:
            os.close(fd)
            raise AuditFailure(f"identity_in_use: {self.state_dir}") from exc
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        """Unlock and close; safe to call repeatedly."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            _unlock(fd)
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def abandon(self) -> None:
        """Close an inherited descriptor in a forked child without unlocking (§24)."""
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _lock_exclusive_nonblocking(fd: int) -> None:
    """Take the platform's exclusive, nonblocking lock; failure raises OSError."""
    if sys.platform == "win32":  # pragma: no cover - POSIX is the tested platform
        _windows_lock_exclusive(fd)
    else:
        _flock_exclusive(fd)


def _unlock(fd: int) -> None:
    """Release the lock taken by :func:`_lock_exclusive_nonblocking`."""
    if sys.platform == "win32":  # pragma: no cover - POSIX is the tested platform
        _windows_unlock(fd)
    else:
        _flock_unlock(fd)


def _flock_exclusive(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _flock_unlock(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)


def _windows_lock_exclusive(fd: int) -> None:
    """``LockFileEx`` exclusive/nonblocking exclusion, failing closed (§24).

    A refused lock, an OSError and an unusable ctypes/kernel32 binding are all
    reported as OSError, so :meth:`DirectoryLock.acquire` turns every one of
    them into ``identity_in_use`` rather than proceeding unprotected.
    """
    try:
        granted = _lock_file_ex(_windows_os_handle(fd))
    except OSError:
        raise
    except Exception as exc:  # ctypes/kernel32 unavailable -> still fail closed
        raise OSError(f"windows_lock_unavailable: {exc}") from exc
    if not granted:
        raise OSError(f"windows_lock_refused: fd {fd}")


def _windows_unlock(fd: int) -> None:
    """Release the ``LockFileEx`` byte lock; failure raises OSError."""
    try:
        released = _unlock_file_ex(_windows_os_handle(fd))
    except OSError:
        raise
    except Exception as exc:
        raise OSError(f"windows_unlock_unavailable: {exc}") from exc
    if not released:
        raise OSError(f"windows_unlock_failed: fd {fd}")


def _windows_os_handle(fd: int) -> int:
    """The Win32 handle behind ``fd``.

    Off Windows there is no handle to fetch; the descriptor is passed through
    and :func:`_lock_file_ex` then refuses for want of a kernel32 binding, so
    exclusion still fails closed instead of being skipped.
    """
    if sys.platform == "win32":  # pragma: no cover - POSIX is the tested platform
        return int(msvcrt.get_osfhandle(fd))
    return fd


def _load_kernel32() -> Any:
    """Bind ``kernel32``; an unavailable binding is a lock failure, not a pass.

    Explicit prototypes are required: without them ctypes marshals bare Python
    ints as 32-bit C ints, truncating a 64-bit ``HANDLE`` above ``2**31`` and
    the ``lpOverlapped`` pointer.
    """
    if sys.platform == "win32":  # pragma: no cover - POSIX is the tested platform
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LockFileEx.argtypes = [
            ctypes.c_void_p,  # hFile
            ctypes.c_ulong,  # dwFlags
            ctypes.c_ulong,  # dwReserved
            ctypes.c_ulong,  # nNumberOfBytesToLockLow
            ctypes.c_ulong,  # nNumberOfBytesToLockHigh
            ctypes.c_void_p,  # lpOverlapped
        ]
        kernel32.LockFileEx.restype = ctypes.c_int
        kernel32.UnlockFileEx.argtypes = [
            ctypes.c_void_p,  # hFile
            ctypes.c_ulong,  # dwReserved
            ctypes.c_ulong,  # nNumberOfBytesToUnlockLow
            ctypes.c_ulong,  # nNumberOfBytesToUnlockHigh
            ctypes.c_void_p,  # lpOverlapped
        ]
        kernel32.UnlockFileEx.restype = ctypes.c_int
        return kernel32
    raise OSError("kernel32_unavailable: not Windows")


def _lock_file_ex(handle: int) -> bool:
    """One exclusive, nonblocking ``LockFileEx`` byte lock; True when granted."""
    kernel32 = _load_kernel32()
    if sys.platform == "win32":  # pragma: no cover - POSIX is the tested platform
        overlapped = _Overlapped()
        return bool(
            kernel32.LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                ctypes.byref(overlapped),
            )
        )
    raise OSError("lock_file_ex_unavailable: not Windows")


def _unlock_file_ex(handle: int) -> bool:
    """Release the single byte locked by :func:`_lock_file_ex`."""
    kernel32 = _load_kernel32()
    if sys.platform == "win32":  # pragma: no cover - POSIX is the tested platform
        overlapped = _Overlapped()
        return bool(kernel32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped)))
    raise OSError("unlock_file_ex_unavailable: not Windows")


class IdentityStore:
    """Reads and atomically replaces ``identity.json`` (§20–§22)."""

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / IDENTITY_FILENAME
        self.tmp_path = self.state_dir / (IDENTITY_FILENAME + ".tmp")

    def read(self) -> dict[str, Any] | None:
        """Return the stored V1 document, or ``None`` when there is none."""
        try:
            info = self.path.stat()
        except FileNotFoundError:
            return None
        self._check_permissions(info.st_mode)
        raw = self.path.read_bytes()
        try:
            document = strict_loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditFailure(f"invalid_identity_file: {self.path}") from exc
        if not isinstance(document, dict):
            raise AuditFailure(f"invalid_identity_file: {self.path}")
        version = document.get("schema_version")
        if type(version) is not int or version != IDENTITY_SCHEMA_VERSION:
            raise AuditFailure(f"unsupported_identity_version: {version!r}")
        return document

    def _check_permissions(self, raw_mode: int) -> None:
        """POSIX requires exactly 0600; anything else refuses startup (§21).

        Checked from the stat of the file that is about to be read, before any
        content is loaded or parsed.
        """
        if os.name != "posix":  # pragma: no cover - POSIX is the tested platform
            return
        mode = stat.S_IMODE(raw_mode)
        if mode != REQUIRED_IDENTITY_MODE:
            raise AuditFailure(
                f"identity_permissions: {self.path} has mode {mode:04o}, requires 0600"
            )

    def write(self, document: dict[str, Any]) -> None:
        """Serialise a complete replacement and swap it in atomically (§22)."""
        payload = json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
        fd = os.open(self.tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(self.tmp_path, self.path)
        _fsync_directory(self.state_dir)


def _fsync_directory(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover - platforms without directory handles
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - filesystems without directory fsync
        pass
    finally:
        os.close(fd)


class Identity:
    """The agent's durable identity and its Ed25519 signing capability.

    Before successful activation nothing is signed (§14, §18); callers check
    :attr:`can_sign` and receive :attr:`blocked_reason` for diagnostics.
    """

    def __init__(
        self,
        state_dir: Path | str,
        *,
        agent_name: str,
        environment: str,
        base_url: str,
        api_key: str,
        timeout: float = REGISTRATION_TIMEOUT_SECONDS,
    ) -> None:
        self.store = IdentityStore(state_dir)
        self._agent_name = agent_name
        self._environment = environment
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._registration_halted = False
        self._last_attempt = 0.0
        document = self.store.read()
        self._document: dict[str, Any] = document if document is not None else self._bootstrap()

    # -- state -------------------------------------------------------------

    @property
    def document(self) -> dict[str, Any]:
        return self._document

    @property
    def agent_id(self) -> str:
        return str(self._document["agent_id"])

    @property
    def organisation_id(self) -> str | None:
        value = self._document.get("organisation_id")
        return None if value is None else str(value)

    @property
    def active_key(self) -> dict[str, Any] | None:
        key = self._document.get("active_key")
        return key if isinstance(key, dict) else None

    @property
    def agent_key_id(self) -> str | None:
        key = self.active_key
        return None if key is None else str(key.get("key_id"))

    @property
    def key_fingerprint(self) -> str | None:
        """The registered fingerprint of the active key (§16), if any."""
        key = self.active_key
        if key is None:
            return None
        value = key.get("key_fingerprint")
        return None if value is None else str(value)

    @property
    def can_sign(self) -> bool:
        """True only for a registered identity with no unresolved pending key."""
        return (
            self.organisation_id is not None
            and self.active_key is not None
            and self.agent_key_id is not None
            and self._document.get("pending_key") is None
        )

    @property
    def blocked_reason(self) -> str:
        if self.active_key is None or self.organisation_id is None:
            return "unregistered_identity"
        if self._document.get("pending_key") is not None:
            return "rotation_reconciliation_blocked"
        return ""

    def sign(self, raw: bytes) -> str:
        """Sign canonical event bytes with the active key (§34)."""
        key = self.active_key
        if key is None or not self.can_sign:
            raise AuditFailure(f"signing_blocked: {self.blocked_reason}")
        seed = b64url_decode(str(key["private_key"]), SEED_LENGTH)
        return sign(seed, raw)

    # -- registration (§14) ------------------------------------------------

    def _bootstrap(self) -> dict[str, Any]:
        """Persist the durable retry identity before any request is sent (§14)."""
        seed = generate_seed()
        public_raw = public_key_from_seed(seed)
        document = {
            "schema_version": IDENTITY_SCHEMA_VERSION,
            "organisation_id": None,
            "agent_id": new_uuid(),
            "registration": {"name": self._agent_name, "environment": self._environment},
            "active_key": None,
            "pending_key": {
                "key_id": None,
                "state": "pending",
                "public_key": b64url_encode(public_raw),
                "private_key": b64url_encode(seed),
                "key_fingerprint": fingerprint(public_raw),
                "expected_predecessor_key_id": None,
            },
        }
        self.store.write(document)
        return document

    def ensure_registered(self) -> bool:
        """Register if required; never raises, and never regenerates material.

        Returns whether the identity may sign. Automatic retries are bounded
        and stop entirely after an explicit conflict, which is left for
        operator resolution (§14).
        """
        if self.can_sign:
            return True
        if self.active_key is not None:
            return False  # an unresolved pending rotation: §75–§77, not registration
        if self._registration_halted:
            return False
        now = time.monotonic()
        if self._last_attempt and now - self._last_attempt < REGISTRATION_RETRY_SECONDS:
            return False
        self._last_attempt = now
        self._attempt_registration()
        return self.can_sign

    def _attempt_registration(self) -> None:
        pending = self._document.get("pending_key")
        registration = self._document.get("registration")
        if not isinstance(pending, dict) or not isinstance(registration, dict):
            self._registration_halted = True
            log_error("sealstack: identity has no persisted registration request")
            return
        payload = {
            "agent_id": self._document["agent_id"],
            "name": registration.get("name"),
            "environment": registration.get("environment"),
            "public_key": pending["public_key"],
            "key_fingerprint": pending["key_fingerprint"],
        }
        try:
            response = httpx.post(
                f"{self._base_url}/v1/agents/register",
                json=payload,
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=self._timeout,
                follow_redirects=False,
            )
        except BaseException as exc:  # noqa: BLE001 - ambiguous failures retain bootstrap
            log_error("sealstack: agent registration failed: %s", exc)
            return
        if response.status_code in (200, 201):
            self._activate(response, pending)
            return
        if 400 <= response.status_code < 500:
            self._registration_halted = True
            log_error(
                "sealstack: agent registration rejected with HTTP %s; "
                "retries stopped for operator resolution",
                response.status_code,
            )
            return
        log_error("sealstack: agent registration unavailable (HTTP %s)", response.status_code)

    def _activate(self, response: httpx.Response, pending: dict[str, Any]) -> None:
        """Validate the response against the persisted request, then install it."""
        try:
            data = response.json()
        except BaseException:  # noqa: BLE001 - malformed body is an ambiguous failure
            log_error("sealstack: agent registration returned an unreadable body")
            return
        if not isinstance(data, dict):
            log_error("sealstack: agent registration returned a non-object body")
            return
        organisation_id = data.get("organisation_id")
        key_id = data.get("key_id")
        if (
            data.get("agent_id") != self._document["agent_id"]
            or data.get("key_fingerprint") != pending["key_fingerprint"]
            or not isinstance(organisation_id, str)
            or not isinstance(key_id, str)
        ):
            log_error("sealstack: agent registration response did not match the persisted request")
            return
        document = {
            "schema_version": IDENTITY_SCHEMA_VERSION,
            "organisation_id": organisation_id,
            "agent_id": self._document["agent_id"],
            "active_key": {
                "key_id": key_id,
                "state": "active",
                "public_key": pending["public_key"],
                "private_key": pending["private_key"],
                "key_fingerprint": pending["key_fingerprint"],
            },
            "pending_key": None,
        }
        self.store.write(document)
        self._document = document


__all__ = [
    "IDENTITY_FILENAME",
    "IDENTITY_SCHEMA_VERSION",
    "LOCK_FILENAME",
    "DirectoryLock",
    "Identity",
    "IdentityStore",
]
