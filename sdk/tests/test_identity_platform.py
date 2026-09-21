"""Platform contracts of the identity file and the directory lock.

SPEC §21 (POSIX mode 0600 is required), §24 (`flock` on POSIX and `LockFileEx`
exclusive/nonblocking on Windows; failure to establish exclusion is a startup
failure on every platform) and the §140 acceptance case "Windows lock failure
without fail-open behavior".

Self-contained: no server, no network and no `tests/` fixtures. The Windows
primitive is exercised on POSIX by swapping the module-level dispatch, so
`sys.platform` is never mutated. These tests mock the Win32 primitive through
that module seam (`_lock_file_ex`/`_load_kernel32`/etc.); real Windows ABI
verification (`LockFileEx`/`UnlockFileEx` via ctypes) requires a Windows CI
runner.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sealstack import identity
from sealstack.events import AuditFailure, new_uuid
from sealstack.signing import b64url_encode, fingerprint, generate_seed, public_key_from_seed

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX-only contract")

# Fixed, genuinely-derived key material so repeated `_minimal_document()`
# calls (write, then read-back comparison) agree on the exact same document.
_ORGANISATION_ID = new_uuid()
_AGENT_ID = new_uuid()
_ACTIVE_KEY_ID = new_uuid()
_ACTIVE_KEY_SEED = generate_seed()
_ACTIVE_KEY_PUBLIC = public_key_from_seed(_ACTIVE_KEY_SEED)


def _minimal_document() -> dict[str, object]:
    """A valid §18 registered identity document (organisation_id, agent_id and
    active_key populated as lowercase UUID4 strings / real Ed25519 key
    material; pending_key null), the smallest shape `IdentityStore.read`
    accepts for a registered identity."""
    return {
        "schema_version": identity.IDENTITY_SCHEMA_VERSION,
        "organisation_id": _ORGANISATION_ID,
        "agent_id": _AGENT_ID,
        "active_key": {
            "key_id": _ACTIVE_KEY_ID,
            "state": "active",
            "public_key": b64url_encode(_ACTIVE_KEY_PUBLIC),
            "private_key": b64url_encode(_ACTIVE_KEY_SEED),
            "key_fingerprint": fingerprint(_ACTIVE_KEY_PUBLIC),
        },
        "pending_key": None,
    }


def _stored(tmp_path: Path) -> identity.IdentityStore:
    store = identity.IdentityStore(tmp_path)
    store.write(_minimal_document())
    return store


def _raiser(error: BaseException):
    def fail(*_args: object) -> bool:
        raise error

    return fail


# -- §21: POSIX identity file mode -------------------------------------------


@POSIX_ONLY
@pytest.mark.parametrize("mode", [0o400, 0o644])
def test_posix_identity_mode_other_than_0600_is_refused(tmp_path, mode):
    store = _stored(tmp_path)
    store.path.chmod(mode)
    with pytest.raises(AuditFailure) as caught:
        store.read()
    assert "identity_permissions" in str(caught.value)


@POSIX_ONLY
def test_posix_identity_mode_0600_is_accepted(tmp_path):
    store = _stored(tmp_path)
    store.path.chmod(0o600)
    document = store.read()
    assert document == _minimal_document()
    assert document["active_key"]["state"] == "active"


# -- §24: Windows LockFileEx path --------------------------------------------


@pytest.fixture
def windows_locking(monkeypatch):
    """Route `DirectoryLock` through the Windows primitive on any platform."""
    monkeypatch.setattr(identity, "_lock_exclusive_nonblocking", identity._windows_lock_exclusive)
    monkeypatch.setattr(identity, "_unlock", identity._windows_unlock)


@pytest.mark.parametrize(
    "attribute,replacement",
    [
        pytest.param("_lock_file_ex", lambda _handle: False, id="lock-refused"),
        pytest.param("_lock_file_ex", _raiser(OSError("LockFileEx failed")), id="lock-oserror"),
        pytest.param("_load_kernel32", _raiser(AttributeError("windll")), id="no-windll"),
        pytest.param("_load_kernel32", _raiser(ImportError("ctypes")), id="no-ctypes"),
    ],
)
def test_windows_lock_failure_fails_closed(
    tmp_path, monkeypatch, windows_locking, attribute, replacement
):
    store = _stored(tmp_path)
    before = store.path.read_bytes()
    monkeypatch.setattr(identity, attribute, replacement)

    lock = identity.DirectoryLock(tmp_path)
    with pytest.raises(AuditFailure) as caught:
        lock.acquire()

    assert "identity_in_use" in str(caught.value)
    assert lock.held is False  # the lock descriptor was closed, not leaked
    assert store.path.read_bytes() == before


def test_windows_lock_success_holds_and_releases_once(tmp_path, monkeypatch, windows_locking):
    locked: list[int] = []
    unlocked: list[int] = []

    def grant(handle: int) -> bool:
        locked.append(handle)
        return True

    def revoke(handle: int) -> bool:
        unlocked.append(handle)
        return True

    monkeypatch.setattr(identity, "_lock_file_ex", grant)
    monkeypatch.setattr(identity, "_unlock_file_ex", revoke)

    lock = identity.DirectoryLock(tmp_path)
    lock.acquire()
    assert lock.held is True
    assert len(locked) == 1

    lock.release()
    assert lock.held is False
    assert len(unlocked) == 1


# -- §24: POSIX flock exclusion ----------------------------------------------


@POSIX_ONLY
def test_posix_second_directory_lock_is_refused(tmp_path):
    owner = identity.DirectoryLock(tmp_path)
    owner.acquire()
    try:
        loser = identity.DirectoryLock(tmp_path)
        with pytest.raises(AuditFailure) as caught:
            loser.acquire()
        assert "identity_in_use" in str(caught.value)
        assert loser.held is False
    finally:
        owner.release()
