"""The API base URL is configuration, never a built-in default.

`AuditClient` resolves the upload origin from the ``base_url`` argument, then
from ``SEALSTACK_API_URL``. From 0.1.4 there is no third step: with neither set
the constructor raises ``ValueError`` and leaves nothing on disk, rather than
sending a registration request carrying the customer's API key to a host this
project does not operate.

Self-contained: no server, no network and no `tests/` fixtures. Identity and the
uploader are replaced by local doubles so a successful construction touches only
a temporary directory, which is also what lets these tests read back the origin
the client actually handed to them.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sealstack import client as client_module
from sealstack.client import API_URL_ENV_VAR, STATE_DIR_ENV_VAR, AuditClient
from sealstack.events import AuditFailure

ARGUMENT_URL = "http://argument.invalid:8000"
ENVIRONMENT_URL = "http://environment.invalid:9000"


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither SDK variable is inherited from the shell or leaked to a sibling."""
    monkeypatch.delenv(API_URL_ENV_VAR, raising=False)
    monkeypatch.delenv(STATE_DIR_ENV_VAR, raising=False)


class _StubIdentity:
    """Records the origin it was configured with; never registers anything."""

    def __init__(self, state_dir: Path, **options: Any) -> None:
        self.state_dir = state_dir
        self.base_url = options["base_url"]
        self.agent_id = "stub-agent"
        self.agent_key_id = None
        self.key_fingerprint = None
        self.can_sign = False
        self.blocked_reason = "stub identity"

    def ensure_registered(self) -> bool:
        return True


class _StubUploader:
    """Records the origin it was configured with; never starts a thread."""

    def __init__(self, state_dir: Path, **options: Any) -> None:
        self.state_dir = state_dir
        self.base_url = options["base_url"]

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


@pytest.fixture
def offline_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Construct a real `AuditClient` whose identity and uploader are doubles."""
    monkeypatch.setattr(client_module, "Identity", _StubIdentity)
    monkeypatch.setattr(client_module, "Uploader", _StubUploader)
    built: list[AuditClient] = []

    def construct(**options: Any) -> AuditClient:
        options.setdefault("api_key", "test-key")
        options.setdefault("agent_name", "base-url-agent")
        options.setdefault("state_dir", tmp_path / f"state-{len(built)}")
        client = AuditClient(**options)
        built.append(client)
        return client

    yield construct
    for client in reversed(built):
        client.close()


def test_neither_argument_nor_variable_is_a_configuration_error(tmp_path: Path) -> None:
    """The refusal is a `ValueError`, not an `AuditFailure`, and names both settings."""
    state_dir = tmp_path / "state"
    with pytest.raises(ValueError) as raised:
        AuditClient(api_key="test-key", agent_name="base-url-agent", state_dir=state_dir)
    message = str(raised.value)
    assert "base_url=" in message, "the error must name the constructor argument"
    assert API_URL_ENV_VAR in message, "the error must name the environment variable"
    assert not isinstance(raised.value, AuditFailure), "configuration is not an audit failure"
    assert not state_dir.exists(), "a refused construction must not create a state directory"
    assert list(tmp_path.iterdir()) == [], "a refused construction must leave nothing behind"


@pytest.mark.parametrize("failure_mode", ["continue", "raise"])
def test_failure_mode_never_swallows_the_configuration_error(
    tmp_path: Path, failure_mode: str
) -> None:
    """`failure_mode` governs audit failures; it does not silence a misconfiguration."""
    state_dir = tmp_path / "state"
    with pytest.raises(ValueError):
        AuditClient(
            api_key="test-key",
            agent_name="base-url-agent",
            state_dir=state_dir,
            failure_mode=failure_mode,
        )
    assert not state_dir.exists()


def test_no_lock_and_no_identity_survive_the_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The state directory named by the variable is not created, locked or written."""
    state_dir = tmp_path / "from-environment"
    monkeypatch.setenv(STATE_DIR_ENV_VAR, str(state_dir))
    with pytest.raises(ValueError):
        AuditClient(api_key="test-key", agent_name="base-url-agent")
    assert not state_dir.exists(), "no directory, so no lock file and no identity file"


def test_the_argument_wins_over_the_variable(
    monkeypatch: pytest.MonkeyPatch, offline_client: Any
) -> None:
    monkeypatch.setenv(API_URL_ENV_VAR, ENVIRONMENT_URL)
    client = offline_client(base_url=ARGUMENT_URL)
    assert client.base_url == ARGUMENT_URL
    assert client.identity.base_url == ARGUMENT_URL
    assert client._uploader.base_url == ARGUMENT_URL


def test_the_variable_is_used_when_the_argument_is_absent(
    monkeypatch: pytest.MonkeyPatch, offline_client: Any
) -> None:
    monkeypatch.setenv(API_URL_ENV_VAR, ENVIRONMENT_URL)
    client = offline_client()
    assert client.base_url == ENVIRONMENT_URL
    assert client.identity.base_url == ENVIRONMENT_URL
    assert client._uploader.base_url == ENVIRONMENT_URL


def test_the_argument_alone_is_enough(offline_client: Any) -> None:
    """With the variable unset, the argument is the whole configuration."""
    client = offline_client(base_url=ARGUMENT_URL)
    assert client.base_url == ARGUMENT_URL


def test_no_module_level_default_remains() -> None:
    """Nothing in the module still carries a fallback origin."""
    assert not hasattr(client_module, "DEFAULT_BASE_URL")
    source = Path(client_module.__file__).read_text(encoding="utf-8")
    assert "api.sealstack.com" not in source
