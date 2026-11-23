from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from yama.grant import Grant, GrantError, GrantNotFound, GrantStore, GrantStoreError, issue_grant


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _past() -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=1)


def test_valid_grant_permits_listed_effect() -> None:
    grant = issue_grant(
        principal="writer",
        purpose="write the report",
        allowed_effects=["write_report", "read_source"],
        expiry=_future(),
    )
    assert grant.is_valid()
    assert grant.permits("write_report")
    assert grant.permits("read_source")
    assert not grant.permits("launch_missile")
    assert grant.denial_reason("launch_missile") == "effect_not_allowed"


def test_expired_grant_is_invalid() -> None:
    grant = issue_grant(
        principal="writer",
        purpose="write the report",
        allowed_effects=["write_report"],
        expiry=_past(),
    )
    assert not grant.is_valid()
    assert not grant.permits("write_report")
    assert grant.denial_reason("write_report") == "expired"


def test_revoked_flag_makes_grant_invalid() -> None:
    grant = issue_grant(
        principal="writer",
        purpose="write the report",
        allowed_effects=["write_report"],
        expiry=_future(),
    )
    revoked = replace(grant, revoked=True)
    assert not revoked.is_valid()
    assert not revoked.permits("write_report")
    assert revoked.denial_reason() == "revoked"


def test_grant_is_immutable() -> None:
    grant = issue_grant(
        principal="writer",
        purpose="write the report",
        allowed_effects=["write_report"],
        expiry=_future(),
    )
    with pytest.raises(FrozenInstanceError):
        grant.revoked = True  # type: ignore[misc]
    with pytest.raises((FrozenInstanceError, AttributeError)):
        grant.allowed_effects = frozenset({"everything"})  # type: ignore[misc]


def test_naive_expiry_is_rejected() -> None:
    with pytest.raises(GrantError, match="timezone-aware"):
        Grant(
            id="g1",
            principal="writer",
            purpose="write",
            allowed_effects=frozenset({"write_report"}),
            expiry=datetime(2026, 11, 23, 12, 0, 0),
        )


def test_json_roundtrip(tmp_path: Path) -> None:
    grant = issue_grant(
        principal="reader",
        purpose="read the source",
        allowed_effects=["read_source"],
        expiry=_future(),
        grant_id="reader-1",
    )
    restored = Grant.from_json(grant.to_json())
    assert restored == grant


def test_store_put_get_and_revoke(tmp_path: Path) -> None:
    store = GrantStore(tmp_path / "store")
    grant = issue_grant(
        principal="shaky",
        purpose="temporary write",
        allowed_effects=["write_report"],
        expiry=_future(),
    )
    store.put(grant)
    loaded = store.get(grant.id)
    assert loaded == grant
    revoked = store.revoke(grant.id)
    assert revoked.revoked is True
    assert store.get(grant.id).revoked is True
    assert not store.get(grant.id).is_valid()


def test_readonly_store_cannot_put_or_revoke(tmp_path: Path) -> None:
    writable = GrantStore(tmp_path / "store")
    grant = issue_grant(
        principal="writer",
        purpose="write the report",
        allowed_effects=["write_report"],
        expiry=_future(),
    )
    writable.put(grant)

    readonly = GrantStore(tmp_path / "store", readonly=True)
    assert readonly.get(grant.id).id == grant.id
    with pytest.raises(GrantStoreError, match="read-only"):
        readonly.revoke(grant.id)
    with pytest.raises(GrantStoreError, match="read-only"):
        readonly.put(replace(grant, purpose="extended by worker"))
    # Supervisor copy on disk is unchanged.
    assert writable.get(grant.id).purpose == "write the report"
    assert writable.get(grant.id).revoked is False


def test_missing_grant_raises(tmp_path: Path) -> None:
    store = GrantStore(tmp_path / "store")
    with pytest.raises(GrantNotFound):
        store.get("does-not-exist")


def test_path_traversal_id_is_rejected(tmp_path: Path) -> None:
    store = GrantStore(tmp_path / "store")
    with pytest.raises(GrantError, match="grant id"):
        store.get("../etc/passwd")
