from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from yama.commit import GrantDenied, atomic_write, check_effect, commit_effect
from yama.grant import GrantStore, issue_grant


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _past() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=1)


def _store_with_grant(tmp_path: Path, **kwargs):
    store = GrantStore(tmp_path / "store")
    values = {
        "principal": "writer",
        "purpose": "write the report",
        "allowed_effects": ["write_report"],
        "expiry": _future(),
    }
    values.update(kwargs)
    grant = issue_grant(**values)
    store.put(grant)
    return store, grant


def test_commit_writes_when_grant_permits(tmp_path: Path) -> None:
    store, grant = _store_with_grant(tmp_path)
    dest = tmp_path / "out" / "report.txt"
    returned = commit_effect(store, grant.id, "write_report", dest, "hello\n")
    assert returned.id == grant.id
    assert dest.read_text(encoding="utf-8") == "hello\n"


def test_commit_denied_for_unknown_effect(tmp_path: Path) -> None:
    store, grant = _store_with_grant(tmp_path)
    dest = tmp_path / "out" / "report.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(store, grant.id, "wipe_disk", dest, "nope")
    assert caught.value.reason == "effect_not_allowed"
    assert not dest.exists()


def test_commit_denied_after_supervisor_revoke(tmp_path: Path) -> None:
    store, grant = _store_with_grant(tmp_path)
    dest = tmp_path / "out" / "report.txt"
    commit_effect(store, grant.id, "write_report", dest, "first\n")

    supervisor = GrantStore(tmp_path / "store")
    supervisor.revoke(grant.id)

    with pytest.raises(GrantDenied) as caught:
        commit_effect(store, grant.id, "write_report", dest, "second\n")
    assert caught.value.reason == "revoked"
    assert dest.read_text(encoding="utf-8") == "first\n"


def test_commit_rereads_store_and_sees_expiry(tmp_path: Path) -> None:
    store, grant = _store_with_grant(tmp_path)
    dest = tmp_path / "out" / "report.txt"

    # Replace the on-disk grant with an expired copy without going through
    # the in-memory object the worker might still be holding.
    expired = issue_grant(
        principal=grant.principal,
        purpose=grant.purpose,
        allowed_effects=grant.allowed_effects,
        expiry=_past(),
        grant_id=grant.id,
    )
    GrantStore(tmp_path / "store").put(expired)

    with pytest.raises(GrantDenied) as caught:
        commit_effect(store, grant.id, "write_report", dest, "too late")
    assert caught.value.reason == "expired"
    assert not dest.exists()


def test_commit_denied_when_grant_missing(tmp_path: Path) -> None:
    store = GrantStore(tmp_path / "store")
    dest = tmp_path / "out" / "report.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(store, "missing-id", "write_report", dest, "nope")
    assert caught.value.reason == "not_found"
    assert not dest.exists()


def test_check_effect_returns_fresh_grant(tmp_path: Path) -> None:
    store, grant = _store_with_grant(tmp_path)
    loaded = check_effect(store, grant.id, "write_report")
    assert loaded.id == grant.id


def test_atomic_write_replaces_existing(tmp_path: Path) -> None:
    dest = tmp_path / "file.txt"
    atomic_write(dest, "one")
    atomic_write(dest, "two")
    assert dest.read_text(encoding="utf-8") == "two"
    leftovers = list(tmp_path.glob(".file.txt.*.tmp"))
    assert leftovers == []
