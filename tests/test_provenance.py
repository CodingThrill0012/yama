from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from yama.commit import GrantDenied, check_commit, commit_effect
from yama.grant import GrantStore, issue_grant
from yama.provenance import Provenance, ProvenanceError, TrustLevel


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _store(tmp_path: Path, **kwargs):
    store = GrantStore(tmp_path / "store")
    values = {
        "principal": "writer",
        "purpose": "write the approved report",
        "allowed_effects": ["write_report"],
        "expiry": _future(),
        "min_trust_level": TrustLevel.MEDIUM,
    }
    values.update(kwargs)
    grant = issue_grant(**values)
    store.put(grant)
    return store, grant


def _prov(grant, *, trust=TrustLevel.HIGH, purpose=None, origin="writer-1") -> Provenance:
    return Provenance(
        origin=origin,
        trust_level=trust,
        purpose_binding=grant.purpose if purpose is None else purpose,
        timestamp=datetime.now(timezone.utc),
    )


def test_allowed_commit_with_matching_purpose_and_sufficient_trust(tmp_path: Path) -> None:
    store, grant = _store(tmp_path)
    dest = tmp_path / "out" / "report.txt"
    returned = commit_effect(
        store, grant.id, "write_report", dest, "ok\n", provenance=_prov(grant, trust=TrustLevel.MEDIUM)
    )
    assert returned.id == grant.id
    assert dest.read_text(encoding="utf-8") == "ok\n"


def test_refuses_missing_provenance(tmp_path: Path) -> None:
    store, grant = _store(tmp_path)
    dest = tmp_path / "out" / "report.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(store, grant.id, "write_report", dest, "nope")
    assert caught.value.reason == "provenance_missing"
    assert not dest.exists()
    with pytest.raises(GrantDenied) as caught:
        check_commit(store, grant.id, "write_report", None)
    assert caught.value.reason == "provenance_missing"


def test_refuses_insufficient_trust(tmp_path: Path) -> None:
    store, grant = _store(tmp_path, min_trust_level=TrustLevel.MEDIUM)
    dest = tmp_path / "out" / "report.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(
            store,
            grant.id,
            "write_report",
            dest,
            "nope",
            provenance=_prov(grant, trust=TrustLevel.LOW),
        )
    assert caught.value.reason == "insufficient_trust"
    assert not dest.exists()


def test_refuses_purpose_mismatch(tmp_path: Path) -> None:
    store, grant = _store(tmp_path)
    dest = tmp_path / "out" / "report.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(
            store,
            grant.id,
            "write_report",
            dest,
            "nope",
            provenance=_prov(grant, purpose="some other purpose"),
        )
    assert caught.value.reason == "purpose_mismatch"
    assert not dest.exists()


def test_effect_level_threshold_raises_the_bar(tmp_path: Path) -> None:
    store, grant = _store(
        tmp_path,
        allowed_effects=["write_report", "write_draft"],
        min_trust_level=TrustLevel.LOW,
        effect_min_trust={"write_report": TrustLevel.HIGH},
    )
    assert grant.required_trust("write_draft") is TrustLevel.LOW
    assert grant.required_trust("write_report") is TrustLevel.HIGH

    dest = tmp_path / "out" / "draft.txt"
    commit_effect(
        store,
        grant.id,
        "write_draft",
        dest,
        "draft\n",
        provenance=_prov(grant, trust=TrustLevel.LOW),
    )
    assert dest.read_text(encoding="utf-8") == "draft\n"

    dest2 = tmp_path / "out" / "report.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(
            store,
            grant.id,
            "write_report",
            dest2,
            "nope",
            provenance=_prov(grant, trust=TrustLevel.MEDIUM),
        )
    assert caught.value.reason == "insufficient_trust"
    assert not dest2.exists()


def test_effect_level_cannot_lower_grant_floor(tmp_path: Path) -> None:
    store, grant = _store(
        tmp_path,
        min_trust_level=TrustLevel.HIGH,
        effect_min_trust={"write_report": TrustLevel.LOW},
    )
    assert grant.required_trust("write_report") is TrustLevel.HIGH
    dest = tmp_path / "out" / "report.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(
            store,
            grant.id,
            "write_report",
            dest,
            "nope",
            provenance=_prov(grant, trust=TrustLevel.LOW),
        )
    assert caught.value.reason == "insufficient_trust"


def test_grant_purpose_is_checked_not_just_stored(tmp_path: Path) -> None:
    store, grant = _store(tmp_path, purpose="write the approved report")
    # Matching purpose is allowed.
    check_commit(store, grant.id, "write_report", _prov(grant))
    # An allowed effect with a different purpose binding is not.
    with pytest.raises(GrantDenied) as caught:
        check_commit(
            store,
            grant.id,
            "write_report",
            _prov(grant, purpose="write the approved report "),
        )
    assert caught.value.reason == "purpose_mismatch"
    with pytest.raises(GrantDenied) as caught:
        check_commit(
            store,
            grant.id,
            "write_report",
            _prov(grant, purpose="write a different report"),
        )
    assert caught.value.reason == "purpose_mismatch"


def test_provenance_json_roundtrip() -> None:
    tag = Provenance(
        origin="tool:retriever",
        trust_level=TrustLevel.MEDIUM,
        purpose_binding="write the approved report",
        timestamp=datetime(2026, 11, 23, 2, 30, 0, tzinfo=timezone.utc),
    )
    restored = Provenance.from_json(tag.to_json())
    assert restored == tag


def test_trust_level_is_ordered() -> None:
    assert TrustLevel.UNTRUSTED < TrustLevel.LOW < TrustLevel.MEDIUM < TrustLevel.HIGH
    assert TrustLevel.parse("medium") is TrustLevel.MEDIUM
    with pytest.raises(ProvenanceError):
        TrustLevel.parse("trusted")


def test_empty_origin_is_rejected() -> None:
    with pytest.raises(ProvenanceError):
        Provenance(
            origin="",
            trust_level=TrustLevel.HIGH,
            purpose_binding="write the approved report",
            timestamp=datetime.now(timezone.utc),
        )
