from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from yama.commit import GrantDenied, commit_effect
from yama.grant import issue_grant
from yama.provenance import Provenance, TrustLevel
from yama.remote import HttpGrantStore, SupervisorServer

from examples.remote_revocation import run_experiment


def _purpose() -> str:
    return "write the delayed report"


def _grant(**kwargs):
    values = {
        "principal": "worker",
        "purpose": _purpose(),
        "allowed_effects": ["write_report"],
        "ttl": timedelta(minutes=5),
    }
    values.update(kwargs)
    return issue_grant(**values)


def _prov(grant) -> Provenance:
    return Provenance(
        origin="worker",
        trust_level=TrustLevel.HIGH,
        purpose_binding=grant.purpose,
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def servers(tmp_path: Path):
    server = SupervisorServer(tmp_path / "store", host="127.0.0.1", port=0).start()
    try:
        yield (
            HttpGrantStore(server.url, readonly=False),
            HttpGrantStore(server.url, readonly=True),
        )
    finally:
        server.stop()


def test_control_commit_is_allowed(tmp_path: Path, servers) -> None:
    supervisor, worker = servers
    grant = _grant()
    supervisor.put(grant)
    dest = tmp_path / "out.txt"
    commit_effect(worker, grant.id, "write_report", dest, "ok\n", provenance=_prov(grant))
    assert dest.read_text(encoding="utf-8") == "ok\n"


def test_revocation_before_commit_is_refused(tmp_path: Path, servers) -> None:
    supervisor, worker = servers
    grant = _grant()
    supervisor.put(grant)
    obtained = worker.get(grant.id)
    assert obtained.is_valid()
    supervisor.revoke(grant.id)
    dest = tmp_path / "out.txt"
    with pytest.raises(GrantDenied) as caught:
        commit_effect(worker, grant.id, "write_report", dest, "nope", provenance=_prov(grant))
    assert caught.value.reason == "revoked"
    assert not dest.exists()


def test_experiment_small_n_matches_expected_outcomes(tmp_path: Path) -> None:
    report = run_experiment(trials=3, delay_s=0.02, work_dir=tmp_path / "exp")
    assert report["treatment"]["n"] == 3
    assert report["treatment"]["refused"] == 3
    assert report["treatment"]["allowed"] == 0
    assert report["treatment"]["reason_counts"] == {"revoked": 3}
    assert report["control"]["allowed"] == 3
    assert report["control"]["refused"] == 0
