#!/usr/bin/env python3
"""Illustrative OT setpoint-change commit path for the use-case document.

This is a local demonstration of grant issue, provenance checks, refusal
reasons, and an allowed commit. The protocol gateway is simulated as a
supervisor-owned sink that writes a file after a successful commit
decision. It does not speak Modbus, EtherNet/IP, or any other industrial
protocol, and it is not a deployed OT system.

Run from the repository root after ``pip install -e .``::

    python examples/ot_setpoint.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if (SRC / "yama").is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from yama.commit import GrantDenied, commit_effect  # noqa: E402
from yama.grant import Grant, GrantStore  # noqa: E402
from yama.provenance import Provenance, TrustLevel  # noqa: E402

GRANT_ID = "grant-ot-2026-11-24-line3"
PURPOSE = "setpoint change \u2013 line 3"
EFFECT = "write_setpoint"
# The draft use-case used Unix 1763917200.0 / 1763913600.0, which are
# 2025-11-23T17:00:00Z and 2025-11-23T16:00:00Z and are already past.
# Samples use the same clock times on 24 Nov 2026.
EXPIRY = datetime(2026, 11, 24, 17, 0, 0, tzinfo=timezone.utc)
PROVENANCE_TS = datetime(2026, 11, 24, 16, 0, 0, tzinfo=timezone.utc)
PAST_EXPIRY = datetime(2025, 11, 23, 17, 0, 0, tzinfo=timezone.utc)
GATEWAY_RECORD = "setpoint write demo only: line 3, work order WO-4412\n"


def sample_grant(*, expiry: datetime = EXPIRY, revoked: bool = False) -> Grant:
    return Grant(
        id=GRANT_ID,
        principal="workorder:WO-4412",
        purpose=PURPOSE,
        allowed_effects={EFFECT},
        expiry=expiry,
        revoked=revoked,
        min_trust_level=TrustLevel.MEDIUM,
    )


def sample_provenance(*, purpose: str = PURPOSE) -> Provenance:
    return Provenance(
        origin="engineering-workstation",
        trust_level=TrustLevel.MEDIUM,
        purpose_binding=purpose,
        timestamp=PROVENANCE_TS,
    )


def refusal(exc: GrantDenied) -> dict:
    return {
        "outcome": "refused",
        "reason": exc.reason,
        "message": str(exc),
        "grant_id": exc.grant_id,
        "effect": exc.effect,
    }


def main() -> int:
    grant = sample_grant()
    provenance = sample_provenance()
    print("=== sample grant (Grant.to_json) ===")
    print(grant.to_json(), end="")
    print("=== sample provenance (Provenance.to_json) ===")
    print(provenance.to_json(), end="")

    with tempfile.TemporaryDirectory(prefix="yama-ot-") as tmp:
        store_dir = Path(tmp) / "store"
        out_dir = Path(tmp) / "out"
        out_dir.mkdir()
        supervisor = GrantStore(store_dir, readonly=False)

        def attempt(label: str, current: Grant, tag: Provenance | None, dest_name: str) -> None:
            supervisor.put(current)
            dest = out_dir / dest_name
            print(f"=== {label} ===")
            try:
                commit_effect(
                    supervisor,
                    current.id,
                    EFFECT,
                    dest,
                    GATEWAY_RECORD,
                    provenance=tag,
                )
            except GrantDenied as exc:
                print(json.dumps(refusal(exc), indent=2, sort_keys=True))
                print(f"file_exists: {dest.exists()}")
                return
            print("unexpected: commit was allowed")

        attempt(
            "refused: revoked grant",
            sample_grant(revoked=True),
            provenance,
            "revoked.txt",
        )
        attempt(
            "refused: expired grant",
            sample_grant(expiry=PAST_EXPIRY),
            provenance,
            "expired.txt",
        )
        attempt(
            "refused: purpose_mismatch",
            grant,
            sample_provenance(purpose="setpoint change \u2013 line 4"),
            "mismatch.txt",
        )
        attempt("refused: provenance_missing", grant, None, "missing.txt")

        supervisor.put(grant)
        dest = out_dir / "setpoint-write.txt"
        print("=== allowed commit ===")
        committed = commit_effect(
            supervisor,
            grant.id,
            EFFECT,
            dest,
            GATEWAY_RECORD,
            provenance=provenance,
        )
        audit = {
            "outcome": "allowed",
            "effect": EFFECT,
            "path": str(dest.name),
            "grant_id": committed.id,
            "provenance": provenance.to_dict(),
        }
        print(json.dumps(audit, indent=2, sort_keys=True))
        print(f"file_exists: {dest.exists()}")
        print(f"file_contents: {dest.read_text(encoding='utf-8')!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
