#!/usr/bin/env python3
"""Illustrative banking-transfer commit path for the use-case document.

This is a local demonstration of grant issue, provenance checks, refusal
reasons, and an allowed commit. It is not a deployed bank system, and it
does not talk to any core-banking API.

Run from the repository root after ``pip install -e .``::

    python examples/banking_transfer.py
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

GRANT_ID = "grant-2026-11-23-7f3a"
PURPOSE = "customer-initiated transfer"
EFFECT = "create_payment_instruction"
# The draft use-case used Unix 1763910000.0, which is 2025-11-23T15:00:00Z
# and is already past. Samples use the same clock time on 23 Nov 2026.
EXPIRY = datetime(2026, 11, 23, 15, 0, 0, tzinfo=timezone.utc)
PROVENANCE_TS = datetime(2026, 11, 23, 14, 55, 0, tzinfo=timezone.utc)


def sample_grant() -> Grant:
    return Grant(
        id=GRANT_ID,
        principal="customer:88421",
        purpose=PURPOSE,
        allowed_effects={EFFECT},
        expiry=EXPIRY,
        revoked=False,
        min_trust_level=TrustLevel.MEDIUM,
    )


def sample_provenance(*, trust: TrustLevel = TrustLevel.MEDIUM, purpose: str = PURPOSE) -> Provenance:
    return Provenance(
        origin="analysis-agent",
        trust_level=trust,
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

    with tempfile.TemporaryDirectory(prefix="yama-banking-") as tmp:
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
                    "instruction: transfer demo only\n",
                    provenance=tag,
                )
            except GrantDenied as exc:
                print(json.dumps(refusal(exc), indent=2, sort_keys=True))
                print(f"file_exists: {dest.exists()}")
                return
            print("unexpected: commit was allowed")

        attempt("refused: revoked grant", replace(grant, revoked=True), provenance, "revoked.txt")
        attempt(
            "refused: purpose_mismatch",
            grant,
            sample_provenance(purpose="limit-increase review"),
            "mismatch.txt",
        )
        attempt("refused: provenance_missing", grant, None, "missing.txt")
        attempt(
            "refused: insufficient_trust",
            grant,
            sample_provenance(trust=TrustLevel.LOW),
            "low-trust.txt",
        )

        supervisor.put(grant)
        dest = out_dir / "payment-instruction.txt"
        print("=== allowed commit ===")
        committed = commit_effect(
            supervisor,
            grant.id,
            EFFECT,
            dest,
            "instruction: transfer demo only\n",
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
