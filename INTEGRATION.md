# Integrating Yama

Yama is intentionally a small, integrable control-plane utility, not a complete banking or agent platform. It exists so that larger products can enforce supervisor-owned commit control, process restraint, and provenance binding on protected effects without rebuilding those mechanisms. The project is released as freeware under the MIT license so that any system can adopt, audit, or extend the control plane while keeping its own business logic, sinks, and user experience.

Larger products keep their own business logic, sinks, and user experience. They call Yama only for protected-effect commit decisions: issue and revoke grants in a supervisor-owned store, attach a provenance tag to each payload, re-check immediately before the effect is made durable, and optionally restrain the agent process.

## Calling the control plane

The names below are the public Python API and CLI in this repository (`src/yama`).

- **Grants.** The supervisor calls `issue_grant(...)` and `GrantStore.put` to issue a grant, and `GrantStore.revoke` to revoke it. Workers open `GrantStore(..., readonly=True)` and must not be able to write the store.
- **Provenance.** Every payload that is committed carries a `Provenance` tag (`origin`, `trust_level`, `purpose_binding`, `timestamp`). `purpose_binding` must equal `grant.purpose`. `trust_level` must meet `grant.required_trust(effect)` (`TrustLevel`: `untrusted < low < medium < high`).
- **Commit-time re-check.** Call `check_commit(store, grant_id, effect, provenance)` or `commit_effect(...)`, which re-reads the grant from the store and then writes atomically. Both raise `GrantDenied` with a stable `reason` of `not_found`, `store_error`, `revoked`, `expired`, `effect_not_allowed`, `provenance_missing`, `purpose_mismatch`, or `insufficient_trust`.
- **Process restraint.** An agent process may call `restrain(...)` (Landlock, optional seccomp-BPF, `PR_SET_NO_NEW_PRIVS`, optional privilege drop / chroot). Read the returned `RestraintReport`; a restraint counts only when its `applied` flag is true.
- **CLI.** `yama grant create|show|revoke|list`, `yama check`, `yama commit`, `yama run --grant ... -- cmd`, and `yama doctor`.

The following snippet was run against the installed package. It issued a grant, refused a purpose-mismatched commit, then allowed a matching one.

```python
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from yama import (
    GrantDenied, GrantStore, Provenance, TrustLevel,
    commit_effect, issue_grant,
)

with TemporaryDirectory() as tmp:
    store = GrantStore(Path(tmp) / "grants")
    grant = issue_grant(
        principal="integration-demo",
        purpose="write the approved report",
        allowed_effects=["write_report"],
        ttl=timedelta(minutes=5),
        min_trust_level=TrustLevel.MEDIUM,
    )
    store.put(grant)
    dest = Path(tmp) / "report.txt"
    now = datetime.now(timezone.utc)
    bad = Provenance(
        origin="demo-agent",
        trust_level=TrustLevel.HIGH,
        purpose_binding="some other purpose",
        timestamp=now,
    )
    try:
        commit_effect(store, grant.id, "write_report", dest, "nope\n", provenance=bad)
    except GrantDenied as exc:
        print(f"refused: {exc.reason}")
    good = Provenance(
        origin="demo-agent",
        trust_level=TrustLevel.HIGH,
        purpose_binding=grant.purpose,
        timestamp=now,
    )
    commit_effect(store, grant.id, "write_report", dest, "ok\n", provenance=good)
    print(f"allowed: {dest.read_text()!r}")
```

## Residual risks

Yama does not replace the product's own sinks or isolation. In particular:

- Filesystem-only Landlock, as applied by the current `restrain()` path, did not block an outbound TCP connection in the measured baseline ([docs/measurements/baseline_attacks-2026-11-23.json](docs/measurements/baseline_attacks-2026-11-23.json)). Network blocking needs Landlock ABI ≥ 4 TCP-connect rules or seccomp-BPF, which are not yet implemented or measured.
- A time-of-check to time-of-write window remains after a successful re-check. On one localhost run it was median 0.001498 s and max 0.002449 s ([docs/measurements/remote_revocation-2026-11-23.json](docs/measurements/remote_revocation-2026-11-23.json)).
- Provenance tags are asserted metadata; Yama does not verify that payload content is truthful. Authorization alone does not provide semantic safety. See [docs/YAMA-RESEARCH-NOTE.md](docs/YAMA-RESEARCH-NOTE.md) and [docs/security-model.md](docs/security-model.md).
