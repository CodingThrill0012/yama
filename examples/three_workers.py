#!/usr/bin/env python3
"""Three-worker demonstration of supervisor-owned grants and restrained commits.

The supervisor issues three grants, starts three worker subprocesses, and
revokes one grant mid-run:

  * reader  — may perform the ``read_source`` effect, not ``write_report``.
  * writer  — may commit ``write_report`` throughout the run.
  * shaky   — may commit ``write_report`` until the supervisor revokes the grant.

Each worker applies process restraints when the kernel supports them, then
attempts commits. If Landlock or seccomp-BPF is unavailable, the process
continues and reports that fact; it does not crash and does not claim
that those restraints were applied.

Run from the repository root after ``pip install -e .``::

    python examples/three_workers.py
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if (SRC / "yama").is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from yama.commit import GrantDenied, commit_effect  # noqa: E402
from yama.grant import GrantStore, GrantStoreError, issue_grant  # noqa: E402
from yama.provenance import Provenance, TrustLevel  # noqa: E402
from yama.restrict import restrain  # noqa: E402


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _wait_for(path: Path, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise SystemExit(f"timed out waiting for {path}")


def worker_main(role: str, store_dir: Path, work_dir: Path, grant_id: str) -> int:
    sync = work_dir / "sync"
    out = work_dir / "out"
    log_path = work_dir / "logs" / f"{role}.log"
    lines: list[str] = []

    # Workers open the store read-only so they cannot self-extend or revoke.
    store = GrantStore(store_dir, readonly=True)

    report = restrain(
        read_paths=[str(store_dir), str(work_dir)],
        write_paths=[str(work_dir)],
        include_runtime_reads=True,
        no_new_privs=True,
    )
    lines.append(f"{role}: restraints:\n{report.format()}")

    # A write against the store should be refused by the API, and also by
    # Landlock when that restraint was actually applied.
    try:
        store.revoke(grant_id)
        lines.append(f"{role}: ERROR: read-only store allowed revoke")
    except GrantStoreError as exc:
        lines.append(f"{role}: store correctly refused worker revoke ({exc})")

    _write(sync / f"{role}.ready", "ready\n")
    _wait_for(sync / "phase1")

    def attempt(phase: str, effect: str, filename: str) -> None:
        dest = out / filename
        grant = store.get(grant_id)
        provenance = Provenance(
            origin=role,
            trust_level=TrustLevel.HIGH,
            purpose_binding=grant.purpose,
            timestamp=datetime.now(timezone.utc),
        )
        try:
            commit_effect(
                store,
                grant_id,
                effect,
                dest,
                f"{role} {phase} {effect}\n",
                provenance=provenance,
            )
            lines.append(f"{role}: {phase} {effect} ALLOWED -> {dest.name}")
        except GrantDenied as exc:
            lines.append(
                f"{role}: {phase} {effect} DENIED ({exc.reason or 'denied'})"
            )

    if role == "reader":
        # "read_source" is permitted, but this demo records that as a check
        # rather than a write. The write_report commit must be denied.
        grant = store.get(grant_id)
        if grant.permits("read_source"):
            source = work_dir / "source.txt"
            text = source.read_text(encoding="utf-8")
            lines.append(f"{role}: phase1 read_source ALLOWED ({len(text)} bytes)")
        else:
            lines.append(f"{role}: phase1 read_source DENIED ({grant.denial_reason('read_source')})")
        attempt("phase1", "write_report", "reader-report.txt")
    else:
        attempt("phase1", "write_report", f"{role}-report-1.txt")

    _write(sync / f"{role}.phase1", "done\n")
    _wait_for(sync / "phase2")

    if role == "reader":
        attempt("phase2", "write_report", "reader-report.txt")
    else:
        attempt("phase2", "write_report", f"{role}-report-2.txt")

    _write(log_path, "\n".join(lines) + "\n")
    _write(sync / f"{role}.done", "done\n")
    return 0


def supervisor_main() -> int:
    work_dir = Path(os.environ.get("YAMA_DEMO_DIR", "/tmp/yama-three-workers"))
    if work_dir.exists():
        for child in sorted(work_dir.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
    store_dir = work_dir / "store"
    sync = work_dir / "sync"
    logs = work_dir / "logs"
    out = work_dir / "out"
    for path in (store_dir, sync, logs, out):
        path.mkdir(parents=True, exist_ok=True)
    _write(work_dir / "source.txt", "source material for the reader worker\n")

    store = GrantStore(store_dir, readonly=False)
    ttl = timedelta(minutes=10)
    grants = {
        "reader": issue_grant(
            principal="reader",
            purpose="read the shared source material",
            allowed_effects=["read_source"],
            ttl=ttl,
        ),
        "writer": issue_grant(
            principal="writer",
            purpose="write the approved report",
            allowed_effects=["write_report"],
            ttl=ttl,
        ),
        "shaky": issue_grant(
            principal="shaky",
            purpose="write the report until the supervisor revokes access",
            allowed_effects=["write_report"],
            ttl=ttl,
        ),
    }
    for grant in grants.values():
        store.put(grant)

    print("Yama three-worker demonstration")
    print(f"work directory: {work_dir}")
    print("issued grants:")
    for role, grant in grants.items():
        print(f"  {role}: {grant.id} effects={sorted(grant.allowed_effects)}")
    print()

    sys.stdout.flush()
    sys.stderr.flush()
    children: list[int] = []
    for role, grant in grants.items():
        pid = os.fork()
        if pid == 0:
            try:
                raise SystemExit(worker_main(role, store_dir, work_dir, grant.id))
            except Exception as exc:  # noqa: BLE001 — surface any worker failure
                _write(logs / f"{role}.log", f"{role}: crashed: {exc}\n")
                _write(sync / f"{role}.done", "crashed\n")
                raise SystemExit(1)
        children.append(pid)

    for role in grants:
        _wait_for(sync / f"{role}.ready")
    print("all workers ready; starting phase 1 (shaky grant still valid)")
    _write(sync / "phase1", "go\n")

    for role in grants:
        _wait_for(sync / f"{role}.phase1")
    print("phase 1 complete; supervisor revokes the shaky grant")
    revoked = store.revoke(grants["shaky"].id)
    print(f"  revoked {revoked.id} (revoked={revoked.revoked})")
    _write(sync / "phase2", "go\n")

    for role in grants:
        _wait_for(sync / f"{role}.done")

    status_ok = True
    for pid in children:
        _, status = os.waitpid(pid, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            status_ok = False
            print(f"worker pid {pid} exited abnormally: {status}", file=sys.stderr)

    print()
    print("worker logs:")
    for role in grants:
        log = logs / f"{role}.log"
        print(f"----- {role} -----")
        if log.exists():
            print(log.read_text(encoding="utf-8"), end="")
        else:
            print("(missing log)")
            status_ok = False

    print("output files:", ", ".join(sorted(p.name for p in out.glob("*"))) or "(none)")
    expected_present = {"writer-report-1.txt", "writer-report-2.txt", "shaky-report-1.txt"}
    expected_absent = {"reader-report.txt", "shaky-report-2.txt"}
    present = {p.name for p in out.glob("*")}
    failed = False
    if not expected_present <= present:
        print(f"error: missing expected output: {sorted(expected_present - present)}", file=sys.stderr)
        failed = True
    unexpected = expected_absent & present
    if unexpected:
        print(f"error: output that should have been denied: {sorted(unexpected)}", file=sys.stderr)
        failed = True
    if failed or not status_ok:
        return 1
    print("demo result: allowed vs denied outcomes match the grants.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        # Reserved for an alternate spawn path; the demo uses fork().
        raise SystemExit("internal worker entry is not used")
    raise SystemExit(supervisor_main())
