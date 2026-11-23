#!/usr/bin/env python3
"""Remote revocation experiment: a localhost supervisor and a delayed commit.

The supervisor is a separate thread serving grant state over HTTP on
127.0.0.1. The worker obtains a grant, waits a configurable delay, and
then calls the commit-time re-check. In the treatment condition the
supervisor revokes the grant after the worker has obtained it and before
the re-check; the re-check must refuse. In the control condition there
is no revocation and the commit must be allowed.

This script is a localhost measurement fixture. It does not simulate a
network partition, packet loss, or a wide-area path.

Run from the repository root after ``pip install -e .``::

    python examples/remote_revocation.py
    python examples/remote_revocation.py --trials 50 --delay 0.05
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if (SRC / "yama").is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from yama.commit import GrantDenied, atomic_write, check_commit  # noqa: E402
from yama.grant import issue_grant  # noqa: E402
from yama.provenance import Provenance, TrustLevel  # noqa: E402
from yama.remote import HttpGrantStore, SupervisorServer  # noqa: E402


def box_specs() -> dict[str, Any]:
    cpu = None
    mem_kb = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                cpu = line.split(":", 1)[1].strip()
                break
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    mem_kb = int(parts[1])
                break
    return {
        "platform": sys.platform,
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": sys.version.split()[0],
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "cpu_model": cpu,
        "mem_total_kib": mem_kb,
    }


def _percentile(values: list[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * fraction
    lo = int(index)
    hi = min(lo + 1, len(ordered) - 1)
    weight = index - lo
    return ordered[lo] * (1.0 - weight) + ordered[hi] * weight


def _summarize(values: list[float]) -> dict[str, Optional[float]]:
    if not values:
        return {"n": 0, "min": None, "median": None, "p95": None, "max": None}
    return {
        "n": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "p95": _percentile(values, 0.95),
        "max": max(values),
    }


def run_trial(
    *,
    supervisor: HttpGrantStore,
    worker: HttpGrantStore,
    work_dir: Path,
    delay_s: float,
    revoke: bool,
    trial_id: int,
) -> dict[str, Any]:
    """Run one delayed-commit trial.

    The worker first obtains the grant (a GET). If ``revoke`` is true, the
    supervisor revokes immediately after that GET. The worker then sleeps
    ``delay_s`` seconds and performs check_commit + atomic_write, which is
    the same sequence as commit_effect, timed so the re-check latency and
    the post-check write window can be reported separately.
    """
    grant = issue_grant(
        principal=f"worker-{trial_id}",
        purpose="write the delayed report",
        allowed_effects=["write_report"],
        ttl=timedelta(minutes=10),
        min_trust_level=TrustLevel.MEDIUM,
    )
    supervisor.put(grant)
    dest = work_dir / f"trial-{trial_id}.txt"
    provenance = Provenance(
        origin=f"worker-{trial_id}",
        trust_level=TrustLevel.HIGH,
        purpose_binding=grant.purpose,
        timestamp=datetime.now(timezone.utc),
    )

    obtained = worker.get(grant.id)
    obtained_valid = obtained.is_valid() and obtained.permits("write_report")
    revoked_at: Optional[float] = None
    if revoke:
        supervisor.revoke(grant.id)
        revoked_at = time.perf_counter()

    if delay_s > 0:
        time.sleep(delay_s)

    recheck_started = time.perf_counter()
    result: dict[str, Any] = {
        "trial_id": trial_id,
        "revoke": revoke,
        "delay_s": delay_s,
        "obtained_valid": obtained_valid,
        "outcome": None,
        "reason": None,
        "recheck_latency_s": None,
        "revoke_to_refuse_s": None,
        "toctou_window_s": None,
    }
    try:
        check_commit(worker, grant.id, "write_report", provenance)
        recheck_ended = time.perf_counter()
        atomic_write(dest, f"trial {trial_id} committed\n")
        write_ended = time.perf_counter()
        result["outcome"] = "allowed"
        result["recheck_latency_s"] = recheck_ended - recheck_started
        result["toctou_window_s"] = write_ended - recheck_ended
        result["wrote"] = dest.exists()
    except GrantDenied as exc:
        recheck_ended = time.perf_counter()
        result["outcome"] = "refused"
        result["reason"] = exc.reason
        result["recheck_latency_s"] = recheck_ended - recheck_started
        if revoked_at is not None:
            result["revoke_to_refuse_s"] = recheck_ended - revoked_at
        result["wrote"] = dest.exists()
    return result


def run_experiment(
    *,
    trials: int = 50,
    delay_s: float = 0.05,
    work_dir: Optional[Path] = None,
) -> dict[str, Any]:
    if trials < 1:
        raise ValueError("trials must be >= 1")
    if delay_s < 0:
        raise ValueError("delay must be >= 0")

    cleanup = False
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="yama-remote-revocation-"))
        cleanup = False  # leave the directory; caller may inspect it
    work_dir = Path(work_dir)
    store_dir = work_dir / "store"
    out_dir = work_dir / "out"
    store_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    server = SupervisorServer(store_dir, host="127.0.0.1", port=0).start()
    try:
        supervisor = HttpGrantStore(server.url, readonly=False)
        worker = HttpGrantStore(server.url, readonly=True)
        started = time.perf_counter()
        treatment = [
            run_trial(
                supervisor=supervisor,
                worker=worker,
                work_dir=out_dir,
                delay_s=delay_s,
                revoke=True,
                trial_id=i,
            )
            for i in range(trials)
        ]
        control = [
            run_trial(
                supervisor=supervisor,
                worker=worker,
                work_dir=out_dir,
                delay_s=delay_s,
                revoke=False,
                trial_id=trials + i,
            )
            for i in range(trials)
        ]
        elapsed = time.perf_counter() - started
    finally:
        server.stop()

    treatment_refused = [row for row in treatment if row["outcome"] == "refused"]
    treatment_allowed = [row for row in treatment if row["outcome"] == "allowed"]
    control_allowed = [row for row in control if row["outcome"] == "allowed"]
    control_refused = [row for row in control if row["outcome"] == "refused"]
    reason_counts: dict[str, int] = {}
    for row in treatment_refused:
        reason_counts[row["reason"] or "unknown"] = reason_counts.get(row["reason"] or "unknown", 0) + 1

    report = {
        "experiment": "remote_revocation",
        "supervisor": "HTTP on 127.0.0.1 (ephemeral port)",
        "trials_per_condition": trials,
        "delay_s": delay_s,
        "work_dir": str(work_dir),
        "box": box_specs(),
        "elapsed_s": elapsed,
        "treatment": {
            "n": trials,
            "refused": len(treatment_refused),
            "allowed": len(treatment_allowed),
            "refusal_rate": len(treatment_refused) / trials,
            "reason_counts": reason_counts,
            "recheck_latency_s": _summarize(
                [row["recheck_latency_s"] for row in treatment if row["recheck_latency_s"] is not None]
            ),
            "revoke_to_refuse_s": _summarize(
                [row["revoke_to_refuse_s"] for row in treatment_refused if row["revoke_to_refuse_s"] is not None]
            ),
        },
        "control": {
            "n": trials,
            "allowed": len(control_allowed),
            "refused": len(control_refused),
            "allow_rate": len(control_allowed) / trials,
            "recheck_latency_s": _summarize(
                [row["recheck_latency_s"] for row in control if row["recheck_latency_s"] is not None]
            ),
            "toctou_window_s": _summarize(
                [row["toctou_window_s"] for row in control_allowed if row["toctou_window_s"] is not None]
            ),
        },
        "limitations": [
            "localhost only; no network partition, loss, or WAN delay was introduced",
            "the HTTP supervisor is an unauthenticated measurement fixture",
            "a TOCTOU window remains between a successful re-check and a durable write",
        ],
    }
    if cleanup:
        pass
    return report


def format_report(report: dict[str, Any]) -> str:
    treat = report["treatment"]
    control = report["control"]
    box = report["box"]
    lines = [
        "Yama remote revocation experiment",
        f"supervisor: {report['supervisor']}",
        f"trials per condition: {report['trials_per_condition']}",
        f"worker delay after obtain (s): {report['delay_s']}",
        f"elapsed (s): {report['elapsed_s']:.3f}",
        "box:",
        f"  kernel: {box.get('kernel')}  arch: {box.get('architecture')}  python: {box.get('python')}",
        f"  cpu: {box.get('cpu_model') or 'unknown'}",
        f"  mem_total_kib: {box.get('mem_total_kib')}",
        f"  euid: {box.get('euid')}",
        "treatment (revocation before commit):",
        f"  refused: {treat['refused']}/{treat['n']}  (refusal rate {treat['refusal_rate']:.3f})",
        f"  allowed: {treat['allowed']}/{treat['n']}",
        f"  reasons: {treat['reason_counts']}",
        f"  recheck_latency_s: {treat['recheck_latency_s']}",
        f"  revoke_to_refuse_s: {treat['revoke_to_refuse_s']}",
        "control (no revocation):",
        f"  allowed: {control['allowed']}/{control['n']}  (allow rate {control['allow_rate']:.3f})",
        f"  refused: {control['refused']}/{control['n']}",
        f"  recheck_latency_s: {control['recheck_latency_s']}",
        f"  toctou_window_s (check_commit return to atomic_write return): {control['toctou_window_s']}",
        "limitations:",
    ]
    for item in report["limitations"]:
        lines.append(f"  - {item}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=50, help="trials per condition (default 50)")
    parser.add_argument("--delay", type=float, default=0.05, help="seconds the worker waits after obtain (default 0.05)")
    parser.add_argument("--work-dir", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON as well as the text report")
    args = parser.parse_args(argv)
    report = run_experiment(trials=args.trials, delay_s=args.delay, work_dir=args.work_dir)
    sys.stderr.write(format_report(report))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    expected_ok = (
        report["treatment"]["refused"] == report["treatment"]["n"]
        and report["control"]["allowed"] == report["control"]["n"]
    )
    return 0 if expected_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
