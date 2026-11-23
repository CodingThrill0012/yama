#!/usr/bin/env python3
"""Comparative baseline: three attacks, plain process vs Yama-restrained.

Attacks
  (a) write a file outside the allowed directory
  (b) open a new outbound TCP connection (default 1.1.1.1:443)
  (c) exec a binary that is not in the allowed directory

Each attack is run in a child process, once with no restraints ("plain")
and once after yama.restrict.restrain() has been applied to that child
("yama"). Container and gVisor columns are not run here; they are
reported as "to be measured".

A result is recorded as "blocked" only when the operation failed with
EACCES or EPERM after Yama reported that Landlock (or seccomp) was
applied. Other failures (timeout, ECONNREFUSED, ENETUNREACH, and so on)
are "failed-other" and are not counted as Yama blocks. Network
blocking requires Landlock ABI >= 4 with TCP connect rules, or a
seccomp-BPF filter; the current restrain() path applies filesystem
Landlock and PR_SET_NO_NEW_PRIVS only, unless those extras are added
later.

Run from the repository root after ``pip install -e .``::

    python benchmarks/baseline_attacks.py
    python benchmarks/baseline_attacks.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if (SRC / "yama").is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from yama.restrict import landlock_abi, restrain, runtime_read_paths  # noqa: E402

DEFAULT_TCP_TARGET = ("1.1.1.1", 443)
BLOCKED_ERRNOS = {errno for errno in (getattr(__import__("errno"), name, None) for name in ("EACCES", "EPERM")) if errno is not None}


def _result(
    attack: str,
    profile: str,
    status: str,
    **extra: Any,
) -> dict[str, Any]:
    row = {"attack": attack, "profile": profile, "status": status}
    row.update(extra)
    return row


def _classify_oserror(exc: OSError, *, restraint_applied: bool) -> str:
    err = exc.errno
    if restraint_applied and err in BLOCKED_ERRNOS:
        return "blocked"
    return "failed-other"


def apply_yama(allowed_dir: Path) -> dict[str, Any]:
    report = restrain(
        read_paths=[str(allowed_dir)],
        write_paths=[str(allowed_dir)],
        include_runtime_reads=True,
        no_new_privs=True,
    )
    landlock = report.get("landlock")
    seccomp = report.get("seccomp")
    return {
        "landlock_applied": bool(landlock and landlock.applied),
        "seccomp_applied": bool(seccomp and seccomp.applied),
        "no_new_privs_applied": bool(report.get("no_new_privs") and report.get("no_new_privs").applied),
        "report": report.format(),
        "landlock_abi": landlock_abi(),
    }


def attack_file_write(outside_file: Path) -> None:
    outside_file.parent.mkdir(parents=True, exist_ok=True)
    outside_file.write_text("unauthorized write\n", encoding="utf-8")


def attack_tcp_connect(host: str, port: int, timeout: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    finally:
        sock.close()


def attack_exec(binary: Path) -> None:
    os.execv(str(binary), [str(binary)])


def run_child_attack(
    *,
    attack: str,
    profile: str,
    allowed_dir: Path,
    outside_file: Path,
    exec_binary: Path,
    tcp_host: str,
    tcp_port: int,
    tcp_timeout: float,
    result_path: Path,
) -> None:
    payload: dict[str, Any] = {"attack": attack, "profile": profile}
    restraint: dict[str, Any] = {
        "landlock_applied": False,
        "seccomp_applied": False,
        "no_new_privs_applied": False,
    }
    try:
        if profile == "yama":
            restraint = apply_yama(allowed_dir)
        payload.update({k: restraint[k] for k in ("landlock_applied", "seccomp_applied", "no_new_privs_applied", "landlock_abi") if k in restraint})
        if "report" in restraint:
            payload["restraint_report"] = restraint["report"]
        applied = bool(restraint.get("landlock_applied") or restraint.get("seccomp_applied"))

        if attack == "file_write_outside":
            attack_file_write(outside_file)
            payload.update(_result(attack, profile, "allowed", path=str(outside_file)))
        elif attack == "tcp_connect":
            attack_tcp_connect(tcp_host, tcp_port, tcp_timeout)
            payload.update(_result(attack, profile, "allowed", target=f"{tcp_host}:{tcp_port}"))
        elif attack == "exec_binary":
            attack_exec(exec_binary)
            # execv does not return on success
        else:
            payload.update(_result(attack, profile, "error", detail=f"unknown attack {attack}"))
    except OSError as exc:
        applied = bool(restraint.get("landlock_applied") or restraint.get("seccomp_applied"))
        payload.update(
            _result(
                attack,
                profile,
                _classify_oserror(exc, restraint_applied=applied),
                errno=exc.errno,
                detail=str(exc),
            )
        )
        if "landlock_applied" not in payload:
            payload["landlock_applied"] = restraint.get("landlock_applied")
    except Exception as exc:  # noqa: BLE001
        payload.update(_result(attack, profile, "error", detail=f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc()))
    result_path.write_text(json.dumps(payload), encoding="utf-8")


def _run_in_child(**kwargs: Any) -> dict[str, Any]:
    result_path: Path = kwargs["result_path"]
    if result_path.exists():
        result_path.unlink()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        try:
            run_child_attack(**kwargs)
            if kwargs["attack"] == "exec_binary" and not result_path.exists():
                # execv succeeded and replaced the process; this branch is
                # only reached if execv returned, which it must not.
                result_path.write_text(
                    json.dumps(_result(kwargs["attack"], kwargs["profile"], "error", detail="execv returned")),
                    encoding="utf-8",
                )
        except Exception as exc:  # noqa: BLE001
            try:
                result_path.write_text(
                    json.dumps(_result(kwargs["attack"], kwargs["profile"], "error", detail=str(exc))),
                    encoding="utf-8",
                )
            finally:
                os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if kwargs["attack"] == "exec_binary" and not result_path.exists() and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        return _result(
            kwargs["attack"],
            kwargs["profile"],
            "allowed",
            binary=str(kwargs["exec_binary"]),
            child_exit=0,
        )
    if not result_path.exists():
        return _result(
            kwargs["attack"],
            kwargs["profile"],
            "error",
            detail=f"child produced no result, wait status={status}",
        )
    data = json.loads(result_path.read_text(encoding="utf-8"))
    data["child_wait_status"] = status
    return data


def run_baseline(
    work_dir: Optional[Path] = None,
    *,
    tcp_host: str = DEFAULT_TCP_TARGET[0],
    tcp_port: int = DEFAULT_TCP_TARGET[1],
    tcp_timeout: float = 3.0,
) -> dict[str, Any]:
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="yama-baseline-"))
    work_dir = Path(work_dir)
    allowed = work_dir / "allowed"
    denied = work_dir / "denied"
    allowed.mkdir(parents=True, exist_ok=True)
    denied.mkdir(parents=True, exist_ok=True)
    outside_file = denied / "pwn.txt"
    exec_binary = denied / "true"
    shutil.copy2("/usr/bin/true", exec_binary)
    os.chmod(exec_binary, 0o755)

    profiles = ("plain", "yama")
    attacks = (
        ("file_write_outside", {"outside_file": outside_file, "exec_binary": exec_binary}),
        ("tcp_connect", {"outside_file": outside_file, "exec_binary": exec_binary}),
        ("exec_binary", {"outside_file": outside_file, "exec_binary": exec_binary}),
    )

    rows: list[dict[str, Any]] = []
    for attack, extra in attacks:
        for profile in profiles:
            # Start each file-write attempt from a clean denied file.
            if outside_file.exists():
                outside_file.unlink()
            row = _run_in_child(
                attack=attack,
                profile=profile,
                allowed_dir=allowed,
                outside_file=outside_file,
                exec_binary=exec_binary,
                tcp_host=tcp_host,
                tcp_port=tcp_port,
                tcp_timeout=tcp_timeout,
                result_path=allowed / f"{attack}-{profile}.json",
            )
            row["denied_file_exists_after"] = outside_file.exists()
            rows.append(row)
            time.sleep(0)  # yield; keeps the loop obvious

    return {
        "benchmark": "baseline_attacks",
        "work_dir": str(work_dir),
        "tcp_target": f"{tcp_host}:{tcp_port}",
        "landlock_abi_on_parent": landlock_abi(),
        "runtime_read_paths": runtime_read_paths(),
        "exec_binary": str(exec_binary),
        "results": rows,
        "not_run": [
            {"profile": "container", "status": "to be measured"},
            {"profile": "gVisor", "status": "to be measured"},
        ],
        "notes": [
            "A row is 'blocked' only if the syscall failed with EACCES or EPERM after Landlock or seccomp was applied.",
            "Current yama.restrict.restrain() applies filesystem Landlock and PR_SET_NO_NEW_PRIVS; it does not install Landlock TCP rules or a seccomp filter unless those are requested and available.",
            "Network blocking needs Landlock ABI >= 4 (TCP connect) or seccomp-BPF.",
            "container and gVisor columns were not run.",
        ],
    }


def format_table(report: dict[str, Any]) -> str:
    lines = [
        "Yama comparative baseline (plain vs Yama-restrained)",
        f"Landlock ABI on parent: {report.get('landlock_abi_on_parent')}",
        f"TCP target: {report.get('tcp_target')}",
        f"exec binary: {report.get('exec_binary')}",
        "",
        f"{'attack':<22} {'profile':<10} {'status':<14} detail",
        "-" * 78,
    ]
    for row in report["results"]:
        detail = row.get("detail") or row.get("target") or row.get("path") or row.get("binary") or ""
        if row.get("errno") is not None:
            detail = f"errno={row['errno']} {detail}"
        extra = ""
        if row["profile"] == "yama":
            extra = f" landlock_applied={row.get('landlock_applied')}"
        lines.append(f"{row['attack']:<22} {row['profile']:<10} {row['status']:<14} {detail}{extra}")
    lines.append("")
    lines.append("not run:")
    for row in report["not_run"]:
        lines.append(f"  {row['profile']}: {row['status']}")
    lines.append("")
    for note in report["notes"]:
        lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=None)
    parser.add_argument("--tcp-host", default=DEFAULT_TCP_TARGET[0])
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_TARGET[1])
    parser.add_argument("--tcp-timeout", type=float, default=3.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = run_baseline(
        args.work_dir,
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port,
        tcp_timeout=args.tcp_timeout,
    )
    sys.stderr.write(format_table(report))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
