from __future__ import annotations

from pathlib import Path

from yama.restrict import landlock_abi

from benchmarks.baseline_attacks import run_baseline


def test_plain_allows_file_write_and_exec(tmp_path: Path) -> None:
    report = run_baseline(tmp_path, tcp_timeout=1.0)
    by = {(row["attack"], row["profile"]): row for row in report["results"]}
    assert by[("file_write_outside", "plain")]["status"] == "allowed"
    assert by[("exec_binary", "plain")]["status"] == "allowed"


def test_yama_blocks_outside_file_and_exec_when_landlock_applies(tmp_path: Path) -> None:
    if landlock_abi() is None:
        report = run_baseline(tmp_path, tcp_timeout=1.0)
        yama_file = next(r for r in report["results"] if r["attack"] == "file_write_outside" and r["profile"] == "yama")
        assert yama_file.get("landlock_applied") is not True
        return
    report = run_baseline(tmp_path, tcp_timeout=1.0)
    by = {(row["attack"], row["profile"]): row for row in report["results"]}
    yama_file = by[("file_write_outside", "yama")]
    yama_exec = by[("exec_binary", "yama")]
    assert yama_file["landlock_applied"] is True
    assert yama_file["status"] == "blocked"
    assert yama_file["errno"] in {13, 1}  # EACCES or EPERM
    assert yama_file["denied_file_exists_after"] is False
    assert yama_exec["landlock_applied"] is True
    assert yama_exec["status"] == "blocked"
    assert yama_exec["errno"] in {13, 1}
