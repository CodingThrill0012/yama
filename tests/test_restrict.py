from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from yama.restrict import (
    apply_landlock,
    doctor_lines,
    landlock_abi,
    restrain,
    runtime_read_paths,
)


def test_doctor_lines_do_not_apply_restraints() -> None:
    lines = doctor_lines()
    joined = "\n".join(lines)
    assert "platform:" in joined
    assert "landlock:" in joined
    assert "seccomp:" in joined
    # doctor must be a probe, not an application.
    assert "applied" not in joined.lower() or "never claims" in joined.lower()


def test_restrain_without_paths_does_not_claim_landlock() -> None:
    report = restrain(read_paths=[], write_paths=[], include_runtime_reads=False, no_new_privs=True)
    landlock = report.get("landlock")
    assert landlock is not None
    assert landlock.applied is False
    assert "landlock" not in report.applied_names


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Landlock is Linux-only")
def test_landlock_probe_or_apply_in_subprocess(tmp_path: Path) -> None:
    abi = landlock_abi()
    if abi is None:
        result = apply_landlock([str(tmp_path)], include_runtime_reads=False)
        assert result.requested is True
        assert result.available is False
        assert result.applied is False
        return

    read_dir = tmp_path / "read"
    write_dir = tmp_path / "write"
    denied_dir = tmp_path / "denied"
    read_dir.mkdir()
    write_dir.mkdir()
    denied_dir.mkdir()
    (read_dir / "in.txt").write_text("ok", encoding="utf-8")
    (denied_dir / "secret.txt").write_text("no", encoding="utf-8")

    # Apply in a child so the test process itself is not confined.
    pid = os.fork()
    if pid == 0:
        try:
            result = apply_landlock(
                [str(read_dir), *runtime_read_paths(), str(write_dir)],
                [str(write_dir)],
                include_runtime_reads=False,
            )
            if not result.applied:
                os._exit(11)
            try:
                (write_dir / "out.txt").write_text("written", encoding="utf-8")
            except OSError:
                os._exit(12)
            try:
                (denied_dir / "out.txt").write_text("should fail", encoding="utf-8")
            except OSError:
                os._exit(0)
            os._exit(13)
        except Exception:
            os._exit(14)

    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status), status
    code = os.WEXITSTATUS(status)
    assert code == 0, f"landlock child exited {code}"
    assert (write_dir / "out.txt").read_text(encoding="utf-8") == "written"
    assert not (denied_dir / "out.txt").exists()
