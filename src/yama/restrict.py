"""Process restraints: Landlock, seccomp-BPF, no_new_privs, privilege drop, chroot.

Every function reports what actually happened. Callers must not treat a
RestraintReport as enforcement unless the corresponding ``applied`` flag
is True. Missing kernel features degrade to an explicit "unavailable"
result rather than a silent claim of protection.

Landlock and seccomp are Linux-only. Landlock requires kernel 5.13 or
later and is invoked with raw syscalls via ctypes (no runtime dependency).
seccomp-BPF is applied only if the optional ``seccomp`` or ``pyseccomp``
module is importable.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

PR_SET_NO_NEW_PRIVS = 38

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_RULE_PATH_BENEATH = 1

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15

# Highest filesystem access bit introduced at each ABI. Network and IPC
# scopes are not handled by this module yet.
_FS_HANDLED_BY_ABI = {
    1: (1 << 13) - 1,
    2: (1 << 14) - 1,
    3: (1 << 15) - 1,
    4: (1 << 15) - 1,
    5: (1 << 16) - 1,
}

# landlock_create_ruleset, landlock_add_rule, landlock_restrict_self
_LANDLOCK_SYSCALLS = {
    "x86_64": (444, 445, 446),
    "amd64": (444, 445, 446),
    "aarch64": (444, 445, 446),
    "arm64": (444, 445, 446),
}

_READ_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
)
_WRITE_ACCESS = (
    _READ_ACCESS
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)


class RestraintError(Exception):
    """Raised when a requested restraint is attempted and fails mid-way."""


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one restraint or probe."""

    name: str
    requested: bool
    available: bool
    applied: bool
    detail: str = ""

    def summary(self) -> str:
        if self.applied:
            state = "applied"
        elif not self.requested:
            state = "not requested"
        elif not self.available:
            state = "unavailable"
        else:
            state = "not applied"
        extra = f" — {self.detail}" if self.detail else ""
        return f"{self.name}: {state}{extra}"


@dataclass
class RestraintReport:
    """What restrain() requested, what the kernel offered, and what ran.

    ``applied`` is True only for restraints that were actually enforced
    in this process. Unavailable features are listed, never implied.
    """

    checks: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> CheckResult:
        self.checks.append(result)
        return result

    def get(self, name: str) -> Optional[CheckResult]:
        for item in self.checks:
            if item.name == name:
                return item
        return None

    @property
    def applied_names(self) -> list[str]:
        return [item.name for item in self.checks if item.applied]

    @property
    def unavailable_names(self) -> list[str]:
        return [
            item.name
            for item in self.checks
            if item.requested and not item.available
        ]

    def all_requested_applied(self) -> bool:
        requested = [item for item in self.checks if item.requested]
        return bool(requested) and all(item.applied for item in requested)

    def format(self) -> str:
        if not self.checks:
            return "no restraints were requested"
        return "\n".join(item.summary() for item in self.checks)

    def __str__(self) -> str:
        return self.format()


class _LandlockPathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
    ]


def _machine() -> str:
    return platform.machine().lower()


def landlock_supported_arch() -> bool:
    return _machine() in _LANDLOCK_SYSCALLS


def _syscall_nrs() -> Optional[tuple[int, int, int]]:
    return _LANDLOCK_SYSCALLS.get(_machine())


def _libc() -> ctypes.CDLL:
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    return lib


def _syscall(number: int, *args: object) -> int:
    libc = _libc()
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(number), *args)
    if result < 0:
        err = ctypes.get_errno() or errno.EIO
        raise OSError(err, os.strerror(err))
    return int(result)


def _fs_handled(abi: int) -> int:
    if abi <= 0:
        return 0
    if abi >= max(_FS_HANDLED_BY_ABI):
        return _FS_HANDLED_BY_ABI[max(_FS_HANDLED_BY_ABI)]
    return _FS_HANDLED_BY_ABI.get(abi, _FS_HANDLED_BY_ABI[1])


def landlock_abi() -> Optional[int]:
    """Return the kernel's Landlock ABI version, or None if unavailable."""
    nrs = _syscall_nrs()
    if nrs is None:
        return None
    if not sys.platform.startswith("linux"):
        return None
    try:
        abi = _syscall(
            nrs[0],
            None,
            ctypes.c_size_t(0),
            ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
        )
    except OSError as exc:
        if exc.errno in (
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            errno.ENOTSUP,
            errno.EINVAL,
        ):
            return None
        return None
    return int(abi) if abi > 0 else None


def _load_seccomp_module():
    for name in ("seccomp", "pyseccomp"):
        try:
            return __import__(name)
        except ImportError:
            continue
    return None


def seccomp_module_name() -> Optional[str]:
    module = _load_seccomp_module()
    return module.__name__ if module is not None else None


def runtime_read_paths() -> list[str]:
    """Paths a typical CPython process still needs to read after Landlock."""
    candidates = [
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        sys.base_exec_prefix,
        os.path.dirname(os.__file__) if os.__file__ else None,
        os.path.dirname(sys.executable) if sys.executable else None,
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/lib32",
        "/etc",
        "/proc",
        "/dev",
        "/run",
    ]
    seen: set[str] = set()
    paths: list[str] = []
    for raw in candidates:
        if not raw:
            continue
        resolved = os.path.realpath(raw)
        if resolved in seen or not os.path.exists(resolved):
            continue
        seen.add(resolved)
        paths.append(resolved)
    return paths


def _prctl_set_no_new_privs() -> None:
    if not sys.platform.startswith("linux"):
        raise RestraintError("PR_SET_NO_NEW_PRIVS is only available on Linux")
    libc = _libc()
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    ctypes.set_errno(0)
    ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret != 0:
        err = ctypes.get_errno() or errno.EIO
        raise OSError(err, os.strerror(err))


def set_no_new_privs() -> None:
    """Set PR_SET_NO_NEW_PRIVS on this process (required before Landlock)."""
    _prctl_set_no_new_privs()


def apply_landlock(
    read_paths: Optional[Iterable[str]] = None,
    write_paths: Optional[Iterable[str]] = None,
    *,
    include_runtime_reads: bool = False,
) -> CheckResult:
    """Apply a Landlock filesystem ruleset to the current process.

    Returns a CheckResult. Does not raise merely because Landlock is
    missing; raises RestraintError only if the kernel supports Landlock
    but installing the ruleset failed after it was requested.
    """
    name = "landlock"
    read_list = [str(p) for p in (read_paths or [])]
    write_list = [str(p) for p in (write_paths or [])]
    if include_runtime_reads:
        read_list = runtime_read_paths() + read_list
    if not read_list and not write_list:
        return CheckResult(
            name,
            requested=False,
            available=landlock_abi() is not None,
            applied=False,
            detail="no paths given",
        )

    if not sys.platform.startswith("linux"):
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail="Landlock is Linux-only",
        )
    if not landlock_supported_arch():
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail=f"Landlock syscalls are not mapped for architecture {_machine()}",
        )

    abi = landlock_abi()
    if abi is None:
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail="Landlock is not available (kernel < 5.13, or disabled)",
        )

    nrs = _syscall_nrs()
    assert nrs is not None
    handled = _fs_handled(abi)
    attr = _LandlockRulesetAttr(handled_access_fs=handled)
    opened: list[int] = []
    ruleset_fd = -1
    try:
        ruleset_fd = _syscall(
            nrs[0],
            ctypes.byref(attr),
            ctypes.c_size_t(ctypes.sizeof(attr)),
            ctypes.c_uint32(0),
        )

        # Later write rules override read rules for the same path.
        path_access: dict[str, int] = {}
        for raw in read_list:
            path_access[os.path.realpath(raw)] = _READ_ACCESS & handled
        for raw in write_list:
            path_access[os.path.realpath(raw)] = _WRITE_ACCESS & handled

        missing = [p for p in path_access if not os.path.exists(p)]
        if missing:
            raise RestraintError(
                "Landlock paths do not exist: " + ", ".join(sorted(missing))
            )

        for path, access in path_access.items():
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            opened.append(fd)
            rule = _LandlockPathBeneath(
                allowed_access=access,
                parent_fd=fd,
            )
            _syscall(
                nrs[1],
                ctypes.c_int(ruleset_fd),
                ctypes.c_uint(LANDLOCK_RULE_PATH_BENEATH),
                ctypes.byref(rule),
                ctypes.c_uint32(0),
            )

        _prctl_set_no_new_privs()
        _syscall(nrs[2], ctypes.c_int(ruleset_fd), ctypes.c_uint32(0))
    except OSError as exc:
        raise RestraintError(f"Landlock failed: {exc}") from exc
    finally:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass
        if ruleset_fd >= 0:
            try:
                os.close(ruleset_fd)
            except OSError:
                pass

    return CheckResult(
        name,
        requested=True,
        available=True,
        applied=True,
        detail=f"ABI {abi}; {len(path_access)} path rule(s)",
    )


def apply_seccomp(
    deny: Optional[Iterable[str]] = None,
    allow: Optional[Iterable[str]] = None,
) -> CheckResult:
    """Apply a seccomp-BPF filter if the optional Python bindings are present.

    Provide either a deny list (default action ALLOW) or an allow list
    (default action EPERM). An allow list that is too narrow will break
    the process; this function does not invent a safe default allow set.
    """
    name = "seccomp"
    deny_list = list(deny or [])
    allow_list = list(allow or [])
    if not deny_list and not allow_list:
        return CheckResult(
            name,
            requested=False,
            available=seccomp_module_name() is not None,
            applied=False,
            detail="no syscall list given",
        )
    if deny_list and allow_list:
        raise RestraintError("apply_seccomp accepts deny or allow, not both")
    if not sys.platform.startswith("linux"):
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail="seccomp-BPF is Linux-only",
        )

    module = _load_seccomp_module()
    if module is None:
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail="optional package not installed (pip install pyseccomp)",
        )

    try:
        if deny_list:
            filt = module.SyscallFilter(defaction=module.ALLOW)
            action = module.ERRNO(errno.EPERM)
            for syscall_name in deny_list:
                filt.add_rule(action, syscall_name)
            detail = f"deny {', '.join(deny_list)} via {module.__name__}"
        else:
            filt = module.SyscallFilter(defaction=module.ERRNO(errno.EPERM))
            for syscall_name in allow_list:
                filt.add_rule(module.ALLOW, syscall_name)
            detail = f"allow {', '.join(allow_list)} via {module.__name__}"
        filt.load()
    except Exception as exc:  # bindings may raise their own types
        raise RestraintError(f"seccomp-BPF failed: {exc}") from exc

    return CheckResult(
        name,
        requested=True,
        available=True,
        applied=True,
        detail=detail,
    )


def drop_privileges(uid: int, gid: Optional[int] = None) -> CheckResult:
    """Drop supplementary groups, then GID, then UID. Irreversible."""
    name = "privilege_drop"
    target_gid = int(gid) if gid is not None else int(uid)
    target_uid = int(uid)
    current_uid = os.geteuid()
    current_gid = os.getegid()
    if current_uid == target_uid and current_gid == target_gid and not os.getgroups():
        return CheckResult(
            name,
            requested=True,
            available=True,
            applied=True,
            detail=f"already running as uid={target_uid} gid={target_gid} with no supplementary groups",
        )
    if current_uid != 0 and (target_uid != current_uid or target_gid != current_gid):
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail=f"not running as root (euid={current_uid}); cannot change to uid={target_uid} gid={target_gid}",
        )
    try:
        if hasattr(os, "setgroups"):
            os.setgroups([])
        os.setgid(target_gid)
        os.setuid(target_uid)
    except OSError as exc:
        raise RestraintError(f"privilege drop failed: {exc}") from exc
    return CheckResult(
        name,
        requested=True,
        available=True,
        applied=True,
        detail=f"now uid={os.geteuid()} gid={os.getegid()}",
    )


def chroot_fallback(path: Union[str, Path]) -> CheckResult:
    """chroot into ``path`` and chdir to /. Typically requires root.

    This is a coarse fallback, not a substitute for Landlock or a
    container. It is applied only when explicitly requested.
    """
    name = "chroot"
    root = os.path.realpath(str(path))
    if not os.path.isdir(root):
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail=f"chroot path does not exist or is not a directory: {root}",
        )
    if os.geteuid() != 0:
        return CheckResult(
            name,
            requested=True,
            available=False,
            applied=False,
            detail=f"chroot typically requires root (euid={os.geteuid()})",
        )
    try:
        os.chdir(root)
        os.chroot(root)
        os.chdir("/")
    except OSError as exc:
        raise RestraintError(f"chroot failed: {exc}") from exc
    return CheckResult(
        name,
        requested=True,
        available=True,
        applied=True,
        detail=f"chrooted to {root}",
    )


def restrain(
    *,
    read_paths: Optional[Iterable[str]] = None,
    write_paths: Optional[Iterable[str]] = None,
    include_runtime_reads: bool = True,
    seccomp_deny: Optional[Iterable[str]] = None,
    seccomp_allow: Optional[Iterable[str]] = None,
    no_new_privs: bool = True,
    drop_uid: Optional[int] = None,
    drop_gid: Optional[int] = None,
    chroot_dir: Optional[Union[str, Path]] = None,
) -> RestraintReport:
    """Apply the requested restraints and return a report of what ran.

    Order: chroot (if requested) → PR_SET_NO_NEW_PRIVS → Landlock →
    seccomp-BPF → privilege drop. Features that are not available are
    recorded as such; this function does not raise for unavailability.
    Unexpected failures are recorded with ``applied=False`` and the
    error in ``detail``, unless a mid-apply failure already restricted
    the process, in which case RestraintError is raised.
    """
    report = RestraintReport()
    read_list = list(read_paths or [])
    write_list = list(write_paths or [])
    landlock_requested = bool(read_list or write_list)
    seccomp_requested = bool(seccomp_deny or seccomp_allow)
    chroot_requested = chroot_dir is not None
    drop_requested = drop_uid is not None

    if chroot_requested:
        try:
            report.add(chroot_fallback(chroot_dir))  # type: ignore[arg-type]
        except RestraintError as exc:
            report.add(
                CheckResult(
                    "chroot",
                    requested=True,
                    available=True,
                    applied=False,
                    detail=str(exc),
                )
            )
    else:
        report.add(
            CheckResult(
                "chroot",
                requested=False,
                available=os.geteuid() == 0,
                applied=False,
                detail="not requested",
            )
        )

    if no_new_privs:
        try:
            _prctl_set_no_new_privs()
            report.add(
                CheckResult(
                    "no_new_privs",
                    requested=True,
                    available=True,
                    applied=True,
                    detail="PR_SET_NO_NEW_PRIVS=1",
                )
            )
        except (RestraintError, OSError) as exc:
            report.add(
                CheckResult(
                    "no_new_privs",
                    requested=True,
                    available=sys.platform.startswith("linux"),
                    applied=False,
                    detail=str(exc),
                )
            )
    else:
        report.add(
            CheckResult(
                "no_new_privs",
                requested=False,
                available=sys.platform.startswith("linux"),
                applied=False,
                detail="not requested",
            )
        )

    if landlock_requested:
        try:
            report.add(
                apply_landlock(
                    read_list,
                    write_list,
                    include_runtime_reads=include_runtime_reads,
                )
            )
        except RestraintError as exc:
            # Landlock is all-or-nothing: restrict_self is the last step,
            # so a failure here means the process was not Landlock-confined.
            report.add(
                CheckResult(
                    "landlock",
                    requested=True,
                    available=landlock_abi() is not None,
                    applied=False,
                    detail=str(exc),
                )
            )
    else:
        report.add(
            CheckResult(
                "landlock",
                requested=False,
                available=landlock_abi() is not None,
                applied=False,
                detail="no paths given",
            )
        )

    if seccomp_requested:
        try:
            report.add(apply_seccomp(deny=seccomp_deny, allow=seccomp_allow))
        except RestraintError as exc:
            report.add(
                CheckResult(
                    "seccomp",
                    requested=True,
                    available=seccomp_module_name() is not None,
                    applied=False,
                    detail=str(exc),
                )
            )
    else:
        report.add(
            CheckResult(
                "seccomp",
                requested=False,
                available=seccomp_module_name() is not None,
                applied=False,
                detail="no syscall list given",
            )
        )

    if drop_requested:
        try:
            report.add(drop_privileges(drop_uid, drop_gid))  # type: ignore[arg-type]
        except RestraintError as exc:
            report.add(
                CheckResult(
                    "privilege_drop",
                    requested=True,
                    available=os.geteuid() == 0,
                    applied=False,
                    detail=str(exc),
                )
            )
    else:
        report.add(
            CheckResult(
                "privilege_drop",
                requested=False,
                available=os.geteuid() == 0,
                applied=False,
                detail="not requested",
            )
        )

    return report


def doctor_lines() -> list[str]:
    """Describe kernel and runtime support without applying restraints."""
    lines = [
        f"platform: {sys.platform}",
        f"architecture: {_machine()}",
        f"kernel: {platform.release()}",
        f"python: {sys.version.split()[0]}",
        f"euid: {os.geteuid()}  egid: {os.getegid()}",
    ]
    if not sys.platform.startswith("linux"):
        lines.append("landlock: unavailable (Linux-only)")
        lines.append("seccomp: unavailable (Linux-only)")
        lines.append("no_new_privs: unavailable (Linux-only)")
        lines.append("chroot: not probed (non-Linux)")
        lines.append("privilege_drop: not probed (non-Linux)")
        return lines

    abi = landlock_abi()
    if abi is None:
        if landlock_supported_arch():
            lines.append(
                "landlock: unavailable (syscall returned ENOSYS/EOPNOTSUPP; "
                "needs Linux kernel >= 5.13 with Landlock enabled)"
            )
        else:
            lines.append(
                f"landlock: unavailable (no syscall numbers for {_machine()}; "
                "Yama maps x86_64 and aarch64)"
            )
    else:
        lines.append(f"landlock: available (ABI {abi})")

    module = seccomp_module_name()
    if module:
        lines.append(f"seccomp: bindings available ({module})")
    else:
        lines.append(
            "seccomp: kernel interface may exist, but Python bindings are "
            "not installed (optional: pip install 'yama[seccomp]')"
        )

    lines.append("no_new_privs: available (PR_SET_NO_NEW_PRIVS)")
    if os.geteuid() == 0:
        lines.append("chroot: available (process is root)")
        lines.append("privilege_drop: available (process is root)")
    else:
        lines.append(f"chroot: unavailable (not root; euid={os.geteuid()})")
        lines.append(
            f"privilege_drop: unavailable for other uids (not root; euid={os.geteuid()})"
        )
    lines.append(
        "note: Yama never claims a restraint is in force unless it was applied"
    )
    return lines
