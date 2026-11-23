"""Yama: supervisor-owned authorization and process restraint for multi-agent systems."""

from __future__ import annotations

from yama.commit import GrantDenied, atomic_write, check_commit, check_effect, commit_effect
from yama.grant import (
    Grant,
    GrantError,
    GrantNotFound,
    GrantStore,
    GrantStoreError,
    issue_grant,
)
from yama.provenance import Provenance, ProvenanceError, TrustLevel
from yama.restrict import (
    RestraintReport,
    apply_landlock,
    apply_seccomp,
    chroot_fallback,
    drop_privileges,
    landlock_abi,
    restrain,
    set_no_new_privs,
)

__version__ = "0.1.0"

__all__ = [
    "Grant",
    "GrantDenied",
    "GrantError",
    "GrantNotFound",
    "GrantStore",
    "GrantStoreError",
    "Provenance",
    "ProvenanceError",
    "RestraintReport",
    "TrustLevel",
    "__version__",
    "apply_landlock",
    "apply_seccomp",
    "atomic_write",
    "check_commit",
    "check_effect",
    "chroot_fallback",
    "commit_effect",
    "drop_privileges",
    "issue_grant",
    "landlock_abi",
    "restrain",
    "set_no_new_privs",
]
