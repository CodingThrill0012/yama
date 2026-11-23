"""Guarded commits: re-check a supervisor grant immediately before a write."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Union

from yama.grant import Grant, GrantError, GrantNotFound, GrantStore

PathLike = Union[str, Path]
Data = Union[str, bytes]


class GrantDenied(Exception):
    """The grant is missing, invalid, or does not permit the effect."""

    def __init__(
        self,
        message: str,
        *,
        grant_id: str | None = None,
        effect: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.grant_id = grant_id
        self.effect = effect
        self.reason = reason


def atomic_write(path: PathLike, data: Data) -> None:
    """Write ``data`` to ``path`` via a same-directory temporary file and os.replace."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, dest)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _fresh_grant(store: GrantStore, grant_id: str) -> Grant:
    try:
        return store.get(grant_id)
    except GrantNotFound as exc:
        raise GrantDenied(
            f"grant not found: {grant_id}",
            grant_id=grant_id,
            reason="not_found",
        ) from exc
    except GrantError as exc:
        raise GrantDenied(
            f"cannot read grant {grant_id}: {exc}",
            grant_id=grant_id,
            reason="store_error",
        ) from exc


def check_effect(store: GrantStore, grant_id: str, effect: str) -> Grant:
    """Re-read the grant from the supervisor store and require ``effect``.

    Returns the freshly loaded Grant if it permits the effect.
    """
    grant = _fresh_grant(store, grant_id)
    if grant.permits(effect):
        return grant
    reason = grant.denial_reason(effect) or "denied"
    raise GrantDenied(
        f"grant {grant_id} does not permit {effect!r} ({reason})",
        grant_id=grant_id,
        effect=effect,
        reason=reason,
    )


def commit_effect(
    store: GrantStore,
    grant_id: str,
    effect: str,
    path: PathLike,
    data: Data,
) -> Grant:
    """Re-check the grant immediately before writing a protected effect.

    The grant is loaded from the supervisor store at the last moment, then
    the bytes are written atomically. A revoked, expired, or too-narrow
    grant raises GrantDenied and no file is published.
    """
    grant = check_effect(store, grant_id, effect)
    atomic_write(path, data)
    return grant
