"""Guarded commits: re-check a supervisor grant and provenance immediately before a write."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional, Union

from yama.grant import Grant, GrantError, GrantNotFound, GrantStore
from yama.provenance import Provenance

PathLike = Union[str, Path]
Data = Union[str, bytes]


class GrantDenied(Exception):
    """The grant is missing, invalid, or the payload is not committable.

    Distinct ``reason`` codes (stable strings, compared in tests):

    - ``not_found``, ``store_error``, ``revoked``, ``expired``,
      ``effect_not_allowed`` — grant / effect checks.
    - ``provenance_missing`` — no provenance tag was supplied.
    - ``purpose_mismatch`` — ``provenance.purpose_binding != grant.purpose``.
    - ``insufficient_trust`` — ``provenance.trust_level`` is below
      ``grant.required_trust(effect)``.
    """

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

    Returns the freshly loaded Grant if it permits the effect. This does
    not inspect provenance; use ``check_commit`` (or ``commit_effect``)
    before writing a payload.
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


def check_commit(
    store: GrantStore,
    grant_id: str,
    effect: str,
    provenance: Optional[Provenance],
) -> Grant:
    """Re-read the grant and refuse if the payload cannot be committed.

    Order of checks: grant presence and validity, allowed effect,
    provenance present, purpose_binding equals grant.purpose, trust_level
    meets grant.required_trust(effect).
    """
    grant = check_effect(store, grant_id, effect)
    if provenance is None:
        raise GrantDenied(
            f"grant {grant_id} cannot commit {effect!r}: provenance is missing",
            grant_id=grant_id,
            effect=effect,
            reason="provenance_missing",
        )
    if provenance.purpose_binding != grant.purpose:
        raise GrantDenied(
            f"grant {grant_id} cannot commit {effect!r}: purpose_binding "
            f"{provenance.purpose_binding!r} does not match grant purpose "
            f"{grant.purpose!r}",
            grant_id=grant_id,
            effect=effect,
            reason="purpose_mismatch",
        )
    required = grant.required_trust(effect)
    if provenance.trust_level < required:
        raise GrantDenied(
            f"grant {grant_id} cannot commit {effect!r}: trust_level "
            f"{provenance.trust_level.name.lower()} is below required "
            f"{required.name.lower()}",
            grant_id=grant_id,
            effect=effect,
            reason="insufficient_trust",
        )
    return grant


def commit_effect(
    store: GrantStore,
    grant_id: str,
    effect: str,
    path: PathLike,
    data: Data,
    provenance: Optional[Provenance] = None,
) -> Grant:
    """Re-check the grant and provenance immediately before a protected write.

    The grant is loaded from the supervisor store at the last moment.
    A revoked, expired, or too-narrow grant, a missing provenance tag,
    a purpose mismatch, or insufficient trust raises GrantDenied and no
    file is published.
    """
    grant = check_commit(store, grant_id, effect, provenance)
    atomic_write(path, data)
    return grant
