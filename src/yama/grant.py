"""Supervisor-owned grants for Yama.

A Grant is immutable. Expiry and allowed effects can only be set at issue
time. Revocation is performed by a supervisor-owned GrantStore; workers
should open the store read-only and must not have write access to the
store directory.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Union

from yama.provenance import TrustLevel, parse_effect_min_trust

_GRANT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class GrantError(Exception):
    """Base error for grant and store operations."""


class GrantNotFound(GrantError):
    def __init__(self, grant_id: str) -> None:
        super().__init__(f"grant not found: {grant_id}")
        self.grant_id = grant_id


class GrantStoreError(GrantError):
    """Raised when a store write is refused or the store is unusable."""


def _require_aware_utc(value: datetime, name: str = "expiry") -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise GrantError(f"{name} must be a timezone-aware datetime (UTC recommended)")
    return value.astimezone(timezone.utc)


def _parse_expiry(value: Union[str, datetime]) -> datetime:
    if isinstance(value, datetime):
        return _require_aware_utc(value)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise GrantError(f"invalid expiry timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_expiry(value: datetime) -> str:
    text = _require_aware_utc(value).isoformat()
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


def _validate_id(grant_id: str) -> str:
    if not _GRANT_ID_RE.match(grant_id):
        raise GrantError(
            "grant id must be 1-128 characters of [A-Za-z0-9._-]; "
            f"got {grant_id!r}"
        )
    return grant_id


@dataclass(frozen=True)
class Grant:
    """An immutable authorization grant issued by a supervisor.

    Attributes:
        id: Stable identifier used by the store and by workers.
        principal: Who the grant is issued to (worker name, agent id, ...).
        purpose: Why the grant exists. At commit time this is compared
            exactly to the payload's provenance.purpose_binding.
        allowed_effects: Names of effects this grant may authorize.
        expiry: UTC instant after which the grant is no longer valid.
        revoked: Set only via GrantStore.revoke; never by the worker.
        min_trust_level: Grant-level floor for provenance.trust_level.
            Default is TrustLevel.MEDIUM.
        effect_min_trust: Optional per-effect thresholds. The required
            trust for effect E is max(min_trust_level,
            effect_min_trust[E] if set else UNTRUSTED).
    """

    id: str
    principal: str
    purpose: str
    allowed_effects: frozenset[str]
    expiry: datetime
    revoked: bool = False
    min_trust_level: TrustLevel = TrustLevel.MEDIUM
    effect_min_trust: tuple[tuple[str, TrustLevel], ...] = ()

    def __post_init__(self) -> None:
        _validate_id(self.id)
        if not self.principal:
            raise GrantError("principal must be a non-empty string")
        if not self.purpose:
            raise GrantError("purpose must be a non-empty string")
        effects = frozenset(self.allowed_effects)
        if not all(isinstance(item, str) and item for item in effects):
            raise GrantError("allowed_effects must be non-empty strings")
        object.__setattr__(self, "allowed_effects", effects)
        object.__setattr__(self, "expiry", _require_aware_utc(self.expiry))
        object.__setattr__(self, "revoked", bool(self.revoked))
        object.__setattr__(self, "min_trust_level", TrustLevel.parse(self.min_trust_level))
        object.__setattr__(self, "effect_min_trust", parse_effect_min_trust(self.effect_min_trust))

    def is_valid(self, now: Optional[datetime] = None) -> bool:
        """Return True if the grant is not revoked and has not expired."""
        if self.revoked:
            return False
        instant = datetime.now(timezone.utc) if now is None else _require_aware_utc(now, "now")
        return instant < self.expiry

    def permits(self, effect: str, now: Optional[datetime] = None) -> bool:
        """Return True if the grant is valid and lists ``effect``."""
        if not effect:
            return False
        return self.is_valid(now) and effect in self.allowed_effects

    def required_trust(self, effect: str) -> TrustLevel:
        """Return the minimum TrustLevel required to commit ``effect``.

        This is the grant-level floor, raised to any per-effect threshold
        configured for ``effect``. It does not depend on provenance; the
        commit path compares the payload's asserted trust_level to this
        value.
        """
        effect_level = TrustLevel.UNTRUSTED
        for name, level in self.effect_min_trust:
            if name == effect:
                effect_level = level
                break
        return TrustLevel(max(self.min_trust_level, effect_level))

    def denial_reason(self, effect: Optional[str] = None, now: Optional[datetime] = None) -> Optional[str]:
        """Return a short reason if the grant cannot authorize, else None."""
        if self.revoked:
            return "revoked"
        instant = datetime.now(timezone.utc) if now is None else _require_aware_utc(now, "now")
        if instant >= self.expiry:
            return "expired"
        if effect is not None and effect not in self.allowed_effects:
            return "effect_not_allowed"
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "principal": self.principal,
            "purpose": self.purpose,
            "allowed_effects": sorted(self.allowed_effects),
            "expiry": _format_expiry(self.expiry),
            "revoked": self.revoked,
            "min_trust_level": self.min_trust_level.name.lower(),
            "effect_min_trust": {
                name: level.name.lower() for name, level in self.effect_min_trust
            },
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Grant":
        try:
            grant_id = data["id"]
            principal = data["principal"]
            purpose = data["purpose"]
            effects = data["allowed_effects"]
            expiry = data["expiry"]
        except KeyError as exc:
            raise GrantError(f"grant is missing field {exc.args[0]!r}") from exc
        min_trust = data.get("min_trust_level", TrustLevel.MEDIUM)
        effect_min = data.get("effect_min_trust", ())
        return cls(
            id=str(grant_id),
            principal=str(principal),
            purpose=str(purpose),
            allowed_effects=frozenset(effects),
            expiry=_parse_expiry(expiry),
            revoked=bool(data.get("revoked", False)),
            min_trust_level=TrustLevel.parse(min_trust),
            effect_min_trust=parse_effect_min_trust(effect_min),
        )

    @classmethod
    def from_json(cls, text: str) -> "Grant":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise GrantError(f"grant JSON is invalid: {exc}") from exc
        if not isinstance(data, dict):
            raise GrantError("grant JSON must be an object")
        return cls.from_dict(data)


def issue_grant(
    *,
    principal: str,
    purpose: str,
    allowed_effects: Iterable[str],
    expiry: Optional[datetime] = None,
    ttl: Optional[timedelta] = None,
    grant_id: Optional[str] = None,
    min_trust_level: Union[TrustLevel, str, int] = TrustLevel.MEDIUM,
    effect_min_trust: Optional[Mapping[str, Union[TrustLevel, str, int]]] = None,
) -> Grant:
    """Issue a new, unrevoked grant.

    Provide either ``expiry`` (timezone-aware) or ``ttl`` relative to now.
    ``min_trust_level`` defaults to MEDIUM. ``effect_min_trust`` may raise
    the required trust for named effects; it cannot lower the grant floor.
    """
    if expiry is None:
        if ttl is None:
            raise GrantError("provide expiry or ttl when issuing a grant")
        expiry = datetime.now(timezone.utc) + ttl
    return Grant(
        id=grant_id or str(uuid.uuid4()),
        principal=principal,
        purpose=purpose,
        allowed_effects=frozenset(allowed_effects),
        expiry=expiry,
        revoked=False,
        min_trust_level=TrustLevel.parse(min_trust_level),
        effect_min_trust=parse_effect_min_trust(effect_min_trust),
    )


class GrantStore:
    """Directory-backed registry of grants, written only by the supervisor.

    Each grant is a ``<id>.json`` file. ``get`` always re-reads the file so a
    later ``commit_effect`` observes revocation or expiry changes immediately.

    Open workers with ``readonly=True``. The supervisor should also make the
    directory unwritable to worker processes (filesystem permissions and,
    where available, Landlock write paths that exclude the store).
    """

    def __init__(self, path: Union[str, Path], *, readonly: bool = False) -> None:
        self.path = Path(path)
        self.readonly = readonly
        if not readonly:
            try:
                self.path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise GrantStoreError(f"cannot create grant store {self.path}: {exc}") from exc
        elif not self.path.is_dir():
            raise GrantStoreError(f"grant store does not exist: {self.path}")

    def _file(self, grant_id: str) -> Path:
        return self.path / f"{_validate_id(grant_id)}.json"

    def _require_writable(self, action: str) -> None:
        if self.readonly:
            raise GrantStoreError(
                f"store is read-only; only the supervisor may {action}"
            )

    def get(self, grant_id: str) -> Grant:
        path = self._file(grant_id)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise GrantNotFound(grant_id) from exc
        except OSError as exc:
            raise GrantStoreError(f"cannot read grant {grant_id}: {exc}") from exc
        return Grant.from_json(text)

    def put(self, grant: Grant) -> None:
        """Write or replace a grant. Refused on a read-only store."""
        self._require_writable("write grants")
        path = self._file(grant.id)
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        payload = grant.to_json()
        try:
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise GrantStoreError(f"cannot write grant {grant.id}: {exc}") from exc

    def revoke(self, grant_id: str) -> Grant:
        """Mark a grant revoked and persist it. Refused on a read-only store."""
        self._require_writable("revoke grants")
        grant = self.get(grant_id)
        if grant.revoked:
            return grant
        revoked = replace(grant, revoked=True)
        self.put(revoked)
        return revoked

    def list_ids(self) -> list[str]:
        if not self.path.is_dir():
            return []
        ids = []
        for entry in sorted(self.path.glob("*.json")):
            if entry.name.startswith("."):
                continue
            ids.append(entry.stem)
        return ids

    def __iter__(self) -> Iterator[Grant]:
        for grant_id in self.list_ids():
            try:
                yield self.get(grant_id)
            except GrantError:
                continue
