"""Asserted provenance tags for payloads that cross a Yama boundary.

A Provenance value is metadata supplied with a payload. Yama checks that
it is present, that its purpose_binding equals the grant's purpose, and
that its trust_level meets the required minimum. It does not verify that
the payload's content is truthful, nor that the stated origin is authentic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Union


class ProvenanceError(ValueError):
    """The provenance tag is malformed."""


class TrustLevel(IntEnum):
    """Ordered trust levels for provenance tags.

    A payload meets a threshold if and only if
    ``provenance.trust_level >= required``. The required minimum for a
    commit of effect *E* on grant *G* is:

    - ``G.effect_min_trust[E]`` if that key is set, otherwise
      ``G.min_trust_level``;
    - and in either case it is raised to at least ``G.min_trust_level``.

    So an effect-level entry can raise the bar for one effect, but it
    cannot lower the grant-level floor.

    These ranks are labels on asserted metadata, not a measured
    assessment of the payload.
    """

    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: Union[str, int, "TrustLevel"]) -> "TrustLevel":
        if isinstance(value, TrustLevel):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return cls(value)
            except ValueError as exc:
                raise ProvenanceError(f"unknown trust level integer: {value}") from exc
        if isinstance(value, str):
            key = value.strip().upper()
            try:
                return cls[key]
            except KeyError as exc:
                names = ", ".join(item.name.lower() for item in cls)
                raise ProvenanceError(
                    f"unknown trust level {value!r}; expected one of: {names}"
                ) from exc
        raise ProvenanceError(f"trust level must be a name or integer, got {type(value).__name__}")


def _require_aware_utc(value: datetime, name: str = "timestamp") -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ProvenanceError(f"{name} must be a timezone-aware datetime (UTC recommended)")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: Union[str, datetime]) -> datetime:
    if isinstance(value, datetime):
        return _require_aware_utc(value)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ProvenanceError(f"invalid provenance timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    text = _require_aware_utc(value).isoformat()
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


@dataclass(frozen=True)
class Provenance:
    """Explicit provenance tag attached to a payload.

    Attributes:
        origin: Stated source of the payload (agent id, tool name, ...).
        trust_level: Asserted rank on the TrustLevel scale.
        purpose_binding: Must equal ``grant.purpose`` at commit time.
        timestamp: When the tag was asserted, as timezone-aware UTC.
    """

    origin: str
    trust_level: TrustLevel
    purpose_binding: str
    timestamp: datetime

    def __post_init__(self) -> None:
        if not self.origin or not str(self.origin).strip():
            raise ProvenanceError("origin must be a non-empty string")
        object.__setattr__(self, "origin", str(self.origin))
        object.__setattr__(self, "trust_level", TrustLevel.parse(self.trust_level))
        if not self.purpose_binding or not str(self.purpose_binding).strip():
            raise ProvenanceError("purpose_binding must be a non-empty string")
        object.__setattr__(self, "purpose_binding", str(self.purpose_binding))
        object.__setattr__(self, "timestamp", _require_aware_utc(self.timestamp))

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "trust_level": self.trust_level.name.lower(),
            "purpose_binding": self.purpose_binding,
            "timestamp": _format_timestamp(self.timestamp),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Provenance":
        try:
            origin = data["origin"]
            trust_level = data["trust_level"]
            purpose_binding = data["purpose_binding"]
            timestamp = data["timestamp"]
        except KeyError as exc:
            raise ProvenanceError(f"provenance is missing field {exc.args[0]!r}") from exc
        return cls(
            origin=str(origin),
            trust_level=TrustLevel.parse(trust_level),
            purpose_binding=str(purpose_binding),
            timestamp=_parse_timestamp(timestamp),
        )

    @classmethod
    def from_json(cls, text: str) -> "Provenance":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ProvenanceError(f"provenance JSON is invalid: {exc}") from exc
        if not isinstance(data, dict):
            raise ProvenanceError("provenance JSON must be an object")
        return cls.from_dict(data)


def parse_effect_min_trust(value: Any) -> tuple[tuple[str, TrustLevel], ...]:
    """Normalize a mapping or sequence of effect-to-threshold pairs."""
    if value is None:
        return ()
    if isinstance(value, dict):
        items = value.items()
    else:
        items = value
    parsed: list[tuple[str, TrustLevel]] = []
    for item in items:
        if isinstance(item, (tuple, list)) and len(item) == 2:
            effect, level = item
        else:
            raise ProvenanceError("effect_min_trust entries must be (effect, level) pairs")
        if not isinstance(effect, str) or not effect:
            raise ProvenanceError("effect_min_trust keys must be non-empty strings")
        parsed.append((effect, TrustLevel.parse(level)))
    parsed.sort(key=lambda pair: pair[0])
    return tuple(parsed)
