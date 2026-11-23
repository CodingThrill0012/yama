# Yama Research Note

This note records the Yama control property and, in later updates, the
experiments used to test it. Claims in this document are limited to
behavior that has been measured, or are marked as still to be measured.

## The Yama Property

Yama is a system-independent control property for multi-agent systems: every protected side-effect must be authorized by a supervisor that does not execute the agent’s code; that authorization must be re-validated immediately before the effect is committed; the agent itself must be incapable of producing the protected side-effect; and every payload that crosses an agent or supervisor boundary must carry an explicit provenance tag such that untagged or insufficiently trusted content cannot acquire new authority. Authorization alone does not provide semantic safety.

## Provenance and purpose binding

A `Provenance` tag has four fields: `origin`, `trust_level`,
`purpose_binding`, and `timestamp`. `commit_effect` re-reads the grant
and then refuses the write with a distinct reason code when:

| Condition | Reason code |
| --- | --- |
| No provenance tag is supplied | `provenance_missing` |
| `purpose_binding` is not exactly equal to `grant.purpose` | `purpose_mismatch` |
| `trust_level` is below the required minimum | `insufficient_trust` |

`TrustLevel` is the ordered enumeration `untrusted < low < medium < high`.
The required minimum for effect *E* is `grant.min_trust_level` (default
`medium`), raised to `grant.effect_min_trust[E]` when that key is set.
An effect-level entry can raise the bar for one effect; it cannot lower
the grant-level floor. A payload meets the threshold if and only if
`provenance.trust_level >= required`.

`grant.purpose` is therefore an authorization condition, not a comment.
This closes the semantic-overclaim gap in the sense that authority can
no longer be acquired by untagged, low-trust, or mis-purposed payloads.
The Yama Property's caveat still stands: authorization alone does not
provide semantic safety. Provenance tags are asserted metadata; Yama
does not verify that the payload's content is truthful, nor that the
stated origin is authentic.
