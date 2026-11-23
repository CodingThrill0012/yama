# Yama Banking Use Case

## Supervisor-owned commit control for AI-assisted payment and servicing workflows

> This document is an illustrative scenario for how Yama's grant,
> provenance, and commit path could be used in a banking workflow. It
> is not a description of a deployed bank system, and it is not a
> statement of RBI or PCI-DSS compliance.

The sample Grant and Provenance objects, refusal bodies, and the
allowed-commit audit line below were produced by
[`examples/banking_transfer.py`](../../examples/banking_transfer.py),
which calls `Grant.to_json()`, `Provenance.to_json()`, and
`commit_effect` in this repository. A draft of the samples used Unix
timestamp `1763910000.0` (`2025-11-23T15:00:00Z`) for expiry, which
is already past. The samples use the same clock time on 23 November
2026, serialized in the package's ISO-8601 UTC form (suffix `Z`).

### What

In a retail or corporate banking setting, AI agents assist with
transfer proposals, limit reviews, dispute summaries, or statement
explanations. Yama ensures that any protected side-effect (creating a
payment instruction, changing a limit, writing a regulated record) can
occur only when a supervisor re-validates a purpose-bound grant at
commit time, the agent process itself cannot perform the effect, and
every payload carries provenance.

### Why

Banking regulations and internal controls require that authority to
move money or alter customer records is explicit, revocable, and
attributable. An agent that can directly call core-banking APIs or
write instruction files creates an unacceptable window: a customer
cancellation, fraud alert, or purpose change may arrive after the
agent has started but before the effect is durable. Yama is intended
to close that window without trusting the agent, by re-validating the
grant immediately before the effect is made durable.

A residual time-of-check to time-of-write window remains after a
successful re-check and before the durable write. On one localhost run
of the remote-revocation experiment, that window was median
0.001498 s and max 0.002449 s (n = 50). A revocation arriving inside
that window would not be observed by the re-check that already
returned. See
[docs/YAMA-RESEARCH-NOTE.md](../YAMA-RESEARCH-NOTE.md)
and
[docs/measurements/remote_revocation-2026-11-23.json](../measurements/remote_revocation-2026-11-23.json).

### Where

- Customer-initiated transfer assistant
- Back-office limit or fee-review agent
- Dispute or complaint summarization that may later create a case record
- Multi-agent hand-off (research agent → analysis agent → execution supervisor)

The supervisor sits in the orchestration / control plane; agents run
under restraint.

### When

- Grant issued when the customer authenticates and states intent.
- Provenance tag attached to every message the agent sends or receives.
- Commit-time re-check immediately before the payment file or API call is made.
- Revocation (customer cancel, fraud system, operator) causes the
  commit to be refused even if the agent has already prepared the
  instruction.

### How (concrete flow)

1. Customer requests a transfer via the banking assistant.
2. Controller issues a Grant (see sample below).
3. Analysis agent (under Yama restraint) may read recent transactions
   and produce a summary. Every payload it emits carries Provenance.
4. If the agent tries to request a different purpose or an untagged
   payload, the supervisor refuses.
5. Supervisor prepares the payment instruction but does not write it yet.
6. Immediately before write/API call, supervisor re-validates the
   grant and provenance.
7. Customer cancels or fraud system revokes → commit refused, no
   payment instruction exists.
8. If all checks pass, supervisor performs the protected effect and
   logs the grant_id + provenance.

The runnable demonstration of steps 2, 4, 6, 7, and 8 is:

```bash
python examples/banking_transfer.py
```

### Sample Grant

Serialized with `Grant.to_json()`. The identifier field in this
package is `id` (not `grant_id`). `min_trust_level` defaults to
`medium`; `effect_min_trust` is empty unless a per-effect threshold
is set.

```json
{
  "allowed_effects": [
    "create_payment_instruction"
  ],
  "effect_min_trust": {},
  "expiry": "2026-11-23T15:00:00Z",
  "id": "grant-2026-11-23-7f3a",
  "min_trust_level": "medium",
  "principal": "customer:88421",
  "purpose": "customer-initiated transfer",
  "revoked": false
}
```

### Sample Provenance

Serialized with `Provenance.to_json()`, using origin
`analysis-agent` and `trust_level` `medium`. The timestamp is
`2026-11-23T14:55:00Z` (five minutes before the grant expiry above).

```json
{
  "origin": "analysis-agent",
  "purpose_binding": "customer-initiated transfer",
  "timestamp": "2026-11-23T14:55:00Z",
  "trust_level": "medium"
}
```

### Sample commit outcomes

These bodies were produced by catching `GrantDenied` from
`commit_effect` (fields `reason`, `grant_id`, `effect`, and
`message` are the exception's own values) or, in the allowed case,
by logging `grant.id` plus `provenance.to_dict()` after a successful
commit. In every refusal, the destination file did not exist
afterwards.

#### (a) Revoked grant

```json
{
  "effect": "create_payment_instruction",
  "grant_id": "grant-2026-11-23-7f3a",
  "message": "grant grant-2026-11-23-7f3a does not permit 'create_payment_instruction' (revoked)",
  "outcome": "refused",
  "reason": "revoked"
}
```

#### (b) Purpose mismatch

The payload's `purpose_binding` was `limit-increase review` instead
of `customer-initiated transfer`.

```json
{
  "effect": "create_payment_instruction",
  "grant_id": "grant-2026-11-23-7f3a",
  "message": "grant grant-2026-11-23-7f3a cannot commit 'create_payment_instruction': purpose_binding 'limit-increase review' does not match grant purpose 'customer-initiated transfer'",
  "outcome": "refused",
  "reason": "purpose_mismatch"
}
```

#### (c) Missing provenance, and insufficient trust

Passing no provenance tag:

```json
{
  "effect": "create_payment_instruction",
  "grant_id": "grant-2026-11-23-7f3a",
  "message": "grant grant-2026-11-23-7f3a cannot commit 'create_payment_instruction': provenance is missing",
  "outcome": "refused",
  "reason": "provenance_missing"
}
```

Passing `trust_level` `low` against the grant's required `medium`:

```json
{
  "effect": "create_payment_instruction",
  "grant_id": "grant-2026-11-23-7f3a",
  "message": "grant grant-2026-11-23-7f3a cannot commit 'create_payment_instruction': trust_level low is below required medium",
  "outcome": "refused",
  "reason": "insufficient_trust"
}
```

#### Allowed commit audit log

After all checks passed, `commit_effect` wrote
`payment-instruction.txt` and the demonstration logged the grant id
together with the provenance tag:

```json
{
  "effect": "create_payment_instruction",
  "grant_id": "grant-2026-11-23-7f3a",
  "outcome": "allowed",
  "path": "payment-instruction.txt",
  "provenance": {
    "origin": "analysis-agent",
    "purpose_binding": "customer-initiated transfer",
    "timestamp": "2026-11-23T14:55:00Z",
    "trust_level": "medium"
  }
}
```

### What the agent cannot do

The intended restraint boundary is that the agent process cannot
itself open the core-banking socket, write the instruction file, or
exec a payment binary. What has been measured so far is narrower.

In one run of `benchmarks/baseline_attacks.py`
([docs/measurements/baseline_attacks-2026-11-23.json](../measurements/baseline_attacks-2026-11-23.json)),
a file write outside the allowed directory and exec of a denied
binary were observed blocked (`errno=13`, `EACCES`) after filesystem
Landlock was applied. A new outbound TCP connection to `1.1.1.1:443`
was allowed under that same filesystem-only Landlock
(`seccomp_applied` was false). Blocking a core-banking socket
therefore requires Landlock ABI ≥ 4 TCP-connect rules or
seccomp-BPF, which are not yet implemented or measured in this
prototype.

### Residual risks (explicit)

- Semantic content inside an authorized, properly provenanced payload
  can still be misleading; Yama does not claim to solve prompt
  injection.
- Already-committed payments are not rolled back by revocation.
- Network-level blocking depends on the restraint implementation. In
  the measured baseline above, filesystem Landlock did not block an
  outbound TCP connect.
- This use case is not a statement of RBI or PCI-DSS compliance.
