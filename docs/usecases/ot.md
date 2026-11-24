# Yama OT Use Case

## Supervisor-owned commit control for protected changes in operational technology environments

> This document is an illustrative scenario for how the Yama property
> can be applied to OT change control. It is not a claim of IEC 62443
> compliance, SIL certification, or readiness for unsupervised
> production use.

The sample Grant and Provenance objects, refusal bodies, and the
allowed-commit audit line below were produced by
[`examples/ot_setpoint.py`](../../examples/ot_setpoint.py),
which calls `Grant.to_json()`, `Provenance.to_json()`, and
`commit_effect` in this repository. The protocol gateway is simulated
as a supervisor-owned sink that writes a file after a successful
commit decision; the example does not speak an industrial protocol.

A draft of the samples used Unix timestamps `1763917200.0`
(`2025-11-23T17:00:00Z`) for expiry and `1763913600.0`
(`2025-11-23T16:00:00Z`) for the provenance timestamp, both already
past. The samples use the same clock times on 24 November 2026,
serialized in the package’s ISO-8601 UTC form (suffix `Z`).

### What

In an OT environment (manufacturing, process, energy, or utilities),
engineering workstations or AI-assisted tools may propose changes such
as setpoint writes, logic downloads, interlock parameter updates, or
commands that affect physical equipment. Yama ensures that any such
protected effect is authorized by a supervisor that does not execute
the proposing code, that the authorization is re-validated immediately
before the change is applied, that the proposing process itself cannot
reach the controller, and that every payload carries provenance.

### Why

OT changes can have immediate physical consequences. A grant or work
order that was valid when an engineer or agent started work may be
revoked, may expire, or may no longer match the intended purpose by
the time the change is ready to apply. Direct credentials on the
engineering station create an unacceptable window. Yama is intended
to close that authorization window without placing the agent or
workstation in the position of being able to write to the controller
itself, by re-validating the grant immediately before the gateway
applies the change.

A residual time-of-check to time-of-write window remains after a
successful re-check and before the gateway write. On one localhost
run of the remote-revocation experiment, that window was median
0.001498 s and max 0.002449 s (n = 50). A revocation arriving inside
that window would not be observed by the re-check that already
returned. See
[docs/YAMA-RESEARCH-NOTE.md](../YAMA-RESEARCH-NOTE.md),
[docs/measurements/remote_revocation-2026-11-23.json](../measurements/remote_revocation-2026-11-23.json),
and the residual-risks list below. Reachability of the controller is
discussed under “What the proposing process cannot do”.

### Where

- Engineering workstation proposing a setpoint or recipe change
- AI-assisted diagnostics tool that recommends a parameter adjustment
- Automated change package that must be applied to a PLC, RTU, or drive
- Gateway or jump host that is the only component allowed to speak the industrial protocol

The supervisor sits in the control plane (or on a dedicated gate
host). Agents and engineering tools run under restraint and never hold
write credentials for the controllers.

### When

- Grant issued against a work order or change request (purpose =
  “setpoint change – line 3”, allowed effect = “write_setpoint”,
  short expiry).
- Provenance tag attached to every proposal that crosses to the supervisor.
- Commit-time re-check immediately before the protocol gateway applies the change.
- Revocation (operator cancel, interlock violation, expired work
  order) causes the commit to be refused even if the proposal has
  already been prepared.

### How (concrete flow)

1. A work order authorizes a limited setpoint change.
2. Controller issues a Grant bound to that purpose and effect.
3. The engineering tool or agent (under restraint) prepares the
   change payload and attaches Provenance.
4. Supervisor receives the proposal but does not apply it.
5. Immediately before the gateway writes to the controller, the
   supervisor re-validates the grant and provenance.
6. If the work order is cancelled or the grant expires, the commit
   is refused and no write occurs.
7. If all checks pass, the gateway (not the agent) performs the
   protected write and the supervisor logs the grant identifier
   together with provenance.

The runnable demonstration of steps 2, 5, 6, and 7 is:

```bash
python examples/ot_setpoint.py
```

### Sample Grant

Serialized with `Grant.to_json()`. The identifier field in this
package is `id`. `min_trust_level` defaults to `medium`;
`effect_min_trust` is empty unless a per-effect threshold is set.
The purpose string contains an en dash (U+2013), which
`json.dumps` encodes as `\u2013`.

```json
{
  "allowed_effects": [
    "write_setpoint"
  ],
  "effect_min_trust": {},
  "expiry": "2026-11-24T17:00:00Z",
  "id": "grant-ot-2026-11-24-line3",
  "min_trust_level": "medium",
  "principal": "workorder:WO-4412",
  "purpose": "setpoint change \u2013 line 3",
  "revoked": false
}
```

### Sample Provenance

Serialized with `Provenance.to_json()`, using origin
`engineering-workstation` and `trust_level` `medium`. The timestamp
is `2026-11-24T16:00:00Z` (one hour before the grant expiry above).

```json
{
  "origin": "engineering-workstation",
  "purpose_binding": "setpoint change \u2013 line 3",
  "timestamp": "2026-11-24T16:00:00Z",
  "trust_level": "medium"
}
```

### Sample commit outcomes

These bodies were produced by catching `GrantDenied` from
`commit_effect` (fields `reason`, `grant_id`, `effect`, and
`message` are the exception’s own values) or, in the allowed case,
by logging `grant.id` plus `provenance.to_dict()` after a successful
commit. The destination file is the simulated gateway sink. In every
refusal, that file did not exist afterwards.

#### (a) Revoked grant

```json
{
  "effect": "write_setpoint",
  "grant_id": "grant-ot-2026-11-24-line3",
  "message": "grant grant-ot-2026-11-24-line3 does not permit 'write_setpoint' (revoked)",
  "outcome": "refused",
  "reason": "revoked"
}
```

#### (b) Expired grant

The stored grant used the draft expiry `2025-11-23T17:00:00Z`,
which is already past.

```json
{
  "effect": "write_setpoint",
  "grant_id": "grant-ot-2026-11-24-line3",
  "message": "grant grant-ot-2026-11-24-line3 does not permit 'write_setpoint' (expired)",
  "outcome": "refused",
  "reason": "expired"
}
```

#### (c) Purpose mismatch

The payload’s `purpose_binding` was “setpoint change – line 4”
instead of “setpoint change – line 3”.

```json
{
  "effect": "write_setpoint",
  "grant_id": "grant-ot-2026-11-24-line3",
  "message": "grant grant-ot-2026-11-24-line3 cannot commit 'write_setpoint': purpose_binding 'setpoint change \u2013 line 4' does not match grant purpose 'setpoint change \u2013 line 3'",
  "outcome": "refused",
  "reason": "purpose_mismatch"
}
```

#### (d) Missing provenance

Passing no provenance tag:

```json
{
  "effect": "write_setpoint",
  "grant_id": "grant-ot-2026-11-24-line3",
  "message": "grant grant-ot-2026-11-24-line3 cannot commit 'write_setpoint': provenance is missing",
  "outcome": "refused",
  "reason": "provenance_missing"
}
```

#### Allowed commit audit log

After all checks passed, `commit_effect` wrote `setpoint-write.txt`
(the simulated gateway sink) and the demonstration logged the grant
id together with the provenance tag:

```json
{
  "effect": "write_setpoint",
  "grant_id": "grant-ot-2026-11-24-line3",
  "outcome": "allowed",
  "path": "setpoint-write.txt",
  "provenance": {
    "origin": "engineering-workstation",
    "purpose_binding": "setpoint change \u2013 line 3",
    "timestamp": "2026-11-24T16:00:00Z",
    "trust_level": "medium"
  }
}
```

### What the proposing process cannot do

The intended restraint boundary is that, because of process restraint
and credential separation, the agent or engineering tool cannot open
a direct protocol connection to the PLC/RTU or issue the write
itself. Only the gateway, after a successful Yama commit decision,
holds the path. Credential separation (not giving the proposing
process write credentials or a live path to the controller) is a
deployment responsibility, not something Yama itself issues or
withdraws.

What has been measured so far is narrower. In one run of
`benchmarks/baseline_attacks.py`
([docs/measurements/baseline_attacks-2026-11-23.json](../measurements/baseline_attacks-2026-11-23.json)),
a file write outside the allowed directory and exec of a denied
binary were observed blocked (`errno=13`, `EACCES`) after filesystem
Landlock was applied. A new outbound TCP connection to `1.1.1.1:443`
was allowed under that same filesystem-only Landlock
(`seccomp_applied` was false). Network-level blocking of industrial
protocol ports such as Modbus/TCP (502) or EtherNet/IP (44818)
therefore needs Landlock ABI ≥ 4 TCP-connect rules, seccomp-BPF, or
network segmentation / firewalling. Those network restraints are not
yet implemented or measured in this prototype.

### OT-specific residual risks and limits (explicit)

- Yama is not a safety function and must sit outside any SIL-rated boundary.
- A non-zero window can still exist between the final re-check and
  the gateway write. On one localhost run, that window was median
  0.001498 s and max 0.002449 s (n = 50); see
  [docs/measurements/remote_revocation-2026-11-23.json](../measurements/remote_revocation-2026-11-23.json)
  and the qualification in Why above.
- Air-gapped or partitioned networks require a local fail-closed
  policy when the supervisor cannot be reached; this is not yet
  implemented.
- Semantic correctness of the proposed value (whether the new
  setpoint is actually safe) is outside Yama’s scope.
- Already-applied changes are not rolled back by later revocation.
- The current Linux restraint mechanisms do not run on most PLCs or
  legacy controllers; restraint is realized at the workstation and
  gateway.
- Network-level blocking depends on the restraint implementation and
  on deployment-time segmentation. In the measured baseline above,
  filesystem Landlock did not block an outbound TCP connect.

### Illustrative only

This is an illustrative scenario for how the Yama property can be applied to OT change control. It is not a claim of IEC 62443 compliance, SIL certification, or readiness for unsupervised production use.
