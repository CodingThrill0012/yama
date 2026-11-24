# Yama

Supervisor-owned authorization and process restraint for multi-agent systems.

## The Yama Property

Yama is a system-independent control property for multi-agent systems: every protected side-effect must be authorized by a supervisor that does not execute the agent’s code; that authorization must be re-validated immediately before the effect is committed; the agent itself must be incapable of producing the protected side-effect; and every payload that crosses an agent or supervisor boundary must carry an explicit provenance tag such that untagged or insufficiently trusted content cannot acquire new authority. Authorization alone does not provide semantic safety.

## Security model

A short write-up of why the property exists, the four conditions, and open research questions is in [docs/security-model.md](docs/security-model.md).

Yama is a small Python utility for systems in which a supervisor issues
short-lived grants to worker processes (agents), and those workers must
re-check the grant immediately before committing a protected effect.
Where the Linux kernel allows it, a worker can also restrain itself with
Landlock, seccomp-BPF, `PR_SET_NO_NEW_PRIVS`, an optional privilege drop,
and an optional chroot fallback.

This project was formerly developed under the working name BEACON.

## What / Why / How

**What.** A `Grant` names a principal, a purpose, a set of allowed
effects, an expiry, and a minimum provenance trust level. Grants are
immutable. A supervisor-owned `GrantStore` is the only place a grant can
be issued or revoked. Workers open the store read-only and call
`commit_effect` with a `Provenance` tag, which re-reads the grant from
the store and checks purpose and trust immediately before an atomic write.

**Why.** In a multi-agent system, a worker that was allowed to write a
file a moment ago may have had that right revoked, or the grant may have
expired, before the write actually happens. A capability baked into the
worker at start time cannot see that change. Yama keeps authorization
with the supervisor and treats process restraints as a separate,
best-effort layer that limits what a worker can touch even if it
misbehaves.

**How.** The supervisor writes grant records into a directory the
workers can read but should not be able to write (filesystem
permissions, and Landlock write paths that exclude the store). A worker
calls `restrain(...)` to apply any available kernel restraints, then
`commit_effect(...)` for each protected write, passing a `Provenance`
tag whose `purpose_binding` equals the grant purpose. If Landlock or
seccomp is unavailable, Yama reports that clearly and does not pretend
the restraint was applied.

## Status

Research prototype based on the BEACON v0.6 controlled experiment.

This repository is a clean, reusable implementation of the supervisor-owned
grant and process-restraint design. It does not republish experimental
measurements from BEACON.

A longer record of the property, provenance rules, and later experiments
is in [docs/YAMA-RESEARCH-NOTE.md](docs/YAMA-RESEARCH-NOTE.md).

## Provenance and purpose binding

`commit_effect` refuses a write unless the payload carries a `Provenance`
tag (`origin`, `trust_level`, `purpose_binding`, `timestamp`) that is
checked against the freshly loaded grant:

- missing tag → `provenance_missing`
- `purpose_binding` is not exactly `grant.purpose` → `purpose_mismatch`
- `trust_level` is below the required minimum → `insufficient_trust`

The required minimum for effect *E* is `grant.min_trust_level` (default
`medium`), raised to `grant.effect_min_trust[E]` when that override is
set. `TrustLevel` is the ordered enum `untrusted < low < medium < high`.
A payload meets the threshold iff `provenance.trust_level >= required`.

This closes the semantic-overclaim gap in the sense that authority can
no longer be acquired by untagged, low-trust, or mis-purposed payloads.
The Yama Property's caveat still stands: authorization alone does not
provide semantic safety. Provenance tags are asserted metadata; Yama
does not verify that the payload's content is truthful, nor that the
stated origin is authentic.

## Installation

Python 3.9 or later is required.

```bash
git clone https://github.com/CodingThrill0012/yama.git
cd yama
python -m pip install -e .

# optional seccomp-BPF Python bindings
python -m pip install -e ".[seccomp]"

# development (pytest)
python -m pip install -e ".[dev]"
```

## Basic usage

### Python API

```python
from datetime import datetime, timedelta, timezone
from yama import (
    GrantStore, issue_grant, restrain, commit_effect, GrantDenied,
    Provenance, TrustLevel,
)

store = GrantStore("/var/lib/yama/grants")  # supervisor, writable
grant = issue_grant(
    principal="writer-1",
    purpose="write the approved report",
    allowed_effects=["write_report"],
    ttl=timedelta(minutes=30),
    min_trust_level=TrustLevel.MEDIUM,
)
store.put(grant)

# In a worker process:
store = GrantStore("/var/lib/yama/grants", readonly=True)
report = restrain(
    read_paths=["/var/lib/yama/grants", "/var/lib/yama/work"],
    write_paths=["/var/lib/yama/work"],
)
print(report)  # shows what was applied vs unavailable

provenance = Provenance(
    origin="writer-1",
    trust_level=TrustLevel.HIGH,
    purpose_binding=grant.purpose,
    timestamp=datetime.now(timezone.utc),
)
try:
    commit_effect(
        store, grant.id, "write_report",
        "/var/lib/yama/work/report.txt", "ok\n",
        provenance=provenance,
    )
except GrantDenied as exc:
    print(f"write refused: {exc.reason}")
```

### CLI

```bash
yama doctor

yama grant create \
  --principal writer-1 \
  --purpose "write the approved report" \
  --effects write_report \
  --ttl 30m \
  --store ./yama-grants

yama grant show GRANT_ID --store ./yama-grants
yama check GRANT_ID --effect write_report --store ./yama-grants
yama check GRANT_ID --effect write_report \
  --origin writer-1 --trust high \
  --purpose-binding "write the approved report" \
  --store ./yama-grants
yama commit GRANT_ID --effect write_report --path ./work/report.txt \
  --data "ok" --origin writer-1 --trust high \
  --purpose-binding "write the approved report" \
  --store ./yama-grants

yama run --grant GRANT_ID --effect write_report \
  --store ./yama-grants \
  --read-path ./yama-grants \
  --write-path ./work \
  -- -- python worker.py

yama grant revoke GRANT_ID --store ./yama-grants
```

`yama run` re-checks the grant, applies any available restraints in the
current process, and then `exec`s the command. The grant store is always
added as a read path. CPython and common OS paths are added as read
paths unless you pass `--no-runtime-reads`.

### Three-worker example

```bash
python examples/three_workers.py
```

The supervisor issues grants to a reader, a writer, and a third worker
whose grant is revoked mid-run. Each worker restrains itself and
attempts commits. The example is designed to run unprivileged on a
normal Linux box and to continue if Landlock or seccomp-BPF is
unavailable.

### Remote revocation example

```bash
python examples/remote_revocation.py --trials 50 --delay 0.05
```

A localhost HTTP supervisor issues a grant; the worker obtains it,
waits, and re-checks at commit time. The treatment condition revokes the
grant during the wait; the control condition does not. Measured refusal
rates, re-check latency, and the post-check write window from a run of
this script are recorded in
[docs/YAMA-RESEARCH-NOTE.md](docs/YAMA-RESEARCH-NOTE.md)
and [docs/measurements/remote_revocation-2026-11-23.json](docs/measurements/remote_revocation-2026-11-23.json).

### Comparative baseline

```bash
python benchmarks/baseline_attacks.py
```

The script runs three attacks in a child process, once plain and once
after `restrain()`: (a) a file write outside the allowed directory,
(b) a new outbound TCP connection, (c) exec of a binary that is not in
the allowed directory. Observed outcomes from one run on this box are
recorded in [docs/YAMA-RESEARCH-NOTE.md](docs/YAMA-RESEARCH-NOTE.md)
and [docs/measurements/baseline_attacks-2026-11-23.json](docs/measurements/baseline_attacks-2026-11-23.json).
Container and gVisor columns are marked "to be measured". A result is
recorded as blocked only when the syscall failed with `EACCES` or
`EPERM` after Landlock or seccomp was applied.

## Use cases

- [Banking: supervisor-owned commit control for AI-assisted payment and servicing workflows](docs/usecases/banking.md) (illustrative scenario, not a deployed bank system).

## Related work

Commit-time re-validation is not claimed as a new idea. See Santos-Grueiro,
*Temporary Authority, Permanent Effects: Commit-Time Authorization for
LLM Agents*, arXiv:2607.10487, https://arxiv.org/abs/2607.10487
(verified 23 Nov 2026). A slightly longer note is in the
[research note](docs/YAMA-RESEARCH-NOTE.md#related-work).

## Security caveats

Yama is a research prototype, not a complete sandbox and not a
substitute for containers or virtual-machine isolation.

- **Linux-only restraints.** Landlock, seccomp-BPF, and
  `PR_SET_NO_NEW_PRIVS` are Linux features. On other platforms the
  authorization store and `commit_effect` still work; kernel restraints
  are reported as unavailable.
- **Landlock needs Linux kernel ≥ 5.13** (and a kernel built with
  Landlock enabled). Yama probes the ABI through the
  `landlock_create_ruleset` syscall on x86_64 and aarch64.
- **seccomp-BPF** is applied only when the optional `seccomp` or
  `pyseccomp` module can be imported. Without those bindings Yama does
  not load a filter.
- **chroot and privilege drop** typically require starting as root. An
  unprivileged process will see them reported as unavailable.
- **Never infer enforcement from a successful function call.** Read the
  `RestraintReport`. A restraint counts only when its `applied` flag is
  true.
- **Workers must not be able to write the grant store.** The read-only
  store API refuses `put` and `revoke`, but a worker that can overwrite
  the JSON files can still forge a grant unless the supervisor also
  enforces that at the filesystem (permissions and, when applied,
  Landlock write paths that exclude the store).
- **Landlock is not a full filesystem LSM.** Some families of syscalls
  (for example `chmod`, `chown`, `stat`) are not restricted by current
  Landlock ABIs. Open file descriptors from before `restrain()` keep
  their access.

## License

The software in this repository is licensed under the MIT License.
See [LICENSE](LICENSE). Copyright (c) 2026 Divyendu Bhatt.

The accompanying documentation may be relicensed under
[CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) if you prefer
that for prose, matching the license used for
[DAIRM](https://github.com/CodingThrill0012/dairm).
