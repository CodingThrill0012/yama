# Yama

Supervisor-owned authorization and process restraint for multi-agent systems.

## The Yama Property

Yama is a system-independent control property for multi-agent systems: every protected side-effect must be authorized by a supervisor that does not execute the agent’s code; that authorization must be re-validated immediately before the effect is committed; the agent itself must be incapable of producing the protected side-effect; and every payload that crosses an agent or supervisor boundary must carry an explicit provenance tag such that untagged or insufficiently trusted content cannot acquire new authority. Authorization alone does not provide semantic safety.

Yama is a small Python utility for systems in which a supervisor issues
short-lived grants to worker processes (agents), and those workers must
re-check the grant immediately before committing a protected effect.
Where the Linux kernel allows it, a worker can also restrain itself with
Landlock, seccomp-BPF, `PR_SET_NO_NEW_PRIVS`, an optional privilege drop,
and an optional chroot fallback.

This project was formerly developed under the working name BEACON.

## What / Why / How

**What.** A `Grant` names a principal, a purpose, a set of allowed
effects, and an expiry. Grants are immutable. A supervisor-owned
`GrantStore` is the only place a grant can be issued or revoked. Workers
open the store read-only and call `commit_effect`, which re-reads the
grant from the store immediately before an atomic write.

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
`commit_effect(...)` for each protected write. If Landlock or seccomp is
unavailable, Yama reports that clearly and does not pretend the
restraint was applied.

## Status

Research prototype based on the BEACON v0.6 controlled experiment.

This repository is a clean, reusable implementation of the supervisor-owned
grant and process-restraint design. It does not republish experimental
measurements from BEACON.

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
from datetime import timedelta
from yama import GrantStore, issue_grant, restrain, commit_effect, GrantDenied

store = GrantStore("/var/lib/yama/grants")  # supervisor, writable
grant = issue_grant(
    principal="writer-1",
    purpose="write the approved report",
    allowed_effects=["write_report"],
    ttl=timedelta(minutes=30),
)
store.put(grant)

# In a worker process:
store = GrantStore("/var/lib/yama/grants", readonly=True)
report = restrain(
    read_paths=["/var/lib/yama/grants", "/var/lib/yama/work"],
    write_paths=["/var/lib/yama/work"],
)
print(report)  # shows what was applied vs unavailable

try:
    commit_effect(store, grant.id, "write_report", "/var/lib/yama/work/report.txt", "ok\n")
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
