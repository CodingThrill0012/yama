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

## Remote revocation experiment

This section records one run of `examples/remote_revocation.py`. The
figures below are from that run only. They are not a deployment
prevalence estimate and are not a bound on behaviour under packet loss
or a wide-area path.

### Setup

- Script: `examples/remote_revocation.py` (defaults: 50 trials per
  condition, 0.05 s worker delay after obtain).
- Supervisor: an unauthenticated `ThreadingHTTPServer` bound to
  `127.0.0.1` on an ephemeral port, serving a directory-backed
  `GrantStore`. Every worker `get()` is a fresh HTTP GET, so
  `commit_effect` / `check_commit` observes a remote revocation on the
  re-check.
- Conditions:
  - *Treatment:* worker obtains a valid grant; the supervisor then
    revokes it; the worker sleeps 0.05 s and re-checks immediately
    before writing.
  - *Control:* the same obtain–sleep–re-check–write sequence, with no
    revocation.
- Provenance tags used in the experiment were well-formed and
  purpose-bound (`trust_level=high`, `purpose_binding` equal to
  `grant.purpose`). This experiment tests revocation, not provenance
  rejection.
- Raw machine-readable output:
  `docs/measurements/remote_revocation-2026-11-23.json`.

### Box

Measured at the time of the run (23 Nov 2026, 8:07 AM Asia/Calcutta):

- kernel: `6.12.113+`
- architecture: `x86_64`
- Python: `3.13.5`
- CPU model (from `/proc/cpuinfo`): `Intel(R) Xeon(R) Processor`
- `MemTotal` (from `/proc/meminfo`): `16386416` KiB
- euid: `1000`

### Measured results

50 trials in each condition, worker delay 0.05 s, elapsed 5.519 s.

**Treatment (revocation before commit):** 50/50 commits refused
(refusal rate 1.000). All 50 refusals had reason `revoked`. 0/50 were
allowed.

- Re-check latency (seconds, start of `check_commit` to `GrantDenied`):
  min 0.001011, median 0.001270, p95 0.001745, max 0.001970
  (n = 50).
- Revoke-to-refusal (seconds, return of `supervisor.revoke` to
  `GrantDenied`): min 0.051151, median 0.051402, p95 0.051850,
  max 0.052095 (n = 50). This is approximately the configured 0.05 s
  delay plus the re-check latency, as expected from the trial
  sequence.

**Control (no revocation):** 50/50 commits allowed (allow rate 1.000).
0/50 were refused.

- Re-check latency (seconds, start of `check_commit` to its return):
  min 0.000890, median 0.001251, p95 0.001560, max 0.001658
  (n = 50).
- TOCTOU window (seconds, return of a successful `check_commit` to
  return of `atomic_write`): min 0.000680, median 0.001498,
  p95 0.002144, max 0.002449 (n = 50).

Times are `time.perf_counter()` intervals on this box. They are
reported here to six decimal places of a second, rounded from the raw
values in the JSON file.

### Limitations

- Localhost only. The supervisor and the worker shared a host. No
  network partition, packet loss, reordering, or WAN delay was
  introduced.
- The HTTP supervisor is a measurement fixture: it has no
  authentication and is refused at construction if asked to bind
  outside `127.0.0.1` / `localhost` / `::1`.
- A time-of-check to time-of-write window remains after a successful
  re-check and before the durable `os.replace`. On this run that window
  was between 0.000680 s and 0.002449 s (median 0.001498 s). The
  experiment does not close that window, and a revocation arriving
  inside it would not be observed by the re-check that already
  returned.
- Results are for this box, this Python, this delay, and this N. They
  should be re-measured before being cited for any other environment.

## Comparative baseline

This section records one run of `benchmarks/baseline_attacks.py` on this
box. Only observed outcomes are reported. Container and gVisor
comparisons were not run and are marked "to be measured". A row is
called "blocked" only when the operation failed with `EACCES` or
`EPERM` after Yama reported that Landlock was applied. Other failures
would have been recorded as `failed-other` and are not treated as Yama
blocks.

### Setup

- Script: `benchmarks/baseline_attacks.py`.
- Profiles: `plain` (no restraints) and `yama` (`restrain()` with
  `write_paths` / `read_paths` limited to an allowed directory,
  `include_runtime_reads=True`, `PR_SET_NO_NEW_PRIVS`). The current
  `restrain()` path applies filesystem Landlock when the kernel
  supports it; it does not install Landlock TCP-connect rules or a
  seccomp-BPF filter in this run (`seccomp_applied` was false in every
  Yama child).
- Attacks:
  - (a) write `denied/pwn.txt` outside the allowed directory;
  - (b) `socket.connect` to `1.1.1.1:443` (timeout 3 s);
  - (c) `os.execv` of a copy of `/usr/bin/true` placed in the denied
    directory (so the binary is not in the Landlock ruleset).
- Raw output: `docs/measurements/baseline_attacks-2026-11-23.json`.

### Box

Same host as the remote-revocation run, measured 23 Nov 2026,
8:08 AM Asia/Calcutta:

- kernel: `6.12.113+`
- architecture: `x86_64`
- Python: `3.13.5`
- Landlock ABI on the parent process: 6
- CPU model (from `/proc/cpuinfo`): `Intel(R) Xeon(R) Processor`
- `MemTotal`: `16386416` KiB
- euid: `1000`

### Observed outcomes

| Attack | plain | Yama (`restrain()`, FS Landlock ABI 6) | container | gVisor |
| --- | --- | --- | --- | --- |
| (a) file write outside allowed directory | allowed (file created) | blocked (`errno=13` EACCES); `landlock_applied=True`; the denied file did not exist afterwards | to be measured | to be measured |
| (b) new outbound TCP connection to 1.1.1.1:443 | allowed (connect succeeded) | allowed (connect succeeded); `landlock_applied=True`; `seccomp_applied=False` | to be measured | to be measured |
| (c) exec of `denied/true` (copy of `/usr/bin/true`) | allowed (child exit 0) | blocked (`errno=13` EACCES); `landlock_applied=True` | to be measured | to be measured |

Network blocking needs Landlock ABI >= 4 with TCP connect rules, or
seccomp-BPF. This run used filesystem Landlock only, and the outbound
connection was not blocked. That is an observed allowance, not a
claim that Yama cannot be configured to block connect() in a later
change.

### Limitations

- One run, this box, this kernel, this Python.
- Container and gVisor were not measured.
- The exec attack used a binary *outside* the allowed directory.
  Exec of a runtime path that `include_runtime_reads=True` leaves
  executable (for example `/usr/bin/true` itself) was not measured
  in this run and must not be assumed blocked.
- No seccomp bindings were installed, and no Landlock net rules were
  applied.

## Related work

Yama is not the first statement of commit-time authorization, and this
repository does not claim that commit-time re-validation is a new
idea.

Santos-Grueiro, Igor. *Temporary Authority, Permanent Effects:
Commit-Time Authorization for LLM Agents*. arXiv:2607.10487 [cs.CR],
https://arxiv.org/abs/2607.10487. First submitted 11 July 2026;
version 2 dated 31 October 2026 (the record resolved as
`2607.10487v2` when checked).

The identifier was verified on 23 Nov 2026 by fetching
`https://arxiv.org/abs/2607.10487` and the export.arxiv.org API
(`https://export.arxiv.org/api/query?id_list=2607.10487`). Both
returned that title, that author, primary category `cs.CR`, and an
abstract about commit-time authorization of durable effects. No
figures or tables from that paper are reproduced here as if they were
measured in this repository, and this prototype is not a comparison
against that work.
