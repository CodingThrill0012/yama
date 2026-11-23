"""Command-line interface for Yama."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Sequence

from yama import __version__
from yama.commit import GrantDenied, check_effect
from yama.grant import GrantError, GrantNotFound, GrantStore, issue_grant
from yama.restrict import doctor_lines, restrain


def _store_path(value: Optional[str]) -> Path:
    if value:
        return Path(value)
    env = os.environ.get("YAMA_STORE")
    if env:
        return Path(env)
    return Path("yama-grants")


def _parse_ttl(text: str) -> timedelta:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if text.isdigit():
        return timedelta(seconds=int(text))
    suffix = text[-1].lower()
    if suffix not in units or not text[:-1].isdigit():
        raise argparse.ArgumentTypeError(
            "ttl must be a number of seconds, or end in s, m, h, or d (for example 30m)"
        )
    return timedelta(seconds=int(text[:-1]) * units[suffix])


def _parse_expiry(text: str) -> datetime:
    raw = text.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid expiry: {text}") from exc
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _open_store(args: argparse.Namespace, *, readonly: bool) -> GrantStore:
    return GrantStore(_store_path(getattr(args, "store", None)), readonly=readonly)


def cmd_grant_create(args: argparse.Namespace) -> int:
    effects = [item.strip() for item in args.effects.split(",") if item.strip()]
    if not effects:
        print("error: --effects must be a comma-separated list of names", file=sys.stderr)
        return 2
    expiry = args.expiry
    ttl = args.ttl
    if expiry is None and ttl is None:
        ttl = timedelta(hours=1)
    try:
        grant = issue_grant(
            principal=args.principal,
            purpose=args.purpose,
            allowed_effects=effects,
            expiry=expiry,
            ttl=ttl,
            grant_id=args.id,
        )
        store = _open_store(args, readonly=False)
        store.put(grant)
    except GrantError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(grant.to_json(), end="")
    return 0


def cmd_grant_show(args: argparse.Namespace) -> int:
    try:
        grant = _open_store(args, readonly=True).get(args.grant_id)
    except (GrantError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(grant.to_json(), end="")
    valid = "valid" if grant.is_valid() else grant.denial_reason() or "invalid"
    print(f"# status: {valid}", file=sys.stderr)
    return 0


def cmd_grant_revoke(args: argparse.Namespace) -> int:
    try:
        grant = _open_store(args, readonly=False).revoke(args.grant_id)
    except (GrantError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(grant.to_json(), end="")
    return 0


def cmd_grant_list(args: argparse.Namespace) -> int:
    try:
        store = _open_store(args, readonly=True)
        grants = list(store)
    except (GrantError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not grants:
        print("# no grants in store", file=sys.stderr)
        return 0
    for grant in grants:
        status = "valid" if grant.is_valid() else grant.denial_reason() or "invalid"
        effects = ",".join(sorted(grant.allowed_effects)) or "-"
        print(f"{grant.id}\t{grant.principal}\t{status}\t{effects}\t{grant.expiry.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        store = _open_store(args, readonly=True)
        if args.effect:
            grant = check_effect(store, args.grant_id, args.effect)
            print(f"permitted: grant {grant.id} allows {args.effect!r}")
            return 0
        grant = store.get(args.grant_id)
        if grant.is_valid():
            print(f"valid: grant {grant.id} is in force until {grant.expiry.strftime('%Y-%m-%dT%H:%M:%SZ')}")
            return 0
        reason = grant.denial_reason() or "invalid"
        print(f"denied: grant {grant.id} is {reason}", file=sys.stderr)
        return 1
    except GrantDenied as exc:
        print(f"denied: {exc}", file=sys.stderr)
        return 1
    except (GrantNotFound, GrantError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    if not args.command:
        print("error: provide a command after --", file=sys.stderr)
        return 2
    try:
        store = _open_store(args, readonly=True)
        if args.effect:
            check_effect(store, args.grant, args.effect)
        else:
            grant = store.get(args.grant)
            if not grant.is_valid():
                raise GrantDenied(
                    f"grant {grant.id} is {grant.denial_reason() or 'invalid'}",
                    grant_id=grant.id,
                    reason=grant.denial_reason(),
                )
    except GrantDenied as exc:
        print(f"denied: {exc}", file=sys.stderr)
        return 1
    except (GrantError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    report = restrain(
        read_paths=list(args.read_path or []) + [str(_store_path(args.store))],
        write_paths=list(args.write_path or []),
        include_runtime_reads=not args.no_runtime_reads,
        seccomp_deny=list(args.seccomp_deny or []) or None,
        no_new_privs=not args.allow_new_privs,
        drop_uid=args.drop_uid,
        drop_gid=args.drop_gid,
        chroot_dir=args.chroot,
    )
    print(report.format(), file=sys.stderr)
    if args.require_landlock and not (report.get("landlock") and report.get("landlock").applied):
        print("error: Landlock was required but was not applied", file=sys.stderr)
        return 1

    executable = args.command[0]
    try:
        os.execvp(executable, args.command)
    except OSError as exc:
        print(f"error: exec failed: {exc}", file=sys.stderr)
        return 127


def cmd_doctor(_args: argparse.Namespace) -> int:
    print("\n".join(doctor_lines()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yama",
        description="Supervisor-owned authorization and process restraint for multi-agent systems.",
    )
    parser.add_argument("--version", action="version", version=f"yama {__version__}")
    store_flags = argparse.ArgumentParser(add_help=False)
    store_flags.add_argument(
        "--store",
        default=None,
        help="grant store directory (default: $YAMA_STORE or ./yama-grants)",
    )
    parser.add_argument(
        "--store",
        default=None,
        help="grant store directory (default: $YAMA_STORE or ./yama-grants)",
    )
    sub = parser.add_subparsers(dest="command_name")

    grant = sub.add_parser(
        "grant",
        parents=[store_flags],
        help="create, show, list, or revoke grants",
    )
    grant_sub = grant.add_subparsers(dest="grant_command")

    create = grant_sub.add_parser(
        "create",
        parents=[store_flags],
        help="issue a grant into the store",
    )
    create.add_argument("--principal", required=True, help="worker or agent this grant is for")
    create.add_argument("--purpose", required=True, help="why the grant is being issued")
    create.add_argument(
        "--effects",
        required=True,
        help="comma-separated list of allowed effect names",
    )
    create.add_argument("--expiry", type=_parse_expiry, help="UTC expiry, for example 2026-11-23T12:00:00Z")
    create.add_argument("--ttl", type=_parse_ttl, help="lifetime, for example 30m or 2h (default 1h)")
    create.add_argument("--id", help="optional grant id (default: a UUID)")
    create.set_defaults(func=cmd_grant_create)

    show = grant_sub.add_parser("show", parents=[store_flags], help="print one grant from the store")
    show.add_argument("grant_id")
    show.set_defaults(func=cmd_grant_show)

    revoke = grant_sub.add_parser("revoke", parents=[store_flags], help="revoke a grant (supervisor only)")
    revoke.add_argument("grant_id")
    revoke.set_defaults(func=cmd_grant_revoke)

    listing = grant_sub.add_parser("list", parents=[store_flags], help="list grants in the store")
    listing.set_defaults(func=cmd_grant_list)

    check = sub.add_parser("check", parents=[store_flags], help="re-read a grant and test whether it is valid or permits an effect")
    check.add_argument("grant_id")
    check.add_argument("--effect", help="effect name to test")
    check.set_defaults(func=cmd_check)

    run = sub.add_parser(
        "run",
        parents=[store_flags],
        help="re-check a grant, apply restraints in this process, then exec a command",
    )
    run.add_argument("--grant", required=True, help="grant id to re-check before exec")
    run.add_argument("--effect", help="require this effect to be permitted")
    run.add_argument(
        "--read-path",
        action="append",
        default=[],
        help="path the process may read (repeatable); the grant store is always included",
    )
    run.add_argument(
        "--write-path",
        action="append",
        default=[],
        help="path the process may write (repeatable)",
    )
    run.add_argument(
        "--no-runtime-reads",
        action="store_true",
        help="do not add default CPython / OS read paths to the Landlock ruleset",
    )
    run.add_argument(
        "--seccomp-deny",
        action="append",
        default=[],
        help="syscall name to deny with seccomp-BPF if bindings are installed (repeatable)",
    )
    run.add_argument("--chroot", help="optional chroot directory (typically requires root)")
    run.add_argument("--drop-uid", type=int, help="optional uid to drop to (typically requires root)")
    run.add_argument("--drop-gid", type=int, help="optional gid to drop to")
    run.add_argument(
        "--allow-new-privs",
        action="store_true",
        help="do not set PR_SET_NO_NEW_PRIVS (Landlock will likely fail)",
    )
    run.add_argument(
        "--require-landlock",
        action="store_true",
        help="abort if Landlock cannot be applied",
    )
    run.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="command to exec; precede it with --",
    )
    run.set_defaults(func=cmd_run)

    doctor = sub.add_parser("doctor", parents=[store_flags], help="report kernel and runtime support without applying restraints")
    doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        if getattr(args, "command_name", None) == "grant" and not getattr(args, "grant_command", None):
            parser.parse_args(["grant", "--help"])
            return 2
        parser.print_help()
        return 2
    # argparse REMAINDER may keep one or more leading "--" separators.
    if getattr(args, "command", None):
        command = list(args.command)
        while command and command[0] == "--":
            command = command[1:]
        args.command = command
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
