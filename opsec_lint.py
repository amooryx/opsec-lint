#!/usr/bin/env python3
"""opsec-lint - Lint an engagement plan for common OPSEC mistakes

Authorised security testing only. See README.
"""
from __future__ import annotations

import argparse
import sys

TOOL = "opsec-lint"
DESCRIPTION = "Lint an engagement plan for common OPSEC mistakes"


def banner() -> None:
    print(f"[ {TOOL} ] {DESCRIPTION}")


def authorised(assume_yes: bool) -> bool:
    """Refuse to run against a target without an explicit authorisation ack.

    This is not legal cover; it is a deliberate speed bump. Offensive tooling
    should never run by accident against the wrong target.
    """
    if assume_yes:
        return True
    ans = input("Do you have written authorisation to test this target? [y/N] ")
    return ans.strip().lower() in ("y", "yes")


def run(args: argparse.Namespace) -> int:
    """Core routine.

    This is a scaffold: it validates input, states scope, and defines the
    workflow. Extend `run()` with the checks your engagement needs.
    """
    banner()
    print(f"[*] target : {args.target}")
    print(f"[*] output : {args.output or '(stdout)'}")
    print("[*] scaffold ready - implement engagement-specific logic in run().")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL, description=DESCRIPTION)
    p.add_argument("target", help="target host, domain, file, or scope identifier")
    p.add_argument("-o", "--output", help="write results to this file")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    p.add_argument("-y", "--yes", action="store_true", help="skip the authorisation prompt")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not authorised(args.yes):
        print("[!] authorisation not confirmed; nothing was done.")
        return 1
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n[!] interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
