#!/usr/bin/env python3
"""opsec-lint - Lint an engagement plan for common OPSEC mistakes

Authorised security testing only. See README.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TOOL = "opsec-lint"
DESCRIPTION = "Lint an engagement plan for common OPSEC mistakes"
MAX_INPUT_BYTES = 1024 * 1024
PRIVATE_KEY_HEADER = re.compile(
    r"^[ \t]*-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[ \t]*$",
    re.MULTILINE,
)


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
    """Run the file checks or retain the scaffold behavior for scope targets."""
    banner()
    print(f"[*] target : {args.target}")
    print(f"[*] output : {args.output or '(stdout)'}")
    source = Path(args.target)
    try:
        is_file = source.is_file()
    except OSError as exc:
        print(f"[!] cannot inspect input file: {exc}", file=sys.stderr)
        return 2

    if is_file:
        output_path = Path(args.output) if args.output else None
        if output_path is not None:
            try:
                same_path = source.resolve() == output_path.resolve()
                try:
                    same_path = same_path or source.samefile(output_path)
                except FileNotFoundError:
                    pass
                if same_path:
                    print("[!] output file must not be the input file.", file=sys.stderr)
                    return 2
            except OSError as exc:
                print(f"[!] cannot resolve file path: {exc}", file=sys.stderr)
                return 2

        try:
            with source.open("rb") as input_file:
                raw_content = input_file.read(MAX_INPUT_BYTES + 1)
        except OSError as exc:
            print(f"[!] cannot read input file: {exc}", file=sys.stderr)
            return 2

        if len(raw_content) > MAX_INPUT_BYTES:
            print(
                f"[!] input file exceeds the {MAX_INPUT_BYTES}-byte limit.",
                file=sys.stderr,
            )
            return 2
        try:
            content = raw_content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            print(f"[!] input file is not valid UTF-8: {exc}", file=sys.stderr)
            return 2

        findings = [
            f"{source}:{line_number}: private-key PEM header found"
            for line_number, line in enumerate(content.splitlines(), start=1)
            if PRIVATE_KEY_HEADER.fullmatch(line)
        ]
        results = "\n".join(findings) if findings else "No private-key PEM headers found."
        if output_path is None:
            print(results)
        else:
            try:
                output_path.write_text(results + "\n", encoding="utf-8")
            except OSError as exc:
                print(f"[!] cannot write output file: {exc}", file=sys.stderr)
                return 2
            print(f"[+] results written to {output_path}")
        return 1 if findings else 0

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
