"""Command-line interface for APISECLINT."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    lint_spec,
    load_spec,
    render_table,
    render_json,
    render_html,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Lint an OpenAPI spec for API security gaps "
                    "(authn/authz, rate limiting, data exposure).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    lint = sub.add_parser("lint", help="Lint an OpenAPI spec file.")
    lint.add_argument("spec", help="Path to an OpenAPI spec (.json/.yaml).")
    lint.add_argument("--format", choices=["table", "json", "html"],
                      default="table", help="Output format (default: table).")
    lint.add_argument("-o", "--output",
                      help="Write report to this file instead of stdout.")
    lint.add_argument("--exit-zero", action="store_true",
                      help="Always exit 0, even when findings are present.")
    return p


def _run_lint(args) -> int:
    try:
        with open(args.spec, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"error: cannot read {args.spec}: {exc}", file=sys.stderr)
        return 2
    try:
        spec = load_spec(text)
    except Exception as exc:
        print(f"error: cannot parse spec: {exc}", file=sys.stderr)
        return 2
    if not isinstance(spec, dict):
        print("error: spec root is not a mapping/object", file=sys.stderr)
        return 2

    report = lint_spec(spec, source=args.spec)

    if args.format == "json":
        rendered = render_json(report)
    elif args.format == "html":
        rendered = render_html(report)
    else:
        rendered = render_table(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        print(rendered)

    if args.exit_zero:
        return 0
    return 1 if report.failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "lint":
        return _run_lint(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
