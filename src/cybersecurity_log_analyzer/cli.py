"""Command-line interface for the defensive log analyzer."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import Sequence

from .analyzer import analyze_lines


def main(argv: Sequence[str] | None = None) -> int:
    """Run the analyzer and return a process exit code."""

    parser = argparse.ArgumentParser(
        description="Analyze synthetic authentication logs defensively."
    )
    parser.add_argument("input_file", type=Path, help="UTF-8 authentication log file")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="failed logins from one IP required to flag it (default: 3)",
    )
    args = parser.parse_args(argv)

    try:
        contents = args.input_file.read_text(encoding="utf-8")
        report = analyze_lines(contents.splitlines(), args.threshold)
    except FileNotFoundError:
        print(f"Input file not found: {args.input_file}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as error:
        print(f"Could not read input file: {error}", file=sys.stderr)
        return 2
    except ValueError as error:
        print(f"Invalid analysis option: {error}", file=sys.stderr)
        return 2

    print(json.dumps(asdict(report), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
