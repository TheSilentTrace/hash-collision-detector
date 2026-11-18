#!/usr/bin/env python3
"""Hash Collision Detector - command-line entry point.

Run ``python main.py`` for the interactive menu or ``python main.py --help``
for the scripting interface.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from collision_detector import (
    CollisionDetector,
    ScanResult,
    render_report,
    results_to_json,
    scan_inputs,
)
from hash_generator import (
    DISPLAY_NAMES,
    SUPPORTED_ALGORITHMS,
    UnsupportedAlgorithmError,
    digest_bits,
    display_name,
    normalize_algorithm,
)
from utils import (
    banner,
    configure_color,
    parse_input_line,
    read_inputs_from_file,
    rule,
    save_report,
    style,
)

__version__ = "1.0.0"

EXIT_OK = 0
EXIT_COLLISION = 1
EXIT_ERROR = 2

SAMPLE_INPUTS = [
    "hello",
    "Hello",
    "hello ",
    "password",
    "passw0rd",
    "The quick brown fox jumps over the lazy dog",
    "The quick brown fox jumps over the lazy dog.",
]


# --------------------------------------------------------------------------
# Argument handling
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-collision-detector",
        description="Detect hash collisions across MD5, SHA-1, SHA-256 and SHA-512.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python main.py                                   interactive menu\n"
            "  python main.py -t apple banana cherry -a sha256  test typed inputs\n"
            "  python main.py -f samples/basic_inputs.txt -a all -o report.txt\n"
            "  python main.py -f samples/md5_collision_pair.txt -a md5 sha256\n"
            "  python main.py --demo                            guided demonstration\n"
            "\n"
            "input files: one input per line; blank lines and lines starting with\n"
            "'#' are ignored; a line starting with 'hex:' is decoded as raw bytes.\n"
            "\n"
            "exit codes: 0 = no collision, 1 = collision detected, 2 = error"
        ),
    )
    parser.add_argument("-t", "--text", nargs="+", metavar="TEXT",
                        help="one or more inputs to test (quote inputs with spaces)")
    parser.add_argument("-f", "--file", metavar="PATH",
                        help="scan a text file with one input per line")
    parser.add_argument("-a", "--algorithm", nargs="+", default=["sha256"],
                        metavar="ALG",
                        help="md5, sha1, sha256, sha512 or 'all' (default: sha256)")
    parser.add_argument("--truncate", type=int, metavar="BITS",
                        help="compare only the first BITS bits of each digest "
                             "(makes collisions findable for demonstrations)")
    parser.add_argument("-o", "--output", metavar="REPORT",
                        help="save the report (.json extension writes JSON)")
    parser.add_argument("--max-display", type=int, default=25, metavar="N",
                        help="max entries shown on screen per algorithm "
                             "(default: 25; reports always list everything)")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="open the interactive menu (default when no input is given)")
    parser.add_argument("--demo", action="store_true",
                        help="run a guided demonstration")
    parser.add_argument("--no-color", action="store_true",
                        help="disable coloured output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def resolve_algorithms(names: List[str]) -> List[str]:
    """Expand ``all``, normalise names and drop duplicates (order preserved)."""
    resolved: List[str] = []
    for name in names:
        if name.strip().lower() == "all":
            candidates = list(SUPPORTED_ALGORITHMS)
        else:
            candidates = [normalize_algorithm(name)]
        for candidate in candidates:
            if candidate not in resolved:
                resolved.append(candidate)
    return resolved


def validate_truncation(bits: Optional[int], algorithms: List[str]) -> None:
    if bits is None:
        return
    limit = min(digest_bits(a) for a in algorithms)
    if bits < 1 or bits > limit:
        raise ValueError(
            f"--truncate must be between 1 and {limit} for the selected algorithm(s)."
        )


# --------------------------------------------------------------------------
# Core actions
# --------------------------------------------------------------------------

def show_results(results: List[ScanResult], source: str, max_display: int) -> None:
    print(render_report(results, source, max_display=max_display,
                        style=style, heading=False))


def write_report(path: str, results: List[ScanResult], source: str) -> None:
    if path.lower().endswith(".json"):
        content = results_to_json(results, source)
    else:
        content = render_report(results, source, max_display=None, max_input_len=None)
    saved = save_report(path, content + "\n")
    print(style(f"Report saved to: {saved}", "green"))


def run_scan(inputs: List[bytes], algorithms: List[str], truncate: Optional[int],
             source: str, max_display: int, output: Optional[str]) -> List[ScanResult]:
    if not inputs:
        raise ValueError("No inputs to test.")
    if len(inputs) < 2:
        print(style("Note: only one input supplied; a collision needs at least two.",
                    "yellow"))
    results = scan_inputs(inputs, algorithms, truncate)
    show_results(results, source, max_display)
    if output:
        write_report(output, results, source)
    return results


def run_demo(max_display: int) -> int:
    print(banner())
    print("\nPart 1 - Ordinary inputs, full-length digests")
    print("Different inputs should never share a full MD5/SHA digest by accident.\n")
    inputs = [s.encode("utf-8") for s in SAMPLE_INPUTS]
    results = scan_inputs(inputs, list(SUPPORTED_ALGORITHMS))
    show_results(results, "demo: sample inputs", max_display=3)

    print("\nPart 2 - Truncated MD5 (16 bits) to demonstrate the birthday effect")
    print("With only 65,536 possible values, a collision appears after a few hundred "
          "inputs.\n")
    detector = CollisionDetector("md5", truncate_bits=16)
    tested = 0
    for tested in range(1, 100001):
        if detector.add(f"input-{tested}"):
            break
    result = detector.result()
    print(render_report([result], "demo: truncated MD5", max_display=3,
                        style=style, heading=False))
    print(style(f"Collision found after {tested} inputs.", "bold"))
    print("\nPart 3 - Real collision: run the bundled MD5 test vectors")
    print("  python main.py -f samples/md5_collision_pair.txt -a md5 sha256\n")
    return EXIT_OK


# --------------------------------------------------------------------------
# Interactive mode
# --------------------------------------------------------------------------

def _ask(prompt: str) -> Optional[str]:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def interactive(max_display: int) -> int:
    print(banner())
    algorithms: List[str] = ["sha256"]
    truncate: Optional[int] = None
    last: Optional[tuple] = None

    while True:
        algs = ", ".join(display_name(a) for a in algorithms)
        trunc = f"{truncate} bits" if truncate else "full digest"
        print(f"\nAlgorithms: {style(algs, 'yellow')}   Digest: {style(trunc, 'yellow')}")
        print(rule())
        print(" 1) Enter inputs manually")
        print(" 2) Scan a text file")
        print(" 3) Choose algorithm(s)")
        print(" 4) Set digest truncation (demo mode)")
        print(" 5) Save last report")
        print(" 6) Run demo")
        print(" 0) Exit")
        choice = _ask("\nSelect an option: ")
        if choice is None or choice.strip() in ("0", "q", "quit", "exit"):
            print("Goodbye.")
            return EXIT_OK
        choice = choice.strip()

        try:
            if choice == "1":
                print("Enter one input per line. Prefix with 'hex:' for raw bytes.")
                print("Submit an empty line when finished.")
                inputs: List[bytes] = []
                while True:
                    line = _ask(f"  input {len(inputs) + 1}> ")
                    if line is None or line == "":
                        break
                    try:
                        inputs.append(parse_input_line(line))
                    except ValueError as exc:
                        print(style(f"  Skipped: {exc}", "yellow"))
                if inputs:
                    results = run_scan(inputs, algorithms, truncate,
                                       "manual entry", max_display, None)
                    last = (results, "manual entry")
                else:
                    print(style("No inputs entered.", "yellow"))

            elif choice == "2":
                path = _ask("File path: ")
                if path:
                    inputs = read_inputs_from_file(path)
                    source = f"file: {path.strip()}"
                    results = run_scan(inputs, algorithms, truncate,
                                       source, max_display, None)
                    last = (results, source)

            elif choice == "3":
                raw = _ask("Algorithms (md5 sha1 sha256 sha512 or 'all'): ")
                if raw and raw.strip():
                    new = resolve_algorithms(raw.replace(",", " ").split())
                    validate_truncation(truncate, new)
                    algorithms = new

            elif choice == "4":
                raw = _ask("Truncate to how many bits? (empty = full digest): ")
                if raw is not None:
                    raw = raw.strip()
                    if raw == "":
                        truncate = None
                    else:
                        if not raw.isdigit():
                            raise ValueError("Please enter a whole number.")
                        bits = int(raw)
                        validate_truncation(bits, algorithms)
                        truncate = bits

            elif choice == "5":
                if last is None:
                    print(style("Nothing to save yet. Run a scan first.", "yellow"))
                else:
                    path = _ask("Report path (e.g. report.txt or report.json): ")
                    if path and path.strip():
                        write_report(path.strip(), last[0], last[1])

            elif choice == "6":
                run_demo(max_display)

            else:
                print(style("Invalid option. Choose 0-6.", "yellow"))

        except (ValueError, OSError, UnsupportedAlgorithmError) as exc:
            print(style(f"Error: {exc}", "red"))
        except KeyboardInterrupt:
            print("\nCancelled.")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_color(False if args.no_color else None)

    try:
        if args.max_display < 1:
            raise ValueError("--max-display must be at least 1.")

        if args.demo:
            return run_demo(args.max_display)

        if args.interactive or not (args.text or args.file):
            return interactive(args.max_display)

        algorithms = resolve_algorithms(args.algorithm)
        validate_truncation(args.truncate, algorithms)

        inputs: List[bytes] = []
        sources = []
        if args.text:
            inputs.extend(parse_input_line(t) for t in args.text)
            sources.append("command-line text")
        if args.file:
            inputs.extend(read_inputs_from_file(args.file))
            sources.append(f"file: {args.file}")

        print(banner())
        results = run_scan(inputs, algorithms, args.truncate,
                           " + ".join(sources), args.max_display, args.output)
        return EXIT_COLLISION if any(r.has_collisions for r in results) else EXIT_OK

    except BrokenPipeError:  # e.g. output piped into `head`
        try:
            sys.stdout.close()
        except Exception:
            pass
        return EXIT_OK
    except (ValueError, OSError, UnsupportedAlgorithmError) as exc:
        print(style(f"Error: {exc}", "red"), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # last-resort guard so users never see a traceback
        print(style(f"Unexpected error: {type(exc).__name__}: {exc}", "red"),
              file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
