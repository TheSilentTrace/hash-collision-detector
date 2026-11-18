"""Shared helpers: terminal styling, input parsing, file I/O."""

from __future__ import annotations

import datetime as _dt
import os
import sys
from typing import List, Optional

HEX_PREFIX = "hex:"
MAX_FILE_BYTES = 100 * 1024 * 1024  # refuse to load files larger than 100 MiB

_COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}
_RESET = "\033[0m"

_color_enabled = False


def configure_color(enabled: Optional[bool] = None) -> bool:
    """Enable or disable ANSI colours. ``None`` auto-detects a TTY."""
    global _color_enabled
    if enabled is None:
        enabled = (
            sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )
    _color_enabled = bool(enabled)
    if _color_enabled and os.name == "nt":  # pragma: no cover
        os.system("")  # enables ANSI escape processing on Windows 10+
    return _color_enabled


def style(text: str, *names: str) -> str:
    """Wrap ``text`` in ANSI styles when colours are enabled."""
    if not _color_enabled or not names:
        return text
    prefix = "".join(_COLORS[n] for n in names if n in _COLORS)
    return f"{prefix}{text}{_RESET}"


def plain(text: str, *names: str) -> str:
    """Style function that never adds colour (used for report files)."""
    return text


def banner() -> str:
    line = "=" * 64
    title = "HASH COLLISION DETECTOR"
    sub = "MD5 | SHA-1 | SHA-256 | SHA-512"
    return "\n".join(
        [
            style(line, "cyan"),
            style(title.center(64), "bold", "cyan"),
            style(sub.center(64), "dim"),
            style(line, "cyan"),
        ]
    )


def rule(char: str = "-", width: int = 64) -> str:
    return char * width


def timestamp() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def display_input(data: bytes, max_len: Optional[int] = 72) -> str:
    """Printable representation of an input.

    UTF-8 text is shown as-is (control characters escaped); anything else is
    shown as ``hex:<digits>``. ``max_len`` truncates long values for the
    console; pass ``None`` for the full value (used in report files).
    """
    try:
        text = data.decode("utf-8")
        if text.isprintable():
            shown = text
        else:
            shown = text.encode("unicode_escape").decode("ascii")
    except UnicodeDecodeError:
        shown = HEX_PREFIX + data.hex()

    if max_len is not None and len(shown) > max_len:
        shown = shown[: max_len - 3] + "..."
        shown += f" ({len(data)} bytes)"
    return shown


def parse_input_line(line: str) -> bytes:
    """Convert one user-supplied line into bytes.

    A line starting with ``hex:`` is decoded as raw hexadecimal bytes, which
    allows binary test vectors (for example known MD5 collision blocks).
    Everything else is encoded as UTF-8 text.
    """
    if line.startswith(HEX_PREFIX):
        digits = "".join(line[len(HEX_PREFIX):].split())
        if not digits:
            raise ValueError("Empty hex input after 'hex:' prefix.")
        try:
            return bytes.fromhex(digits)
        except ValueError as exc:
            raise ValueError(f"Invalid hex input: {exc}") from None
    return line.encode("utf-8")


def read_inputs_from_file(path: str) -> List[bytes]:
    """Load inputs from a text file, one per line.

    Blank lines and lines beginning with ``#`` are ignored. Only the line
    terminator is removed; other whitespace is part of the input.

    Raises:
        FileNotFoundError, IsADirectoryError, PermissionError, ValueError
    """
    if not path or not path.strip():
        raise ValueError("No file path provided.")
    path = os.path.expanduser(path.strip().strip('"').strip("'"))

    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    if os.path.isdir(path):
        raise IsADirectoryError(f"Expected a file but got a directory: {path}")
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise ValueError(
            f"File is too large ({size:,} bytes). Limit is {MAX_FILE_BYTES:,} bytes."
        )

    inputs: List[bytes] = []
    with open(path, "r", encoding="utf-8", newline="") as handle:
        try:
            for line_no, raw in enumerate(handle, start=1):
                line = raw.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                try:
                    inputs.append(parse_input_line(line))
                except ValueError as exc:
                    raise ValueError(f"{path}, line {line_no}: {exc}") from None
        except UnicodeDecodeError:
            raise ValueError(
                f"{path} is not valid UTF-8 text. Use 'hex:' lines for binary data."
            ) from None
    return inputs


def save_report(path: str, content: str) -> str:
    """Write ``content`` to ``path`` (creating parent folders). Returns the path."""
    if not path or not path.strip():
        raise ValueError("No report path provided.")
    path = os.path.expanduser(path.strip().strip('"').strip("'"))
    if os.path.isdir(path):
        raise IsADirectoryError(f"Report path is a directory: {path}")
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return os.path.abspath(path)
