"""Collision detection engine and report rendering."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from hash_generator import (
    digest_bits,
    display_name,
    generate_hash,
    normalize_algorithm,
)
from utils import display_input, plain, rule, timestamp

StyleFn = Callable[..., str]


@dataclass(frozen=True)
class Collision:
    """Two different inputs that produced the same digest."""

    algorithm: str
    digest: str
    first_input: bytes
    second_input: bytes


@dataclass
class ScanResult:
    """Outcome of scanning a set of inputs with a single algorithm."""

    algorithm: str
    truncate_bits: Optional[int]
    total_inputs: int = 0
    duplicates_skipped: int = 0
    entries: List[Tuple[bytes, str]] = field(default_factory=list)
    collisions: List[Collision] = field(default_factory=list)
    unique_hashes: int = 0

    @property
    def unique_inputs(self) -> int:
        return len(self.entries)

    @property
    def collision_count(self) -> int:
        return len(self.collisions)

    @property
    def has_collisions(self) -> bool:
        return bool(self.collisions)

    @property
    def effective_bits(self) -> int:
        return self.truncate_bits or digest_bits(self.algorithm)


class CollisionDetector:
    """Incrementally hashes inputs and records collisions.

    An *exact repeat* of an earlier input is not a collision (the same input
    must always give the same hash), so repeats are counted separately as
    duplicates. A collision is recorded only when two inputs with different
    bytes yield the same digest.
    """

    def __init__(self, algorithm: str = "sha256", truncate_bits: Optional[int] = None):
        self.algorithm = normalize_algorithm(algorithm)
        if truncate_bits is not None:
            # Validates the range and type early.
            generate_hash(b"", self.algorithm, truncate_bits)
        self.truncate_bits = truncate_bits
        self._seen_inputs: Dict[bytes, str] = {}
        self._by_digest: Dict[str, bytes] = {}
        self._result = ScanResult(self.algorithm, truncate_bits)

    def add(self, data) -> Optional[Collision]:
        """Hash one input. Returns a :class:`Collision` if one was found."""
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        self._result.total_inputs += 1

        if raw in self._seen_inputs:
            self._result.duplicates_skipped += 1
            return None

        digest = generate_hash(raw, self.algorithm, self.truncate_bits)
        self._seen_inputs[raw] = digest
        self._result.entries.append((raw, digest))

        earlier = self._by_digest.get(digest)
        if earlier is None:
            self._by_digest[digest] = raw
            self._result.unique_hashes = len(self._by_digest)
            return None

        collision = Collision(self.algorithm, digest, earlier, raw)
        self._result.collisions.append(collision)
        return collision

    def add_many(self, items: Iterable) -> List[Collision]:
        found = []
        for item in items:
            hit = self.add(item)
            if hit:
                found.append(hit)
        return found

    def result(self) -> ScanResult:
        return self._result


def scan_inputs(
    inputs: Iterable,
    algorithms: Iterable[str],
    truncate_bits: Optional[int] = None,
) -> List[ScanResult]:
    """Scan ``inputs`` once per algorithm and return one result for each."""
    items = list(inputs)
    results = []
    for algorithm in algorithms:
        detector = CollisionDetector(algorithm, truncate_bits)
        detector.add_many(items)
        results.append(detector.result())
    return results


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _differing_offsets(a: bytes, b: bytes) -> Optional[List[int]]:
    """Byte offsets where two equal-length inputs differ (None if lengths differ)."""
    if len(a) != len(b):
        return None
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


def render_result(
    result: ScanResult,
    max_display: Optional[int] = None,
    max_input_len: Optional[int] = 72,
    style: StyleFn = plain,
) -> List[str]:
    """Return the report lines for one :class:`ScanResult`."""
    name = display_name(result.algorithm)
    lines: List[str] = []

    lines.append(style(rule("="), "cyan"))
    lines.append(style(f" ALGORITHM: {name}", "bold"))
    if result.truncate_bits:
        full = digest_bits(result.algorithm)
        lines.append(
            f" Digest   : truncated to first {result.truncate_bits} of {full} bits"
        )
    else:
        lines.append(f" Digest   : full {result.effective_bits}-bit")
    lines.append(style(rule("="), "cyan"))
    lines.append("")

    lines.append(style("Inputs and hashes", "bold"))
    lines.append(rule())
    shown = result.entries
    hidden = 0
    if max_display is not None and len(shown) > max_display:
        hidden = len(shown) - max_display
        shown = shown[:max_display]
    if not shown:
        lines.append("(no inputs)")
    for index, (raw, digest) in enumerate(shown, start=1):
        lines.append(f"[{index}] Input : {display_input(raw, max_input_len)}")
        lines.append(f"    Hash  : {style(digest, 'yellow')}")
    if hidden:
        lines.append(f"... {hidden} more entries not shown (use a report file for all)")
    lines.append("")

    lines.append(style("Collision analysis", "bold"))
    lines.append(rule())
    if result.has_collisions:
        lines.append(
            style(
                f"!! COLLISION DETECTED: {result.collision_count} found !!",
                "bold",
                "red",
            )
        )
        for number, hit in enumerate(result.collisions, start=1):
            lines.append("")
            lines.append(f" Collision #{number}")
            lines.append(f"   Algorithm : {name}")
            lines.append(f"   Hash      : {style(hit.digest, 'red')}")
            lines.append(f"   Input A   : {display_input(hit.first_input, max_input_len)}")
            lines.append(f"   Input B   : {display_input(hit.second_input, max_input_len)}")
            offsets = _differing_offsets(hit.first_input, hit.second_input)
            if offsets is not None and max_input_len is not None and (
                len(hit.first_input) * 2 > max_input_len
            ):
                shown_offsets = ", ".join(str(o) for o in offsets[:12])
                more = " ..." if len(offsets) > 12 else ""
                lines.append(
                    f"   Differ at : byte offset(s) {shown_offsets}{more} "
                    f"({len(offsets)} of {len(hit.first_input)} bytes differ)"
                )
    else:
        lines.append(style("No collision detected.", "green"))
        lines.append("All different inputs produced different hashes.")
    lines.append("")

    lines.append(style("Statistics", "bold"))
    lines.append(rule())
    lines.append(f" Total inputs tested   : {result.total_inputs}")
    lines.append(f" Exact duplicates      : {result.duplicates_skipped} (skipped, not collisions)")
    lines.append(f" Distinct inputs       : {result.unique_inputs}")
    lines.append(f" Unique hashes         : {result.unique_hashes}")
    verdict = "YES" if result.has_collisions else "NO"
    lines.append(f" Collisions detected   : {result.collision_count} ({verdict})")
    lines.append("")
    return lines


def render_report(
    results: List[ScanResult],
    source: str,
    max_display: Optional[int] = None,
    max_input_len: Optional[int] = 72,
    style: StyleFn = plain,
    heading: bool = True,
) -> str:
    """Render all results as a single text report."""
    lines: List[str] = []
    if heading:
        lines.append("HASH COLLISION DETECTOR - SCAN REPORT")
        lines.append(f"Generated : {timestamp()}")
        lines.append(f"Source    : {source}")
        lines.append(
            "Algorithms: " + ", ".join(display_name(r.algorithm) for r in results)
        )
        lines.append("")

    for result in results:
        lines.extend(render_result(result, max_display, max_input_len, style))

    if len(results) > 1:
        lines.append(style(rule("="), "cyan"))
        lines.append(style(" SUMMARY", "bold"))
        lines.append(style(rule("="), "cyan"))
        for result in results:
            flag = (
                style("COLLISION", "red", "bold")
                if result.has_collisions
                else style("clean", "green")
            )
            lines.append(
                f" {display_name(result.algorithm):<8} "
                f"inputs={result.total_inputs:<6} "
                f"unique hashes={result.unique_hashes:<6} "
                f"collisions={result.collision_count:<4} {flag}"
            )
        lines.append("")
    return "\n".join(lines)


def results_to_json(results: List[ScanResult], source: str) -> str:
    """Serialise results as JSON (used when the report path ends in .json)."""
    payload = {
        "tool": "hash-collision-detector",
        "generated": timestamp(),
        "source": source,
        "results": [],
    }
    for result in results:
        payload["results"].append(
            {
                "algorithm": display_name(result.algorithm),
                "truncate_bits": result.truncate_bits,
                "statistics": {
                    "total_inputs": result.total_inputs,
                    "duplicates_skipped": result.duplicates_skipped,
                    "distinct_inputs": result.unique_inputs,
                    "unique_hashes": result.unique_hashes,
                    "collisions": result.collision_count,
                },
                "entries": [
                    {"input": display_input(raw, None), "hash": digest}
                    for raw, digest in result.entries
                ],
                "collisions": [
                    {
                        "hash": hit.digest,
                        "input_a": display_input(hit.first_input, None),
                        "input_b": display_input(hit.second_input, None),
                    }
                    for hit in result.collisions
                ],
            }
        )
    return json.dumps(payload, indent=2, ensure_ascii=False)
