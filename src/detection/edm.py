"""
Exact Data Match (EDM): detect values from a protected dataset (e.g. the real customer table),
not just values that look like an identifier.

  * The index stores only keyed hashes (BLAKE2b keyed MAC, 96-bit) of normalized cell values
    plus the row numbers they occur in. No plaintext leaves the build step.
  * A record matches when at least `min_fields` distinct columns of the SAME row appear within
    `window` characters of each other, e.g. name + SSN, or email + card number. One common
    value (a first name) on its own never matches.

Build an index:
    python -m src.detection.edm build customers.csv --columns name,email,ssn,card \
        --out data/edm/customers.edm --min-fields 2

Indexes in TRON_EDM_DIR (default data/edm) are loaded by the API at startup. The HMAC key is
TRON_EDM_KEY (or data/edm/.key, created on first build); without the key, hashes cannot be
tested against guesses offline.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import secrets
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

DIGEST_BYTES = 12
DEFAULT_DIR = Path(os.getenv("TRON_EDM_DIR") or Path(__file__).resolve().parents[2] / "data" / "edm")

_TOKEN = re.compile(r"[a-z0-9._%+@'-]+")
_DIGITS_ONLY = re.compile(r"[\s\-./()]")
_NUM_RUN = re.compile(r"\d[\d \-./()]{2,40}\d")
_NUM_PART = re.compile(r"\d+")


def _key(directory: Path = DEFAULT_DIR, create: bool = False) -> bytes:
    env = os.getenv("TRON_EDM_KEY")
    if env:
        return env.encode()
    path = directory / ".key"
    if path.exists():
        return path.read_bytes().strip()
    if not create:
        raise RuntimeError("EDM key not found: set TRON_EDM_KEY or build an index first")
    directory.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32).encode()
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return key


def normalize(value: str) -> str:
    """Canonical form: NFKC, lowercase, collapsed spaces; separators removed from numeric values."""
    v = unicodedata.normalize("NFKC", str(value or "")).strip().lower()
    compact = _DIGITS_ONLY.sub("", v)
    if compact.isdigit():
        return compact
    return " ".join(v.split())


def _digest(key: bytes, value: str) -> bytes:
    # Keyed BLAKE2b is a proper MAC and ~4x faster than hmac+sha256 in CPython.
    return hashlib.blake2b(value.encode("utf-8"), key=key[:64], digest_size=DIGEST_BYTES).digest()


@dataclass
class EDMMatch:
    index: str
    row: int
    columns: List[str]
    start: int
    end: int


class EDMIndex:
    def __init__(self, name: str, columns: List[str], min_fields: int, max_words: int,
                 table: Dict[bytes, Dict[int, int]], key: bytes, window: int = 300,
                 prefixes: Optional[Set[bytes]] = None):
        self.name = name
        self.columns = columns
        self.min_fields = min_fields
        self.max_words = max_words      # longest multi-word value (e.g. "jane a doe" = 3)
        self.table = table              # digest -> {row: column index}
        self.key = key
        self.window = window
        self.prefixes = prefixes or set()   # digests of first words of multi-word values

    # ------------------------------------------------------------------ build / persist
    @classmethod
    def build(cls, csv_path: str, columns: List[str], name: Optional[str] = None,
              min_fields: int = 2, key: Optional[bytes] = None) -> "EDMIndex":
        key = key or _key(create=True)
        table: Dict[bytes, Dict[int, int]] = {}
        prefixes: Set[bytes] = set()
        max_words = 1
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            missing = [c for c in columns if c not in (reader.fieldnames or [])]
            if missing:
                raise ValueError(f"columns not in CSV header: {missing}")
            for row_no, row in enumerate(reader):
                for ci, col in enumerate(columns):
                    v = normalize(row.get(col, ""))
                    if len(v) < 3:
                        continue
                    words = v.split()
                    if len(words) > 1 and not v.replace(" ", "").isdigit():
                        prefixes.add(_digest(key, words[0]))
                    max_words = max(max_words, len(words))
                    table.setdefault(_digest(key, v), {})[row_no] = ci
        return cls(name or Path(csv_path).stem, columns, min_fields, min(max_words, 5), table, key,
                   prefixes=prefixes)

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "name": self.name, "columns": self.columns, "min_fields": self.min_fields,
            "max_words": self.max_words, "window": self.window,
            "prefixes": [d.hex() for d in self.prefixes],
            "entries": [[d.hex(), rows] for d, rows in self.table.items()],
        }
        with open(path, "w") as f:
            json.dump(payload, f, separators=(",", ":"))

    @classmethod
    def load(cls, path: str, key: Optional[bytes] = None) -> "EDMIndex":
        with open(path) as f:
            p = json.load(f)
        table = {bytes.fromhex(d): {int(r): c for r, c in rows.items()} for d, rows in p["entries"]}
        return cls(p["name"], p["columns"], p["min_fields"], p["max_words"], table,
                   key or _key(Path(path).parent), p.get("window", 300),
                   prefixes={bytes.fromhex(d) for d in p.get("prefixes", [])})

    # ------------------------------------------------------------------ matching
    def scan(self, text: str) -> List[EDMMatch]:
        """One keyed hash per token; multi-word values only when the first word is a known prefix;
        numeric runs (536 22 1234, 4111-1111-...) are re-joined without separators."""
        low = unicodedata.normalize("NFKC", text).lower() if not text.isascii() else text.lower()
        table, key = self.table, self.key
        hits: Dict[int, Dict[int, tuple]] = {}

        def record(digest: bytes, start: int, end: int) -> None:
            rows = table.get(digest)
            if rows:
                for row, ci in rows.items():
                    hits.setdefault(row, {}).setdefault(ci, (start, end))

        tokens = []
        for m in _TOKEN.finditer(low):
            tok = m.group(0).strip(".-'")
            if tok:
                tokens.append((tok, m.start(), m.end()))
        for i, (tok, start, end) in enumerate(tokens):
            if len(tok) < 2:
                continue  # initials only count as part of a multi-word value
            d = _digest(key, tok)
            record(d, start, end)
            if d in self.prefixes:
                words = [tok]
                for j in range(i + 1, min(i + self.max_words, len(tokens))):
                    if tokens[j][1] - tokens[j - 1][2] > 2:
                        break
                    words.append(tokens[j][0])
                    record(_digest(key, " ".join(words)), start, tokens[j][2])
        for m in _NUM_RUN.finditer(low):
            parts = [(p.group(0), m.start() + p.start(), m.start() + p.end()) for p in _NUM_PART.finditer(m.group(0))]
            if len(parts) < 2:
                continue
            for a in range(len(parts)):
                joined = parts[a][0]
                for b in range(a + 1, min(a + 6, len(parts))):
                    joined += parts[b][0]
                    if len(joined) >= 6:
                        record(_digest(key, joined), parts[a][1], parts[b][2])

        matches = []
        for row, cols in hits.items():
            if len(cols) < self.min_fields:
                continue
            spans = sorted(cols.values())
            if spans[-1][0] - spans[0][0] > self.window:
                continue
            matches.append(EDMMatch(self.name, row, [self.columns[c] for c in sorted(cols)],
                                    spans[0][0], spans[-1][1]))
        return sorted(matches, key=lambda m: m.start)


def load_indexes(directory: Path = DEFAULT_DIR) -> List[EDMIndex]:
    if not directory.is_dir():
        return []
    out = []
    for p in sorted(directory.glob("*.edm")):
        try:
            out.append(EDMIndex.load(str(p)))
        except Exception as e:
            print(f"⚠️  EDM index {p.name} not loaded: {e}")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m src.detection.edm")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build an index from a CSV file")
    b.add_argument("csv")
    b.add_argument("--columns", required=True, help="comma-separated column names to protect")
    b.add_argument("--out", help="output .edm path (default: data/edm/<csv name>.edm)")
    b.add_argument("--name")
    b.add_argument("--min-fields", type=int, default=2)
    t = sub.add_parser("test", help="scan a text file against an index")
    t.add_argument("index")
    t.add_argument("file")
    args = ap.parse_args(argv)
    if args.cmd == "build":
        idx = EDMIndex.build(args.csv, [c.strip() for c in args.columns.split(",")], args.name, args.min_fields)
        out = args.out or str(DEFAULT_DIR / f"{idx.name}.edm")
        idx.save(out)
        rows = len({r for v in idx.table.values() for r in v})
        print(f"EDM index '{idx.name}': {rows} rows, {len(idx.table)} hashed values -> {out}")
    else:
        idx = EDMIndex.load(args.index)
        for m in idx.scan(Path(args.file).read_text(errors="replace")):
            print(f"row {m.row}: {', '.join(m.columns)} at {m.start}-{m.end}")


if __name__ == "__main__":
    sys.exit(main())
