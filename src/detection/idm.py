"""
Indexed Document Matching (IDM): detect copies and excerpts of specific protected documents.

Detectors and EDM find sensitive *values*; IDM finds sensitive *documents* that contain no
recognisable identifiers at all (board minutes, source code, M&A drafts, design docs).

Method
    1. Normalize: NFKC, casefold, collapse everything that is not a letter or digit, so
       reformatting, re-wrapping or converting DOCX -> PDF does not change the token stream.
    2. Shingle: every run of K consecutive words is hashed with keyed BLAKE2b to 63 bits.
       The key is per deployment, so a leaked index cannot be tested against guessed text
       without it.
    3. Winnow: in every window of W consecutive shingle hashes keep the minimum (Schleimer,
       Wilkerson, Aiken 2003). Any passage of at least K + W - 1 words copied from a
       protected document is guaranteed to share a fingerprint with it, while the index
       stays roughly 2 / (W + 1) the size of the full shingle set.
    4. Match: fingerprints of scanned content are looked up in the index. A document is
       reported when enough of its fingerprints are present (containment), which holds for
       both a full copy and a pasted section.

Only fingerprints are stored. Registered documents are not retained.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set

SHINGLE_WORDS = 8        # K
WINDOW = 6               # W  -> guaranteed detection of copied runs >= 13 words
MIN_WORDS = 40           # shorter documents do not fingerprint reliably
MIN_HITS = 3             # never report on a single shared fingerprint
DEFAULT_CONTAINMENT = 0.10   # report when >= 10% of a document's fingerprints are present
STRONG_HITS = 25         # ... or when a long excerpt of a large document is present

_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)


def tokenize(text: str) -> List[str]:
    return _WORD_RE.findall(unicodedata.normalize("NFKC", text or "").casefold())


def _shingle_hashes(words: Sequence[str], key: bytes) -> List[int]:
    if len(words) < SHINGLE_WORDS:
        return []
    out = []
    for i in range(len(words) - SHINGLE_WORDS + 1):
        digest = hashlib.blake2b(" ".join(words[i:i + SHINGLE_WORDS]).encode("utf-8"),
                                 digest_size=8, key=key).digest()
        # 63 bits: fits SQLite's signed INTEGER without sign handling.
        out.append(int.from_bytes(digest, "big") >> 1)
    return out


def _winnow(hashes: Sequence[int]) -> Set[int]:
    n = len(hashes)
    if n == 0:
        return set()
    if n <= WINDOW:
        return {min(hashes)}
    selected: Set[int] = set()
    # Monotonic deque of indices: O(n) sliding-window minimum.
    from collections import deque
    dq: "deque[int]" = deque()
    for i, h in enumerate(hashes):
        while dq and hashes[dq[-1]] >= h:
            dq.pop()
        dq.append(i)
        if dq[0] <= i - WINDOW:
            dq.popleft()
        if i >= WINDOW - 1:
            selected.add(hashes[dq[0]])
    return selected


def fingerprint(text: str, key: bytes) -> Set[int]:
    """Winnowed fingerprint set of a text."""
    return _winnow(_shingle_hashes(tokenize(text), key))


@dataclass
class IDMMatch:
    doc_id: str
    name: str
    sensitivity: str
    matched: int
    total: int

    @property
    def containment(self) -> float:
        return self.matched / self.total if self.total else 0.0


class DocumentTooShort(ValueError):
    pass


class IDMIndex:
    """Registers protected documents and matches content against them."""

    def __init__(self, database, containment_threshold: float = DEFAULT_CONTAINMENT):
        self.db = database
        self.containment_threshold = containment_threshold
        self._key: Optional[bytes] = None
        self._docs: Dict[str, dict] = {}
        self._generation: Optional[str] = None

    # ---- key ----

    def key(self) -> bytes:
        if self._key is None:
            stored = self.db.get_platform_setting("idm_key")
            if not stored:
                import secrets
                stored = secrets.token_hex(32)
                self.db.set_platform_setting("idm_key", stored, actor="system", secret=True)
                # Another process may have created it first; read back the winner.
                stored = self.db.get_platform_setting("idm_key") or stored
            self._key = bytes.fromhex(stored)
        return self._key

    # ---- registry ----

    def _refresh(self) -> None:
        generation = self.db.idm_generation()
        if generation != self._generation:
            self._docs = {d["doc_id"]: d for d in self.db.list_idm_documents(active_only=True)}
            self._generation = generation

    @property
    def generation(self) -> str:
        self._refresh()
        return self._generation or ""

    @property
    def active(self) -> bool:
        self._refresh()
        return bool(self._docs)

    def register(self, name: str, text: str, description: str = "", sensitivity: str = "HIGH",
                 raw: Optional[bytes] = None, created_by: Optional[str] = None) -> dict:
        words = tokenize(text)
        if len(words) < MIN_WORDS:
            raise DocumentTooShort(
                f"document has {len(words)} words of extractable text; at least {MIN_WORDS} are needed "
                "to fingerprint it (use a detector or Exact Data Match for short values)")
        fps = _winnow(_shingle_hashes(words, self.key()))
        content_hash = hashlib.sha256(raw if raw is not None else text.encode("utf-8")).hexdigest()
        existing = self.db.find_idm_document_by_hash(content_hash)
        if existing:
            return {**existing, "duplicate": True}
        doc_id = self.db.add_idm_document(
            name=name, description=description, sensitivity=sensitivity, content_sha256=content_hash,
            size_bytes=len(raw) if raw is not None else len(text.encode("utf-8")),
            word_count=len(words), fingerprints=fps, created_by=created_by)
        self._generation = None
        return {**(self.db.get_idm_document(doc_id) or {}), "duplicate": False}

    # ---- matching ----

    def match(self, text: str) -> List[IDMMatch]:
        self._refresh()
        if not self._docs or not text:
            return []
        fps = fingerprint(text, self.key())
        if not fps:
            return []
        out: List[IDMMatch] = []
        for doc_id, hits in self.db.idm_match_counts(fps).items():
            doc = self._docs.get(doc_id)
            if not doc:
                continue
            total = int(doc.get("fingerprint_count") or 0)
            if hits < min(MIN_HITS, total):
                continue
            if hits / max(total, 1) >= self.containment_threshold or hits >= STRONG_HITS:
                out.append(IDMMatch(doc_id=doc_id, name=doc["name"], sensitivity=doc.get("sensitivity") or "HIGH",
                                    matched=hits, total=total))
        out.sort(key=lambda m: m.containment, reverse=True)
        return out
