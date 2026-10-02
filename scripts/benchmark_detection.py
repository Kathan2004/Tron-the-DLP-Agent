#!/usr/bin/env python3
"""
Detection quality + latency benchmark.

  python scripts/benchmark_detection.py                 # current engine
  python scripts/benchmark_detection.py --legacy PATH   # also score a legacy file_scanner.py

Quality: precision / recall / F1 over tests/detection_corpus.py (type level, per case).
Latency: scan time for synthetic business documents of 100 KB, 1 MB and 10 MB.
"""

import argparse
import importlib.util
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.detection import get_engine, LEGACY_ALIASES  # noqa: E402
from tests.detection_corpus import CASES, card, ssn, aadhaar  # noqa: E402


def score(predict, label):
    tp = fp = fn = 0
    misses, false_hits = [], []
    for text, expected in CASES:
        got = predict(text)
        tp += len(got & expected)
        fp += len(got - expected)
        fn += len(expected - got)
        if expected - got:
            misses.append((sorted(expected - got), text[:70]))
        if got - expected:
            false_hits.append((sorted(got - expected), text[:70]))
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    print(f"\n[{label}] cases={len(CASES)} TP={tp} FP={fp} FN={fn}  precision={p:.3f} recall={r:.3f} F1={f1:.3f}")
    return misses, false_hits


def synthetic_doc(size_bytes: int, seed: int = 7) -> str:
    rnd = random.Random(seed)
    words = ("the quarterly report shows revenue growth across regions with order volume "
             "increasing and customer retention improving invoice shipment reference total").split()
    lines, size = [], 0
    while size < size_bytes:
        r = rnd.random()
        if r < 0.002:
            line = f"customer card {card()} ssn {ssn()} aadhaar {aadhaar()}"
        elif r < 0.05:
            line = f"order {rnd.randint(10**15, 10**16 - 1)} qty {rnd.randint(1, 99)} on 2026-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}"
        else:
            line = " ".join(rnd.choice(words) for _ in range(12))
        lines.append(line)
        size += len(line) + 1
    return "\n".join(lines)


def time_it(fn, text, repeat=3):
    runs = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn(text)
        runs.append(time.perf_counter() - t)
    return statistics.median(runs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy", help="path to a legacy src/file_scanner.py to compare against")
    args = ap.parse_args()

    engine = get_engine()
    new_predict = lambda t: {m.detector for m in engine.scan(t).matches}  # noqa: E731
    misses, fps = score(new_predict, "engine")
    for kind, rows in (("missed", misses), ("false positive", fps)):
        for names, text in rows:
            print(f"   {kind:15s} {','.join(names):30s} | {text!r}")

    legacy = None
    if args.legacy:
        spec = importlib.util.spec_from_file_location("legacy_scanner", args.legacy)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        legacy = mod.FileContentScanner.__new__(mod.FileContentScanner)  # skip legacy heavy init
        legacy.patterns = mod.SENSITIVE_PATTERNS
        legacy._compiled_patterns = {}
        legacy._compile_patterns()

        def legacy_predict(t):
            names = {f.pattern_name for f in legacy.scan_text(t)}
            return {LEGACY_ALIASES.get(n, n) for n in names}
        lm, lf = score(legacy_predict, "legacy")
        print(f"   legacy missed {len(lm)} cases, false positives in {len(lf)} cases")

    print("\nLatency (median of 3):")
    for size in (100_000, 1_000_000, 10_000_000):
        doc = synthetic_doc(size)
        t_new = time_it(lambda s: engine.scan(s), doc)
        line = f"  {size / 1e6:>5.1f} MB  engine {t_new * 1000:8.1f} ms ({size / 1e6 / t_new:6.1f} MB/s)"
        if legacy:
            t_old = time_it(lambda s: legacy.scan_text(s), doc, repeat=1)
            n_old = len(legacy.scan_text(doc)) if size <= 1_000_000 else None
            line += f" | legacy {t_old * 1000:9.1f} ms"
            n_new = len(engine.scan(doc).matches)
            if n_old is not None:
                line += f" | findings engine={n_new} legacy={n_old}"
        print(line)


if __name__ == "__main__":
    main()
