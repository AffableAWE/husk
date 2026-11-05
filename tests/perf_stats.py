#!/usr/bin/env python3
import csv, glob, json, os, statistics, sys

def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo = int(k); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)

for path in sorted(glob.glob(sys.argv[1] if len(sys.argv) > 1 else "build/evidence/perf/*.csv")):
    rows = list(csv.DictReader(open(path)))
    out = {"file": path, "runs": len(rows), "failures": 0}
    for col in ("startup_ns", "full_ns"):
        xs = [int(r[col]) for r in rows if r[col] not in ("", "-1")]
        out[col] = {
            "median_ms": round(statistics.median(xs) / 1e6, 3) if xs else None,
            "p95_ms": round(pct(xs, 0.95) / 1e6, 3) if xs else None,
            "p99_ms": round(pct(xs, 0.99) / 1e6, 3) if xs else None,
            "min_ms": round(min(xs) / 1e6, 3) if xs else None,
            "max_ms": round(max(xs) / 1e6, 3) if xs else None,
        }
    out["failures"] = sum(1 for r in rows if r["rc"] != "0")
    print(json.dumps(out, indent=2))
