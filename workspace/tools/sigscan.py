#!/usr/bin/env python3
"""
sigscan — identify a BIOS dump by scanning it for known model names and
motherboard board IDs from the facts-only catalog (data/models/model_catalog.tsv).

For each catalog row it searches the raw dump for:

  1. model     — human model name; visible in the SMBIOS/DMI "System Product
                 Name" region (~0x400000 on 16MB BIOS-region dumps)
  2. board_id  — motherboard PCB ID (LA-xxxx, NM-xxxx, 6050Axxxx...) — usually
                 only inside compressed UEFI volumes, so rarely raw-visible

Findings are ranked by specificity (longest matched string). Note: 8MB dumps
are usually the ME/descriptor chip and contain no model strings at all.

Usage:
    python bioskit.py sigscan bios.bin
    python tools/sigscan.py bios.bin --min-len 6 --top 10
    python tools/sigscan.py bios.bin --json
"""

import argparse
import json
import sys
from pathlib import Path

CATALOG = Path(__file__).parent.parent / "data" / "models" / "model_catalog.tsv"

TYPE_WEIGHT = {"model": 3, "board_id": 2}


def load_catalog() -> list[dict]:
    if not CATALOG.exists():
        print(f"[!] Catalog not found: {CATALOG}", file=sys.stderr)
        print("    Run: python tools/import_model_catalog.py", file=sys.stderr)
        return []
    rows = []
    for line in CATALOG.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if not parts or not parts[0] or parts[0] == "vendor":
            continue
        while len(parts) < 3:
            parts.append("")
        rows.append({"vendor": parts[0], "model": parts[1], "board_id": parts[2]})
    return rows


def scan_dump(data: bytes, catalog: list[dict], min_len: int = 5) -> list[dict]:
    """Return catalog entries whose model/board_id string appears in the dump."""
    results: list[dict] = []
    for e in catalog:
        hits: list[dict] = []
        for kind in ("model", "board_id"):
            needle = (e.get(kind) or "").strip()
            if not needle or len(needle) < min_len:
                continue
            b = needle.encode("latin-1", "replace")
            off = data.find(b)
            if off >= 0:
                hits.append({"type": kind, "string": needle, "offset": off})

        if hits:
            best = max(hits, key=lambda h: (TYPE_WEIGHT[h["type"]], len(h["string"])))
            results.append({
                "vendor": e["vendor"], "model": e["model"], "board_id": e["board_id"],
                "hits": hits,
                "score": TYPE_WEIGHT[best["type"]] * 10 + len(best["string"]),
            })

    results.sort(key=lambda r: (-r["score"], r["vendor"], r["model"].lower()))
    return results


def print_results(results: list[dict], top: int) -> None:
    if not results:
        print("  No model/board-ID matches found.")
        print("  (8MB ME-only dumps contain no model strings; 16/32MB BIOS-region")
        print("   dumps expose the model name in the DMI region.)")
        return

    print(f"\n{'Score':>5} {'Vendor':<10} {'Model':<38} {'Type':<10} {'Offset':<10} Matched string")
    print("-" * 108)
    for r in results[:top]:
        for h in r["hits"]:
            print(f"{r['score']:>5} {r['vendor']:<10} {r['model']:<38} "
                  f"{h['type']:<10} 0x{h['offset']:08x}  {h['string']}")
    if len(results) > top:
        print(f"  ... and {len(results) - top} more entries (use --top to raise).")


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan BIOS dump for known model names / board IDs")
    ap.add_argument("dump", help="Path to .bin BIOS dump")
    ap.add_argument("--min-len", type=int, default=5,
                    help="Minimum string length to consider (default 5)")
    ap.add_argument("--top", type=int, default=20, help="Max entries to show")
    ap.add_argument("--json", action="store_true", help="Output JSON to stdout")
    args = ap.parse_args()

    dump = Path(args.dump)
    if not dump.exists():
        print(f"[!] File not found: {dump}", file=sys.stderr)
        return 1

    catalog = load_catalog()
    if not catalog:
        return 1

    print(f"[*] Scanning {dump.name} ({dump.stat().st_size:,} bytes) "
          f"against {len(catalog)} catalog entries...")
    data = dump.read_bytes()
    results = scan_dump(data, catalog, args.min_len)

    print(f"[*] Matched {len(results)} model entries.")

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print_results(results, args.top)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
