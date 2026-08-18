#!/usr/bin/env python3
"""
Import a hardware model catalog from vendor model-detection .db files — facts only.

Extracts only factual, independently-verifiable data (vendor, model name,
motherboard board ID) and writes a compact TSV. The vendor-tool-internal
signature keys are NOT exported by default, because those are the tool author's
own technical choices (and they are not greppable in raw dumps anyway).

    <Model Name> [(<Board ID>)];<internal signature>   →   vendor\tmodel\tboard_id

Usage:
    python tools/import_model_catalog.py --source-dir PATH [--output PATH.tsv]
    python tools/import_model_catalog.py --source-dir PATH --include-signatures
"""

import argparse
import re
from pathlib import Path

_BOARD_RE = re.compile(r"\s*\(([^()]*)\)\s*$")

VENDOR_DB_FILES = [
    "Lenovo.db", "Dell.db", "HP.db", "Acer.db",
    "Microsoft.db", "Samsung.db", "GigaByte.db",
]


def parse_db_file(path: Path, vendor: str, include_signatures: bool) -> list[tuple]:
    rows: list[tuple] = []
    text = path.read_text(encoding="cp1252", errors="replace")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ";" in line:
            model, signature = line.split(";", 1)
        else:
            model, signature = line, ""
        model = model.strip()
        signature = signature.strip().rstrip(";").strip()

        m = _BOARD_RE.search(model)
        if m:
            board_id = m.group(1).strip()
            model = _BOARD_RE.sub("", model).strip()
        else:
            board_id = ""

        if not model and not board_id:
            continue

        if include_signatures:
            rows.append((vendor, model, board_id, signature))
        else:
            rows.append((vendor, model, board_id))

    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Import vendor .db files → compact facts-only catalog")
    ap.add_argument("--source-dir", required=True,
                    help="Directory containing the vendor .db files (Lenovo.db, Dell.db, ...)")
    ap.add_argument("--output", default=None, help="Output .tsv path")
    ap.add_argument("--include-signatures", action="store_true",
                    help="Export the internal signature column too (only if you own the data)")
    args = ap.parse_args()

    source_dir = Path(args.source_dir)
    output = Path(args.output) if args.output else \
        Path(__file__).parent.parent / "data" / "models" / "model_catalog.tsv"

    if not source_dir.is_dir():
        print(f"[!] Source directory not found: {source_dir}")
        return 1

    all_rows: list[tuple] = []
    per_vendor: dict[str, int] = {}
    missing: list[str] = []

    for fname in VENDOR_DB_FILES:
        fpath = source_dir / fname
        if not fpath.exists():
            missing.append(fname)
            continue
        vendor = fname[:-3]
        rows = parse_db_file(fpath, vendor, args.include_signatures)
        per_vendor[vendor] = len(rows)
        all_rows.extend(rows)

    # Dedupe (vendor, model, board_id[, signature])
    seen: set = set()
    deduped: list[tuple] = []
    dupes = 0
    for r in all_rows:
        key = tuple(x.lower() for x in r)
        if key in seen:
            dupes += 1
            continue
        seen.add(key)
        deduped.append(r)

    deduped.sort(key=lambda r: (r[0], r[1].lower(), r[2].lower()))

    header = ["vendor", "model", "board_id"] + (["signature"] if args.include_signatures else [])
    lines = ["\t".join(header)]
    for r in deduped:
        lines.append("\t".join(r))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[*] Source: {source_dir}")
    print(f"[*] Files: {len(VENDOR_DB_FILES) - len(missing)}/{len(VENDOR_DB_FILES)}"
          + (f"  (missing: {', '.join(missing)})" if missing else ""))
    print(f"[*] Raw rows: {len(all_rows)}, duplicates removed: {dupes}")
    print(f"[*] Final rows: {len(deduped)}")
    print(f"[*] Per-vendor:")
    for v in sorted(per_vendor):
        print(f"      {v:<12} {per_vendor[v]}")
    print(f"[*] Signatures included: {'yes' if args.include_signatures else 'NO (facts only)'}")
    print(f"[*] Written: {output} ({output.stat().st_size:,} bytes)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
