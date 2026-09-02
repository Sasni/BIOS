#!/usr/bin/env python3
"""
ME Info Hash Cache

Provides SHA256 → ME info lookup for files where the ME FPT has been
cleaned/erased but we previously analyzed an intact copy.

Stores ME data in bios_models.json alongside existing model entries.
"""

import json
from pathlib import Path
from typing import Optional, Dict

_MODELS_PATH = Path(__file__).resolve().parent.parent / "data" / "models" / "bios_models.json"


def lookup_me_by_sha256(sha256: str) -> Optional[Dict]:
    """Look up cached ME info by file SHA256 hash.

    Returns a dict with ME info fields if found, or None.
    The dict always includes ``from_database: True`` so the GUI
    can distinguish live-parsed data from cached lookups.
    """
    if not _MODELS_PATH.exists():
        return None

    try:
        with open(_MODELS_PATH, "r") as f:
            models = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    if not isinstance(models, list):
        return None

    for entry in models:
        if entry.get("sha256") == sha256:
            me = entry.get("me_info")
            if me and isinstance(me, dict) and me.get("version"):
                result = dict(me)
                result["from_database"] = True
                return result
            return None

    return None


def lookup_me_by_file(filepath: str) -> Optional[Dict]:
    """Look up cached ME info by file path (computes SHA256 internally)."""
    import hashlib

    p = Path(filepath)
    if not p.exists():
        return None

    sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
    return lookup_me_by_sha256(sha256)


def store_me_info(sha256: str, me_info: Dict, vendor: str = "", model: str = "",
                  bios_version: str = "", bios_date: str = "", board_id: str = "",
                  source_file: str = "") -> bool:
    """Store ME info in the database, keyed by SHA256.

    If an entry with this SHA256 already exists, updates its me_info.
    Otherwise creates a minimal entry.
    """
    models = []
    if _MODELS_PATH.exists():
        try:
            with open(_MODELS_PATH, "r") as f:
                models = json.load(f)
        except (json.JSONDecodeError, OSError):
            models = []

    if not isinstance(models, list):
        models = []

    # Find existing entry or create new one
    for entry in models:
        if entry.get("sha256") == sha256:
            entry["me_info"] = me_info
            break
    else:
        # Create minimal entry
        entry = {
            "vendor": vendor,
            "model": model,
            "bios_version": bios_version,
            "bios_date": bios_date,
            "board_id": board_id,
            "sha256": sha256,
            "source_file": source_file,
            "me_info": me_info,
        }
        models.append(entry)

    # Write back
    _MODELS_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(_MODELS_PATH, "w") as f:
            json.dump(models, f, indent=2, ensure_ascii=False, default=str)
        return True
    except OSError:
        return False


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    import argparse
    import hashlib

    parser = argparse.ArgumentParser(description="ME Info Hash Cache")
    sub = parser.add_subparsers(dest="cmd")

    lookup_p = sub.add_parser("lookup", help="Look up ME info by SHA256 or file")
    lookup_p.add_argument("input", help="SHA256 hex string or file path")

    store_p = sub.add_parser("store", help="Store ME info from a file with known ME")
    store_p.add_argument("input", help="File to store hash for")
    store_p.add_argument("--me-version", help="ME version (e.g. 9.0.3.1347)")
    store_p.add_argument("--me-platform", help="Platform (e.g. LynxPoint)")
    store_p.add_argument("--me-sku", help="SKU size (e.g. 1.5MB)")
    store_p.add_argument("--me-release", help="Release type")
    store_p.add_argument("--me-svn", type=int, default=0)
    store_p.add_argument("--me-vcn", type=int, default=0)
    store_p.add_argument("--me-date", default="")
    store_p.add_argument("--vendor", default="")
    store_p.add_argument("--model", default="")

    args = parser.parse_args()

    if args.cmd == "lookup":
        # Try as SHA256 first, then as file path
        if len(args.input) == 64 and all(c in "0123456789abcdefABCDEF" for c in args.input):
            result = lookup_me_by_sha256(args.input.lower())
        else:
            result = lookup_me_by_file(args.input)

        if result:
            print("ME Info (from database):")
            for k, v in sorted(result.items()):
                print(f"  {k}: {v}")
        else:
            print("Not found in database")
            return 1

    elif args.cmd == "store":
        p = Path(args.input)
        if not p.exists():
            print(f"File not found: {args.input}")
            return 1
        sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
        me_info = {
            "version": args.me_version or "",
            "platform": args.me_platform or "",
            "sku_size": args.me_sku or "",
            "release_type": args.me_release or "",
            "svn": args.me_svn,
            "vcn": args.me_vcn,
            "build_date": args.me_date,
        }
        ok = store_me_info(sha256, me_info, vendor=args.vendor, model=args.model,
                          source_file=args.input)
        print(f"Stored: {ok}, SHA256: {sha256}")
        return 0 if ok else 1

    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
