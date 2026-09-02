#!/usr/bin/env python3
"""
MEA.dat Database Lookup

Parses the MEA.dat firmware repository from ME Analyzer
(https://github.com/platomav/meanalyzer) and provides
SHA-256 → ME firmware identification lookup.

Entry format:
    VERSION_SKU[STATUS_STAGE_HASH]
    VERSION_PLATFORM_VARIANT_MEDIA_STATUS_STAGE_HASH  (ME 11+)

Hash is SHA-256 of the ME firmware region blob (not the full SPI dump).
"""

import struct
from pathlib import Path
from typing import Optional, Dict, List

# Platform code → human-readable name
PLATFORM_NAMES = {
    "LPT": "LynxPoint",
    "CPT": "Cougar Point",
    "PPT": "Panther Point",
    "SPT": "Sunrise Point",
    "KBL": "Kaby Lake",
    "CNL": "Cannon Lake",
    "CML": "Comet Lake",
    "TGL": "Tiger Lake",
    "ADL": "Alder Lake",
    "RPL": "Raptor Lake",
    "MTL": "Meteor Lake",
    "SVR": "Server",
    "CON": "Consumer",
    "COR": "Corporate",
    "CHR": "Chrome",
    "LIT": "Lite",
    "SLM": "Slim",
}


def _parse_mea_entry(line: str) -> Optional[Dict]:
    """Parse a single MEA.dat entry line into a dict."""
    line = line.strip()
    if not line or line.startswith("*") or len(line) < 70:
        return None

    parts = line.rsplit("_", 1)
    if len(parts) != 2 or len(parts[1]) != 64:
        return None

    left, sha256 = parts
    sha256 = sha256.lower()
    tokens = left.split("_")

    if len(tokens) < 3:
        return None

    version = tokens[0]

    # Try to parse version: MAJOR.MINOR.HOTFIX.BUILD
    ver_parts = version.split(".")
    ver_major = ver_minor = ver_hotfix = ver_build = 0
    try:
        if len(ver_parts) >= 4:
            ver_major = int(ver_parts[0])
            ver_minor = int(ver_parts[1])
            ver_hotfix = int(ver_parts[2])
            ver_build = int(ver_parts[3])
    except ValueError:
        pass

    # Detect format: old (VERSION_SKU_...) or new (VERSION_PLATFORM_...)
    sku = platform = status = stage = variant = ""
    t1 = tokens[1].upper() if len(tokens) > 1 else ""

    if t1.endswith("MB") and "MB" in t1:
        # Old format: VERSION_SKU_STATUS_STAGE_HASH
        sku = tokens[1]
        status = tokens[2] if len(tokens) > 2 else ""
        stage  = tokens[3] if len(tokens) > 3 else ""
        # Platform inferred from version
        if ver_major == 9:
            platform = "LynxPoint"
        elif ver_major == 8:
            platform = "LynxPoint"
        elif ver_major == 7:
            platform = "Panther Point"
        elif ver_major == 6:
            platform = "Cougar Point"
    else:
        # New format: VERSION_PLATFORM_VARIANT_MEDIA_STATUS_STAGE_HASH
        platform = PLATFORM_NAMES.get(t1, t1)
        variant = tokens[2] if len(tokens) > 2 else ""
        sku = ""
        status_idx = 3
        # Some entries have SPI/UFS media marker
        if len(tokens) > 4 and tokens[3] in ("SPI", "UFS"):
            status_idx = 4
        status = tokens[status_idx] if len(tokens) > status_idx else ""
        stage  = tokens[status_idx + 1] if len(tokens) > status_idx + 1 else ""

    release = "Production" if status == "PRD" else "Pre-Production" if status == "PRE" else status

    return {
        "sha256": sha256,
        "version": version,
        "version_major": ver_major,
        "version_minor": ver_minor,
        "version_hotfix": ver_hotfix,
        "version_build": ver_build,
        "platform": platform,
        "sku_size": sku if "MB" in sku else "",
        "release_type": release,
        "status": status,
        "stage": stage,
        "variant": variant,
    }


def load_mea_database(path: Optional[Path] = None) -> Dict[str, Dict]:
    """Load and parse MEA.dat into a SHA256 → entry dict.

    Args:
        path: Path to MEA.dat. If None, tries default locations:
              ./MEA.dat, ../data/MEA.dat, data/MEA.dat

    Returns:
        Dict mapping lowercase SHA256 → entry dict.
    """
    if path is None:
        candidates = [
            Path("MEA.dat"),
            Path(__file__).resolve().parent.parent / "data" / "MEA.dat",
            Path("data") / "MEA.dat",
        ]
        for c in candidates:
            if c.exists():
                path = c
                break

    if path is None or not path.exists():
        return {}

    db = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = _parse_mea_entry(line)
            if entry:
                db[entry["sha256"]] = entry

    return db


# ── Global cache ─────────────────────────────────────────────────────────

_mea_db: Optional[Dict[str, Dict]] = None


def _get_db() -> Dict[str, Dict]:
    """Lazy-load MEA.dat database."""
    global _mea_db
    if _mea_db is None:
        _mea_db = load_mea_database()
    return _mea_db


def lookup_me_region(me_data: bytes) -> Optional[Dict]:
    """Hash ME region bytes with SHA-256 and look up in MEA.dat.

    Args:
        me_data: Raw bytes of the ME firmware region.

    Returns:
        Entry dict with version, platform, SKU, etc., or None if not found.
    """
    import hashlib
    sha = hashlib.sha256(me_data).hexdigest().lower()
    db = _get_db()
    return db.get(sha)


def lookup_me_region_file(filepath: str) -> Optional[Dict]:
    """Hash a file containing ME region bytes and look up in MEA.dat."""
    p = Path(filepath)
    if not p.exists():
        return None
    return lookup_me_region(p.read_bytes())


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    import argparse, hashlib

    parser = argparse.ArgumentParser(description="MEA.dat Database Lookup")
    parser.add_argument("input", nargs="?", help="ME region file or SHA256 hex string")
    parser.add_argument("--mea-path", help="Path to MEA.dat file")
    parser.add_argument("--stats", action="store_true", help="Show database stats")
    parser.add_argument("--platform", help="Filter by platform name (e.g. LynxPoint)")
    parser.add_argument("--version", help="Filter by version prefix (e.g. 9.0)")

    args = parser.parse_args()

    if args.mea_path:
        db = load_mea_database(Path(args.mea_path))
    else:
        db = _get_db()

    if args.stats:
        platforms = {}
        versions = {}
        for e in db.values():
            p = e.get("platform", "unknown")
            platforms[p] = platforms.get(p, 0) + 1
            v = e["version"]
            versions[v] = versions.get(v, 0) + 1
        print(f"MEA.dat entries: {len(db)}")
        print(f"Platforms: {len(platforms)}")
        for p, c in sorted(platforms.items(), key=lambda x: -x[1])[:15]:
            print(f"  {p}: {c}")
        print(f"Unique versions: {len(versions)}")
        return 0

    if args.platform or args.version:
        for e in db.values():
            if args.platform and e.get("platform", "").lower() != args.platform.lower():
                continue
            if args.version and not e["version"].startswith(args.version):
                continue
            print(f'{e["version"]}  {e.get("platform","?"):20s}  {e.get("sku_size",""):8s}  {e.get("release_type",""):14s}  {e["sha256"]}')
        return 0

    if args.input:
        # Try as SHA256 first, then as file
        inp = args.input.strip()
        if len(inp) == 64 and all(c in "0123456789abcdefABCDEF" for c in inp):
            entry = db.get(inp.lower())
        else:
            entry = lookup_me_region_file(inp)

        if entry:
            print(f'Version:  {entry["version"]}')
            print(f'Platform: {entry.get("platform", "?")}')
            print(f'SKU:      {entry.get("sku_size", "?")}')
            print(f'Release:  {entry.get("release_type", "?")}')
            print(f'Status:   {entry.get("status", "?")}')
            print(f'Stage:    {entry.get("stage", "?")}')
            print(f'SHA256:   {entry["sha256"]}')
        else:
            print("Not found in MEA.dat")
            return 1

    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
