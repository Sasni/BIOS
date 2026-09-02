#!/usr/bin/env python3
"""
Intel Management Engine (ME) Region Parser

Extracts ME firmware metadata from SPI dumps:
  - ME version (major.minor.hotfix.build)
  - FPT (Flash Partition Table) layout
  - Platform / SKU identification
  - Release type (Production / Pre-Production / Debug)
  - ME region lock status
  - Build date (when available)

Handles ME versions 6 through 16 (LynxPoint through Meteor Lake).
"""

import struct
import re
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass, field

# ── Signatures ───────────────────────────────────────────────────────────

FPT_SIGNATURE = 0x46505424  # "$FPT" stored little-endian

# Partition type names (common across ME versions)
PART_NAMES = {
    0x50525446: "FTPR",  # Main ME firmware
    0x5054464E: "NFTP",  # Backup ME firmware
    0x5345444D: "MDES",  # MFS / MDes
    0x52544B46: "FKTR",  # Token Repository
    0x47444C46: "FLDG",  # Log Data
    0x524F4C43: "CLOR",  # CBM / ROM
    0x4C544946: "FITL",  # FITC
    0x52524556: "VERR",  # Version
    0x4B534944: "DISK",  # Disk / misc
    0x54534F50: "POST",  # Post-boot
}

# ME SKU / platform identification (by partition layout + version)
PLATFORM_DB = {
    # (major, minor): "Platform name"
    (6, 0): "Cougar Point",  (6, 1): "Cougar Point",
    (7, 0): "Panther Point", (7, 1): "Panther Point",
    (8, 0): "LynxPoint",     (8, 1): "LynxPoint",
    (9, 0): "LynxPoint",     (9, 1): "LynxPoint",
    (10, 0): "Sunrise Point", (10, 1): "Sunrise Point",
    (11, 0): "Union Point",  (11, 1): "Union Point",
    (12, 0): "Cannon Point", (12, 1): "Cannon Point",
    (14, 0): "Comet Lake",   (14, 1): "Comet Lake",
    (15, 0): "Tiger Lake",   (15, 1): "Tiger Lake",
    (16, 0): "Alder Lake",   (16, 1): "Alder Lake",
}

# ME SKU sizes (approximate, from FPT layout)
SKU_SIZES = {
    0x170000: "1.5MB", 0x180000: "1.5MB",
    0x280000: "2.5MB", 0x2A0000: "2.5MB",
    0x500000: "5MB",   0x520000: "5MB",
    0x700000: "7MB",   0x720000: "7MB",
    0xA00000: "10MB", 0xA20000: "10MB",
}


# ── Dataclasses ──────────────────────────────────────────────────────────

@dataclass
class MePartition:
    """One FPT partition entry."""
    name: str           # e.g. "FTPR", "NFTP"
    owner: int
    offset: int         # offset within ME region
    length: int         # partition size in bytes


# Latest ME versions per platform (major.minor.hotfix.build) — used to check "Latest: Yes/No"
LATEST_ME_VERSIONS = {
    "LynxPoint":     (9, 0, 30, 1482),
    "Sunrise Point": (10, 0, 55, 3000),
    "Union Point":   (11, 0, 25, 3001),
    "Cannon Point":  (12, 0, 60, 2000),
    "Comet Lake":    (14, 0, 45, 2000),
    "Tiger Lake":    (15, 0, 40, 2000),
    "Alder Lake":    (16, 0, 30, 2000),
    "Panther Point": (7, 1, 80, 2000),
    "Cougar Point":  (6, 1, 80, 2000),
}


@dataclass
class MeInfo:
    """Complete ME region analysis result."""
    found: bool = False
    version: str = ""           # "9.0.3.1347"
    version_major: int = 0
    version_minor: int = 0
    version_hotfix: int = 0
    version_build: int = 0
    platform: str = ""          # "LynxPoint"
    release_type: str = ""      # "Production" / "Pre-Production" / "Debug"
    sku_size: str = ""          # "1.5MB" / "2.5MB" / "5MB"
    svn: int = 0                # Security Version Number (anti-rollback)
    vcn: int = 0                # Version Control Number
    production_ready: bool = False  # PV (Production Version) bit
    me_type: str = "Region, Stock"  # "Region, Stock" / "Region, Modified" / "Extracted"
    is_latest: Optional[bool] = None  # None = unknown, True/False
    fpt_offset: int = 0         # offset of FPT header within ME region
    fpt_version: int = 0
    me_region_offset: int = 0   # absolute SPI offset of ME region
    me_region_size: int = 0
    locked: bool = False        # ME region locked (from IFD master access)
    partitions: List[MePartition] = field(default_factory=list)
    build_date: str = ""        # when extractable
    notes: List[str] = field(default_factory=list)
    summary: str = ""


# ── FPT Parser ───────────────────────────────────────────────────────────

def _find_fpt(data: bytes) -> Optional[int]:
    """Find $FPT signature within the data.

    First tries the standard location (first 4 KB), then expands
    to the full data range. Returns offset relative to start of data.
    """
    sig_bytes = struct.pack('<I', FPT_SIGNATURE)
    # Standard location
    pos = data.find(sig_bytes, 0, min(0x1000, len(data)))
    if pos >= 0:
        return pos
    # Broader scan: full ME region (some layouts place FPT deeper)
    pos = data.find(sig_bytes, 0, len(data))
    if pos >= 0:
        return pos
    return None


def _read_svn_vcn_from_rom_bypass(data: bytes) -> Tuple[int, int, bool]:
    """Try to read SVN, VCN, and PV from ROM Bypass at start of ME region.

    ROM Bypass is typically in the first 0x10-0x40 bytes of the ME region.
    Structure varies by ME version. We try multiple known layouts.

    Returns (svn, vcn, pv).
    """
    if len(data) < 0x20:
        return 0, 0, False

    # Layout A (ME 6-10): SVN at +0x04, VCN at +0x08, PV flag in +0x0C
    if len(data) >= 0x10:
        svn = struct.unpack_from('<I', data, 0x04)[0]
        vcn = struct.unpack_from('<I', data, 0x08)[0]
        pv  = (data[0x0C] & 0x01) != 0 if len(data) > 0x0C else False
        if 0 < svn < 256 and 0 <= vcn < 256:
            return svn, vcn, pv

    # Layout B (ME 11+): different offsets
    if len(data) >= 0x30:
        svn = struct.unpack_from('<I', data, 0x24)[0]
        vcn = struct.unpack_from('<I', data, 0x28)[0]
        pv  = (data[0x2C] & 0x01) != 0 if len(data) > 0x2C else False
        if 0 < svn < 256 and 0 <= vcn < 256:
            return svn, vcn, pv

    return 0, 0, False


def _check_latest(platform: str, version_major: int, version_minor: int,
                  version_hotfix: int, version_build: int) -> Optional[bool]:
    """Check if this ME version is the latest known for this platform."""
    if platform not in LATEST_ME_VERSIONS:
        return None
    lmaj, lmin, lhot, lbld = LATEST_ME_VERSIONS[platform]
    current = (version_major, version_minor, version_hotfix, version_build)
    latest  = (lmaj, lmin, lhot, lbld)
    return current >= latest


def _read_version_from_fpt(data: bytes, fpt_off: int) -> Tuple[int, int, int, int]:
    """Extract ME version (4 x u32) from FPT header.

    In ME 6-10 the version is at FPT + 0x14 (16 bytes, 4 x u32).
    In ME 11+ it may be at different offsets; we try multiple locations.
    """
    # FPT header version field: try offsets 0x14 (ME 6-12), 0x18 (ME 14+)
    for ver_off in (0x14, 0x18, 0x20):
        if fpt_off + ver_off + 16 <= len(data):
            maj = struct.unpack_from('<I', data, fpt_off + ver_off)[0]
            min_ = struct.unpack_from('<I', data, fpt_off + ver_off + 4)[0]
            hot = struct.unpack_from('<I', data, fpt_off + ver_off + 8)[0]
            bld = struct.unpack_from('<I', data, fpt_off + ver_off + 12)[0]
            # Validate: major should be 6-20, minor 0-50, hotfix 0-9999, build 0-99999
            if 6 <= maj <= 20 and 0 <= min_ <= 50 and 0 <= hot <= 10000 and 0 <= bld <= 100000:
                return maj, min_, hot, bld
    return 0, 0, 0, 0


def _parse_partitions(data: bytes, fpt_off: int, num_parts: int, entry_size: int = 0x18) -> List[MePartition]:
    """Parse partition entries from FPT.

    Each entry is typically 0x18 bytes for ME 6-12, 0x20 for ME 14+.
    """
    partitions = []
    # FPT header is typically 0x20 or 0x30 bytes; entries start after the header
    # Standard FPT header size: 0x20 for older ME, 0x30 for newer
    header_sizes_to_try = [0x20, 0x30, 0x40]

    for hdr_size in header_sizes_to_try:
        entries_start = fpt_off + hdr_size
        if entries_start + num_parts * entry_size <= len(data):
            parts = []
            for i in range(num_parts):
                e_off = entries_start + i * entry_size
                name_raw = struct.unpack_from('<I', data, e_off)[0]
                owner = struct.unpack_from('<I', data, e_off + 4)[0]
                offset = struct.unpack_from('<I', data, e_off + 8)[0]
                length = struct.unpack_from('<I', data, e_off + 12)[0]

                name = PART_NAMES.get(name_raw, f"0x{name_raw:08X}")
                if length == 0 or offset + length > len(data) * 2:
                    continue  # invalid partition

                parts.append(MePartition(
                    name=name,
                    owner=owner,
                    offset=offset,
                    length=length,
                ))
            if len(parts) >= num_parts * 0.5:  # at least half the partitions valid
                return parts

    return []


def _extract_build_date(data: bytes) -> str:
    """Try to find a build date string in the ME region (e.g. '2013-11-04' or '11/04/2013')."""
    # Look for date patterns in the first 1 MB (FTPR partition area)
    text = data[:min(len(data), 0x100000)].decode('ascii', errors='ignore')

    patterns = [
        r'(\d{4})-(\d{2})-(\d{2})',       # 2013-11-04
        r'(\d{2})/(\d{2})/(\d{4})',       # 11/04/2013
        r'(\w{3})\s+(\d{1,2})\s+(\d{4})', # Nov  4 2013
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(0)
    return ""


def _detect_release_type(data: bytes, fpt_off: int) -> str:
    """Try to determine if this is Production, Pre-Production, or Debug ME firmware.

    Look for known markers in the ME image:
    - Production: 'Production' string, specific HAP bit
    - Debug: debug tokens, larger partition sizes
    """
    if len(data) < 0x100000:
        return "unknown"
    sample = data[:min(len(data), 0x200000)].decode('ascii', errors='ignore')

    if 'Debug' in sample or 'DEBUG' in sample:
        return "Debug"
    if 'Pre-Production' in sample or 'PREPROD' in sample or 'Alpha' in sample:
        return "Pre-Production"
    if 'Production' in sample or 'PROD' in sample:
        return "Production"

    # Heuristic: Production builds typically have the HAP (Host Access Permit) bit cleared
    # The HAP status is at offset 0x0D of the ROM Bypass (first 16 bytes of ME region)
    if len(data) >= 0x10:
        hap_byte = data[0x0D] if len(data) > 0x0D else 0
        # bit 0 = HAP disable (0 = production, 1 = debug/pre-prod)
        if hap_byte & 0x01:
            return "Debug/Pre-Production"

    return "Production"


def _guess_sku(data: bytes, fpt_offset: int, partitions: List[MePartition]) -> str:
    """Guess the ME SKU size based on FTPR partition size or total region."""
    if not partitions:
        # Try to guess from total data size
        sz = len(data)
        for size_bytes, label in sorted(SKU_SIZES.items(), reverse=True):
            if sz >= size_bytes * 0.8:
                return label
        return f"{sz // (1024*1024)} MB"

    # FTPR is typically the largest partition; use its size
    ftpr = next((p for p in partitions if p.name == "FTPR"), None)
    if ftpr:
        for size_bytes, label in sorted(SKU_SIZES.items(), reverse=True):
            if ftpr.length >= size_bytes * 0.8:
                return label
        return f"{ftpr.length // (1024*1024)} MB (FTPR)"

    # Fallback: total sum of partition sizes
    total = sum(p.length for p in partitions)
    return f"~{total // (1024*1024)} MB"


# ── Main Parser ──────────────────────────────────────────────────────────

def parse_me_region(data: bytes, me_offset: int = 0, locked: bool = False) -> MeInfo:
    """Parse Intel ME region from a SPI dump.

    Args:
        data: ME region bytes (raw bytes from the ME partition).
        me_offset: Absolute SPI offset of the ME region (for display).
        locked: Whether the ME region is locked against writes (from IFD).

    Returns:
        MeInfo with version, platform, SKU, partitions, and metadata.
    """
    info = MeInfo(
        me_region_offset=me_offset,
        me_region_size=len(data),
        locked=locked,
    )

    if len(data) < 0x100:
        info.me_type = "Region, Invalid"
        info.summary = "ME region too small (<256 bytes) — not a valid ME image"
        return info

    # 1) Find FPT ($FPT signature)
    fpt_off = _find_fpt(data)
    if fpt_off is None:
        info.me_type = "Region, Cleaned"
        info.summary = "FPT signature ($FPT) not found — ME region may be empty or erased"
        info.notes.append("No FPT found; ME firmware may not be present or has been cleaned")
        return info

    info.fpt_offset = fpt_off
    info.found = True

    # 2) Read FPT header
    if fpt_off + 0x14 > len(data):
        info.me_type = "Region, Corrupted"
        info.summary = "FPT header truncated — ME region may be corrupted"
        return info

    header_ver = struct.unpack_from('<I', data, fpt_off + 4)[0]
    info.fpt_version = header_ver

    # Number of partitions
    num_parts = struct.unpack_from('<I', data, fpt_off + 0x14)[0]
    if num_parts > 64:
        num_parts = struct.unpack_from('<I', data, fpt_off + 0x10)[0]  # try alternate offset

    # 3) Extract version
    maj, mn, hot, bld = _read_version_from_fpt(data, fpt_off)
    info.version_major = maj
    info.version_minor = mn
    info.version_hotfix = hot
    info.version_build = bld

    if maj > 0:
        info.version = f"{maj}.{mn}.{hot}.{bld}"
    else:
        # Try to find version as string
        text_sample = data[:min(len(data), 0x10000)].decode('ascii', errors='ignore')
        m = re.search(r'(\d{1,2})\.(\d{1,2})\.(\d{1,4})\.(\d{1,6})', text_sample)
        if m:
            info.version = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
            info.version_major = int(m.group(1))
            info.version_minor = int(m.group(2))
            info.version_hotfix = int(m.group(3))
            info.version_build = int(m.group(4))

    # 4) Platform
    platform_key = (info.version_major, info.version_minor)
    info.platform = PLATFORM_DB.get(platform_key, "")
    if not info.platform and 6 <= info.version_major <= 20:
        info.platform = f"ME {info.version_major}.x"

    # 5) Parse partitions
    info.partitions = _parse_partitions(data, fpt_off, num_parts)

    # 6) Release type
    info.release_type = _detect_release_type(data, fpt_off)

    # 7) SKU size
    info.sku_size = _guess_sku(data, fpt_off, info.partitions)

    # 8) SVN / VCN / PV from ROM Bypass
    svn, vcn, pv = _read_svn_vcn_from_rom_bypass(data)
    info.svn = svn
    info.vcn = vcn
    info.production_ready = pv
    if not pv and info.release_type == "Production":
        # Sometimes PV bit is in a different location; if we detected
        # Production from strings, mark as production-ready anyway
        info.production_ready = (info.release_type == "Production")

    # 9) Check if latest version
    if info.platform:
        info.is_latest = _check_latest(info.platform, info.version_major,
                                       info.version_minor, info.version_hotfix,
                                       info.version_build)

    # 10) Build date
    info.build_date = _extract_build_date(data)

    # 11) ME type
    # "Region, Stock" = ME region from a full SPI dump with original firmware
    # "Region, Modified" = ME region present but signs of modification
    # "Extracted" = just the ME region bytes (not from full SPI)
    if info.me_region_offset > 0:
        info.me_type = "Region, Stock"
    else:
        info.me_type = "Extracted"
    # Check for signs of modification
    if info.notes:
        for note in info.notes:
            if 'cleaned' in note.lower() or 'empty' in note.lower() or 'erased' in note.lower():
                info.me_type = "Region, Cleaned"

    # 12) Summary
    parts = []
    if info.version:
        parts.append(f"ME v{info.version}")
    if info.platform:
        parts.append(info.platform)
    if info.release_type and info.release_type != "unknown":
        parts.append(info.release_type)
    if info.sku_size:
        parts.append(f"SKU: {info.sku_size}")
    if info.svn > 0:
        parts.append(f"SVN: {info.svn}")
    if info.vcn > 0:
        parts.append(f"VCN: {info.vcn}")
    parts.append(f"PV: {'Yes' if info.production_ready else 'No'}")
    if info.locked:
        parts.append("FD: Locked")
    else:
        parts.append("FD: Unlocked")
    if info.build_date:
        parts.append(f"Date: {info.build_date}")
    parts.append(f"{len(info.partitions)} partitions")
    if info.is_latest is not None:
        parts.append(f"Latest: {'Yes' if info.is_latest else 'No'}")
    info.summary = "; ".join(parts)

    return info


# ── JSON Serialization ───────────────────────────────────────────────────

def me_info_to_dict(info: MeInfo) -> dict:
    """Convert MeInfo to JSON-serializable dict."""
    return {
        "found": info.found,
        "version": info.version,
        "version_major": info.version_major,
        "version_minor": info.version_minor,
        "version_hotfix": info.version_hotfix,
        "version_build": info.version_build,
        "platform": info.platform,
        "release_type": info.release_type,
        "sku_size": info.sku_size,
        "me_type": info.me_type,
        "svn": info.svn,
        "vcn": info.vcn,
        "production_ready": info.production_ready,
        "is_latest": info.is_latest,
        "fpt_offset": f"0x{info.fpt_offset:X}",
        "fpt_version": info.fpt_version,
        "me_region_offset": f"0x{info.me_region_offset:X}",
        "me_region_size": info.me_region_size,
        "me_region_size_formatted": f"{info.me_region_size / (1024*1024):.1f} MB" if info.me_region_size > 0 else "0 MB",
        "locked": info.locked,
        "partitions": [
            {
                "name": p.name,
                "owner": f"0x{p.owner:08X}",
                "offset": f"0x{p.offset:X}",
                "length": p.length,
                "length_formatted": f"{p.length / 1024:.0f} KB" if p.length >= 1024 else f"{p.length} B",
            }
            for p in info.partitions
        ],
        "build_date": info.build_date,
        "notes": info.notes,
        "summary": info.summary,
    }


# ── CLI ──────────────────────────────────────────────────────────────────

def _print_me_info(info: MeInfo, verbose: bool = False) -> None:
    """Print a human-readable ME info report."""
    print(f"\n{'='*50}")
    print(f"  Intel Management Engine (ME) Analysis")
    print(f"{'='*50}")

    if not info.found:
        print(f"\n  [!] ME FPT not found")
        if info.notes:
            for n in info.notes:
                print(f"  {n}")
        print(f"  {info.summary}")
        return

    print(f"\n  Family:        ME")
    print(f"  Version:       {info.version or 'unknown'}")
    print(f"  Release:       {info.release_type or 'unknown'}")
    print(f"  Type:          {info.me_type}")
    print(f"  FD:            {'Locked' if info.locked else 'Unlocked'}")
    print(f"  SKU:           {info.sku_size or 'unknown'}")
    if info.svn > 0:
        print(f"  SVN:           {info.svn}")
    if info.vcn > 0:
        print(f"  VCN:           {info.vcn}")
    print(f"  PV:            {'Yes' if info.production_ready else 'No'}")
    if info.platform:
        print(f"  Platform:      {info.platform}")
    if info.build_date:
        print(f"  Date:          {info.build_date}")
    print(f"  Size:          0x{info.me_region_size:X}")
    print(f"  FPT version:   {info.fpt_version}")
    print(f"  Partitions:    {len(info.partitions)}")
    if info.is_latest is not None:
        print(f"  Latest:        {'Yes' if info.is_latest else 'No'}")

    if info.partitions:
        print(f"\n  ── Partitions ──")
        for p in info.partitions:
            print(f"  {p.name:8s}  offset=0x{p.offset:06X}  size={p.length//1024:>5,} KB")

    if verbose and info.notes:
        print(f"\n  ── Notes ──")
        for n in info.notes:
            print(f"  {n}")

    print(f"\n  Summary: {info.summary}")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Intel Management Engine (ME) Region Parser")
    parser.add_argument("input", help="ME region binary or full SPI dump (.bin)")
    parser.add_argument("--me-offset", type=lambda x: int(x, 0), default=None,
                       help="ME region offset within the file (hex, e.g. 0x1000)")
    parser.add_argument("--me-size", type=lambda x: int(x, 0), default=None,
                       help="ME region size in bytes (hex)")
    parser.add_argument("--full-spi", action="store_true",
                       help="File is a full SPI dump; auto-detect ME region from IFD")
    parser.add_argument("--locked", action="store_true",
                       help="Mark ME region as locked (for display)")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        return 1

    data = input_path.read_bytes()

    # Determine ME region
    if args.full_spi:
        # Auto-detect ME region from IFD
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fit_parser import parse_ifd_regions, _read_ifd_section_offset, FLVALSIG, IFD_FCBA_OFFSET, IFD_FRBA_OFFSET

        me_data = data
        me_offset = 0
        locked = False

        if len(data) >= 0x54 and struct.unpack_from('<I', data, 0x10)[0] == FLVALSIG:
            frba = _read_ifd_section_offset(data, IFD_FRBA_OFFSET)
            if frba > 0:
                regions = parse_ifd_regions(data, frba)
                me_region = next((r for r in regions if r.name == "ME" and r.is_populated), None)
                if me_region:
                    me_offset = me_region.offset
                    me_size = me_region.size
                    me_data = data[me_offset:me_offset + me_size]

                    # Check if ME region is locked (from master access)
                    fmba = _read_ifd_section_offset(data, 0x38)
                    if fmba > 0:
                        from fit_parser import parse_ifd_master_access
                        master_access = parse_ifd_master_access(data, fmba)
                        me_access = master_access[1] if len(master_access) > 1 else None
                        if me_access:
                            locked = len(me_access.write_masters) == 0
    elif args.me_offset is not None:
        me_offset = args.me_offset
        end = me_offset + (args.me_size or (len(data) - me_offset))
        me_data = data[me_offset:end]
        locked = args.locked
    else:
        # Assume the file IS the ME region itself
        me_data = data
        me_offset = 0
        locked = args.locked

    info = parse_me_region(me_data, me_offset=me_offset, locked=locked)

    if args.json:
        import json as _json
        out = me_info_to_dict(info)
        out["file"] = str(input_path)
        out["file_size"] = len(data)
        print(_json.dumps(out, indent=2, default=str))
        return 0 if info.found else 1

    print(f"[*] ME Region Parser")
    print(f"[*] File: {input_path} ({len(data):,} bytes)")
    print(f"[*] ME offset: 0x{me_offset:X}")
    _print_me_info(info, verbose=args.verbose)

    return 0 if info.found else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
