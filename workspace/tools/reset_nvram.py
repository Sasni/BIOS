#!/usr/bin/env python3
"""
BIOS NVRAM Reset Tool — Clears corrupted UEFI variables to factory defaults.

Use when a BIOS fails to boot due to corrupted NVRAM variables
(common symptoms: stuck at logo, boot loop, settings corruption).

Supported formats:
  - NVAR  (AMI Aptio V)       — primary target, widely tested
  - VSS   (Insyde H2O)        — basic detection, reset not yet implemented
  - VSS2  (Insyde H2O v2)     — basic detection, reset not yet implemented

NVAR / VSS are UEFI variable markers. Each entry is one variable with
name + GUID + attributes + data. They interleave — there is no single
header/data boundary in the region.

Strategy (NVAR):
  1. Parse individual variables (name, data bounds)
  2. Clear the DATA portion of each variable (fill 0xFF), keeping the
     variable header intact so the BIOS still recognizes them
  3. On first boot after reset, BIOS rebuilds default values

Usage:
  python reset_nvram.py corrupted.bin [-o repaired.bin] [--list]

References:
  - ASUS X550EP (AMI Aptio V): corrupted SecureBootSetup variable → boot loop
  - Dell Inspiron 5558 (Insyde H2O): uses VSS format
"""

import sys
import struct
import hashlib
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass


NVAR_SIGNATURE = b'NVAR'
VSS_SIGNATURES = (b'$VSS', b'VSS2', b'$VSS2')


@dataclass
class NVRAMVariable:
    """A single UEFI variable found in the NVRAM region."""
    offset: int             # offset of "NVAR" signature
    name: str               # variable name (e.g., "StdDefaults", "SecureBootSetup")
    guid: bytes             # 16-byte GUID identifying the variable store
    header_size: int        # total header bytes (sig + name + null + GUID + attrs)
    data_offset: int        # where variable DATA begins
    data_size: int          # size of variable data (estimated)
    total_size: int         # total bytes this variable occupies


def _read_cstring(data: bytes, start: int) -> Tuple[str, int, bytes]:
    """Read a null-terminated string from data at start.
    Returns (display_name, offset_after_null, raw_bytes).
    """
    end = start
    while end < len(data) and data[end] not in (0, 0xFF):
        end += 1
    raw = data[start:end]
    # Build display-safe name
    name = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in raw)
    if len(name) > 40:
        name = name[:40] + '...'
    return name, end + 1, raw


def _is_readable_name(raw: bytes) -> bool:
    """Check if raw bytes look like a human-readable variable name."""
    if len(raw) < 2:
        return False
    alpha = sum(1 for b in raw if 65 <= b <= 90 or 97 <= b <= 122)
    return alpha >= 2 and alpha >= len(raw) * 0.5


def parse_nvram_variables(data: bytes) -> Tuple[List[NVRAMVariable], int, int]:
    """Parse all NVAR variables in a BIOS dump.

    Returns:
        (variables, region_start, region_end)
        region_start/end are the bounds of the NVRAM area.
        Returns empty list if no NVAR region found.
    """
    # Find all NVAR positions
    positions = [p for p in range(len(data))
                 if data[p:p + 4] == NVAR_SIGNATURE]

    if not positions:
        return [], 0, 0

    # Cluster nearby positions to find the main NVRAM region
    sorted_pos = sorted(positions)
    clusters = [[sorted_pos[0]]]
    for p in sorted_pos[1:]:
        if p - clusters[-1][-1] <= 0x2000:
            clusters[-1].append(p)
        else:
            clusters.append([p])
    main_cluster = max(clusters, key=len)
    region_start = min(main_cluster)
    region_end = max(p + 0x100 for p in main_cluster)  # generous end

    # Parse each NVAR entry.
    # AMI Aptio V variable format: NVAR + cookie + name(null-term) + GUID + attrs + data
    # Rather than parsing GUID/attrs precisely (which varies), we locate the
    # variable DATA by finding the next NVAR or FF fill boundary.
    variables = []
    for i, pos in enumerate(sorted(main_cluster)):
        if pos + 8 > len(data):
            continue

        # Find the variable name: scan forward from pos+4 for a readable
        # ASCII sequence. Binary metadata between sig and name varies
        # (typically 7-11 bytes in AMI Aptio V).
        name = "<binary>"
        name_end = pos + 4
        for scan_start in [pos + 4, pos + 7, pos + 8, pos + 11, pos + 12]:
            if scan_start >= len(data):
                continue
            trial_name, trial_end, trial_raw = _read_cstring(data, scan_start)
            if _is_readable_name(trial_raw):
                name = trial_name
                name_end = trial_end
                break
        else:
            name = f"var_0x{pos:04X}"
            name_end = pos + 4

        # GUID and attributes follow the name. GUID is 16 bytes.
        # After the null terminator, skip null padding to GUID (16-byte aligned)
        guid_start = (name_end + 15) & ~15  # align to 16
        if guid_start + 20 > len(data):
            guid_start = name_end
        guid = data[guid_start:guid_start + 16] if guid_start + 16 <= len(data) else b'\x00' * 16

        # Variable DATA starts after GUID + attributes.
        # Without precise format knowledge, estimate: data starts after
        # a reasonable header size from the NVAR signature.
        header_size = guid_start + 20 - pos  # sig + meta + name + GUID + attrs
        data_offset = min(pos + header_size, name_end + 24)

        # Find data end: next NVAR or FF fill
        next_nvar = None
        for np in sorted_pos:
            if np > pos:
                next_nvar = np
                break
        if next_nvar:
            data_end = next_nvar
        else:
            # Scan forward for 0xFF fill
            scan = data_offset
            while scan < min(len(data), data_offset + 0x10000):
                if data[scan:scan + 16] == b'\xff' * 16:
                    data_end = scan
                    break
                scan += 1
            else:
                data_end = min(data_offset + 0x1000, len(data))

        data_size = max(0, data_end - data_offset)
        total_size = header_size + data_size

        variables.append(NVRAMVariable(
            offset=pos,
            name=name,
            guid=guid,
            header_size=header_size,
            data_offset=data_offset,
            data_size=data_size,
            total_size=total_size,
        ))

    return variables, region_start, region_end


def reset_variable_data(data: bytearray, variables: List[NVRAMVariable],
                        keep: Optional[List[str]] = None) -> int:
    """Fill variable DATA portions with 0xFF.

    Args:
        data: mutable bytearray of the BIOS dump.
        variables: parsed NVAR variables.
        keep: if set, only clear variables NOT in this name list.

    Returns:
        Number of bytes cleared.
    """
    cleared = 0
    for v in variables:
        if keep and v.name in keep:
            continue
        end = min(v.data_offset + v.data_size, len(data))
        if end <= v.data_offset:
            continue
        chunk = data[v.data_offset:end]
        cleared += len(chunk) - chunk.count(0xFF)
        data[v.data_offset:end] = b'\xFF' * (end - v.data_offset)
    return cleared


# ═══════════════════════════════════════════════════════════════════════════════
# VSS / VSS2 Support (Insyde H2O)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VSSStore:
    offset: int
    size: int           # total store size from header
    header_size: int    # bytes before variable data starts (~40)


def parse_vss_stores(data: bytes) -> List[VSSStore]:
    """Find VSS/VSS2 variable stores in a BIOS dump.

    VSS format (Insyde H2O):
      $VSS (4) + StoreSize:u32 (4) + header_meta (~32) + variables...

    Returns list of detected stores. Only stores with plausible sizes
    and header structure are included.
    """
    stores = []
    for sig in (b'$VSS',):
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos == -1:
                break
            start = pos + 1

            if pos + 8 > len(data):
                continue
            store_size = struct.unpack_from('<I', data, pos + 4)[0]
            # Sanity: store size must be between 4KB and half the file
            if not (0x1000 <= store_size <= len(data) // 2):
                continue
            if pos + store_size > len(data):
                continue

            # VSS header is typically ~40 bytes. Verify by checking
            # that the area after the header contains variable-like data
            # (not FFs or zeros).
            header_size = 40
            if pos + header_size + 16 > len(data):
                continue
            after_header = data[pos + header_size:pos + header_size + 32]
            if after_header == b'\xff' * 32 or after_header == b'\x00' * 32:
                continue  # empty store

            stores.append(VSSStore(
                offset=pos,
                size=store_size,
                header_size=header_size,
            ))
    return stores


def reset_vss_data(data: bytearray, stores: List[VSSStore]) -> int:
    """Clear variable data in VSS stores, keeping headers intact.

    Fills everything after the VSS header with 0xFF.
    """
    cleared = 0
    for store in stores:
        clear_start = store.offset + store.header_size
        clear_end = store.offset + store.size
        if clear_end > len(data):
            clear_end = len(data)
        if clear_start >= clear_end:
            continue
        chunk = data[clear_start:clear_end]
        cleared += len(chunk) - chunk.count(0xFF)
        data[clear_start:clear_end] = b'\xFF' * (clear_end - clear_start)
    return cleared


def find_nvram_region(data: bytes) -> Optional['NVRAMRegion']:
    """Backward-compatible wrapper — returns a region object for the API.

    Deprecated by parse_nvram_variables. Kept for app.py compatibility.
    """
    variables, start, end = parse_nvram_variables(data)
    if not variables:
        return None
    return NVRAMRegion(
        start=start,
        end=end,
        header_end=variables[0].data_offset if variables else start,
        store_count=len(variables),
        size=end - start,
    )


@dataclass
class NVRAMRegion:
    start: int
    end: int
    header_end: int
    store_count: int
    size: int


def reset_nvram(data: bytes, region: NVRAMRegion) -> bytes:
    """Backward-compatible wrapper — clear all variable data.

    Uses parse_nvram_variables internally for correct per-variable clearing.
    """
    result = bytearray(data)
    variables, _, _ = parse_nvram_variables(data)
    if variables:
        cleared = reset_variable_data(result, variables)
        print(f"[*] Cleared {cleared} bytes across {len(variables)} variables")
    else:
        # Fallback to old region-based clearing
        end = min(region.end, len(result))
        if end > region.header_end:
            result[region.header_end:end] = b'\xFF' * (end - region.header_end)
    return bytes(result)


def validate_result(original: bytes, repaired: bytes, region: NVRAMRegion) -> List[str]:
    """Run safety checks on the repaired BIOS.

    Ensures the area BEFORE the NVRAM region (boot block, DMI, firmware)
    was not touched — only the NVRAM region itself should change.
    """
    warnings = []
    if len(repaired) != len(original):
        warnings.append("Size mismatch — repair corrupted the file structure!")

    # Safety boundary: everything before the NVRAM region must be untouched
    safe_boundary = region.start
    if safe_boundary > 0:
        before = original[:safe_boundary]
        after = repaired[:safe_boundary]
        if before != after:
            # Count differing bytes using fast slice comparison
            changed = sum(1 for a, b in zip(before, after) if a != b)
            warnings.append(
                f"Pre-NVRAM area (0x0-0x{safe_boundary:X}) was modified! "
                f"{changed} bytes changed. This area should NOT be touched."
            )

    # Also verify the area AFTER the NVRAM region
    after_nvram = region.end
    if after_nvram < len(original):
        tail_before = original[after_nvram:]
        tail_after = repaired[after_nvram:]
        if tail_before != tail_after:
            changed = sum(1 for a, b in zip(tail_before, tail_after) if a != b)
            warnings.append(
                f"Post-NVRAM area (0x{after_nvram:X}-EOF) was modified! "
                f"{changed} bytes changed."
            )

    return warnings


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="BIOS NVRAM Reset Tool — Clear corrupted UEFI variables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reset_nvram.py corrupted.bin
  python reset_nvram.py corrupted.bin -o repaired.bin
  python reset_nvram.py corrupted.bin --list    # just list variables, don't reset
        """
    )
    parser.add_argument("input", help="Path to BIOS dump (.bin)")
    parser.add_argument("-o", "--output", help="Output path (default: input_nvram_reset.bin)")
    parser.add_argument("--list", action="store_true", help="List NVAR variables without resetting")
    parser.add_argument("--keep", nargs="*", help="Variable names to preserve (others cleared)")
    parser.add_argument("--force", action="store_true", help="Skip confirmation")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    data = bytearray(input_path.read_bytes())
    print(f"[*] Input: {input_path.name} ({len(data):,} bytes)")
    print(f"    SHA256: {hashlib.sha256(data).hexdigest()}")

    variables, region_start, region_end = parse_nvram_variables(data)

    if not variables:
        # Check for VSS (Insyde H2O)
        vss_stores = parse_vss_stores(data)
        if vss_stores:
            print(f"[*] VSS stores found: {len(vss_stores)}")
            for s in vss_stores:
                print(f"    0x{s.offset:06X}: {s.size/1024:.0f} KB")
            if args.list:
                return
            if not args.force:
                print(f"\n[?] Will clear variable data in {len(vss_stores)} VSS stores.")
                print(f"    Store headers (first {vss_stores[0].header_size} bytes each) preserved.")
                response = input("    Continue? [y/N]: ")
                if response.lower() not in ('y', 'yes', 't', 'tak'):
                    print("[*] Aborted.")
                    sys.exit(0)
            cleared = reset_vss_data(data, vss_stores)
            output_path = Path(args.output) if args.output else input_path.with_stem(input_path.stem + "_nvram_reset")
            output_path.write_bytes(data)
            print(f"\n[+] Cleared {cleared:,} bytes across {len(vss_stores)} VSS stores")
            print(f"[+] Written: {output_path}")
            return
        print("[!] No NVRAM variable store found (neither NVAR nor VSS).")
        print("    This BIOS may use a different variable format.")
        sys.exit(1)

    print(f"\n[*] NVRAM region: 0x{region_start:06X} - 0x{region_end:06X}")
    print(f"[*] NVAR variables found: {len(variables)}")
    print()

    # List variables
    for i, v in enumerate(variables):
        guid_str = v.guid.hex()[:8]
        name_display = v.name[:30].ljust(30)
        print(f"  {i:3d}: 0x{v.offset:06X}  {name_display}"
              f"  hdr={v.header_size:3d}  data={v.data_size:5d}  GUID={guid_str}...")

    if args.list:
        return

    # Confirm
    if not args.force:
        keep_list = args.keep if args.keep else []
        target = "ALL variables" if not keep_list else f"variables NOT in {keep_list}"
        print(f"\n[?] Will clear variable DATA for: {target}")
        print(f"    Variable headers (name + GUID) will be preserved.")
        response = input("    Continue? [y/N]: ")
        if response.lower() not in ('y', 'yes', 't', 'tak'):
            print("[*] Aborted.")
            sys.exit(0)

    # Perform reset
    cleared = reset_variable_data(data, variables, keep=args.keep)

    # Write output
    output_path = Path(args.output) if args.output else input_path.with_stem(input_path.stem + "_nvram_reset")
    output_path.write_bytes(data)

    print(f"\n[+] Cleared {cleared:,} bytes across {len(variables)} variables")
    print(f"[+] Written: {output_path}")
    print(f"    SHA256: {hashlib.sha256(data).hexdigest()}")
    print(f"[*] Flash this file and boot. BIOS will rebuild default settings.")


if __name__ == "__main__":
    main()
