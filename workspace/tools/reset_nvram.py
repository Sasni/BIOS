#!/usr/bin/env python3
"""
BIOS NVRAM Reset Tool — Clears corrupted UEFI variables to factory defaults.

Use when a BIOS fails to boot due to corrupted NVRAM variables
(common symptoms: stuck at logo, boot loop, settings corruption).

Supported formats:
  - NVAR  (AMI Aptio V)       — primary target, widely tested
  - VSS   (Insyde H2O)        — full detection + reset with header preservation
  - VSS2  (Insyde H2O v2)     — detected via same VSS path
  - EVSA  (AMI EVSA)          — Lenovo ideapad 700, AMI platforms without NVAR
  - FPT dead zones (Insyde)   — all-zero NVRAM blocks inside firmware volumes

NVAR / VSS are UEFI variable markers. Each entry is one variable with
name + GUID + attributes + data. They interleave — there is no single
header/data boundary in the region.

Strategy (NVAR):
  1. Parse individual variables (name, data bounds)
  2. Clear the DATA portion of each variable (fill 0xFF), keeping the
     variable header intact so the BIOS still recognizes them
  3. On first boot after reset, BIOS rebuilds default values

Strategy (VSS):
  1. Find $VSS store signature and size
  2. Preserve $VSS signature (4 bytes), invalidate size field (0xFFFFFFFF)
     to signal "reinitialize" to the BIOS
  3. Clear variable data area (offset +16 to end of store) to 0xFF

Strategy (FPT dead zones):
  1. Scan Flash Partition Table for NVxx entries (Insyde H2O)
  2. Locate all-zero blocks in the firmware volume area
  3. Write 0x01 marker byte + fill remainder with 0xFF
     (BIOS interprets 0x01 as "initialized, needs rebuild")

Strategy (EVSA):
  1. Find EVSA signature with 42-byte header
  2. Preserve pre-header DWORD + signature + metadata (42 bytes total)
  3. Invalidate data_size field → 0xFFFFFFFF (signals "rebuild")
  4. Clear variable data (EVSA+38 to end of store) to 0xFF

Donor recovery (--donor):
  For bytes matching corruption markers (0x00 = erased, 0x55 = incomplete
  SPI write), copy the corresponding byte from a clean donor dump of the
  same model. Applied BEFORE clearing, so recovered data is preserved.

Usage:
  python reset_nvram.py corrupted.bin [-o repaired.bin] [--list]
  python reset_nvram.py corrupted.bin --donor clean_donor.bin -o repaired.bin

References:
  - ASUS X550EP (AMI Aptio V): corrupted SecureBootSetup variable → boot loop
  - Dell Inspiron 5558 (Insyde H2O): uses VSS format
  - Lenovo Y50-70 (Insyde H2O): dead NVRAM zones + VSS corruption → no display
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
    """A single UEFI variable found in the NVRAM region.

    AMI Aptio V NVAR entry structure:
      +0  Signature  (4)  \"NVAR\"
      +4  TotalSize  (2)  u16 LE — full entry size (header + data)
      +6  State      (3)  0xFFFFFF = active/valid
      +9  StoreType  (2)  u16 LE — variable store identifier
      +11 Name       (var) null-terminated ASCII
      ??  Data       (var) to end of entry (TotalSize from +4)
    """
    offset: int             # offset of \"NVAR\" signature
    name: str               # variable name
    total_size: int         # from header field +4
    state: int              # 0xFFFFFF = active, 0 = deleted
    store_type: int         # store identifier
    data_offset: int        # where variable DATA begins
    data_size: int          # size of variable data


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
    # Find all NVAR positions using fast C-level search
    positions = []
    pos = data.find(NVAR_SIGNATURE)
    while pos != -1:
        positions.append(pos)
        pos = data.find(NVAR_SIGNATURE, pos + 1)

    if not positions:
        return [], 0, 0

    # Cluster nearby positions to find NVRAM regions (primary + optional backup).
    # AMI often keeps two copies — both must be reset.
    sorted_pos = sorted(positions)
    clusters = [[sorted_pos[0]]]
    for p in sorted_pos[1:]:
        if p - clusters[-1][-1] <= 0x2000:
            clusters[-1].append(p)
        else:
            clusters.append([p])

    # Process all significant clusters (>= 3 NVAR entries).
    # Skip tiny isolated references.
    significant = [c for c in clusters if len(c) >= 3]
    if not significant:
        return [], 0, 0

    region_start = min(c[0] for c in significant)
    region_end = max(c[-1] + 0x100 for c in significant)

    # Parse each NVAR entry using the actual header structure:
    #   NVAR(4) + TotalSize:u16(2) + State:u24(3) + StoreType:u16(2) + name + data
    variables = []
    for cluster_idx, cluster in enumerate(significant):
        for pos in sorted(cluster):
            if pos + 11 > len(data):
                continue

            total_size = struct.unpack_from('<H', data, pos + 4)[0]
            state = (data[pos + 6] << 16) | (data[pos + 7] << 8) | data[pos + 8]
            store_type = struct.unpack_from('<H', data, pos + 9)[0]

            # Name at +11, null-terminated
            name, name_end, name_raw = _read_cstring(data, pos + 11)
            if not _is_readable_name(name_raw):
                name = f"var_0x{pos:04X}"

            # Data starts right after the name's null terminator
            data_offset = name_end

            # TotalSize from header is the authoritative size to next entry.
            # For the last variable in a cluster, TotalSize still gives the
            # correct end — no FF-scan heuristic needed.
            if total_size > 0 and pos + total_size <= len(data):
                data_end = pos + total_size
            else:
                # Only reached for corrupted entries with invalid TotalSize
                data_end = data_offset

            data_size = max(0, data_end - data_offset)

            prefix = f"[store{cluster_idx}] " if len(significant) > 1 else ""
            variables.append(NVRAMVariable(
                offset=pos,
                name=prefix + name,
                total_size=total_size,
                state=state,
                store_type=store_type,
                data_offset=data_offset,
                data_size=data_size,
            ))

    # Multiple stores (primary + backup) are handled transparently —
    # each variable gets a [storeN] prefix in its name.
    return variables, region_start, region_end


def reset_variable_data(data: bytearray, variables: List[NVRAMVariable],
                        keep: Optional[List[str]] = None,
                        target: Optional[List[str]] = None,
                        state_filter: Optional[int] = None) -> int:
    """Fill variable DATA portions with 0xFF.

    Args:
        data: mutable bytearray of the BIOS dump.
        variables: parsed NVAR variables.
        keep: if set, preserve variables in this name list.
        target: if set, ONLY clear variables in this name list.
        state_filter: if set, ONLY clear variables with this state
                      (e.g. 0x000000 = deleted, 0xFFFFFF = active).

    Returns:
        Number of bytes cleared.
    """
    cleared = 0
    for v in variables:
        # Apply filters
        if keep and v.name in keep:
            continue
        if target and v.name not in target:
            continue
        if state_filter is not None and v.state != state_filter:
            continue

        end = min(v.data_offset + v.data_size, len(data))
        if end <= v.data_offset:
            continue
        chunk = data[v.data_offset:end]
        cleared += len(chunk) - chunk.count(0xFF)
        data[v.data_offset:end] = b'\xFF' * (end - v.data_offset)
    return cleared


# ═══════════════════════════════════════════════════════════════════════════════
# EVSA Support (AMI EVSA — found on Lenovo 700-17ISK, ideapad 700 etc.)
# ═══════════════════════════════════════════════════════════════════════════════

EVSA_SIGNATURE = b'EVSA'
EVSA_HEADER_SIZE = 42  # bytes from EVSA-4 to first variable (EE marker)


@dataclass
class EVSAStore:
    """AMI EVSA variable store descriptor.

    Structure (offsets from EVSA-4):
      -4   PreHeader  (4)  — CRC or store identifier
      +0   Signature  (4)  — \"EVSA\"
      +4   Version    (4)  — always 1
      +8   DataSize   (4)  — approximate variable data size in bytes
      +12  Flags      (4)  — always 0
      +16  Meta       (20) — store GUID (16B) + common flags (4B)
      +36  StoreMeta  (6)  — store-specific field (size/version?)
      +42  Variables  (var) — EE-delimited variable records

    Each variable:
      EE xx xx xx xx yy yy name\0\0 [data]
      EE = delimiter byte (0xEE)
      xx xx xx xx = 4-byte field
      yy yy = 2-byte variable index
      name = UTF-16LE null-terminated
    """
    offset: int         # absolute offset of EVSA-4 (store base)
    evsa_offset: int    # absolute offset of \"EVSA\" signature
    data_size: int      # from header field +8
    variable_count: int  # number of EE markers found
    size: int           # estimated total store size (header + data)


def parse_evsa_stores(data: bytes) -> List[EVSAStore]:
    """Find and parse AMI EVSA variable stores.

    EVSA is the AMI equivalent of Insyde's VSS. It stores UEFI variables
    (Setup, SecureBoot keys, BootOrder, etc.) with a 42-byte header.

    Returns list of EVSAStore objects. Empty list if none found.
    """
    stores = []
    pos = data.find(EVSA_SIGNATURE)
    while pos != -1:
        if pos < 4:
            pos = data.find(EVSA_SIGNATURE, pos + 1)
            continue

        hdr_base = pos - 4
        if hdr_base + EVSA_HEADER_SIZE > len(data):
            pos = data.find(EVSA_SIGNATURE, pos + 1)
            continue

        # Verify: pre-header DWORD should be non-zero, non-FF
        pre = int.from_bytes(data[hdr_base:hdr_base + 4], 'little')
        if pre == 0 or pre == 0xFFFFFFFF:
            pos = data.find(EVSA_SIGNATURE, pos + 1)
            continue

        # Verify version field = 1
        ver = int.from_bytes(data[pos + 4:pos + 8], 'little')
        if ver != 1:
            pos = data.find(EVSA_SIGNATURE, pos + 1)
            continue

        # Verify flags field = 0
        flags = int.from_bytes(data[pos + 12:pos + 16], 'little')
        if flags != 0:
            pos = data.find(EVSA_SIGNATURE, pos + 1)
            continue

        data_sz = int.from_bytes(data[pos + 8:pos + 12], 'little')

        # Sanity: data size should be between 256 bytes and 1 MB
        if not (256 <= data_sz <= 0x100000):
            pos = data.find(EVSA_SIGNATURE, pos + 1)
            continue

        # Count EE markers in the data region (rough variable count)
        ee_start = hdr_base + EVSA_HEADER_SIZE
        ee_limit = min(ee_start + data_sz, len(data))
        var_count = data.count(b'\xEE', ee_start, ee_limit)

        # Estimate full store size: header + data rounded to next 4KB
        store_size = EVSA_HEADER_SIZE + data_sz

        stores.append(EVSAStore(
            offset=hdr_base,
            evsa_offset=pos,
            data_size=data_sz,
            variable_count=var_count,
            size=store_size,
        ))

        pos = data.find(EVSA_SIGNATURE, pos + 1)

    return stores


def reset_evsa_data(data: bytearray, stores: List[EVSAStore]) -> int:
    """Clear variable data in EVSA stores, keeping headers intact.

    Strategy:
      - Preserve the 42-byte header (EVSA-4 through EVSA+37).
      - Clear everything from EVSA+38 (first variable) to the end of the
        store (header + data_size).
      - The BIOS reinitializes variables on next boot.

    This is analogous to VSS reset: keep signature + header metadata,
    invalidate size field, clear the rest.
    """
    cleared = 0
    for store in stores:
        # Preserve pre-header DWORD (possible CRC)
        # Invalidate the data_size field to signal "store needs rebuild"
        sz_off = store.evsa_offset + 8
        if sz_off + 4 <= len(data):
            current = data[sz_off:sz_off + 4]
            target = b'\xFF\xFF\xFF\xFF'
            if current != target:
                data[sz_off:sz_off + 4] = target
                cleared += 4 - current.count(0xFF)

        # Clear variable data (from EVSA+38 to end of store)
        clear_start = store.offset + EVSA_HEADER_SIZE  # EVSA-4 + 42
        clear_end = min(store.offset + store.size, len(data))

        if clear_start >= clear_end:
            continue

        chunk = data[clear_start:clear_end]
        cleared += len(chunk) - chunk.count(0xFF)
        data[clear_start:clear_end] = b'\xFF' * (clear_end - clear_start)

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
    """Clear variable data in VSS stores.

    VSS header (Insyde H2O):
      +0  $VSS      (4)  signature — MUST be preserved
      +4  StoreSize (4)  u32 LE — invalidated to 0xFFFFFFFF
      +8  Meta      (8)  flags/reserved — preserved as-is
      +16 Data      (var) — cleared to 0xFF

    The $VSS signature is essential for the BIOS to recognize the store.
    Size is set to 0xFFFFFFFF — this signals the BIOS to reinitialize
    the store from scratch on next boot. Metadata at +8 is kept intact.
    """
    HDR_KEEP_SIG = 4       # preserve $VSS signature
    HDR_GAP = 4            # bytes 4-7: size field → 0xFFFFFFFF
    HDR_KEEP_META = 8      # bytes 8-15: store metadata
    HDR_TOTAL = HDR_KEEP_SIG + HDR_GAP + HDR_KEEP_META  # 16-byte header

    cleared = 0
    for store in stores:
        # Invalidate the size field (offset +4 to +7) → signals BIOS to reinit
        size_off = store.offset + 4
        if size_off + 4 <= len(data):
            current = data[size_off:size_off + 4]
            target = b'\xFF\xFF\xFF\xFF'
            if current != target:
                data[size_off:size_off + 4] = target
                cleared += 4 - current.count(0xFF)

        # Clear variable data (from +16 to end of store)
        clear_start = store.offset + HDR_TOTAL
        clear_end = store.offset + store.size
        if clear_end > len(data):
            clear_end = len(data)
        if clear_start >= clear_end:
            continue
        chunk = data[clear_start:clear_end]
        cleared += len(chunk) - chunk.count(0xFF)
        data[clear_start:clear_end] = b'\xFF' * (clear_end - clear_start)
    return cleared


# ═══════════════════════════════════════════════════════════════════════════════
# FPT-based NVRAM Detection (Insyde H2O Flash Partition Table)
# ═══════════════════════════════════════════════════════════════════════════════

FPT_SIGNATURE = b'$FPT'
FPT_NV_PREFIXES = (b'NVCL', b'NVCP', b'NVHM', b'NVJC', b'NVSG', b'NVST',
                   b'NVAR', b'NVRM', b'NVSM', b'NVLM')


def parse_fpt_entries(data: bytes) -> List[Tuple[str, int, int]]:
    """Parse Insyde Flash Partition Table to find NVRAM-related entries.

    The FPT lives in the ROM Hole (typically around 0x1000 in an 8 MB SPI).
    Each entry is 16 bytes: 8-byte signature + 4-byte attr + 4-byte size/offset.

    Returns list of (signature, offset_in_file, size_bytes) for NVRAM entries.
    Only entries whose attribute field is 0xFFFFFFFF (marker for NVRAM stores)
    are included — these define the NVRAM variable stores.
    """
    results = []
    pos = data.find(FPT_SIGNATURE)
    if pos == -1 or pos + 16 > len(data):
        return results

    # $FPT header: sig(4) + ver(4?) + entry_info...
    # Entries start at pos + some header offset.
    # The FPT structure for Insyde:
    #   $FPT (4) + Version (2) + EntrySize (2) + Flags (4) + NumEntries (4)
    # But variants exist — scan for entry signatures heuristically.
    entry_start = pos + 0x10  # typical: entries start 16 bytes after $FPT
    if entry_start + 16 > len(data):
        return results

    # Scan forward from entry_start looking for NVxx entries
    max_scan = min(pos + 0x400, len(data) - 16)
    for off in range(entry_start, max_scan, 16):
        sig = data[off:off + 8]
        # Check if this is an NVRAM-related entry
        is_nv = any(sig.startswith(pfx) for pfx in FPT_NV_PREFIXES)
        if not is_nv:
            # Also check legacy: sig is ASCII + rest is 0xFF padding
            sig_clean = sig.rstrip(b'\xFF')
            if not sig_clean or len(sig_clean) < 4:
                continue
            sig_str = sig_clean.decode('ascii', errors='replace')
            if not any(sig_str.startswith(pfx.decode()) for pfx in FPT_NV_PREFIXES):
                continue

        # Found an NVxx entry
        sig_clean = sig.rstrip(b'\xFF').decode('ascii', errors='replace')
        attr = int.from_bytes(data[off + 8:off + 12], 'little')
        val = int.from_bytes(data[off + 12:off + 16], 'little')

        if attr == 0xFFFFFFFF:
            # val is the NVRAM store descriptor — could be size, offset, or ID
            results.append((sig_clean, off, val))

    return results


def _find_dead_zones(data: bytes, fpt_entries: List[Tuple[str, int, int]],
                     vss_stores: List[VSSStore]) -> List[Tuple[int, int]]:
    """Find large all-zero blocks that are likely corrupted NVRAM.

    These are regions within the firmware volume that should contain
    variable data but are zeroed out (common symptom: BIOS stuck at logo).

    Strategy:
      - Scan the firmware area (first half of the image) for blocks
        of >= 256 consecutive zeros.
      - Exclude areas already covered by known VSS/NVAR stores.
      - Only exclude blocks at the very end of the file (last 64 KB)
        that bleed into unprogrammed flash space.
      - Zero blocks in the middle of active firmware are always included
        — even if preceded by FF padding (common FV layout).
    Returns list of (start, end) byte offsets.
    """
    min_size = 256
    tail_margin = 64 * 1024  # only skip at the very end of the flash
    search_limit = min(len(data) // 2, 4 * 1024 * 1024)  # first 4 MB or half

    # Build set of offsets already covered by VSS
    covered = set()
    for store in vss_stores:
        for i in range(store.offset, min(store.offset + store.size, len(data))):
            covered.add(i)

    dead_regions = []
    pos = 0
    while pos < search_limit:
        if data[pos] != 0:
            pos += 1
            continue

        # Found start of zero region
        start = pos
        while pos < search_limit and data[pos] == 0:
            pos += 1
        size = pos - start

        if size < min_size:
            continue

        # Skip if already covered by a VSS store
        if start in covered:
            continue

        # Only skip if this zero block is at the very end of the file
        # (unprogrammed flash space). Any zeros in the main firmware area
        # are suspicious — they indicate corrupted NVRAM.
        if start > len(data) - tail_margin:
            continue

        # Extend to the next 4KB boundary (round up). This covers the full
        # NVRAM variable store even when corruption is only partial.
        end = pos
        next_page = ((end + 0xFFF) // 0x1000) * 0x1000  # round up to 4KB
        if next_page == end:
            next_page += 0x1000  # at least one page extra for store metadata
        dead_regions.append((start, min(next_page, len(data))))

    return dead_regions


def reset_dead_zones(data: bytearray, zones: List[Tuple[int, int]]) -> int:
    """Clear dead (all-zero) NVRAM zones to 0xFF, with a marker byte.

    Strategy: write 0x01 as first byte (marks the region as "initialized but
    variables cleared"), then 0xFF for the rest. This matches how Insyde
    BIOS repair tools handle corrupted NVRAM blocks.
    """
    cleared = 0
    for start, end in zones:
        if start >= len(data):
            continue
        end = min(end, len(data))
        if end <= start:
            continue

        # First byte: marker 0x01 (signals "initialized, needs rebuild")
        if data[start] != 0x01:
            data[start] = 0x01
            cleared += 1

        # Rest: fill with 0xFF
        fill_start = start + 1
        if fill_start < end:
            chunk = data[fill_start:end]
            not_ff = len(chunk) - chunk.count(0xFF)
            cleared += not_ff
            data[fill_start:end] = b'\xFF' * (end - fill_start)

    return cleared


# ═══════════════════════════════════════════════════════════════════════════════
# Donor Recovery
# ═══════════════════════════════════════════════════════════════════════════════

_CORRUPTION_MARKERS = (0x00, 0x55)  # 0x00=erased, 0x55=incomplete SPI write


def recover_from_donor(data: bytearray, donor: bytes,
                       regions: List[Tuple[int, int]]) -> int:
    """Recover corrupted bytes from a donor BIOS dump.

    For each region, bytes that match corruption markers (0x00, 0x55)
    are replaced with the donor's value — but only when the donor byte
    is a non-corruption value.

    Common corruption patterns:
      0x00 — erased/flash failure
      0x55 (ASCII 'U') — incomplete SPI programmer write

    Args:
        data: mutable bytearray of the corrupted BIOS.
        donor: clean BIOS dump from the same or similar model.
        regions: list of (start, end) byte offsets to check.

    Returns:
        Number of bytes recovered from donor.
    """
    if len(donor) < len(data):
        donor = donor + b'\x00' * (len(data) - len(donor))

    recovered = 0
    for start, end in regions:
        end = min(end, len(data), len(donor))
        for i in range(start, end):
            if data[i] in _CORRUPTION_MARKERS and donor[i] not in _CORRUPTION_MARKERS:
                data[i] = donor[i]
                recovered += 1
    return recovered


def _find_corruption_markers(data: bytearray) -> List[Tuple[int, int]]:
    """Scan the full file for corruption marker runs (0x00, 0x55).

    0x00 = erased / flash failure
    0x55 = incomplete SPI programmer write (common 'UUUU' pattern)

    Returns list of (start, end) covering any run of >= 16 corruption bytes.
    These regions are candidates for donor recovery.
    """
    min_run = 16
    regions = []
    pos = 0
    while pos < len(data):
        if data[pos] not in _CORRUPTION_MARKERS:
            pos += 1
            continue

        start = pos
        marker = data[pos]
        while pos < len(data) and data[pos] == marker:
            pos += 1
        size = pos - start

        if size >= min_run:
            # Extend to include context on both sides (corruption may
            # bleed into adjacent bytes)
            ctx_start = max(0, start - 16)
            ctx_end = min(len(data), pos + 16)
            regions.append((ctx_start, ctx_end))

    return regions


def _overlaps_known_store(zone: Tuple[int, int],
                         variables: List[NVRAMVariable],
                         vss_stores: List[VSSStore],
                         evsa_stores: List[EVSAStore],
                         nvar_start: int, nvar_end: int) -> bool:
    """Check if a dead zone overlaps with a known variable store.

    Dead zones inside NVAR, VSS, or EVSA stores are normal empty space
    between variables — not corruption. Only zones OUTSIDE known stores
    are likely to be genuine corruption (Insyde H2O front NVRAM in FV).
    """
    zs, ze = zone
    # Check NVAR region
    if variables and nvar_start < nvar_end:
        if ze > nvar_start and zs < nvar_end:
            return True
    # Check each VSS store
    for store in vss_stores:
        vs, ve = store.offset, store.offset + store.size
        if ze > vs and zs < ve:
            return True
    # Check each EVSA store
    for store in evsa_stores:
        vs, ve = store.offset, store.offset + store.size
        if ze > vs and zs < ve:
            return True
    return False


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


def _find_crc32_footer(data: bytes, region_start: int, region_end: int) -> Optional[Tuple[int, int]]:
    """Try to locate a CRC32 footer in the NVRAM region.

    Some AMI Aptio V implementations store a CRC32 at the end of the
    NVRAM region. Returns (crc_offset, data_end_exclusive) or None.

    Heuristic: scan the last 64 bytes for a 4-byte value that equals
    CRC32 of the region data before it. Common layouts:
      - CRC32 at region_end - 4, covering region_start..crc_offset
      - CRC32 at region_end - 16 (inside a footer struct)
    """
    import binascii
    tail_start = max(region_start, region_end - 1024)
    for crc_off in range(region_end - 4, tail_start, -4):
        data_region = data[region_start:crc_off]
        if len(data_region) < 256:
            continue
        expected = binascii.crc32(data_region) & 0xFFFFFFFF
        actual = struct.unpack_from('<I', data, crc_off)[0]
        if expected == actual and actual != 0xFFFFFFFF:
            return (crc_off, crc_off + 4)
    return None


def _update_nvram_crc32(data: bytearray, region_start: int, region_end: int) -> bool:
    """Recalculate and update CRC32 footer if one is found."""
    import binascii
    footer = _find_crc32_footer(bytes(data), region_start, region_end)
    if footer is None:
        return False
    crc_off, _ = footer
    new_crc = binascii.crc32(data[region_start:crc_off]) & 0xFFFFFFFF
    struct.pack_into('<I', data, crc_off, new_crc)
    return True


def reset_nvram(data: bytes, region: NVRAMRegion) -> bytes:
    """Backward-compatible wrapper — clear all variable data.

    Uses parse_nvram_variables internally for correct per-variable clearing.
    Also updates CRC32 footer if present.
    """
    result = bytearray(data)
    variables, region_start, region_end = parse_nvram_variables(data)
    if variables:
        cleared = reset_variable_data(result, variables)
        print(f"[*] Cleared {cleared} bytes across {len(variables)} variables")
        # Update CRC32 if present
        if _update_nvram_crc32(result, region_start, region_end):
            print("[*] CRC32 footer updated")
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
  python reset_nvram.py corrupted.bin --donor clean_donor.bin -o repaired.bin
  python reset_nvram.py corrupted.bin --scan-dead     # force dead zone scan without FPT/VSS
        """
    )
    parser.add_argument("input", help="Path to BIOS dump (.bin)")
    parser.add_argument("-o", "--output", help="Output path (default: input_nvram_reset.bin)")
    parser.add_argument("--list", action="store_true", help="List variables/stores without resetting")
    parser.add_argument("--keep", nargs="*", help="Variable names to preserve (NVAR only)")
    parser.add_argument("--target", nargs="*", help="Only clear specific variables (NVAR only)")
    parser.add_argument("--state", help="Only clear variables with given state (e.g. 0x000000)")
    parser.add_argument("--donor", help="Path to clean donor BIOS for data recovery")
    parser.add_argument("--force", action="store_true", help="Skip confirmation")
    parser.add_argument("--scan-dead", action="store_true",
                       help="Force scan for dead (all-zero) NVRAM zones even without FPT/VSS evidence")
    parser.add_argument("--json", action="store_true",
                       help="Output detection results as JSON (for GUI, use with --list)")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    data = bytearray(input_path.read_bytes())
    if not args.json:
        print(f"[*] Input: {input_path.name} ({len(data):,} bytes)")
        print(f"    SHA256: {hashlib.sha256(data).hexdigest()}")

    # Load donor if provided
    donor_data = None
    if args.donor:
        donor_path = Path(args.donor)
        if not donor_path.exists():
            print(f"[!] Donor file not found: {args.donor}")
            sys.exit(1)
        donor_data = donor_path.read_bytes()
        if len(donor_data) != len(data):
            print(f"[!] Donor size ({len(donor_data):,}) differs from input "
                  f"({len(data):,}) — must be same flash size")
            sys.exit(1)
        print(f"[*] Donor: {donor_path.name}")
        print(f"    SHA256: {hashlib.sha256(donor_data).hexdigest()}")

    # ── Phase 1: Detect all NVRAM stores ──────────────────────────────────────

    # 1a. NVAR (AMI Aptio V)
    variables, nvar_start, nvar_end = parse_nvram_variables(data)

    # 1b. VSS / VSS2 (Insyde H2O)
    vss_stores = parse_vss_stores(data)

    # 1c. EVSA (AMI EVSA — Lenovo ideapad 700, etc.)
    evsa_stores = parse_evsa_stores(data)

    # 1d. FPT-based dead zones (Insyde H2O — front NVRAM inside FV).
    # Dead zones are Insyde-specific: NVRAM variables live in FV without
    # a clear store marker, so corruption appears as blocks of zeros.
    #
    # Auto-activate ONLY with Insyde evidence (FPT/NVxx or VSS store).
    # NVAR (AMI Aptio V) is self-contained — its parser already handles
    # the entire NVRAM store, so dead zones in AMI are just empty FFS space.
    # Use --scan-dead to force scan regardless.
    fpt_entries = parse_fpt_entries(data)
    dead_zones: List[Tuple[int, int]] = []
    _insyde_evidence = bool(fpt_entries) or bool(vss_stores)
    if _insyde_evidence or args.scan_dead:
        dead_zones = _find_dead_zones(data, fpt_entries, vss_stores)
        # Filter out zones that overlap with NVAR/VSS stores —
        # those parsers already handle their own regions correctly.
        # Dead zones inside known stores are just empty gaps between
        # variables, not corruption.
        dead_zones = [dz for dz in dead_zones
                      if not _overlaps_known_store(dz, variables, vss_stores,
                                                   evsa_stores,
                                                   nvar_start, nvar_end)]
        if not _insyde_evidence and dead_zones:
            print("[*] --scan-dead: forced dead zone scan (no Insyde FPT/VSS evidence)")

    # ── Phase 2: JSON output (early exit) ──────────────────────────────────────

    if args.json:
        import json as _json
        out = {
            "file": str(input_path),
            "file_size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "nvram": {
                "detected": bool(variables) or bool(vss_stores) or bool(evsa_stores) or bool(dead_zones),
                "formats": [],
            },
        }
        nv = out["nvram"]
        if variables:
            nv["formats"].append("NVAR (AMI Aptio V)")
            nv["nvar"] = {
                "variables": len(variables),
                "region_start": nvar_start,
                "region_end": nvar_end,
                "region_size": nvar_end - nvar_start,
                "stores": len(set(v.store_type for v in variables)),
            }
        if vss_stores:
            nv["formats"].append("VSS (Insyde H2O)")
            nv["vss"] = [
                {"offset": s.offset, "size": s.size, "size_kb": s.size // 1024}
                for s in vss_stores
            ]
        if evsa_stores:
            nv["formats"].append("EVSA (AMI)")
            nv["evsa"] = [
                {"offset": s.offset, "size": s.size, "size_kb": s.size // 1024,
                 "variables": s.variable_count}
                for s in evsa_stores
            ]
        if dead_zones:
            nv["formats"].append("FPT dead zones (Insyde H2O)")
            nv["dead_zones"] = [
                {"start": s, "end": e, "size": e - s}
                for s, e in dead_zones
            ]
            nv["dead_zones_total_bytes"] = sum(e - s for s, e in dead_zones)
        if fpt_entries:
            nv["fpt_entries"] = [
                {"signature": sig, "value": val}
                for sig, _, val in fpt_entries
            ]
        if not nv["detected"]:
            nv["note"] = "No supported NVRAM format found. Try --donor for recovery."

        print(_json.dumps(out, indent=2, default=str))
        return

    # ── Phase 3: Report findings (text) ────────────────────────────────────────

    found_any = bool(variables) or bool(vss_stores) or bool(evsa_stores) or bool(dead_zones)
    if not found_any:
        print("[!] No NVRAM store found (neither NVAR, VSS, EVSA, nor FPT dead zones).")
        print("    This BIOS may use an unsupported format. Try --donor for recovery.")
        sys.exit(1)

    all_regions: List[Tuple[int, int]] = []

    if variables:
        nvar_region = (nvar_start, nvar_end)
        all_regions.append(nvar_region)
        print(f"\n[*] NVAR region: 0x{nvar_start:06X} - 0x{nvar_end:06X}")
        print(f"[*] NVAR variables found: {len(variables)}")
        for i, v in enumerate(variables):
            name_display = v.name[:35].ljust(35)
            state_str = "active" if v.state == 0xFFFFFF else f"0x{v.state:06X}"
            print(f"  {i:3d}: 0x{v.offset:06X}  {name_display}"
                  f"  size={v.total_size:4d}  data={v.data_size:5d}  {state_str}")

    if vss_stores:
        print(f"\n[*] VSS stores found: {len(vss_stores)}")
        for s in vss_stores:
            all_regions.append((s.offset, s.offset + s.size))
            print(f"    0x{s.offset:06X}: {s.size/1024:.0f} KB")

    if evsa_stores:
        print(f"\n[*] EVSA stores found: {len(evsa_stores)}")
        for s in evsa_stores:
            all_regions.append((s.offset, s.offset + s.size))
            print(f"    0x{s.offset:06X}: {s.size/1024:.0f} KB, {s.variable_count} vars")

    if dead_zones:
        print(f"\n[*] Dead (all-zero) NVRAM zones found: {len(dead_zones)}")
        for start, end in dead_zones:
            all_regions.append((start, end))
            print(f"    0x{start:06X}-0x{end:06X}: {end-start:,} bytes")

    if args.list:
        return

    # ── Phase 3: Donor recovery (before clearing) ────────────────────────────

    recovered = 0
    if donor_data:
        # Expand regions to cover all corruption markers across the full file.
        # This catches programmer errors (0x55 'UUUU' pattern from incomplete
        # SPI writes) and erased areas (0x00) that fall outside known stores.
        corruption_regions = _find_corruption_markers(data)
        all_affected = dict.fromkeys(all_regions)  # deduplicate
        for r in corruption_regions:
            all_affected[r] = None
        expanded_regions = list(all_affected.keys())

        if expanded_regions:
            recovered = recover_from_donor(data, donor_data, expanded_regions)
            if recovered:
                print(f"\n[*] Recovered {recovered:,} bytes from donor "
                      f"({len(expanded_regions)} regions checked)")

        # Re-detect dead zones after recovery — some may have been healed
        if _insyde_evidence or args.scan_dead:
            dead_zones = _find_dead_zones(data, fpt_entries, vss_stores)
        else:
            dead_zones = []

    # ── Phase 4: Confirm ─────────────────────────────────────────────────────

    if not args.force:
        actions = []
        if variables:
            if args.target:
                actions.append(f"clear targeted NVAR variables: {args.target}")
            elif args.keep:
                actions.append(f"clear all NVAR variables EXCEPT {args.keep}")
            else:
                actions.append(f"clear {len(variables)} NVAR variables")
        if vss_stores:
            actions.append(f"reset {len(vss_stores)} VSS stores")
        if evsa_stores:
            actions.append(f"reset {len(evsa_stores)} EVSA stores")
        if dead_zones:
            actions.append(f"clear {len(dead_zones)} dead zones")
        if donor_data:
            actions.append("recover data from donor")

        print(f"\n[?] Planned actions:")
        for a in actions:
            print(f"    - {a}")
        response = input("\n    Continue? [y/N]: ")
        if response.lower() not in ('y', 'yes', 't', 'tak'):
            print("[*] Aborted.")
            sys.exit(0)

    # ── Phase 5: Apply fixes ─────────────────────────────────────────────────

    total_cleared = 0

    # State filter for NVAR
    state_filter = None
    if args.state:
        try:
            state_filter = int(args.state, 16)
        except ValueError:
            print(f"[!] Invalid state value: {args.state}")
            sys.exit(1)

    if variables:
        cleared = reset_variable_data(data, variables, keep=args.keep,
                                       target=args.target, state_filter=state_filter)
        total_cleared += cleared
        print(f"[*] NVAR: cleared {cleared:,} bytes across {len(variables)} variables")
        if _update_nvram_crc32(data, nvar_start, nvar_end):
            print("[*] NVAR CRC32 footer updated")

    if vss_stores:
        cleared = reset_vss_data(data, vss_stores)
        total_cleared += cleared
        print(f"[*] VSS:  cleared {cleared:,} bytes across {len(vss_stores)} stores")

    if evsa_stores:
        cleared = reset_evsa_data(data, evsa_stores)
        total_cleared += cleared
        print(f"[*] EVSA: cleared {cleared:,} bytes across {len(evsa_stores)} stores")

    if dead_zones:
        cleared = reset_dead_zones(data, dead_zones)
        total_cleared += cleared
        print(f"[*] Dead zones: cleared {cleared:,} bytes across {len(dead_zones)} zones")

    # ── Phase 6: Write output ────────────────────────────────────────────────

    output_path = Path(args.output) if args.output else input_path.with_stem(input_path.stem + "_nvram_reset")
    output_path.write_bytes(data)

    print(f"\n[+] Total cleared: {total_cleared:,} bytes")
    if donor_data:
        print(f"[+] Donor recovery applied: {recovered:,} bytes")
    print(f"[+] Written: {output_path}")
    print(f"    SHA256: {hashlib.sha256(data).hexdigest()}")
    print(f"[*] Flash this file and boot. BIOS will rebuild default settings.")


if __name__ == "__main__":
    main()
