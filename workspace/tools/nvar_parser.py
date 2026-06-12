#!/usr/bin/env python3
"""
NVAR Parser — Parse AMI Aptio V NVRAM variable stores from BIOS dumps.

Extracts the NVAR variable structure:
  +0  Signature  (4)  "NVAR"
  +4  TotalSize  (2)  u16 LE — full entry size (header + data)
  +6  State      (3)  bitmask — bit[0] = VALID (1=active, 0=deleted)
  +9  StoreType  (2)  u16 LE — store identifier (0=primary, 1=backup, …)
  +11 Name       (var) null-terminated ASCII
  +?  Data       (var) remaining bytes up to offset + TotalSize

Handles primary + backup store clusters, GUID table resolution from
store headers, and provides JSON serialisation for CLI / GUI use.
"""

import sys
import struct
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass, field

# ── Constants ───────────────────────────────────────────────────────────

NVAR_SIGNATURE = b'NVAR'

# Clustering
NVAR_STORE_GAP_MAX = 0x2000         # max gap for fallback proximity clustering
NVAR_MIN_CLUSTER_SIZE = 3           # minimum entries for a valid store
NVAR_ENTRY_MIN_SIZE = 11            # sig(4) + TotalSize(2) + State(3) + StoreType(2)

# State field (3-byte bitmask — flash NVRAM toggles individual bits)
NVAR_STATE_VALID       = 0x01       # bit 0: variable is valid / active
NVAR_STATE_CHECK_MASK  = 0x01       # mask for validity test

# Descriptor bounds
IFD_MAX_SECTION_OFFSET = 0x1000     # first 4 KB may contain store header


# ── Dataclasses ─────────────────────────────────────────────────────────

@dataclass
class NVARVariable:
    """A single UEFI variable entry from an AMI Aptio V NVRAM store."""
    offset: int                      # absolute offset of "NVAR" signature
    name: str                        # variable name (human-readable or synthetic)
    total_size: int                  # u16 LE at offset+4, full entry size
    state: int                       # u24 bitmask at offset+6
    store_type: int                  # u16 LE at offset+9
    data_offset: int                 # where variable DATA begins
    data_size: int                   # size of variable data in bytes
    name_raw: bytes = field(default=b'', repr=False)
    guid_index: Optional[int] = None # index into store GUID table (if locatable)
    guid: Optional[bytes] = None     # resolved 16-byte namespace GUID (or store fallback)
    cluster_index: int = 0           # which store cluster (0=primary, …)


@dataclass
class NVARStoreHeader:
    """Parsed store-level header with GUID table."""
    guid: bytes                      # 16-byte store GUID
    guid_table: List[bytes] = field(default_factory=list)  # indexed GUID entries
    attributes: int = 0
    header_size: int = 0


@dataclass
class NVARStore:
    """A contiguous NVAR variable store (primary or backup copy)."""
    offset: int                      # offset of first NVAR entry in this store
    end_offset: int                  # offset after last NVAR entry + its data
    variables: List[NVARVariable] = field(default_factory=list)
    store_index: int = 0             # 0 = primary, 1 = backup, …
    store_type: int = 0
    header: Optional[NVARStoreHeader] = None
    variable_count: int = 0
    size: int = 0

    def __post_init__(self):
        self.variable_count = len(self.variables)
        if self.end_offset > self.offset:
            self.size = self.end_offset - self.offset


@dataclass
class NVARParseResult:
    """Complete result of parsing NVAR stores from a BIOS dump."""
    found: bool = False
    stores: List[NVARStore] = field(default_factory=list)
    variables: List[NVARVariable] = field(default_factory=list)
    total_variables: int = 0
    region_start: int = 0
    region_end: int = 0
    summary: str = ""


# ── Private helpers ─────────────────────────────────────────────────────

def _read_cstring(data: bytes, start: int) -> Tuple[str, int, bytes]:
    """Read null-terminated ASCII string from *data* at *start*.
    Returns ``(display_name, offset_after_null, raw_bytes)``.
    """
    end = start
    while end < len(data) and data[end] not in (0, 0xFF):
        end += 1
    raw = data[start:end]
    # Build display-safe name — printable ASCII retained, everything else hex-escaped
    name = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in raw)
    if len(name) > 40:
        name = name[:40] + '...'
    return name, end + 1, raw


def _is_readable_name(raw: bytes) -> bool:
    """Return True if *raw* looks like a human-readable variable name."""
    if len(raw) < 2:
        return False
    alpha = sum(1 for b in raw if 65 <= b <= 90 or 97 <= b <= 122)
    return alpha >= 2 and alpha >= len(raw) * 0.5


def _read_entry_total_size(data: bytes, offset: int) -> int:
    """Read the TotalSize field (u16 LE) of an NVAR entry at *offset*."""
    if offset + 6 > len(data):
        return 0
    return struct.unpack_from('<H', data, offset + 4)[0]


def _parse_state(state: int) -> Tuple[bool, str]:
    """Return ``(is_active, label)`` for a 3-byte State bitmask."""
    is_active = (state & NVAR_STATE_CHECK_MASK) == NVAR_STATE_VALID
    label = "active" if is_active else "deleted"
    return is_active, label


# ── Store header / GUID table probing ───────────────────────────────────

def parse_store_header(data: bytes, store_offset: int, first_entry_offset: int
                       ) -> Optional[NVARStoreHeader]:
    """Attempt to parse an AMI Aptio V store header preceding the NVAR list.

    The store header lives between *store_offset* and *first_entry_offset*.
    It contains a 16-byte store GUID and, on many implementations, a GUID
    table — an array of 16-byte GUIDs indexed by number.  Each NVAR variable
    references one of these GUIDs via an index stored in its extended
    attributes.

    Probing is heuristic because the header layout varies across AMI Aptio
    versions.  Returns ``NVARStoreHeader`` on success, ``None`` if no
    recognisable header is found.
    """
    header_region = first_entry_offset - store_offset
    if header_region < 24:                     # need at least GUID + minimal metadata
        return None

    # Scan backward from first_entry_offset looking for a plausible GUID table.
    # A GUID table entry is 16 non-trivial bytes (not all-FF, not all-00).
    # We search for a contiguous run of such entries.
    candidates: List[bytes] = []

    # Strategy: walk backward in 16-byte steps looking for plausible GUIDs.
    # The table typically ends just before the first NVAR entry.
    probe = first_entry_offset - 16
    while probe >= store_offset:
        chunk = data[probe:probe + 16]
        if len(chunk) < 16:
            break
        # A valid GUID is neither all-FF nor all-00 and has non-zero first byte
        # (most UEFI GUIDs start with a non-zero time_low component).
        if chunk in (b'\x00' * 16, b'\xFF' * 16):
            probe -= 16
            continue
        # Plausible: non-trivial content
        candidates.insert(0, chunk)             # prepend — we're walking backward
        probe -= 16

    if not candidates:
        # No GUID table found — try reading just the store GUID from a fixed offset
        store_guid = data[store_offset:store_offset + 16]
        if store_guid not in (b'\x00' * 16, b'\xFF' * 16):
            return NVARStoreHeader(
                guid=store_guid,
                guid_table=[store_guid],
                header_size=16,
            )
        return None

    # First candidate = store GUID (entry 0 in the table)
    store_guid = candidates[0]
    return NVARStoreHeader(
        guid=store_guid,
        guid_table=candidates,
        header_size=first_entry_offset - store_offset,
    )


def _probe_guid_index(data: bytes, name_end: int, entry_end: int) -> Optional[int]:
    """Attempt to locate a GUID table index in the extended attributes area.

    After the null-terminated name (ending at *name_end*) and before the
    effective entry end (*entry_end*), AMI Aptio V may place extended
    attributes that include a GUID index.  The exact location varies —
    this function tries several known positions.

    Returns the index as int, or ``None`` if not locatable.
    """
    avail = entry_end - name_end
    if avail < 1:
        return None

    # Heuristic 1: single byte immediately after null terminator
    idx = data[name_end]
    if 0 <= idx <= 31:                         # plausible table index range
        return idx

    # Heuristic 2: byte at name_end+1 (some versions have a padding byte)
    if avail >= 2:
        idx = data[name_end + 1]
        if 0 <= idx <= 31:
            return idx

    # Heuristic 3: last byte before entry_end (extended attr footer)
    if avail >= 1:
        idx = data[entry_end - 1]
        if 0 <= idx <= 31:
            return idx

    return None


def _resolve_guid(guid_index: Optional[int], header: Optional[NVARStoreHeader]) -> Optional[bytes]:
    """Resolve a GUID index against the store header's GUID table."""
    if header is None:
        return None
    if guid_index is not None and 0 <= guid_index < len(header.guid_table):
        return header.guid_table[guid_index]
    return header.guid                                 # fall back to store GUID


# ── Core parsing ────────────────────────────────────────────────────────

def parse_nvar_entry(data: bytes, offset: int) -> Optional[NVARVariable]:
    """Parse a single NVAR entry at *offset*.  Returns None on failure."""
    if offset + NVAR_ENTRY_MIN_SIZE > len(data):
        return None
    if data[offset:offset + 4] != NVAR_SIGNATURE:
        return None

    total_size = struct.unpack_from('<H', data, offset + 4)[0]
    # Reconstruct 24-bit State field (3 bytes, big-endian byte order within)
    state = (data[offset + 6] << 16) | (data[offset + 7] << 8) | data[offset + 8]
    store_type = struct.unpack_from('<H', data, offset + 9)[0]

    name, name_end, name_raw = _read_cstring(data, offset + 11)
    if not _is_readable_name(name_raw):
        name = f"var_0x{offset:04X}"

    data_offset = name_end

    if total_size > 0 and offset + total_size <= len(data):
        data_end = offset + total_size
    else:
        data_end = data_offset

    data_size = max(0, data_end - data_offset)

    return NVARVariable(
        offset=offset,
        name=name,
        total_size=total_size,
        state=state,
        store_type=store_type,
        data_offset=data_offset,
        data_size=data_size,
        name_raw=name_raw,
    )


def find_all_nvar_positions(data: bytes) -> List[int]:
    """Fast byte-level scan for all NVAR signature positions."""
    positions: List[int] = []
    pos = data.find(NVAR_SIGNATURE)
    while pos != -1:
        positions.append(pos)
        pos = data.find(NVAR_SIGNATURE, pos + 1)
    return positions


def cluster_nvar_positions(data: bytes, positions: List[int]) -> List[List[int]]:
    """Group NVAR offsets into logical store chains.

    Primary criterion — chain continuity via TotalSize:
      ``prev.offset + prev.total_size <= curr.offset`` → same chain.

    Fallback — proximity:
      ``curr - prev.offset <= NVAR_STORE_GAP_MAX`` → same store.

    Otherwise → new store.
    """
    if not positions:
        return []

    sorted_pos = sorted(positions)
    chains: List[List[int]] = [[sorted_pos[0]]]
    for curr in sorted_pos[1:]:
        prev = chains[-1][-1]
        prev_total = _read_entry_total_size(data, prev)
        if prev_total > 0 and curr >= prev + prev_total:
            chains[-1].append(curr)              # TotalSize-linked chain
        elif curr - prev <= NVAR_STORE_GAP_MAX:
            chains[-1].append(curr)              # fallback: close enough
        else:
            chains.append([curr])                # new store
    return chains


def parse_nvar_store(data: bytes,
                     cluster: List[int],
                     store_index: int = 0) -> NVARStore:
    """Parse all NVAR entries in a single cluster into an ``NVARStore``.

    Also attempts to detect and parse the store header (GUID table) that
    precedes the variable list.
    """
    sorted_cluster = sorted(cluster)
    first_offset = sorted_cluster[0]

    # ── Probe store header (bytes before first NVAR entry) ──────────
    store_header: Optional[NVARStoreHeader] = None
    if first_offset >= 32:
        store_header = parse_store_header(data, first_offset - 256, first_offset)
        if store_header is None:
            store_header = parse_store_header(data, first_offset - 64, first_offset)

    # ── Parse entries ───────────────────────────────────────────────
    variables: List[NVARVariable] = []
    for pos in sorted_cluster:
        var = parse_nvar_entry(data, pos)
        if var is None:
            continue

        var.cluster_index = store_index

        # Resolve GUID index and GUID
        entry_end = pos + var.total_size if var.total_size > 0 else var.data_offset
        var.guid_index = _probe_guid_index(data, var.data_offset, entry_end)
        var.guid = _resolve_guid(var.guid_index, store_header)

        variables.append(var)

    if not variables:
        return NVARStore(offset=0, end_offset=0, store_index=store_index)

    start = min(v.offset for v in variables)
    end = max(v.offset + v.total_size for v in variables if v.total_size > 0)
    if end <= start:
        end = start + 0x100

    return NVARStore(
        offset=start,
        end_offset=end,
        variables=variables,
        store_index=store_index,
        store_type=variables[0].store_type if variables else 0,
        header=store_header,
    )


def parse_nvar(data: bytes) -> NVARParseResult:
    """Main entry point: parse all NVAR variable stores from a BIOS dump."""
    positions = find_all_nvar_positions(data)
    if not positions:
        return NVARParseResult()

    chains = cluster_nvar_positions(data, positions)

    # Filter to significant clusters
    significant = [c for c in chains if len(c) >= NVAR_MIN_CLUSTER_SIZE]
    if not significant:
        return NVARParseResult()

    stores: List[NVARStore] = []
    all_vars: List[NVARVariable] = []
    for idx, cluster in enumerate(significant):
        store = parse_nvar_store(data, cluster, store_index=idx)
        if store.variables:
            stores.append(store)
            # Prefix names with store index when multiple stores exist
            if len(significant) > 1:
                for v in store.variables:
                    if not v.name.startswith('[store'):
                        v.name = f"[store{idx}] {v.name}"
            all_vars.extend(store.variables)

    region_start = min(s.offset for s in stores)
    region_end = max(s.end_offset for s in stores)

    summary = (
        f"NVAR: {len(all_vars)} variables in {len(stores)} store(s), "
        f"region 0x{region_start:06X}–0x{region_end:06X}"
    )

    return NVARParseResult(
        found=True,
        stores=stores,
        variables=all_vars,
        total_variables=len(all_vars),
        region_start=region_start,
        region_end=region_end,
        summary=summary,
    )


# ── JSON serialisation ──────────────────────────────────────────────────

def nvar_to_dict(result: NVARParseResult) -> dict:
    """Convert ``NVARParseResult`` to a JSON-serialisable dict."""
    return {
        "found": result.found,
        "total_variables": result.total_variables,
        "region_start": result.region_start,
        "region_end": result.region_end,
        "region_size": result.region_end - result.region_start,
        "stores": [
            {
                "index": s.store_index,
                "store_type": s.store_type,
                "offset": s.offset,
                "end_offset": s.end_offset,
                "size": s.size,
                "variable_count": s.variable_count,
                "store_guid": s.header.guid.hex() if s.header else None,
                "guid_table_size": len(s.header.guid_table) if s.header else 0,
                "variables": [
                    {
                        "offset": v.offset,
                        "name": v.name,
                        "total_size": v.total_size,
                        "state": v.state,
                        "state_label": _parse_state(v.state)[1],
                        "store_type": v.store_type,
                        "data_offset": v.data_offset,
                        "data_size": v.data_size,
                        "guid": v.guid.hex() if v.guid else None,
                        "guid_index": v.guid_index,
                    }
                    for v in s.variables
                ],
            }
            for s in result.stores
        ],
        "summary": result.summary,
    }


# ── CLI ─────────────────────────────────────────────────────────────────

def main() -> int:
    """CLI entry point."""
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(
        description="NVAR Parser — Parse AMI Aptio V NVRAM variable stores"
    )
    parser.add_argument("input", help="Path to BIOS dump (.bin)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON (for GUI)")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {args.input}")
        return 1

    data = input_path.read_bytes()
    result = parse_nvar(data)

    if args.json:
        out = nvar_to_dict(result)
        out["file"] = str(input_path)
        out["file_size"] = len(data)
        print(_json.dumps(out, indent=2, default=str))
        return 0 if result.found else 1

    if not result.found:
        print("[!] No NVAR variable store found")
        return 1

    print(f"[*] NVAR region: 0x{result.region_start:06X} – 0x{result.region_end:06X}")
    print(f"[*] Stores: {len(result.stores)}")
    print(f"[*] Variables: {result.total_variables}")

    for store in result.stores:
        guid_str = store.header.guid.hex() if store.header else "?"
        print(f"\n  Store {store.store_index} (type={store.store_type}, "
              f"GUID={guid_str}): "
              f"0x{store.offset:06X} – 0x{store.end_offset:06X} "
              f"({store.variable_count} vars)")
        for v in store.variables:
            guids = v.guid.hex() if v.guid else "?"
            _, s_label = _parse_state(v.state)
            print(f"    0x{v.offset:06X}  {v.name[:40]:40s}  "
                  f"size={v.total_size:4d}  data={v.data_size:5d}  "
                  f"{s_label:7s}  GUID={guids}")

    if args.verbose:
        for v in result.variables:
            _, s_label = _parse_state(v.state)
            print(f"\n  Variable: {v.name}")
            print(f"    Offset:     0x{v.offset:06X}")
            print(f"    TotalSize:  {v.total_size}")
            print(f"    State:      0x{v.state:06X} ({s_label})")
            print(f"    StoreType:  {v.store_type}")
            print(f"    GUID index: {v.guid_index}")
            print(f"    GUID:       {v.guid.hex() if v.guid else '?'}")
            print(f"    Data offset: 0x{v.data_offset:06X}")
            print(f"    Data size:   {v.data_size}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
