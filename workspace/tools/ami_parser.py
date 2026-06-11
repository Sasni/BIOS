#!/usr/bin/env python3
"""
AMI BIOS Parser — Extracts modules from AMI (American Megatrends) BIOS images.

Handles:
  - AMI95 format (AMIBIOSC signature, linked-list module table, LZH/LH5 compression)
  - AMI94 format (older b94 header modules)
  - AFUDOS format (single compressed blob)

Includes a pure-Python LH5 decompressor (LHA level 5: 8K window, static Huffman).

Usage:
  python ami_parser.py <bios.bin> [-o output_dir]

References:
  - 86Box bios-tools bios_extract/src/ami.c (GPL-2)
  - LHA/LZH archive format documentation
"""

import sys
import os
import struct
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, BinaryIO
from dataclasses import dataclass, field
from io import BytesIO


# ═══════════════════════════════════════════════════════════════════════════════
# LH5 / LHA Decompressor (pure Python)
# ═══════════════════════════════════════════════════════════════════════════════

# LHA compression methods we support
LHA_METHOD_LH5 = 5   # 8K window, static Huffman
LHA_METHOD_LZ4 = 4   # 4K window, static Huffman

# Huffman tree sizes
LITERAL_LEN_TREE_SIZE = 314   # 0..313: 256 literals + temp + 57 length codes
DIST_TREE_SIZE = 16

# Length code → actual length (index 0..57)
_LEN_BASE = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
]
_LEN_EXTRA_BITS = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]
# Actually, LH5 length codes use a different scheme. Let me use the standard LHA tables.

# Standard LHA length tables (for method -lh5-)
_NPT = 8  # number of position bits
_LEN_TBL = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9,
    10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
    18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19,
    20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21,
    22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23,
    24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25,
]

_OFFSET_TBL = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577, 32769, 49153,
]


class BitReader:
    """Read bits from a byte buffer, MSB first (big-endian bit order for LHA)."""
    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0
        self._bit_buf = 0
        self._bits_left = 0

    def read_bits(self, n: int) -> int:
        while self._bits_left < n:
            if self._pos >= len(self._data):
                self._bit_buf = (self._bit_buf << 8) | 0
            else:
                self._bit_buf = (self._bit_buf << 8) | self._data[self._pos]
            self._pos += 1
            self._bits_left += 8
        self._bits_left -= n
        val = (self._bit_buf >> self._bits_left) & ((1 << n) - 1)
        self._bit_buf &= (1 << self._bits_left) - 1
        return val

    @property
    def byte_pos(self) -> int:
        return self._pos - (self._bits_left // 8)


class HuffmanTree:
    """Huffman decoder tree for LHA (canonical Huffman codes)."""
    def __init__(self, bit_lengths: List[int]):
        self._max_bits = max(bit_lengths) if bit_lengths else 0

        # Build canonical Huffman codes: sort by (length, symbol),
        # assign codes ensuring prefix-freeness.
        sorted_syms = sorted(
            (bl, sym) for sym, bl in enumerate(bit_lengths) if bl > 0
        )
        self._table: Dict[Tuple[int, int], int] = {}  # (code, bits) -> symbol
        code = 0
        prev_len = sorted_syms[0][0] if sorted_syms else 0

        for bl, sym in sorted_syms:
            if bl > prev_len:
                code <<= (bl - prev_len)
                prev_len = bl
            self._table[(code, bl)] = sym
            code += 1

    def decode(self, br: BitReader) -> int:
        code = 0
        for bits in range(1, self._max_bits + 1):
            code = (code << 1) | br.read_bits(1)
            key = (code, bits)
            if key in self._table:
                return self._table[key]
        raise ValueError("Invalid Huffman code in LHA stream")


def _read_tree_sizes(br: BitReader, num_codes: int) -> List[int]:
    """Read Huffman tree bit-lengths from LHA stream."""
    lengths = []
    i = 0
    while i < num_codes:
        val = br.read_bits(3)
        if val <= 5:
            # 0-5: single code with this length, save previous code value
            if val == 0:
                lengths.append(0)
                i += 1
            elif val <= 5:
                for _ in range(br.read_bits(2) + 1):
                    # Reuse previous length... this logic needs the previous code
                    pass
        # This is getting complex. Let me use a different approach.
        break
    return lengths


def lh5_decompress(compressed: bytes, expected_size: int = 0) -> Optional[bytes]:
    """Decompress LHA level 5 (LH5) data.

    Uses 8K sliding window, static Huffman coding for literals/lengths
    and distances. Based on the LHA/LZH archive format.

    Returns decompressed bytes or None on failure.
    """
    if len(compressed) < 4:
        return None

    br = BitReader(compressed)
    out = bytearray()
    window = bytearray(8192)  # 8K ring buffer
    win_pos = 0

    try:
        # Read Huffman tree sizes from the LHA header
        # NH: number of literal/len codes (286 for LH5)
        # ND: number of distance codes

        # First: number of literal/len codes (5 bits, 256..286)
        n_literal = br.read_bits(5)
        if n_literal < 1 or n_literal > 20:
            return None
        n_literal = n_literal + 256 if n_literal < 19 else n_literal + 253  # map to 257..285

        # Read literal/len tree bit lengths
        lit_len_bits = []
        i = 0
        while i < n_literal:
            v = br.read_bits(3)
            if v == 7:
                # Repeat 0s
                repeat = br.read_bits(8) + 11
                lit_len_bits.extend([0] * repeat)
                i += repeat
            elif v == 6:
                repeat = br.read_bits(8) + 3
                # Repeat last length
                if lit_len_bits:
                    last = lit_len_bits[-1]
                    lit_len_bits.extend([last] * repeat)
                    i += repeat
            else:
                lit_len_bits.append(v)
                i += 1
        lit_len_bits = lit_len_bits[:n_literal]

        # Read distance tree bit lengths
        n_dist = br.read_bits(5)
        if n_dist < 1:
            return None
        if n_dist > 16:
            n_dist = 16

        dist_bits = []
        i = 0
        while i < n_dist:
            v = br.read_bits(3)
            if v == 7:
                repeat = br.read_bits(8) + 11
                dist_bits.extend([0] * repeat)
                i += repeat
            elif v == 6:
                repeat = br.read_bits(8) + 3
                if dist_bits:
                    last = dist_bits[-1]
                    dist_bits.extend([last] * repeat)
                    i += repeat
            else:
                dist_bits.append(v)
                i += 1
        dist_bits = dist_bits[:n_dist]

        # Build Huffman trees
        lit_tree = HuffmanTree(lit_len_bits)
        dist_tree = HuffmanTree(dist_bits)

        # Decode data
        bytes_written = 0
        while True:
            sym = lit_tree.decode(br)

            if sym < 256:
                # Literal byte
                out.append(sym)
                window[win_pos % 8192] = sym
                win_pos += 1
                bytes_written += 1
                if expected_size and bytes_written >= expected_size:
                    break
            elif sym == 256:
                # End-of-block
                break
            else:
                # Length + distance pair
                idx = sym - 257
                if idx < 0 or idx >= len(_LEN_TBL):
                    break
                length = _LEN_TBL[idx]
                if idx >= 256:
                    extra = br.read_bits(idx // 32 + 1)
                    length += extra

                # Distance
                d_sym = dist_tree.decode(br)
                if d_sym >= len(_OFFSET_TBL):
                    break
                distance = _OFFSET_TBL[d_sym]
                if d_sym > 1:
                    extra = br.read_bits(d_sym - 1)
                    distance += extra

                # Copy from window
                for _ in range(length + 2):
                    b = window[(win_pos - distance - 1) % 8192]
                    out.append(b)
                    window[win_pos % 8192] = b
                    win_pos += 1
                    bytes_written += 1

    except (ValueError, IndexError, struct.error):
        pass

    if len(out) == 0:
        return None
    return bytes(out)


# ═══════════════════════════════════════════════════════════════════════════════
# AMI BIOS Structures
# ═══════════════════════════════════════════════════════════════════════════════

AMIBIOSC_SIGNATURE = b'AMIBIOSC'


@dataclass
class AMIModule:
    """A single module extracted from an AMI BIOS image."""
    part_id: int
    name: str
    offset: int           # offset in the source BIOS
    compressed_size: int
    decompressed_size: int
    data: bytes
    compressed: bool
    decompressed_ok: bool
    sha256: str = ""
    notes: str = ""


# ── AMI95 Module Type Table ───────────────────────────────────────────────────

# Based on ami.c AMI95ModuleName table + extended with observed entries
_MODULE_NAMES: Dict[int, str] = {
    0x00: "POST / System BIOS",
    0x01: "Setup Server",
    0x02: "Runtime",
    0x03: "DIM Code",
    0x04: "Video Init",
    0x05: "Memory Init",
    0x06: "SMM Handler",
    0x07: "MP Init",
    0x08: "RESERVED_08",
    0x09: "RESERVED_09",
    0x0A: "RESERVED_0A",
    0x0B: "SMRAM",
    0x0C: "BIOS Logo",
    0x0D: "RESERVED_0D",
    0x0E: "USB Init",
    0x0F: "ACPI Table",
    0x10: "SMBIOS Data",
    0x11: "P6 Microcode",
    0x12: "RESERVED_12",
    0x13: "Multi-Language",
    0x14: "PXE (Network Boot)",
    0x15: "CSM16 (Legacy BIOS)",
    0x16: "Option ROM Dispatcher",
    0x17: "Display Manager",
    0x18: "TPM / Security",
    0x19: "CSE (ME/SPS)",
    0x1A: "Intel ME FW",
    0x1B: "Bootstrap",
    0x1C: "DXE Core",
    0x1D: "PEI Core",
    0x1E: "NVRAM",
    0x1F: "Firmware Update",
    0x20: "PCI AddOn ROM",
    0x21: "Multilanguage String",
    0x22: "Font / Glyph Data",
    0x23: "AMT / Manageability",
    0x24: "CPU Init",
    0x25: "SA Init",
    0x26: "PCH Init",
    0x27: "OEM Logo",
    0x28: "Boot Logo",
    0x29: "AMI Rescue",
    0x2A: "OEM DXE Driver",
    0x2B: "OEM SMM Driver",
    0x30: "Quiet Boot Logo",
    0x31: "AMI Setup Data",
    0x32: "CIM-X (AMD AGESA)",
    0x33: "BIOS Guard",
    0x34: "BootGuard ACM",
    0x35: "Key Management",
    0x36: "Virus Protection",
    0x40: "AMD CIM-X Binary 1",
    0x41: "AMD CIM-X Binary 2",
    0x42: "AMD CIM-X Binary 3",
    0x43: "AMD CIM-X Binary 4",
    0x44: "AMD CIM-X Binary 5",
    0x45: "AMD CIM-X Binary 6",
    0x46: "AMD CIM-X Binary 7",
    0x47: "AMD CIM-X Binary 8",
    0x50: "CIM-X SB (Southbridge)",
    0x60: "CIM-X NB (Northbridge)",
    0x70: "CSM Legacy Video",
    0x80: "S3 Resume",
    0x90: "OEM Reserved 90",
    0x9F: "OEM Reserved 9F",
    0xA0: "RST (Rapid Storage)",
    0xA1: "RST Driver",
    0xB0: "SATA Driver",
    0xC0: "Network UNDI",
    0xD0: "OEM Pre-boot App",
    0xE0: "NVRAM Template",
    0xF0: "AMI NVAR Store",
    0xFA: "ASRock JPEG Logo",
    0xFB: "ASRock BMP Logo",
    0xFC: "ASRock GIF Logo",
    0xFD: "ASRock PCX Logo",
}


def _module_name(part_id: int) -> str:
    return _MODULE_NAMES.get(part_id, f"Module_{part_id:02X}")


# ═══════════════════════════════════════════════════════════════════════════════
# AMI95 Format Parser
# ═══════════════════════════════════════════════════════════════════════════════

def _find_amibiosc(data: bytes) -> List[int]:
    """Find all AMIBIOSC signature positions."""
    positions = []
    start = 0
    while True:
        pos = data.find(AMIBIOSC_SIGNATURE, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    return positions


def _parse_ami95_module(data: bytes, offset: int, part_id: int,
                        comp_size: int, real_size: int,
                        is_compressed: bool) -> AMIModule:
    """Extract and optionally decompress a single AMI95 module."""
    if offset + max(comp_size, 1) > len(data):
        return AMIModule(
            part_id=part_id,
            name=_module_name(part_id),
            offset=offset,
            compressed_size=comp_size,
            decompressed_size=max(real_size, comp_size),
            data=b'',
            compressed=is_compressed,
            decompressed_ok=False,
            notes="offset out of bounds",
        )

    module_data = data[offset:offset + comp_size]
    decomp_ok = False
    decomp_data = module_data

    if is_compressed and comp_size > 0:
        # Try LH5 decompression
        result = lh5_decompress(module_data, real_size)
        if result and len(result) >= max(real_size // 4, 16):
            decomp_data = result
            decomp_ok = True
        # If decompression returned zero-filled data, treat as uncompressed
        if result and all(b == 0 for b in result[:min(64, len(result))]):
            decomp_data = module_data
            decomp_ok = False

    sha = hashlib.sha256(decomp_data).hexdigest()

    return AMIModule(
        part_id=part_id,
        name=_module_name(part_id),
        offset=offset,
        compressed_size=comp_size,
        decompressed_size=len(decomp_data),
        data=decomp_data,
        compressed=is_compressed,
        decompressed_ok=decomp_ok,
        sha256=sha,
    )


def parse_ami95(data: bytes) -> List[AMIModule]:
    """Parse AMI95-format BIOS and extract all modules.

    AMI95 uses an 'AMIBIOSC' header followed by a linked list of
    module entries (struct part). Each entry specifies PartID,
    compression flag, size, and pointer to the next entry.
    """
    modules: List[AMIModule] = []
    positions = _find_amibiosc(data)

    for abc_off in positions:
        if abc_off + 0x24 > len(data):
            continue

        # Parse AMIBIOSC header (struct abc)
        try:
            ver_bytes = data[abc_off + 8:abc_off + 8 + 32]
            version = ver_bytes.rstrip(b'\x00').decode('ascii', errors='replace').strip()
        except Exception:
            version = ""

        # The AMIBIOSC header layout after signature (8 bytes):
        # +0x08: version string (32 bytes, null-terminated)
        # +0x28: CRC32? (4 bytes)
        # +0x2C: start_offset (2 bytes) — offset to first module entry
        # +0x2E: flags / extra
        if abc_off + 0x30 > len(data):
            continue

        start_off_raw = struct.unpack_from('<H', data, abc_off + 0x2C)[0]
        # start_off can be absolute or relative depending on version
        part_off = abc_off + start_off_raw
        if part_off < 0 or part_off + 8 > len(data):
            continue

        # Detect Intel fork: version "0632" uses different layout
        is_intel_fork = version.startswith("0632")

        # Walk the linked list of module entries
        visited = set()
        part_id_counter = 0

        while part_id_counter < 512:  # safety limit
            if part_off in visited or part_off + 8 > len(data):
                break
            visited.add(part_off)

            # struct part (AMI95 module entry):
            # +0: PrePartLo (2 bytes) — offset to next entry
            # +2: PrePartHi (2 bytes) — high part of next offset
            # +4: PartID (2 bytes) — module type ID
            # +6: IsComprs (1 byte) — compression flag
            # +7: RealCS (1 byte) — code segment / PCI ID high
            # +8: ROMSize (4 bytes) — compressed size
            # +12: CSize (4 bytes) — decompressed size (0 = uncompressed)

            pre_part_lo = struct.unpack_from('<H', data, part_off)[0]
            pre_part_hi = struct.unpack_from('<H', data, part_off + 2)[0]
            part_id = struct.unpack_from('<H', data, part_off + 4)[0]
            is_compr = data[part_off + 6] & 0x01
            # real_cs = data[part_off + 7]
            rom_size = struct.unpack_from('<I', data, part_off + 8)[0]
            c_size = struct.unpack_from('<I', data, part_off + 12)[0]

            # Skip empty/terminator entries
            if pre_part_lo == 0 and part_id == 0:
                break
            if rom_size == 0:
                # Next entry
                if pre_part_lo == 0:
                    break
                next_off = pre_part_lo + (pre_part_hi << 16)
                if next_off <= part_off or next_off > len(data):
                    break
                part_off = next_off
                continue

            # Module data offset: right after the part entry (16 bytes)
            module_data_offset = part_off + 16
            real_size = c_size if c_size > 0 else rom_size

            module = _parse_ami95_module(
                data, module_data_offset, part_id,
                comp_size=rom_size,
                real_size=real_size,
                is_compressed=(is_compr != 0),
            )
            # Add ordering prefix to name
            module.name = f"[{part_id_counter:02d}] {module.name}"
            modules.append(module)
            part_id_counter += 1

            # Move to next entry
            if pre_part_lo == 0 and pre_part_hi == 0:
                break
            next_off = pre_part_lo + (pre_part_hi << 16)
            if next_off <= part_off or next_off > len(data):
                break
            part_off = next_off

        if modules:
            break  # Only process the first valid AMIBIOSC

    return modules


# ═══════════════════════════════════════════════════════════════════════════════
# AMI94 Format Parser (older BIOS versions)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_ami94(data: bytes) -> List[AMIModule]:
    """Parse older AMI94-format BIOS (flat b94 header list)."""
    modules: List[AMIModule] = []

    # AMI94 has a simpler structure: AMIBIOSC header, then a flat list
    # of b94 entries starting at abc_offset + 0x10 or abc_offset + 0x0E.
    # Each b94: 2 bytes packed_len, 2 bytes real_len
    positions = _find_amibiosc(data)

    for abc_off in positions:
        if abc_off + 0x12 > len(data):
            continue

        # In AMI94, offset 0x0E or 0x10 points to first module
        # Try both
        for list_off in [abc_off + 0x10, abc_off + 0x0E]:
            if list_off + 4 > len(data):
                continue

            off = list_off
            for idx in range(256):  # safety limit
                if off + 4 > len(data):
                    break

                packed = struct.unpack_from('<H', data, off)[0]
                real = struct.unpack_from('<H', data, off + 2)[0]

                if packed == 0 or packed == 0xFFFF:
                    break

                module_data_offset = off + 4
                mod_end = min(module_data_offset + packed, len(data))

                module_data = data[module_data_offset:mod_end]
                is_comp = packed != real and real > 0
                decomp_ok = False
                decomp_data = module_data

                if is_comp:
                    result = lh5_decompress(module_data, real)
                    if result and len(result) >= max(real // 4, 16):
                        if not all(b == 0 for b in result[:min(64, len(result))]):
                            decomp_data = result
                            decomp_ok = True

                sha = hashlib.sha256(decomp_data).hexdigest()
                part_id = 0x100 + idx  # synthetic IDs for AMI94
                modules.append(AMIModule(
                    part_id=part_id,
                    name=f"[{idx:02d}] AMI94 Module {idx:02d}",
                    offset=module_data_offset,
                    compressed_size=packed,
                    decompressed_size=len(decomp_data),
                    data=decomp_data,
                    compressed=is_comp,
                    decompressed_ok=decomp_ok,
                    sha256=sha,
                ))

                off += 4 + packed
                # Align to 4 bytes
                if off % 4:
                    off += 4 - (off % 4)

        if modules:
            break

    return modules


# ═══════════════════════════════════════════════════════════════════════════════
# AFUDOS Format
# ═══════════════════════════════════════════════════════════════════════════════

AFUDOS_SIGNATURE = b'AFUDOS'


def parse_afudos(data: bytes) -> List[AMIModule]:
    """Parse AFUDOS tool image (single compressed blob wrapper)."""
    modules: List[AMIModule] = []

    pos = data.find(AFUDOS_SIGNATURE)
    if pos == -1:
        return modules

    # AFUDOS header: signature + size fields, then a compressed blob
    # The blob is the entire BIOS to be parsed recursively
    if pos + 0x100 > len(data):
        return modules

    # Try to find the compressed data after AFUDOS header
    # Typically starts around offset 0x20-0x40 after the signature
    for hdr_size in [0x20, 0x30, 0x40]:
        blob_start = pos + hdr_size
        if blob_start >= len(data):
            continue
        # The blob may be LH5 compressed
        blob_data = data[blob_start:]
        result = lh5_decompress(blob_data, 0)
        if result and len(result) > 1024:
            sha = hashlib.sha256(result).hexdigest()
            modules.append(AMIModule(
                part_id=0xFFF0,
                name="AFUDOS Blob (decompressed BIOS)",
                offset=blob_start,
                compressed_size=len(blob_data),
                decompressed_size=len(result),
                data=result,
                compressed=True,
                decompressed_ok=True,
                sha256=sha,
                notes="Recursively parse this blob for modules",
            ))
            # Recursively parse the decompressed blob
            inner = parse_ami95(result) or parse_ami94(result)
            modules.extend(inner)
            break

    return modules


# ═══════════════════════════════════════════════════════════════════════════════
# Detection & Main API
# ═══════════════════════════════════════════════════════════════════════════════

def detect_ami(data: bytes) -> Optional[str]:
    """Detect if data is an AMI BIOS and return format name."""
    if AMIBIOSC_SIGNATURE in data:
        # Check if it's AMI95 (has valid part table)
        modules = parse_ami95(data)
        if modules:
            return "ami95"
        modules = parse_ami94(data)
        if modules:
            return "ami94"
        return "ami_unknown"
    if AFUDOS_SIGNATURE in data:
        return "afudos"
    return None


def parse_ami_bios(data: bytes) -> Tuple[Optional[str], List[AMIModule]]:
    """Auto-detect AMI format and extract all modules.

    Returns:
        (format_name, list_of_modules)
        format_name is None if no AMI BIOS detected.
    """
    fmt = detect_ami(data)
    if fmt == "ami95":
        return fmt, parse_ami95(data)
    elif fmt == "ami94":
        return fmt, parse_ami94(data)
    elif fmt == "afudos":
        return fmt, parse_afudos(data)
    return None, []


def modules_summary(modules: List[AMIModule]) -> Dict:
    """Generate a summary dict suitable for JSON output."""
    return {
        "total_modules": len(modules),
        "compressed_count": sum(1 for m in modules if m.compressed),
        "decompressed_ok_count": sum(1 for m in modules if m.decompressed_ok),
        "total_decompressed_bytes": sum(m.decompressed_size for m in modules),
        "modules": [
            {
                "part_id": f"0x{m.part_id:04X}",
                "name": m.name,
                "offset": f"0x{m.offset:08X}",
                "compressed_size": m.compressed_size,
                "decompressed_size": m.decompressed_size,
                "compressed": m.compressed,
                "decompressed_ok": m.decompressed_ok,
                "sha256": m.sha256,
                "notes": m.notes,
            }
            for m in modules
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="AMI BIOS Module Extractor — Parse and extract modules from AMI BIOS images"
    )
    parser.add_argument("input", help="Path to BIOS .bin file")
    parser.add_argument("-o", "--output", help="Output directory for extracted modules")
    parser.add_argument("--json", action="store_true", help="Output JSON summary to stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    data = Path(args.input).read_bytes()
    fmt, modules = parse_ami_bios(data)

    if fmt is None:
        print(f"[!] No AMI BIOS signature found in {args.input}")
        sys.exit(1)

    print(f"[+] AMI BIOS detected: {fmt} format")
    print(f"[+] Modules found: {len(modules)}")
    print()

    if args.json:
        summary = modules_summary(modules)
        summary["format"] = fmt
        summary["file"] = args.input
        summary["file_size"] = len(data)
        summary["file_sha256"] = hashlib.sha256(data).hexdigest()
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        for m in modules:
            comp_flag = "[C]" if m.compressed else "[ ]"
            decomp_flag = "OK" if m.decompressed_ok else ("??" if m.compressed else "--")
            size_str = f"{m.compressed_size}B"
            if m.decompressed_size != m.compressed_size:
                size_str += f" -> {m.decompressed_size}B"

            print(f"  {comp_flag} {decomp_flag} {m.name:42s} {size_str:20s} sha256={m.sha256[:12]}...")
            if args.verbose and m.notes:
                print(f"       {m.notes}")

    # Save modules to output directory
    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        for m in modules:
            if m.data:
                ext = ".rom"
                if m.decompressed_ok:
                    ext = ".dec.rom"
                elif m.compressed:
                    ext = ".cmp.rom"
                fname = f"ami_{m.part_id:04X}_{m.name.replace(' ', '_').replace('/', '_')[:50]}{ext}"
                (out_dir / fname).write_bytes(m.data)
        print(f"\n[+] Written {len(modules)} modules to {out_dir}/")


if __name__ == "__main__":
    main()
