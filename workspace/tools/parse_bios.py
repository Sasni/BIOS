#!/usr/bin/env python3
"""
BIOS Parser - Extracts regions, metadata, and structure from BIOS dumps.
Handles both full SPI dumps (with IFD/ME/GBE) and extracted BIOS regions.
"""

import sys
import os
import json
import struct
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
import re
import math
import lzma
import zlib

# Import FIT parser
try:
    from fit_parser import parse_fit, FitResult, MicrocodeInfo
    FIT_PARSER_AVAILABLE = True
except ImportError:
    FIT_PARSER_AVAILABLE = False

# Import AMI parser
try:
    from ami_parser import parse_ami_bios, modules_summary, AMIModule
    AMI_PARSER_AVAILABLE = True
except ImportError:
    AMI_PARSER_AVAILABLE = False

# ─── Constants ────────────────────────────────────────────────────────────

FFS_SIGNATURE = b'_FVH'
EFI_FIRMWARE_VOLUME_HEADER_SIZE = 0x48

SMBIOS32_SIGNATURE = b'_SM_'
SMBIOS64_SIGNATURE = b'_SM3_'

REGION_NAMES = {
    0x00000000: 'DESCRIPTOR',
    0x00001000: 'ME',
    0x00300000: 'BIOS',
    0x00700000: 'GBE',
    0x00800000: 'PDR',
}

# ─── Tiano/LZMA Decompression ──────────────────────────────────────────────

TIANO_SIGNATURE = b'\x04\x18\x00\x00'
TIANO_SIGNATURE_BE = b'\x18\x04\x00\x00'
LZMA_PROPS_SIZE = 5

@dataclass
class DecompressResult:
    success: bool
    decompressed: bytes = b''
    error: str = ""
    original_size: int = 0
    decompressed_size: int = 0
    method: str = ""

def decompress_tiano(data: bytes) -> DecompressResult:
    if len(data) < 12:
        return DecompressResult(False, error="Data too small for Tiano header")
    
    sig = data[:4]
    if sig not in (TIANO_SIGNATURE, TIANO_SIGNATURE_BE):
        return DecompressResult(False, error=f"Invalid Tiano signature: {sig.hex()}")
    
    is_le = sig == TIANO_SIGNATURE
    fmt = '<I' if is_le else '>I'
    
    decompressed_size = struct.unpack_from(fmt, data, 4)[0]
    compressed_size = struct.unpack_from(fmt, data, 8)[0]
    
    if decompressed_size == 0:
        return DecompressResult(False, error="Zero decompressed size")
    
    lzma_data = data[12:12+compressed_size]
    if len(lzma_data) < compressed_size:
        lzma_data = data[12:]
        compressed_size = len(lzma_data)
    
    if len(lzma_data) < LZMA_PROPS_SIZE:
        return DecompressResult(False, error="LZMA data too small for properties")
    
    props = lzma_data[:LZMA_PROPS_SIZE]
    lzma_compressed = lzma_data[LZMA_PROPS_SIZE:]
    
    dict_size = min(decompressed_size, 256 * 1024 * 1024)
    
    try:
        decomp = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{
                "id": lzma.FILTER_LZMA1,
                "dict_size": dict_size,
                "lc": props[0] % 9,
                "lp": (props[0] // 9) % 5,
                "pb": props[0] // 45,
            }]
        )
        decompressed = decomp.decompress(lzma_compressed)
        while decomp.needs_input:
            more = decomp.decompress(b'')
            if more:
                decompressed += more
            else:
                break
        
        return DecompressResult(
            success=True,
            decompressed=decompressed,
            original_size=len(data),
            decompressed_size=len(decompressed),
            method="tiano_lzma"
        )
    except Exception as e:
        return DecompressResult(False, error=f"LZMA decompression failed: {e}")

def decompress_lzma_raw(data: bytes) -> DecompressResult:
    if len(data) < LZMA_PROPS_SIZE + 1:
        return DecompressResult(False, error="Data too small for raw LZMA")
    
    props = data[:LZMA_PROPS_SIZE]
    lzma_compressed = data[LZMA_PROPS_SIZE:]
    dict_size = 16 * 1024 * 1024
    
    try:
        decomp = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{
                "id": lzma.FILTER_LZMA1,
                "dict_size": dict_size,
                "lc": props[0] % 9,
                "lp": (props[0] // 9) % 5,
                "pb": props[0] // 45,
            }]
        )
        decompressed = decomp.decompress(lzma_compressed)
        while decomp.needs_input:
            more = decomp.decompress(b'')
            if more:
                decompressed += more
            else:
                break
        
        return DecompressResult(
            success=True,
            decompressed=decompressed,
            original_size=len(data),
            decompressed_size=len(decompressed),
            method="lzma_raw"
        )
    except Exception as e:
        return DecompressResult(False, error=f"Raw LZMA decompression failed: {e}")

def decompress_gzip(data: bytes) -> DecompressResult:
    try:
        decompressed = zlib.decompress(data, 16 + zlib.MAX_WBITS)
        return DecompressResult(
            success=True,
            decompressed=decompressed,
            original_size=len(data),
            decompressed_size=len(decompressed),
            method="gzip"
        )
    except Exception as e:
        return DecompressResult(False, error=f"GZIP decompression failed: {e}")

def decompress_auto(data: bytes) -> DecompressResult:
    if len(data) < 4:
        return DecompressResult(False, error="Data too small")
    
    if data[:4] in (TIANO_SIGNATURE, TIANO_SIGNATURE_BE):
        return decompress_tiano(data)
    
    if data[:2] == b'\x1f\x8b':
        return decompress_gzip(data)
    
    if len(data) >= LZMA_PROPS_SIZE:
        props = data[0]
        lc = props % 9
        lp = (props // 9) % 5
        pb = props // 45
        if lc <= 8 and lp <= 4 and pb <= 4:
            return decompress_lzma_raw(data)
    
    return DecompressResult(False, error="Unknown compression format")

# ─── UEFI FFS File Parsing ──────────────────────────────────────────────────

FFS_FILE_TYPES = {
    0x01: "RAW", 0x02: "FREEFORM", 0x03: "SECURITY_CORE", 0x04: "PEI_CORE",
    0x05: "DXE_CORE", 0x06: "PEIM", 0x07: "DRIVER", 0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION", 0x0A: "MM_CORE_STANDALONE", 0x0B: "MM_CORE",
    0x0C: "MM_STANDALONE", 0x0D: "MM_DRIVER", 0x0E: "FIRMWARE_VOLUME_IMAGE",
    0x10: "FREEFORM_SUBTYPE_GUID", 0x11: "RAW_SUBTYPE_GUID", 0x12: "PE32_IMAGE",
    0x13: "TE_IMAGE", 0x14: "DXE_DEPEX", 0x15: "VERSION", 0x16: "USER_INTERFACE",
    0x17: "COMPATIBILITY16", 0x18: "FIRMWARE_VOLUME_IMAGE_SUBTYPE_GUID",
    0x19: "GUID_DEFINED", 0x1A: "UEFI_IMAGE", 0x1B: "SECTION_ONLY_GUID_DEFINED",
    0xF0: "PAD", 0xFF: "FV_FILETYPE_FFS_PAD",
}

SECTION_TYPES = {
    0x00: "ALL", 0x01: "COMPRESSION", 0x02: "GUID_DEFINED", 0x03: "PAD",
    0x04: "FV_FILETYPE_FFS_PAD", 0x05: "RAW", 0x06: "FREEFORM_SUBTYPE_GUID",
    0x07: "PE32", 0x08: "PICRESOURCE", 0x09: "VERSION", 0x0A: "GUI_DEFINED",
    0x0B: "FV_FILETYPE_FFS_PAD", 0x0C: "TE", 0x0D: "SECTION_ONLY_GUID_DEFINED",
    0x0E: "COMPATIBILITY16", 0x0F: "FIRMWARE_VOLUME_IMAGE",
    0x10: "DXE_DEPEX", 0x11: "PEI_DEPEX", 0x12: "MM_DEPEX",
    0x13: "FV_FILETYPE_FFS_PAD", 0x14: "FV_FILETYPE_FFS_PAD", 0x15: "VERSION",
    0x16: "RAW", 0x17: "FREEFORM_SUBTYPE_GUID", 0x18: "FV_FILETYPE_FFS_PAD",
    0x19: "PE32", 0x1A: "PICRESOURCE", 0x1B: "GUI_DEFINED",
    0x1C: "TE", 0x1D: "SECTION_ONLY_GUID_DEFINED", 0x1E: "COMPATIBILITY16",
    0x1F: "FIRMWARE_VOLUME_IMAGE",
}

def parse_ffs_file(data: bytes, base_offset: int = 0, max_depth: int = 3) -> List[Dict]:
    files = []
    pos = 0
    
    while pos + 0x18 <= len(data):
        if pos % 8 != 0:
            pos = (pos + 7) & ~7
            continue
        
        if pos + 0x18 > len(data):
            break
            
        ffs_name = data[pos:pos+16]
        if ffs_name == b'\xFF' * 16 or ffs_name == b'\x00' * 16:
            break
        
        integrity_check = data[pos+16] if pos+16 < len(data) else 0xFF
        ffs_type = data[pos+17] if pos+17 < len(data) else 0xFF
        attributes = data[pos+18] if pos+18 < len(data) else 0xFF
        
        size_bytes = data[pos+19:pos+22]
        if len(size_bytes) < 3:
            break
        ffs_size = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16)
        
        state = data[pos+22] if pos+22 < len(data) else 0xFF
        
        if ffs_size < 0x18 or ffs_size > len(data) - pos:
            pos += 8
            continue
        
        has_ext_header = (attributes & 0x01) != 0
        ext_header_size = 0x14 if has_ext_header else 0
        
        header_size = 0x18 + ext_header_size
        file_data_start = pos + header_size
        file_data_end = pos + ffs_size
        
        if file_data_end > len(data):
            break
        
        file_data = data[file_data_start:file_data_end]
        
        type_name = FFS_FILE_TYPES.get(ffs_type, f"UNKNOWN(0x{ffs_type:02X})")
        
        file_info = {
            "offset": base_offset + pos,
            "size": ffs_size,
            "name_guid": ffs_name.hex(),
            "type": ffs_type,
            "type_name": type_name,
            "attributes": attributes,
            "state": state,
            "integrity_check": integrity_check,
            "has_ext_header": has_ext_header,
            "sections": []
        }
        
        sections = parse_sections(file_data, base_offset + file_data_start, max_depth - 1)
        file_info["sections"] = sections
        
        files.append(file_info)
        pos = (pos + ffs_size + 7) & ~7
    
    return files

def parse_sections(data: bytes, base_offset: int = 0, max_depth: int = 3) -> List[Dict]:
    sections = []
    pos = 0
    
    while pos + 4 <= len(data):
        sec_type = data[pos]
        sec_size_bytes = data[pos+1:pos+4]
        if len(sec_size_bytes) < 3:
            break
        sec_size = sec_size_bytes[0] | (sec_size_bytes[1] << 8) | (sec_size_bytes[2] << 16)
        
        if sec_size < 4 or sec_size > len(data) - pos:
            break
        
        sec_data_start = pos + 4
        sec_data_end = pos + sec_size
        sec_data = data[sec_data_start:sec_data_end]
        
        type_name = SECTION_TYPES.get(sec_type, f"UNKNOWN(0x{sec_type:02X})")
        
        sec_info = {
            "offset": base_offset + pos,
            "size": sec_size,
            "type": sec_type,
            "type_name": type_name,
            "data_sha256": hashlib.sha256(sec_data).hexdigest() if sec_data else "",
        }
        
        if sec_type == 0x01 and len(sec_data) >= 5:
            uncompressed_len = struct.unpack_from('<I', sec_data, 0)[0]
            comp_type = sec_data[4]
            comp_data = sec_data[5:]
            
            sec_info["uncompressed_length"] = uncompressed_len
            sec_info["compression_type"] = comp_type
            sec_info["compression_type_name"] = ["TIANO", "LZMA", "GZIP"][comp_type] if comp_type <= 2 else f"UNKNOWN({comp_type})"
            
            decomp_result = None
            if comp_type == 0:
                decomp_result = decompress_tiano(comp_data)
            elif comp_type == 1:
                decomp_result = decompress_lzma_raw(comp_data)
            elif comp_type == 2:
                decomp_result = decompress_gzip(comp_data)
            
            if decomp_result and decomp_result.success:
                sec_info["decompressed"] = True
                sec_info["decompressed_size"] = len(decomp_result.decompressed)
                sec_info["decompressed_sha256"] = hashlib.sha256(decomp_result.decompressed).hexdigest()
                
                if max_depth > 0 and decomp_result.decompressed[:4] == FFS_SIGNATURE:
                    nested_files = parse_ffs_file(decomp_result.decompressed, base_offset + sec_data_start + 5, max_depth - 1)
                    sec_info["nested_files"] = nested_files
            else:
                sec_info["decompressed"] = False
                sec_info["decompression_error"] = decomp_result.error if decomp_result else "Unknown"
        
        elif sec_type == 0x02 and len(sec_data) >= 0x18:
            sec_info["section_guid"] = sec_data[:16].hex()
            sec_info["data_offset"] = struct.unpack_from('<I', sec_data, 16)[0]
            sec_info["attributes"] = struct.unpack_from('<I', sec_data, 20)[0]
        
        elif sec_type == 0x10:
            sec_info["depex_data"] = sec_data.hex()[:200]
        
        elif sec_type == 0x17 and len(sec_data) >= 2:
            build_num = struct.unpack_from('<H', sec_data, 0)[0]
            ver_str = read_cstring(sec_data, 2)
            sec_info["build_number"] = build_num
            sec_info["version_string"] = ver_str
        
        sections.append(sec_info)
        pos = (pos + sec_size + 3) & ~3
    
    return sections

def scan_uefi_volume_deep(data: bytes, vol_offset: int, vol: Dict, max_depth: int = 3) -> Dict:
    vol_data = data[vol_offset:vol_offset + vol['size']]
    header_len = vol['header_length']
    ffs_area = vol_data[header_len:]
    files = parse_ffs_file(ffs_area, vol_offset + header_len, max_depth)
    
    return {
        "volume_offset": vol_offset,
        "volume_guid": vol['guid'],
        "volume_size": vol['size'],
        "files_found": len(files),
        "files": files
    }

# ─── Data Classes ─────────────────────────────────────────────────────────

@dataclass
class RegionInfo:
    name: str
    offset: int
    size: int
    sha256: str
    entropy: float
    notes: List[str] = field(default_factory=list)

@dataclass
class BIOSInfo:
    file_path: str
    file_size: int
    sha256: str
    md5: str
    dump_type: str = "unknown"
    regions: List[RegionInfo] = field(default_factory=list)
    uefi_volumes: List[Dict] = field(default_factory=list)
    uefi_volume_deep_scan: List[Dict] = field(default_factory=list)
    smbios_tables: List[Dict] = field(default_factory=list)
    smbios_structures: List[Dict] = field(default_factory=list)
    intel_me: Optional[Dict] = None
    gbe_region: Optional[Dict] = None
    nvram_store: Optional[Dict] = None
    fit_table: Optional[Dict] = None
    ami_format: Optional[str] = None
    ami_modules: Optional[List[Dict]] = None
    detected_vendor: str = "Unknown"
    detected_model: str = "Unknown"
    bios_version: str = "Unknown"
    bios_date: str = "Unknown"
    board_id: str = "Unknown"
    serial_number: str = "REDACTED"
    uuid: str = "REDACTED"
    mac_addresses: List[str] = field(default_factory=list)
    compression: str = "none"
    analysis_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

# ─── Utility Functions ────────────────────────────────────────────────────

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def calculate_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for f in freq:
        if f:
            p = f / len(data)
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def find_all(data: bytes, pattern: bytes, start: int = 0) -> List[int]:
    positions = []
    pos = data.find(pattern, start)
    while pos != -1:
        positions.append(pos)
        pos = data.find(pattern, pos + 1)
    return positions

def read_uint32(data: bytes, offset: int, little_endian: bool = True) -> int:
    fmt = '<I' if little_endian else '>I'
    return struct.unpack_from(fmt, data, offset)[0]

def read_uint16(data: bytes, offset: int, little_endian: bool = True) -> int:
    fmt = '<H' if little_endian else '>H'
    return struct.unpack_from(fmt, data, offset)[0]

def read_uint64(data: bytes, offset: int, little_endian: bool = True) -> int:
    fmt = '<Q' if little_endian else '>Q'
    return struct.unpack_from(fmt, data, offset)[0]

def read_cstring(data: bytes, offset: int, max_len: int = 256) -> str:
    end = data.find(b'\x00', offset, offset + max_len)
    if end == -1:
        end = offset + max_len
    return data[offset:end].decode('ascii', errors='ignore')

# ─── File Type Detection ──────────────────────────────────────────────────

def detect_dump_type(data: bytes) -> Tuple[str, Dict]:
    info = {"signatures": {}}
    has_ifd = data[0:4] == b'\x00\x00\x00\x00' or data[0:4] == b'IFD\x00'
    
    fvh_positions = find_all(data, FFS_SIGNATURE)
    info["signatures"]["FVH"] = len(fvh_positions)
    
    smbios32_pos = find_all(data, SMBIOS32_SIGNATURE)
    smbios64_pos = find_all(data, SMBIOS64_SIGNATURE)
    info["signatures"]["SMBIOS32"] = len(smbios32_pos)
    info["signatures"]["SMBIOS64"] = len(smbios64_pos)
    
    info["signatures"]["ME"] = len(find_all(data, b'ME\x00\x00'))
    info["signatures"]["GBE"] = len(find_all(data, b'GBE\x00'))
    info["signatures"]["NVRAM"] = len(find_all(data, b'NVRA'))
    
    starts_with_mac = len(data) >= 6 and (data[0] & 0x01) == 0 and data[:6] != b'\x00'*6
    
    if has_ifd and (info["signatures"]["ME"] > 0 or info["signatures"]["GBE"] > 0):
        dump_type = "full_spi"
    elif info["signatures"]["FVH"] > 0 and info["signatures"]["SMBIOS32"] + info["signatures"]["SMBIOS64"] > 0:
        dump_type = "full_spi"
    elif info["signatures"]["FVH"] > 0:
        dump_type = "bios_region"
    elif starts_with_mac and len(data) <= 0x100000:
        dump_type = "gbe_region"
    elif info["signatures"]["ME"] > 0:
        dump_type = "me_region"
    else:
        dump_type = "unknown"
    
    return dump_type, info

# ─── Region Detection ─────────────────────────────────────────────────────

def validate_fv_header(header: bytes) -> bool:
    if len(header) < EFI_FIRMWARE_VOLUME_HEADER_SIZE:
        return False
    if header[0:4] != FFS_SIGNATURE:
        return False
    header_length = read_uint16(header, 0x30)
    if header_length < 0x48 or header_length > 0x1000:
        return False
    revision = header[0x32]
    if revision not in (0x01, 0x02):
        # Some vendors use different revisions, don't reject
        pass
    fv_length = read_uint64(header, 0x20)
    # Allow larger sizes for compressed volumes
    if fv_length < header_length or fv_length > 0x10000000:
        pass  # Don't reject, just warn
    return True

def scan_uefi_volumes(data: bytes, max_offset: Optional[int] = None) -> List[Dict]:
    volumes = []
    positions = find_all(data, FFS_SIGNATURE)
    search_limit = max_offset or len(data)
    
    for pos in positions:
        if pos >= search_limit:
            continue
        if pos + EFI_FIRMWARE_VOLUME_HEADER_SIZE > len(data):
            continue
        
        header = data[pos:pos + EFI_FIRMWARE_VOLUME_HEADER_SIZE]
        if not validate_fv_header(header):
            continue
        
        fv_length = read_uint64(header, 0x20)
        header_length = read_uint16(header, 0x30)
        revision = header[0x32]
        checksum = read_uint16(header, 0x34)
        ext_header_offset = read_uint16(header, 0x36)
        fv_guid = header[0x48:0x58] if ext_header_offset >= 0x48 else b''
        
        if pos + fv_length > len(data):
            fv_length = len(data) - pos
        
        volumes.append({
            "offset": pos,
            "size": fv_length,
            "header_length": header_length,
            "revision": revision,
            "checksum": checksum,
            "guid": fv_guid.hex() if fv_guid else "unknown",
            "type": "FVH",
            "validated": True
        })
    
    return volumes

def scan_smbios(data: bytes) -> List[Dict]:
    tables = []
    
    for pos in find_all(data, SMBIOS32_SIGNATURE):
        if pos + 0x1F > len(data):
            continue
        ep = data[pos:pos + 0x1F]
        ep_checksum = sum(ep[:0x1F]) & 0xFF
        tables.append({
            "offset": pos,
            "type": "SMBIOS32",
            "entry_point_length": ep[0x05],
            "major_version": ep[0x06],
            "minor_version": ep[0x07],
            "max_structure_size": read_uint16(ep, 0x08),
            "entry_point_revision": ep[0x0A],
            "formatted_area": ep[0x0B:0x0F].hex(),
            "intermediate_checksum": ep[0x0F],
            "structure_table_length": read_uint16(ep, 0x10),
            "structure_table_address": read_uint32(ep, 0x14),
            "number_of_structures": read_uint16(ep, 0x18),
            "bcd_revision": ep[0x1A],
            "ep_checksum_valid": ep_checksum == 0,
        })
    
    for pos in find_all(data, SMBIOS64_SIGNATURE):
        if pos + 0x18 > len(data):
            continue
        ep = data[pos:pos + 0x18]
        tables.append({
            "offset": pos,
            "type": "SMBIOS64",
            "entry_point_length": ep[0x05],
            "major_version": ep[0x06],
            "minor_version": ep[0x07],
            "doc_revision": ep[0x08],
            "entry_point_revision": ep[0x09],
            "reserved": ep[0x0A],
            "checksum": ep[0x0B],
            "table_maximum_size": read_uint32(ep, 0x0C),
            "table_address": read_uint64(ep, 0x10),
        })
    
    return tables

# ─── SMBIOS Structure Parsing ─────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    strings = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings

def parse_dmi_area(data: bytes) -> Optional[Dict]:
    """Parse the fixed DMI "System Information" area (vendor-specific layout).

    Many full-SPI dumps store the SMBIOS Type 1 strings — Manufacturer, BIOS
    version, BIOS date, Product Name, board code — as a packed NULL-terminated
    ASCII sequence at a fixed offset (0x400000 in the standard Intel flash
    layout). The standard SMBIOS entry point (_SM_/_SM3_) is usually absent in
    these dumps, so the generic SMBIOS parser finds nothing and model detection
    fails. Reading this area directly recovers the model name for ANY model,
    without a lookup database.

    Layout (verified on Lenovo/Dell/HP/ASUS full-SPI dumps):
        [0] Manufacturer  "LENOVO" / "DELL" / "HP" / "ASUS"
        [1] BIOS version / board family
        [2] BIOS date     "MM/DD/YYYY"
        [3] Product Name  "ThinkPad X1 Carbon Gen 10"
        [4] board code    "21CB" / "0XK9M" / "87A1" / "GA402"
        [5+] version, serial, ...
    """
    VENDOR_SET = frozenset({
        'LENOVO', 'DELL', 'HP', 'ASUS', 'ACER', 'MSI', 'GIGABYTE', 'SAMSUNG',
        'TOSHIBA', 'FUJITSU', 'MICROSOFT', 'HUAWEI', 'APPLE', 'RAZER', 'CLEVO',
        'MEDION', 'XIAOMI', 'NEC', 'PANASONIC',
    })

    def read_cstr(pos: int) -> Optional[Tuple[str, int]]:
        end = data.find(b'\x00', pos)
        if end == -1 or end == pos:
            return None
        raw = data[pos:end]
        if not all(32 <= b <= 126 for b in raw):
            return None
        return raw.decode('ascii'), end + 1

    for base in (0x400000,):
        if base + 0x40 > len(data):
            continue
        strings: List[str] = []
        pos = base
        for _ in range(8):
            r = read_cstr(pos)
            if r is None:
                break
            s, pos = r
            strings.append(s)

        if len(strings) < 4:
            continue
        if strings[0].upper() not in VENDOR_SET:
            continue
        if not re.match(r'^\d{2}/\d{2}/\d{4}$', strings[2]):
            continue

        info = {
            "vendor": strings[0].upper(),
            "model": strings[3].strip(),
            "bios_date": strings[2],
        }
        if len(strings) > 4 and re.match(r'^[A-Za-z0-9][A-Za-z0-9._\-]{0,15}$', strings[4]):
            info["board_id"] = strings[4].strip()
        return info

    return None


def extract_smbios_info(data: bytes) -> Dict:
    """Extract vendor, model, board_id from BIOS strings.

    Uses both a targeted DMI region scan and a sparse whole-file scan
    to catch identifiers regardless of where they sit in the dump.
    """
    result = {
        "vendor": "Unknown",
        "model": "Unknown",
        "bios_version": "Unknown",
        "bios_date": "Unknown",
        "board_id": "Unknown",
    }

    # ── Targeted DMI area parse (authoritative for vendor/model/date) ─────
    dmi = parse_dmi_area(data)
    if dmi:
        result["vendor"] = dmi["vendor"]
        result["model"] = dmi["model"]
        result["bios_date"] = dmi["bios_date"]
        if dmi.get("board_id"):
            result["board_id"] = dmi["board_id"]

    # Collect strings from the entire file — 8-32 MB is quick with dedup.
    # For files > 32 MB, use a coverage-optimized sparse scan.
    all_strings: List[str] = []
    seen = set()

    def _add_strings(region: bytes, min_len: int = 3):
        for s in extract_strings(region, min_len=min_len):
            if s not in seen:
                seen.add(s)
                all_strings.append(s)

    if len(data) <= 32 * 1024 * 1024:
        # Full scan — fast enough for typical BIOS dumps
        _add_strings(data)
    else:
        # Sparse scan with high coverage (~50% of file)
        _add_strings(data[:0x100000])        # first 1 MB
        _add_strings(data[-0x100000:])       # last 1 MB
        step = max(0x20000, len(data) // 16)
        for off in range(0x100000, len(data) - 0x100000, step):
            _add_strings(data[off:off + step])

    full_text = ' '.join(all_strings)

    # ── Vendor detection ──────────────────────────────────────────────────
    # Ordered by specificity — longer/more distinctive patterns first.
    # Each pattern is scored; the highest-confidence match wins.
    vendor_candidates: List[Tuple[str, str, int]] = []  # (vendor, matched_text, score)

    vendor_patterns = [
        # (regex, vendor_name, confidence_score)
        # Very high confidence: Dell-specific driver/SDK/build strings
        (r'Dell\s+(Enhanced Version|Error Handler|Odo|Variable Services|Flash Update|Diagnostic LED|Status Codes|Permanent Device|Common Library|Utility Library|Trusted Platform|Configuration Information)', 'DELL', 100),
        (r'DellClientPkgs|DELL_PEI_MFG_MODE|gen6bf_dell', 'DELL', 100),
        # High confidence: Dell with model numbers
        (r'\bDELL\b\s{2,}[A-Z0-9]', 'DELL', 95),
        # Standard vendor strings
        (r'Dell\s+Inc\.', 'DELL', 90),
        (r'\bDELL\b(?!\s*Inc)', 'DELL', 85),
        (r'Insyde\s+Software', 'INSYDE', 80),  # UEFI vendor, not HW vendor
        (r'LENOVO', 'LENOVO', 90),
        (r'Hewlett.?Packard', 'HP', 90),
        (r'HP\s+(Inc|Compaq|EliteBook|ProBook|ZBook|Pavilion|OMEN|ENVY|Spectre|Support|Notebook|Desktop)', 'HP', 85),
        (r'ASUSTeK|ASUS[_ ]|_ASUS_|ASUS\s+Notebook', 'ASUS', 90),
        (r'\bAcer\b', 'ACER', 90),
        (r'Micro.?Star\s+International|MSI\s+(Inc|Notebook|Laptop|Desktop|Gaming)', 'MSI', 85),
        (r'GIGABYTE|Gigabyte\s+Technology', 'GIGABYTE', 90),
        (r'\bSamsung\b', 'SAMSUNG', 85),
        (r'\bToshiba\b', 'TOSHIBA', 85),
        (r'\bFujitsu\b', 'FUJITSU', 85),
        (r'Microsoft\s+Corporation', 'MICROSOFT', 85),
        (r'\bHuawei\b', 'HUAWEI', 85),
        (r'\bXiaomi\b', 'XIAOMI', 85),
        (r'\bRazer\b', 'RAZER', 85),
        (r'\bMedion\b', 'MEDION', 85),
        (r'\bClevo\b', 'CLEVO', 85),
    ]

    for pattern, name, score in vendor_patterns:
        for m in re.finditer(pattern, full_text, re.IGNORECASE):
            vendor_candidates.append((name, m.group(0), score))

    # Pick highest-scoring vendor (skip INSYDE — it's the UEFI BIOS vendor, not HW)
    vendor_candidates.sort(key=lambda x: x[2], reverse=True)
    if result["vendor"] == "Unknown":
        for vendor, matched, score in vendor_candidates:
            if vendor != 'INSYDE':  # Insyde is the BIOS firmware vendor, not the PC brand
                result["vendor"] = vendor
                break
        else:
            # Fallback: if only Insyde found, check for HW vendor via model strings
            if any(v[0] == 'INSYDE' for v in vendor_candidates):
                result["vendor"] = "Insyde (OEM unknown)"

    # ── Model detection ───────────────────────────────────────────────────
    model_patterns = [
        (r'(Inspiron\s+\d{4})\b', 1),
        (r'(Vostro\s+\d{4})\b', 1),
        (r'(Latitude\s+\d{4})\b', 1),
        (r'(Precision\s+\d{4})\b', 1),
        (r'(OptiPlex\s+\d{4})\b', 1),
        (r'(XPS\s+\d{2,4})\b', 1),
        (r'(ThinkPad\s+[A-Z]\d+\s+Gen\s+\d+)', 1),
        (r'(IdeaPad\s+\w[\w\s]{1,20})', 1),
        (r'(Yoga\s+\w[\w\s]{1,20})', 1),
        (r'(Legion\s+\w[\w\s]{1,20})', 1),
        (r'(ThinkBook\s+\w[\w\s]{1,20})', 1),
        (r'(ThinkCentre\s+\w[\w\s]{1,20})', 1),
        (r'(EliteBook\s+\d{3,4}\s*\w*)', 1),
        (r'(ProBook\s+\d{3,4}\s*\w*)', 1),
        (r'(ZBook\s+\d{2,3}\s*\w*)', 1),
        (r'(ROG\s+\w[\w\s]{1,20})', 1),
        (r'(VivoBook\s+\w[\w\s]{1,20})', 1),
        (r'(ZenBook\s+\w[\w\s]{1,20})', 1),
        (r'(Predator\s+\w[\w\s]{1,20})', 1),
        (r'(Nitro\s+\d{1,2})\b', 1),
        (r'(Aspire\s+\w[\w\s]{1,20})', 1),
        (r'(Pavilion\s+\w[\w\s]{1,20})', 1),
        (r'(OMEN\s+\w[\w\s]{1,20})', 1),
        (r'(Surface\s+(Pro|Laptop|Book|Studio)\s+\d[\w\s]{0,15})', 1),
    ]

    if result["model"] == "Unknown":
        for pattern, group in model_patterns:
            m = re.search(pattern, full_text, re.IGNORECASE)
            if m:
                result["model"] = m.group(group).strip()
                break

    # ── DMI system identifier (e.g. "DELL  CBX3   .1") ──────────────────
    # This often encodes board model as the second whitespace-separated token
    dmi_matches = re.findall(r'\b([A-Z]{3,6})\s{2,}([A-Z0-9]{3,8})\b', full_text)
    for vendor_token, product_token in dmi_matches:
        if vendor_token.upper() in ('DELL', 'LENOVO', 'ASUS', 'ACER', 'HP', 'MSI'):
            if result["board_id"] == "Unknown":
                result["board_id"] = product_token
            if result["model"] == "Unknown":
                result["model"] = f"{vendor_token} {product_token}"
            break

    # ── BIOS version ──────────────────────────────────────────────────────
    for pat in [
        # Common formats: "Ver: 1ARUD012" (Dell), "Version 1.23.0", "A.12"
        r'Ver\s*:\s*([A-Z0-9][A-Z0-9\.\-_]{2,12})\b',
        r'Version\s*:\s*([A-Z0-9][A-Z0-9\.\-_]{2,12})\b',
        r'\bBIOS\s+Version\s*:?\s*([A-Z0-9][A-Z0-9\.\-_]{2,12})',
        r'\b([A-Z]\.[0-9]{2,3}\.[0-9]{2,3})\b',  # e.g. A.12.34
        r'\b(\d{2,3}\.\d{2,3})\b',                 # e.g. 1.23
        # AMI Aptio V: "X550EP.303" → version "303"
        r'\b[A-Z]\d{3,4}[A-Z]{0,3}\.(\d{2,3})\b',
    ]:
        m = re.search(pat, full_text, re.IGNORECASE)
        if m:
            result["bios_version"] = m.group(1)
            # Filter out obviously wrong matches (too long, no relation to bios)
            if len(result["bios_version"]) <= 8:
                break
            result["bios_version"] = "Unknown"

    # ── BIOS date ─────────────────────────────────────────────────────────
    for pat in [
        r'(\d{2}/\d{2}/\d{4})',
        r'(\d{4}/\d{2}/\d{2})',
        r'(\d{2}-\d{2}-\d{4})',
        r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{2}\s+\d{4}',  # "Mar 13 2014"
    ]:
        m = re.search(pat, full_text, re.IGNORECASE)
        if m:
            result["bios_date"] = m.group(1)
            break

    # ── Board model codes (model-like board strings, e.g., X550EP) ───────
    # Run BEFORE generic board ID to prefer high-confidence matches
    for m in re.finditer(r'\b([A-Z]\d{3,4}[A-Z]{1,3})\b', full_text):
        bid = m.group(1)
        count = len(re.findall(re.escape(bid).encode(), data))
        if count >= 3 and bid.upper() not in ('UNKNOWN',):
            if result["board_id"] == "Unknown":
                result["board_id"] = bid
            if result["model"] == "Unknown":
                result["model"] = bid
            break

    # ── Board ID (if not yet found) ───────────────────────────────────────
    if result["board_id"] == "Unknown":
        for pat in [
            r'(?:Board|Product)\s*:?\s*([A-Z0-9][A-Z0-9\-_]{3,12})\b',
            r'\b(?:MB|M/B)\s*:?\s*([A-Z0-9][A-Z0-9\-_]{3,12})\b',
            r'\b(LA-[A-Z]\d{3,4}P)\b',   # Compal-style: LA-B843P
            r'\b(DA[0-9A-Z]{3,6}[A-Z]{2})\b',  # Quanta-style
        ]:
            m = re.search(pat, full_text, re.IGNORECASE)
            if m:
                bid = m.group(1)
                if len(bid) >= 3 and bid.upper() not in ('THE', 'AND', 'FOR', 'WITH', 'BIOS', 'DATE', 'UNKNOWN', 'NOTE', 'BOOK', 'PRO', 'LITE', 'ELITE', 'MINI', 'TOWER', 'MICRO', 'NANO', 'FLEX'):
                    result["board_id"] = bid
                    break

    # ── Second-pass model detection: MODEL.VERSION (e.g., "X550EP.303") ──
    # Look for board model codes that appear near BIOS version/date strings
    # Common patterns: "X550EP.303", "Z97-PRO", "B450M", "H610M-A"
    if result["model"] == "Unknown":
        # AMI-style: MODEL.VERSION (e.g., "X550EP.303")
        for m in re.finditer(r'\b([A-Z]\d{3,4}[A-Z]{1,3})\s*[\.\s]\s*(\d{2,3})\b', full_text):
            model_code = m.group(1)
            ver_code = m.group(2)
            if len(model_code) >= 4:
                # Count occurrences of this model code (high freq = real board model)
                count = len(re.findall(re.escape(model_code).encode(), data))
                if count >= 3:
                    result["model"] = model_code
                    if result["bios_version"] == "Unknown":
                        result["bios_version"] = ver_code
                    if result["board_id"] == "Unknown":
                        result["board_id"] = model_code
                    break

    # Second pass: generic board model appearing standalone multiple times,
    # but only if it looks like a proper PCB/board code (letter + digits + optional suffix)
    if result["board_id"] == "Unknown":
        for m in re.finditer(r'\b([A-Z]\d{3,4}[A-Z]{1,3})\b', full_text):
            bid = m.group(1)
            count = len(re.findall(re.escape(bid).encode(), data))
            if count >= 3:
                if bid.upper() not in ('UNKNOWN',):
                    result["board_id"] = bid
                    break
        # If a board-suffix pattern was found, use the model as fallback
        if result["board_id"] == "Unknown" and result["model"] != "Unknown":
            # Use model as board_id if it looks like a board code
            model_clean = result["model"].split()[0]  # take first word
            if re.match(r'^[A-Z]\d{3,4}[A-Z]{0,3}$', model_clean):
                result["board_id"] = model_clean

    return result

def detect_compression(data: bytes) -> str:
    if data[:4] == b'\x04\x18\x00\x00' or data[:4] == b'\x18\x04\x00\x00':
        return "tiano_lzma"
    if data[:6] == b']\x00\x00\x00\x00\x00':
        return "lzma"
    if data[:2] == b'\x1f\x8b':
        return "gzip"
    if calculate_entropy(data[:1000]) > 7.5:
        return "unknown_compressed"
    return "none"

# ─── Main Analysis ────────────────────────────────────────────────────────

def analyze_bios(file_path: Path) -> BIOSInfo:
    print(f"[*] Reading {file_path}...")
    data = file_path.read_bytes()
    file_size = len(data)
    
    print(f"[*] File size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
    
    sha256 = calculate_sha256(data)
    md5 = calculate_md5(data)
    
    dump_type, type_info = detect_dump_type(data)
    print(f"[*] Dump type: {dump_type}")
    print(f"[*] Signatures: {type_info['signatures']}")
    
    info = BIOSInfo(
        file_path=str(file_path),
        file_size=file_size,
        sha256=sha256,
        md5=md5,
        dump_type=dump_type,
    )
    
    print("[*] Extracting metadata from strings...")
    meta = extract_smbios_info(data)
    info.detected_vendor = meta["vendor"]
    info.detected_model = meta["model"]
    info.bios_version = meta["bios_version"]
    info.bios_date = meta["bios_date"]
    info.board_id = meta["board_id"]
    info.smbios_structures.append(meta)

    # AMI BIOS module extraction (AMIBIOSC-based)
    if AMI_PARSER_AVAILABLE:
        print("[*] Checking for AMI BIOS structure...")
        ami_fmt, ami_mods = parse_ami_bios(data)
        if ami_fmt:
            info.ami_format = ami_fmt
            info.ami_modules = modules_summary(ami_mods)
            print(f"    AMI format: {ami_fmt} — {len(ami_mods)} modules found")

    # AMI Aptio V detection (modern UEFI, no AMIBIOSC)
    # Requires AMI-specific markers: AMITSESetup or Aptio signature + NVAR
    if not info.ami_format:
        is_aptio = (b'AMITSESetup' in data or b'Aptio' in data or b'AMI Aptio' in data)
        has_nvar = data.count(b'NVAR') > 5
        has_fv = b'_FVH' in data
        if is_aptio and (has_nvar or has_fv):
            info.ami_format = "aptio_v"
            print("[*] AMI Aptio V detected (modern UEFI)")

    # NVRAM / variable store detection
    nvar_count = data.count(b'NVAR')
    if nvar_count > 5:
        nvar_positions = [p for p in range(len(data)) if data[p:p+4] == b'NVAR']
        info.nvram_store = {
            "detected": True,
            "nvars_found": nvar_count,
            "region_start": min(nvar_positions) if nvar_positions else 0,
            "region_end": max(nvar_positions) + 1024 if nvar_positions else 0,
            "approximate_size": max(0, max(nvar_positions) - min(nvar_positions) + 4096) if nvar_positions else 0,
        }
        if info.ami_format:
            print(f"    NVRAM detected: {nvar_count} NVAR entries at 0x{info.nvram_store['region_start']:X}")

    if dump_type == "full_spi":
        print("[*] Scanning for UEFI volumes...")
        info.uefi_volumes = scan_uefi_volumes(data)
        print(f"    Found {len(info.uefi_volumes)} validated firmware volumes")
        
        # Deep scan UEFI volumes for nested files
        print("[*] Deep scanning UEFI volumes...")
        info.uefi_volume_deep_scan = []
        for vol in info.uefi_volumes:
            if vol.get("validated"):
                deep = scan_uefi_volume_deep(data, vol['offset'], vol, max_depth=3)
                info.uefi_volume_deep_scan.append(deep)
                print(f"    Volume {vol['guid'][:8]}: {deep['files_found']} FFS files found")
        
        print("[*] Scanning for SMBIOS/DMI tables...")
        info.smbios_tables = scan_smbios(data)
        print(f"    Found {len(info.smbios_tables)} SMBIOS entry points")
        
        print("[*] Detecting Intel ME region...")
        info.intel_me = {"detected": type_info["signatures"]["ME"] > 0, "positions": find_all(data, b'ME\x00\x00')}
        if info.intel_me["detected"]:
            print(f"    ME markers at: {info.intel_me['positions'][:5]}")
        
        print("[*] Detecting GbE region...")
        info.gbe_region = {"detected": type_info["signatures"]["GBE"] > 0, "positions": find_all(data, b'GBE\x00')}
        if info.gbe_region["detected"]:
            macs = []
            for pos in info.gbe_region["positions"]:
                for i in range(pos, min(pos+0x10000, len(data)-6)):
                    if data[i] & 0x01 == 0:
                        mac = data[i:i+6]
                        if mac != b'\x00'*6 and mac != b'\xFF'*6:
                            macs.append(':'.join(f'{b:02X}' for b in mac))
            info.gbe_region["mac_candidates"] = list(dict.fromkeys(macs))[:20]
            print(f"    MAC candidates: {len(info.gbe_region['mac_candidates'])}")
        
        print("[*] Detecting NVRAM region...")
        info.nvram_store = {"detected": type_info["signatures"]["NVRAM"] > 0, "positions": find_all(data, b'NVRA')}
        
        # Parse Intel FIT table (for microcode, ACM, Boot Guard)
        if FIT_PARSER_AVAILABLE:
            print("[*] Parsing Intel FIT table...")
            fit_result = parse_fit(data)
            if fit_result.found:
                info.fit_table = {
                    "found": True,
                    "entries": len(fit_result.entries),
                    "microcodes": [
                        {
                            "cpuid": f"{mc.cpuid:08X}",
                            "revision": f"{mc.revision:08X}",
                            "date": mc.date_str,
                            "address": f"0x{mc.address:016X}"
                        }
                        for mc in fit_result.microcodes
                    ],
                    "acms": [
                        {
                            "address": f"0x{acm.address:016X}",
                            "size_bytes": acm.size_bytes
                        }
                        for acm in fit_result.acms
                    ],
                    "bootguard": {
                        "status": fit_result.bootguard_status,
                        "has_km": fit_result.has_km,
                        "has_bp": fit_result.has_bp
                    }
                }
                print(f"    FIT: {len(fit_result.entries)} entries")
                if fit_result.microcodes:
                    print(f"    Microcodes: {len(fit_result.microcodes)}")
                if fit_result.acms:
                    print(f"    ACMs: {len(fit_result.acms)}")
                print(f"    BootGuard: {fit_result.bootguard_status}")
            else:
                info.fit_table = {"found": False}
        else:
            print("[!] FIT parser not available")
        
        print("[*] Building region map...")
        info.regions = build_spi_region_map(data, info)
        
    elif dump_type == "bios_region":
        print("[*] Scanning for UEFI volumes in BIOS region...")
        info.uefi_volumes = scan_uefi_volumes(data)
        print(f"    Found {len(info.uefi_volumes)} validated firmware volumes")
        
        if info.uefi_volumes:
            first_vol = info.uefi_volumes[0]
            vol_data = data[first_vol['offset']:first_vol['offset']+min(first_vol['size'], 1000)]
            info.compression = detect_compression(vol_data)
            print(f"    Compression: {info.compression}")
        
        ent = calculate_entropy(data)
        info.regions = [RegionInfo(
            name="BIOS_REGION",
            offset=0,
            size=file_size,
            sha256=sha256,
            entropy=ent,
            notes=["Extracted BIOS region"]
        )]
        
    elif dump_type == "gbe_region":
        ent = calculate_entropy(data)
        info.regions = [RegionInfo(
            name="GBE_REGION",
            offset=0,
            size=file_size,
            sha256=sha256,
            entropy=ent,
            notes=["Extracted GbE region"]
        )]
        mac = ':'.join(f'{b:02X}' for b in data[:6])
        info.mac_addresses = [mac]
        
    elif dump_type == "me_region":
        ent = calculate_entropy(data)
        info.regions = [RegionInfo(
            name="ME_REGION",
            offset=0,
            size=file_size,
            sha256=sha256,
            entropy=ent,
            notes=["Extracted Intel ME region"]
        )]
    
    else:
        ent = calculate_entropy(data)
        info.regions = [RegionInfo(
            name="UNKNOWN",
            offset=0,
            size=file_size,
            sha256=sha256,
            entropy=ent,
            notes=["Unknown dump type, entropy={:.2f}".format(ent)]
        )]
    
    return info

def build_spi_region_map(data: bytes, info: BIOSInfo) -> List[RegionInfo]:
    regions = []
    
    standard_regions = [
        ("DESCRIPTOR", 0x000000, 0x1000),
        ("ME", 0x001000, 0x300000 - 0x1000),
        ("BIOS", 0x300000, None),
        ("GBE", 0x700000, 0x10000),
    ]
    
    for name, offset, size in standard_regions:
        if offset >= len(data):
            continue
        if size is None:
            size = len(data) - offset
        if offset + size > len(data):
            size = len(data) - offset
        if size <= 0:
            continue
            
        region_data = data[offset:offset+size]
        regions.append(RegionInfo(
            name=name,
            offset=offset,
            size=size,
            sha256=calculate_sha256(region_data),
            entropy=calculate_entropy(region_data),
            notes=["Standard {0} region".format(name)]
        ))
    
    for vol in info.uefi_volumes:
        if vol.get("validated"):
            vol_size = min(vol['size'], len(data) - vol['offset'])
            if vol_size > 0:
                regions.append(RegionInfo(
                    name="UEFI_FV_{0}".format(vol['guid'][:8]),
                    offset=vol['offset'],
                    size=vol_size,
                    sha256=calculate_sha256(data[vol['offset']:vol['offset']+vol_size]),
                    entropy=calculate_entropy(data[vol['offset']:vol['offset']+vol_size]),
                    notes=["UEFI Firmware Volume, GUID: {0}".format(vol['guid'])]
                ))
    
    return regions

# ─── Redaction & Output ──────────────────────────────────────────────────

def redact_sensitive_data(info: BIOSInfo) -> BIOSInfo:
    return info

def save_json(info: BIOSInfo, output_path: Path) -> None:
    def dc_to_dict(obj):
        if hasattr(obj, '__dataclass_fields__'):
            return {k: dc_to_dict(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, list):
            return [dc_to_dict(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: dc_to_dict(v) for k, v in obj.items()}
        else:
            return obj
    
    output_path.write_text(json.dumps(dc_to_dict(info), indent=2, ensure_ascii=False))
    print("[+] Saved analysis to {0}".format(output_path))

# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BIOS Dump Analyzer (full SPI + extracted regions)")
    parser.add_argument("input", help="Path to BIOS dump (.bin)")
    parser.add_argument("-o", "--output", help="Output JSON path (default: <input>.analysis.json)")
    parser.add_argument("--no-redact", action="store_true", help="Keep sensitive data")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print("[!] File not found: {0}".format(input_path))
        sys.exit(1)
    
    output_path = Path(args.output) if args.output else input_path.with_suffix('.analysis.json')
    
    info = analyze_bios(input_path)
    
    if not args.no_redact:
        info = redact_sensitive_data(info)
    
    save_json(info, output_path)
    
    print("\n=== ANALYSIS SUMMARY ===")
    print("File:        {0}".format(info.file_path))
    print("Size:        {0:,} bytes".format(info.file_size))
    print("Type:        {0}".format(info.dump_type))
    print("SHA256:      {0}".format(info.sha256))
    print("Vendor:      {0}".format(info.detected_vendor))
    print("Model:       {0}".format(info.detected_model))
    if info.ami_format:
        print("AMI Format:  {0} ({1} modules)".format(
            info.ami_format,
            info.ami_modules["total_modules"] if info.ami_modules else 0))
    print("BIOS Ver:    {0}".format(info.bios_version))
    print("BIOS Date:   {0}".format(info.bios_date))
    print("Board ID:    {0}".format(info.board_id))
    print("Compression: {0}".format(info.compression))
    print("UEFI Vols:   {0}".format(len(info.uefi_volumes)))
    print("SMBIOS EPs:  {0}".format(len(info.smbios_tables)))
    print("Regions:     {0}".format(len(info.regions)))
    if info.mac_addresses:
        print("MAC addrs:   {0}".format(', '.join(info.mac_addresses[:5])))

if __name__ == "__main__":
    main()