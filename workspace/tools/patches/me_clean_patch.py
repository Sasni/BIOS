#!/usr/bin/env python3
"""
ME Clean Patch Template - Applies UBT2-style ME region clean to BIOS dump.
Based on real repair patterns from:
- Lenovo Legion stachurki (8MB BIOS region)
- Lenovo Legion stachurki2 (16MB full SPI)
- HP monika walczyk (8MB BIOS region)

Usage: python me_clean_patch.py <input.bin> <output.bin> [--spi-size 8|16]
"""

import sys
import struct
import hashlib
from pathlib import Path
from typing import List, Tuple, Optional

# ─── Configuration ────────────────────────────────────────────────────────

PATCH_NAME = "ME Clean Patch (UBT2-style)"
DESCRIPTION = "Erase ME region to clean state (0xFF) + update descriptor checksum"

# Patch operations: (offset, size, new_bytes_or_FILL, description)
# If new_bytes_or_FILL is "FILL_FF", fill with 0xFF
PATCHES_SPI_16MB: List[Tuple[int, int, str, str]] = [
    # Descriptor checksum at 0x4C (4 bytes) - will be recalculated
    # ME region erase: 0x003A61 to ~0x15279 (observed in stachurki2)
    (0x003A61, 0x11818, "FILL_FF", "Erase ME firmware to clean state"),
    # ME module structures at 0x2E020-0x2E638 (49 bytes each, repeated)
    (0x02E020, 0x618, "FILL_FF", "Erase ME module headers"),
    # Descriptor checksum update at 0x4C (4 bytes) - set to 0xFFFFFFFF placeholder
    (0x00004C, 4, b'\xFF\xFF\xFF\xFF', "Descriptor checksum placeholder"),
]

PATCHES_BIOS_8MB: List[Tuple[int, int, str, str]] = [
    # For extracted BIOS regions (no IFD), ME modules embedded at specific offsets
    # Lenovo Legion stachurki pattern: repeated 384/48-byte blocks
    # These are heuristic offsets - adjust per model!
    (0x004260, 384, "FILL_FF", "Erase ME module block 1"),
    (0x004428, 48, "FILL_FF", "Erase ME module block 2"),
    (0x00447C, 48, "FILL_FF", "Erase ME module block 3"),
    (0x004720, 48, "FILL_FF", "Erase ME module block 4"),
    # Large compressed sections rewritten - heuristic
    (0x005077, 3602, "REBUILD", "Rebuild compressed volume 1"),
    (0x005EB8, 2921, "REBUILD", "Rebuild compressed volume 2"),
    (0x006A38, 81344, "REBUILD", "Rebuild compressed volume 3"),
]

PATCHES_HP_8MB: List[Tuple[int, int, str, str]] = [
    # HP monika walczyk pattern
    # MFS Header init at 0x4008
    (0x004008, 875, b'MFS.>' + b'\x00'*870, "Write MFS header"),
    # ME modules at 0x22C020-0x22C428 (49 bytes each, ~16 modules)
    (0x022C020, 0x408, "FILL_FF", "Erase ME module array"),
    # ME firmware bulk at 0x260070-0x2AD08D
    (0x0260070, 0x4D01D, "FILL_FF", "Erase ME firmware region"),
    # BBL update at 0x201000
    (0x0201000, 528, "FILL_FF", "Clear BBL strings"),
]


# ─── Core Functions ──────────────────────────────────────────────────────

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def calculate_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def apply_patches(data: bytearray, patches: List[Tuple]) -> List[str]:
    """Apply patches to data. Returns list of applied descriptions."""
    applied = []
    for offset, size, new_bytes, desc in patches:
        if offset + size > len(data):
            applied.append(f"SKIP {desc}: offset 0x{offset:08X} + {size} exceeds file size")
            continue
        
        if new_bytes == "FILL_FF":
            data[offset:offset+size] = b'\xFF' * size
            applied.append(f"APPLIED: {desc} at 0x{offset:08X} ({size} bytes -> 0xFF)")
        elif new_bytes == "REBUILD":
            # Placeholder - would need actual volume rebuild logic
            applied.append(f"SKIP {desc}: REBUILD requires volume reconstruction")
        elif isinstance(new_bytes, bytes):
            if len(new_bytes) != size:
                applied.append(f"SKIP {desc}: byte length mismatch ({len(new_bytes)} != {size})")
                continue
            data[offset:offset+size] = new_bytes
            applied.append(f"APPLIED: {desc} at 0x{offset:08X} ({size} bytes)")
        else:
            applied.append(f"SKIP {desc}: unknown patch type {new_bytes}")
    
    return applied

def recalculate_descriptor_checksum(data: bytearray) -> None:
    """Recalculate Intel Flash Descriptor checksum at offset 0x4C.
    Descriptor is at 0x0, checksum covers first 0x4C bytes (excluding checksum itself)."""
    if len(data) < 0x50:
        return
    # Zero out checksum bytes
    data[0x4C] = 0
    data[0x4D] = 0
    # Calculate 16-bit sum
    checksum = sum(data[0x00:0x4C]) & 0xFFFF
    data[0x4C] = checksum & 0xFF
    data[0x4D] = (checksum >> 8) & 0xFF

def detect_dump_type(data: bytes) -> str:
    """Detect if 8MB (bios_region) or 16MB+ (full_spi)"""
    if len(data) >= 16 * 1024 * 1024:
        # Check for IFD at start
        if data[0:4] in (b'\x00\x00\x00\x00', b'IFD\x00'):
            return "full_spi"
    return "bios_region"

# ─── Main ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.bin> <output.bin> [--type 8|16|hp|auto]")
        print(f"  --type 8   : 8MB extracted BIOS region (Lenovo Legion)")
        print(f"  --type 16  : 16MB+ full SPI dump (Lenovo Legion stachurki2)")
        print(f"  --type hp  : 8MB HP BIOS region (monika walczyk)")
        print(f"  --type auto: Auto-detect (default)")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    
    patch_type = "auto"
    if "--type" in sys.argv:
        idx = sys.argv.index("--type")
        if idx + 1 < len(sys.argv):
            patch_type = sys.argv[idx + 1]
    
    if not input_path.exists():
        print(f"[!] Input not found: {input_path}")
        sys.exit(1)
    
    print(f"[*] {PATCH_NAME}")
    print(f"[*] Reading: {input_path}")
    
    data = bytearray(input_path.read_bytes())
    original_hash = calculate_sha256(data)
    print(f"[*] Original SHA256: {original_hash}")
    print(f"[*] File size: {len(data):,} bytes ({len(data)/1024/1024:.1f} MB)")
    
    # Auto-detect
    if patch_type == "auto":
        patch_type = detect_dump_type(data)
        print(f"[*] Auto-detected type: {patch_type}")
    
    # Select patches
    if patch_type == "16":
        patches = PATCHES_SPI_16MB
        print(f"[*] Using 16MB full SPI patches ({len(patches)} operations)")
    elif patch_type == "hp":
        patches = PATCHES_HP_8MB
        print(f"[*] Using HP 8MB patches ({len(patches)} operations)")
    else:
        patches = PATCHES_BIOS_8MB
        print(f"[*] Using generic 8MB BIOS region patches ({len(patches)} operations)")
    
    # Apply patches
    print(f"\n[*] Applying patches...")
    applied = apply_patches(data, patches)
    for msg in applied:
        print(f"  {msg}")
    
    # Recalculate descriptor checksum for full SPI
    if patch_type == "16":
        print(f"[*] Recalculating descriptor checksum...")
        recalculate_descriptor_checksum(data)
    
    new_hash = calculate_sha256(data)
    print(f"\n[*] New SHA256: {new_hash}")
    print(f"[*] Changed: {original_hash != new_hash}")
    
    if output_path.exists():
        print(f"[!] Output exists, overwriting: {output_path}")
    
    output_path.write_bytes(data)
    print(f"[+] Written: {output_path}")
    
    print(f"\n=== SUMMARY ===")
    print(f"Input:  {input_path} ({original_hash[:16]}...)")
    print(f"Output: {output_path} ({new_hash[:16]}...)")
    print(f"Size:   {len(data):,} bytes")

if __name__ == "__main__":
    main()