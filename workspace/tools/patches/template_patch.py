#!/usr/bin/env python3
"""
Patch Template - Apply documented BIOS fix to a dump.
Copy this template and customize for each repair type.
"""

import sys
import struct
import hashlib
from pathlib import Path
from typing import List, Tuple

# ─── Configuration ────────────────────────────────────────────────────────

PATCH_NAME = "EXAMPLE: Lenovo ThinkPad T14 Gen 3 - KBC Unlock"
TARGET_MODEL = "ThinkPad T14 Gen 3"
TARGET_BOARD_ID = "21AJ"
TARGET_BIOS_VERSION = "1.23"

# Patches: (offset, original_bytes, new_bytes, description)
# original_bytes can be None (don't verify) or bytes/hex string
PATCHES: List[Tuple[int, bytes, bytes, str]] = [
    # Example patches - REPLACE WITH REAL ONES FROM diff_bios.py
    # (0x1A3000, b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF', "Clear password hash in NVRAM"),
    # (0x00400, b'\x00', b'\x01', "Set KBC unlock flag in EC RAM"),
]

# ─── Functions ────────────────────────────────────────────────────────────

def read_bin(path: Path) -> bytearray:
    return bytearray(path.read_bytes())

def write_bin(path: Path, data: bytearray) -> None:
    path.write_bytes(data)

def verify_original(data: bytearray, offset: int, expected: bytes) -> bool:
    """Verify original bytes match (safety check)."""
    if expected is None:
        return True
    actual = data[offset:offset+len(expected)]
    return actual == expected

def apply_patch(data: bytearray, offset: int, new_bytes: bytes, description: str) -> bool:
    """Apply a single patch."""
    if offset + len(new_bytes) > len(data):
        print(f"  [!] Patch at 0x{offset:08X} exceeds file size")
        return False
    
    print(f"  [+] Applying at 0x{offset:08X}: {description}")
    print(f"      Old: {data[offset:offset+len(new_bytes)].hex().upper()}")
    print(f"      New: {new_bytes.hex().upper()}")
    
    data[offset:offset+len(new_bytes)] = new_bytes
    return True

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ─── Main ─────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bin> <output.bin>")
        print(f"\nPatch: {PATCH_NAME}")
        print(f"Target: {TARGET_MODEL} ({TARGET_BOARD_ID}) BIOS {TARGET_BIOS_VERSION}")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    
    if not input_path.exists():
        print(f"[!] Input not found: {input_path}")
        sys.exit(1)
    
    print(f"[*] {PATCH_NAME}")
    print(f"[*] Reading: {input_path}")
    
    data = read_bin(input_path)
    original_hash = calculate_sha256(data)
    print(f"[*] Original SHA256: {original_hash}")
    print(f"[*] File size: {len(data):,} bytes")
    
    # Verify target model (optional safety check)
    # Could add SMBIOS parsing here to verify board ID
    
    # Apply patches
    print(f"\n[*] Applying {len(PATCHES)} patch(es)...")
    success_count = 0
    for offset, orig_bytes, new_bytes, desc in PATCHES:
        if verify_original(data, offset, orig_bytes):
            if apply_patch(data, offset, new_bytes, desc):
                success_count += 1
        else:
            actual = data[offset:offset+len(orig_bytes)].hex().upper() if orig_bytes else "N/A"
            expected = orig_bytes.hex().upper() if orig_bytes else "N/A"
            print(f"  [!] VERIFICATION FAILED at 0x{offset:08X}")
            print(f"      Expected: {expected}")
            print(f"      Actual:   {actual}")
            print(f"      Skipping patch: {desc}")
    
    if success_count == 0:
        print("\n[!] No patches applied. Aborting.")
        sys.exit(1)
    
    new_hash = calculate_sha256(data)
    print(f"\n[*] New SHA256: {new_hash}")
    print(f"[*] Patches applied: {success_count}/{len(PATCHES)}")
    
    if output_path.exists():
        print(f"[!] Output exists, overwriting: {output_path}")
    
    write_bin(output_path, data)
    print(f"[+] Written: {output_path}")
    
    # Print summary
    print(f"\n=== SUMMARY ===")
    print(f"Input:  {input_path} ({original_hash[:16]}...)")
    print(f"Output: {output_path} ({new_hash[:16]}...)")
    print(f"Size:   {len(data):,} bytes")
    print(f"Patches: {success_count} applied")

if __name__ == "__main__":
    main()