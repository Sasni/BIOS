#!/usr/bin/env python3
"""
BIOS Diff Tool - Compares two BIOS dumps (before/after repair) to find exact changes.
"""

import sys
import os
import json
import struct
import hashlib
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime

# ─── Data Classes ─────────────────────────────────────────────────────────

@dataclass
class DiffRegion:
    offset: int
    size: int
    original_hash: str
    modified_hash: str
    original_bytes: str  # hex sample
    modified_bytes: str  # hex sample
    description: str = ""

@dataclass
class DiffResult:
    file1: str
    file2: str
    file1_sha256: str
    file2_sha256: str
    total_size: int
    identical: bool
    diff_regions: List[DiffRegion] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

# ─── Utility Functions ────────────────────────────────────────────────────

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_file(path: Path) -> bytes:
    return path.read_bytes()

def find_diff_regions(data1: bytes, data2: bytes, min_region_size: int = 4, merge_distance: int = 16) -> List[Tuple[int, int]]:
    """Find contiguous regions where files differ."""
    if len(data1) != len(data2):
        raise ValueError("Files must be same size for diff")
    
    diffs = []
    in_diff = False
    diff_start = 0
    
    for i in range(len(data1)):
        if data1[i] != data2[i]:
            if not in_diff:
                in_diff = True
                diff_start = i
        else:
            if in_diff:
                in_diff = False
                if i - diff_start >= min_region_size:
                    diffs.append((diff_start, i))
    
    if in_diff and len(data1) - diff_start >= min_region_size:
        diffs.append((diff_start, len(data1)))
    
    # Merge nearby regions
    if not diffs:
        return []
    
    merged = [diffs[0]]
    for start, end in diffs[1:]:
        last_start, last_end = merged[-1]
        if start - last_end <= merge_distance:
            merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    
    return merged

def bytes_to_hex_sample(data: bytes, max_len: int = 32) -> str:
    """Convert bytes to hex string with truncation."""
    if len(data) <= max_len:
        return data.hex().upper()
    return data[:max_len//2].hex().upper() + "..." + data[-max_len//2:].hex().upper()

def describe_region(offset: int, size: int, data1: bytes, data2: bytes) -> str:
    """Attempt to describe what changed in a region."""
    descriptions = []
    
    # Check for known patterns
    region1 = data1[:min(size, 64)]
    region2 = data2[:min(size, 64)]
    
    # ASCII strings changed?
    str1 = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in region1)
    str2 = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in region2)
    
    if str1 != str2 and any(c != '.' for c in str1 + str2):
        descriptions.append(f"String change: '{str1.strip()}' -> '{str2.strip()}'")
    
    # All bytes changed to same value (fill/erase)?
    if len(set(data2[:size])) == 1:
        descriptions.append(f"Filled with 0x{data2[0]:02X}")
    
    # Counter/increment?
    if size >= 4:
        try:
            val1 = struct.unpack('<I', data1[:4])[0]
            val2 = struct.unpack('<I', data2[:4])[0]
            if val2 == val1 + 1:
                descriptions.append(f"Counter increment: {val1} -> {val2}")
        except:
            pass
    
    # Checksum/update?
    if size <= 8:
        descriptions.append("Possible checksum/update")
    
    return "; ".join(descriptions) if descriptions else "Binary data change"

# ─── Main Diff Logic ──────────────────────────────────────────────────────

def diff_bios(file1_path: Path, file2_path: Path, min_region_size: int = 4, merge_distance: int = 16) -> DiffResult:
    """Compare two BIOS files and return detailed diff."""
    print(f"[*] Reading {file1_path}...")
    data1 = read_file(file1_path)
    print(f"[*] Reading {file2_path}...")
    data2 = read_file(file2_path)
    
    if len(data1) != len(data2):
        print(f"[!] Size mismatch: {len(data1)} vs {len(data2)}")
        # Pad shorter with 0xFF (erased flash state)
        max_len = max(len(data1), len(data2))
        data1 = data1.ljust(max_len, b'\xFF')
        data2 = data2.ljust(max_len, b'\xFF')
    
    sha1 = calculate_sha256(data1)
    sha2 = calculate_sha256(data2)
    
    print(f"[*] File 1 SHA256: {sha1}")
    print(f"[*] File 2 SHA256: {sha2}")
    
    if sha1 == sha2:
        print("[*] Files are identical")
        return DiffResult(
            file1=str(file1_path),
            file2=str(file2_path),
            file1_sha256=sha1,
            file2_sha256=sha2,
            total_size=len(data1),
            identical=True,
            summary={"message": "Files are identical"}
        )
    
    print("[*] Finding differences...")
    diff_regions_raw = find_diff_regions(data1, data2, min_region_size, merge_distance)
    
    diff_regions = []
    total_changed_bytes = 0
    
    for offset, end in diff_regions_raw:
        size = end - offset
        total_changed_bytes += size
        
        orig_bytes = data1[offset:end]
        mod_bytes = data2[offset:end]
        
        desc = describe_region(offset, size, orig_bytes, mod_bytes)
        
        diff_regions.append(DiffRegion(
            offset=offset,
            size=size,
            original_hash=calculate_sha256(orig_bytes),
            modified_hash=calculate_sha256(mod_bytes),
            original_bytes=bytes_to_hex_sample(orig_bytes),
            modified_bytes=bytes_to_hex_sample(mod_bytes),
            description=desc
        ))
        
        print(f"    Offset 0x{offset:08X} ({offset:,}): {size:,} bytes - {desc}")
    
    result = DiffResult(
        file1=str(file1_path),
        file2=str(file2_path),
        file1_sha256=sha1,
        file2_sha256=sha2,
        total_size=len(data1),
        identical=False,
        diff_regions=diff_regions,
        summary={
            "total_diff_regions": len(diff_regions),
            "total_changed_bytes": total_changed_bytes,
            "change_percentage": round(total_changed_bytes / len(data1) * 100, 4)
        }
    )
    
    print(f"\n[*] Summary: {len(diff_regions)} regions, {total_changed_bytes:,} bytes changed ({result.summary['change_percentage']}%)")
    
    return result

def save_diff(result: DiffResult, output_path: Path) -> None:
    """Save diff result to JSON."""
    def dc_to_dict(obj):
        if hasattr(obj, '__dataclass_fields__'):
            return {k: dc_to_dict(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, list):
            return [dc_to_dict(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: dc_to_dict(v) for k, v in obj.items()}
        else:
            return obj
    
    output_path.write_text(json.dumps(dc_to_dict(result), indent=2, ensure_ascii=False))
    print(f"[+] Saved diff to {output_path}")

def generate_patch_script(result: DiffResult, output_path: Path) -> None:
    """Generate a Python script to apply the patch."""
    lines = [
        "#!/usr/bin/env python3",
        f"# Auto-generated patch script for {result.file1} -> {result.file2}",
        f"# Generated: {result.timestamp}",
        "",
        "import sys",
        "from pathlib import Path",
        "",
        "def apply_patch(input_path: Path, output_path: Path):",
        f"    data = bytearray(input_path.read_bytes())",
        ""
    ]
    
    for dr in result.diff_regions:
        mod_bytes = bytes.fromhex(dr.modified_bytes.replace("...", "").strip()) if "..." not in dr.modified_bytes else b""
        # For simplicity, we'll embed the full modified bytes
        lines.append(f"    # Offset 0x{dr.offset:08X}, size {dr.size}: {dr.description}")
        lines.append(f"    data[{dr.offset}:{dr.offset+dr.size}] = bytes.fromhex('{dr.modified_bytes.replace('...', '')}')")
    
    lines.extend([
        "",
        "    output_path.write_bytes(data)",
        "    print(f'Applied patch: {input_path} -> {output_path}')",
        "",
        "if __name__ == '__main__':",
        "    if len(sys.argv) != 3:",
        "        print('Usage: python patch.py <input.bin> <output.bin>')",
        "        sys.exit(1)",
        "    apply_patch(Path(sys.argv[1]), Path(sys.argv[2]))",
    ])
    
    output_path.write_text('\n'.join(lines))
    print(f"[+] Generated patch script: {output_path}")

# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Compare two BIOS dumps (before/after repair)")
    parser.add_argument("before", help="Original BIOS dump (before repair)")
    parser.add_argument("after", help="Modified BIOS dump (after repair)")
    parser.add_argument("-o", "--output", help="Output JSON path")
    parser.add_argument("--patch", help="Generate patch script path")
    parser.add_argument("--min-size", type=int, default=4, help="Minimum diff region size")
    parser.add_argument("--merge-dist", type=int, default=16, help="Merge nearby diffs within this distance")
    
    args = parser.parse_args()
    
    before_path = Path(args.before)
    after_path = Path(args.after)
    
    if not before_path.exists():
        print(f"[!] File not found: {before_path}")
        sys.exit(1)
    if not after_path.exists():
        print(f"[!] File not found: {after_path}")
        sys.exit(1)
    
    output_path = Path(args.output) if args.output else before_path.with_suffix('.diff.json')
    
    result = diff_bios(before_path, after_path, args.min_size, args.merge_dist)
    save_diff(result, output_path)
    
    if args.patch:
        generate_patch_script(result, Path(args.patch))

if __name__ == "__main__":
    main()