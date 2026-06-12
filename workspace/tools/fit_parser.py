#!/usr/bin/env python3
"""
Intel Firmware Interface Table (FIT) Parser
Based on UEFIExtract's FIT parser implementation.
Parses Intel FIT from firmware images for microcode, ACM, Boot Guard detection.
"""

import struct
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import IntEnum

# FIT Entry structure (16 bytes)
FIT_ENTRY_SIZE = 16
FIT_SIGNATURE = 0x2020205F5449465F  # "_FIT_   "

class FitType(IntEnum):
    HEADER = 0x00
    MICROCODE = 0x01
    ACM = 0x02  # Authenticated Code Module
    BIOS_SM = 0x07
    BIOS_SM2 = 0x08
    TPM = 0x0C
    KM = 0x10   # Boot Guard Key Manifest
    BP = 0x11   # Boot Guard Boot Policy

@dataclass
class FitEntry:
    address: int      # Physical address (or signature for header)
    size: int         # Size granules / entry count (24-bit)
    version: int      # FIT version
    type: int         # Type code (bit7=checksum valid, bits[6:0]=type)
    checksum: int
    
    @property
    def type_code(self) -> int:
        return self.type & 0x7F
    
    @property
    def checksum_valid(self) -> bool:
        return (self.type & 0x80) != 0
    
    @property
    def is_header(self) -> bool:
        return self.type_code == FitType.HEADER
    
    @property
    def entry_count(self) -> int:
        if self.is_header:
            return self.size & 0x00FFFFFF
        return 0

@dataclass
class MicrocodeInfo:
    cpuid: int
    revision: int
    date_bcd: int
    address: int
    size: int
    
    @property
    def date_str(self) -> str:
        """Convert BCD date to MM/DD/YYYY"""
        mm = (self.date_bcd >> 24) & 0xFF
        dd = (self.date_bcd >> 16) & 0xFF
        yyyy = self.date_bcd & 0xFFFF
        return f"{mm:02X}/{dd:02X}/{yyyy:04X}"

@dataclass
class AcmInfo:
    address: int
    size_bytes: int

@dataclass
class FitResult:
    """Complete FIT parsing result"""
    found: bool = False
    header: Optional[FitEntry] = None
    entries: List[FitEntry] = None
    microcodes: List[MicrocodeInfo] = None
    acms: List[AcmInfo] = None
    has_km: bool = False
    has_bp: bool = False
    bootguard_status: str = "not_detected"
    summary: str = ""
    
    def __post_init__(self):
        if self.entries is None:
            self.entries = []
        if self.microcodes is None:
            self.microcodes = []
        if self.acms is None:
            self.acms = []

def parse_fit(data: bytes, base_address: int | None = None) -> FitResult:
    """
    Parse Intel FIT from firmware image.

    The FIT is located in the last 4KB of the 4GB address space.
    In a firmware dump, the FIT pointer is at offset (size - 0x40).

    Args:
        data: Firmware image bytes
        base_address: Base physical address where image is mapped.
            None (default): auto-detect — tries standard SPI mapping
            (4GB - image_size) first, then falls back to 0 (linear dump).

    Limitations:
        Auto-detection uses ``base = 0x1_0000_0000 - len(data)`` which
        assumes the firmware image occupies the top of the 4 GB SPI address
        space.  This is correct for standard 8–16 MB SPI dumps (Haswell
        through Comet Lake), but can fail for:

        * 32+ MB images (Alder Lake+) where the Flash Descriptor may
          place the BIOS region at a different base.
        * Images that do NOT include the full SPI flash (e.g., BIOS-region-
          only dumps).  For those the 4 GB formula over-estimates the base
          and the FIT pointer falls outside the image.

        The proper long-term fix is to parse the Flash Descriptor (offset 0x10
        in the SPI image) to read the actual base addresses of each region
        (FLREG0–FLREGn).  Until then, pass an explicit ``--base`` for
        non‑standard dumps.
    """
    result = FitResult()

    if len(data) < 0x48:
        return result

    # FIT pointer is at offset (size - 0x40) - 64-bit physical address
    fit_ptr_offset = len(data) - 0x40
    fit_phys = struct.unpack_from('<Q', data, fit_ptr_offset)[0]

    # Reject obviously invalid FIT pointers
    if fit_phys == 0 or fit_phys == 0xFFFFFFFFFFFFFFFF:
        return result

    # Auto-detect base address if not provided.
    #
    # The standard SPI flash layout places the firmware at the top of the
    # 4 GB address space:  base = 0x1_0000_0000 - image_size.
    #
    # This works for 8 MB  (0xFF800000) and 16 MB (0xFF000000) dumps.
    # For newer platforms (32 MB → 0xFE000000) the Flash Descriptor may
    # remap regions — see the Limitations section in the docstring above.
    if base_address is None:
        bases = [0x100000000 - len(data), 0]
        candidates = []
        for b in bases:
            image_base = b
            image_end = b + len(data)
            if image_base <= fit_phys < image_end:
                fit_off = fit_phys - image_base
                if fit_off + 16 <= len(data):
                    # Quick sanity: check for FIT signature at candidate offset
                    sig_check = struct.unpack_from('<Q', data, fit_off)[0]
                    if sig_check == FIT_SIGNATURE:
                        candidates.append((b, fit_off))
        if candidates:
            base_address, fit_offset = candidates[0]
        elif fit_phys < len(data):
            # Fallback: treat fit_phys as a direct file offset (base=0)
            base_address = 0
            fit_offset = fit_phys
        else:
            return result
    else:
        # Image maps to physical [base_address, base_address + len(data))
        image_base = base_address
        image_end = base_address + len(data)

        if fit_phys < image_base or fit_phys >= image_end:
            return result

        fit_offset = fit_phys - image_base
        if fit_offset + 16 > len(data):
            return result

    # Parse header entry
    header_data = data[fit_offset:fit_offset + 16]
    address, size, version, ftype, checksum = struct.unpack('<QIHBB', header_data[:16])
    
    # Verify signature
    if address != FIT_SIGNATURE:
        return result
    if ftype & 0x7F != FitType.HEADER:
        return result
    
    entry_count = size & 0x00FFFFFF
    if entry_count == 0 or entry_count > 512:
        return result
    if fit_offset + entry_count * 16 > len(data):
        return result
    
    result.found = True
    result.header = FitEntry(
        address=address, size=size, version=version,
        type=ftype, checksum=checksum
    )
    
    has_km = False
    has_bp = False
    
    # Parse entries (skip header at index 0)
    for i in range(1, entry_count):
        entry_offset = fit_offset + i * 16
        entry_data = data[entry_offset:entry_offset + 16]
        addr, sz, ver, typ, chk = struct.unpack('<QIHBB', entry_data[:16])
        
        entry = FitEntry(
            address=addr, size=sz, version=ver,
            type=typ, checksum=chk
        )
        result.entries.append(entry)
        
        # Type-specific parsing
        tcode = entry.type_code
        
        if tcode == FitType.MICROCODE:
            # Intel microcode header at entry.address
            mc_phys = entry.address
            if image_base <= mc_phys < image_end:
                mc_offset = mc_phys - image_base
                if mc_offset + 16 <= len(data):
                    mc_data = data[mc_offset:mc_offset + 16]
                    # Microcode header: 4-byte header + rev(4) + date(4) + cpuid(4)
                    # Offset 4: revision, 8: date, 12: cpuid
                    rev = struct.unpack_from('<I', mc_data, 4)[0]
                    date = struct.unpack_from('<I', mc_data, 8)[0]
                    cpuid = struct.unpack_from('<I', mc_data, 12)[0]
                    
                    result.microcodes.append(MicrocodeInfo(
                        cpuid=cpuid,
                        revision=rev,
                        date_bcd=date,
                        address=mc_phys,
                        size=0  # Size not in FIT, would need to parse microcode header
                    ))
        
        elif tcode == FitType.ACM:
            # ACM size in 64-byte granules
            acm_bytes = (entry.size & 0x00FFFFFF) * 64
            result.acms.append(AcmInfo(
                address=entry.address,
                size_bytes=acm_bytes
            ))
        
        elif tcode == FitType.KM:
            has_km = True
        elif tcode == FitType.BP:
            has_bp = True
    
    result.has_km = has_km
    result.has_bp = has_bp
    
    if has_km and has_bp:
        result.bootguard_status = "enabled"
    elif has_km or has_bp:
        result.bootguard_status = "partial"
    else:
        result.bootguard_status = "not_detected"
    
    result.summary = (
        f"FIT: {len(result.entries)} entries, "
        f"{len(result.microcodes)} microcodes, "
        f"{len(result.acms)} ACMs, "
        f"BootGuard: {result.bootguard_status}"
    )
    return result

def parse_fit_legacy(data: bytes) -> FitResult:
    """Parse FIT with standard SPI mapping: base = 4 GB - image_size.

    Kept for backward compatibility.  Prefer the auto-detecting
    ``parse_fit(data)`` (base_address=None) for new code.

    Limitation:
        Assumes the image occupies the top of the 4 GB SPI address
        space.  Works for 8–16 MB dumps; may need an explicit base for
        32+ MB images (Alder Lake+) or BIOS-region-only dumps.
        See ``parse_fit`` docstring for details.
    """
    return parse_fit(data, 0x100000000 - len(data))

# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    import argparse
    from pathlib import Path
    
    parser = argparse.ArgumentParser(description="Intel FIT Table Parser")
    parser.add_argument("input", help="Firmware image file (.bin/.rom)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--base", type=lambda x: int(x, 0), default=None,
                       help="Base physical address (default: auto-detect 4GB mapping)")
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        return 1
    
    data = input_path.read_bytes()
    print(f"[*] Parsing FIT from {input_path} ({len(data):,} bytes)")
    
    result = parse_fit(data, args.base)
    
    if not result.found:
        print("[!] No valid FIT found")
        return 1
    
    print(f"\n=== Intel FIT ({len(result.entries)} entries) ===")
    
    if result.microcodes:
        print(f"\nMicrocodes ({len(result.microcodes)}):")
        for mc in result.microcodes:
            print(f"  CPUID={mc.cpuid:08X}  Rev={mc.revision:08X}  Date={mc.date_str}  @0x{mc.address:016X}")
    
    if result.acms:
        print(f"\nStartup ACMs ({len(result.acms)}):")
        for acm in result.acms:
            print(f"  @0x{acm.address:016X}  size={acm.size_bytes:,} bytes")
    
    print(f"\nBoot Guard: {result.bootguard_status.upper()}")
    if result.has_km:
        print("  Key Manifest: PRESENT")
    if result.has_bp:
        print("  Boot Policy: PRESENT")
    
    # Print all entries
    if args.verbose:
        print("\nAll FIT entries:")
        for i, e in enumerate(result.entries):
            type_name = FitType(e.type_code).name if e.type_code in FitType._value2member_map_ else f"0x{e.type_code:02X}"
            print(f"  [{i:2d}] Type={type_name:12s}  Addr=0x{e.address:016X}  Size={e.size}  Ver={e.version}")

if __name__ == "__main__":
    main()