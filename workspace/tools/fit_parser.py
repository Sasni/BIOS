#!/usr/bin/env python3
"""
Intel Firmware Interface Table (FIT) Parser
Based on UEFIExtract's FIT parser implementation.
Parses Intel FIT from firmware images for microcode, ACM, Boot Guard detection.
"""

import struct
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
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
        """Convert BCD date to MM/DD/YYYY.

        Intel microcode date field is packed BCD:
          bits 31:24 — month   (BCD byte,   0x01–0x12)
          bits 23:16 — day     (BCD byte,   0x01–0x31)
          bits 15:0  — year    (BCD 2-byte, 0x0001–0x9999)

        Each nibble carries a decimal digit 0–9, NOT a hex digit.
        We convert BCD → int before formatting to avoid the (mostly
        coincidental) appearance of correctness that raw hex formatting
        would produce.
        """
        def _bcd_byte(b: int) -> int:
            return ((b >> 4) & 0xF) * 10 + (b & 0xF)

        def _bcd_word(w: int) -> int:
            return (_bcd_byte((w >> 8) & 0xFF) * 100 +
                    _bcd_byte(w & 0xFF))

        mm = _bcd_byte((self.date_bcd >> 24) & 0xFF)
        dd = _bcd_byte((self.date_bcd >> 16) & 0xFF)
        yyyy = _bcd_word(self.date_bcd & 0xFFFF)
        return f"{mm:02d}/{dd:02d}/{yyyy:04d}"

@dataclass
class AcmInfo:
    address: int
    size_bytes: int

@dataclass
class FitResult:
    """Complete FIT parsing result"""
    found: bool = False
    header: Optional[FitEntry] = None
    entries: List[FitEntry] = field(default_factory=list)
    microcodes: List[MicrocodeInfo] = field(default_factory=list)
    acms: List[AcmInfo] = field(default_factory=list)
    has_km: bool = False
    has_bp: bool = False
    bootguard_status: str = "not_detected"
    bg_entries_present: bool = False  # FIT entries exist (may be empty placeholders)
    summary: str = ""

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
    # ── Resolve base_address ──────────────────────────────────────────────────

    explicit_base = base_address is not None

    if base_address is None:
        # Auto-detect: try standard SPI mapping first, then linear dump.
        bases = [0x100000000 - len(data), 0]
        candidates = []
        for b in bases:
            ib = b
            ie = b + len(data)
            if ib <= fit_phys < ie:
                fo = fit_phys - ib
                if fo + 16 <= len(data):
                    sig_check = struct.unpack_from('<Q', data, fo)[0]
                    if sig_check == FIT_SIGNATURE:
                        candidates.append((b, fo))
        if candidates:
            base_address, fit_offset = candidates[0]
        elif fit_phys < len(data):
            base_address = 0
            fit_offset = fit_phys
        else:
            return result

    # ── Compute image window from the resolved base ──────────────────────────
    #
    # IMPORTANT:  image_base / image_end are set from the WINNING
    # base_address, NOT from whatever the auto-detect loop left in its
    # last iteration.  The loop iterates over candidates; the last one
    # tried may have been rejected — using its values would silently
    # skip microcode / ACM parsing below.

    assert base_address is not None, "base_address must be resolved by now"
    image_base: int = base_address
    image_end: int = base_address + len(data)

    # For explicit (user-supplied) base, validate that the FIT pointer
    # actually falls within the claimed window.
    if explicit_base:
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
                # Microcode header needs at least offset 0x20 for Total Size.
                # Read up to 64 bytes — header is typically 48–64 bytes.
                if mc_offset + 64 <= len(data):
                    mc_data = data[mc_offset:mc_offset + 64]
                elif mc_offset + 16 <= len(data):
                    mc_data = data[mc_offset:mc_offset + 16]
                else:
                    mc_data = b''

                if len(mc_data) >= 16:
                    # Intel microcode header layout:
                    #   +0  HeaderVersion (4)
                    #   +4  UpdateRevision (4)
                    #   +8  Date BCD (4)
                    #   +12 Processor CPUID (4)
                    #   +16 Checksum (4)
                    #   +20 LoaderRevision (4)
                    #   +24 PlatformID (4)
                    #   +28 DataSize (4)  — size of encrypted data
                    #   +32 TotalSize (4) — total microcode update size
                    rev = struct.unpack_from('<I', mc_data, 4)[0]
                    date = struct.unpack_from('<I', mc_data, 8)[0]
                    cpuid = struct.unpack_from('<I', mc_data, 12)[0]
                    total_size = struct.unpack_from('<I', mc_data, 32)[0] if len(mc_data) > 32 else 0
                else:
                    rev, date, cpuid, total_size = 0, 0, 0, 0

                result.microcodes.append(MicrocodeInfo(
                    cpuid=cpuid,
                    revision=rev,
                    date_bcd=date,
                    address=mc_phys,
                    size=total_size,  # from microcode header offset 0x20
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
            # Try to validate the Key Manifest structure at the entry address.
            # A valid KM starts with a non-zero tag/version — all-FF or
            # all-zero means the FIT entry exists but KM was never provisioned.
            km_phys = entry.address
            if image_base <= km_phys < image_end:
                km_off = km_phys - image_base
                if km_off + 8 <= len(data):
                    km_tag = struct.unpack_from('<I', data, km_off)[0]
                    if km_tag not in (0, 0xFFFFFFFF):
                        has_km = True
                    else:
                        has_km = False  # placeholder entry, not real

        elif tcode == FitType.BP:
            has_bp = True
            bp_phys = entry.address
            if image_base <= bp_phys < image_end:
                bp_off = bp_phys - image_base
                if bp_off + 8 <= len(data):
                    bp_tag = struct.unpack_from('<I', data, bp_off)[0]
                    if bp_tag not in (0, 0xFFFFFFFF):
                        has_bp = True
                    else:
                        has_bp = False

    result.has_km = has_km
    result.has_bp = has_bp

    # ══════════════════════════════════════════════════════════════════════
    # Boot Guard status determination.
    #
    # CAVEAT:  FIT entry presence alone does NOT mean Boot Guard is active.
    # The KM/BP structures can exist as empty placeholders (all FFs/zeros).
    # Even with valid structures, the final determination requires reading
    # PCH Field Programmable Fuses (FPF) — which is impossible from a SPI
    # dump alone.
    #
    # Values:
    #   structures_found — valid KM + BP headers at FIT addresses
    #   entries_present  — FIT entries exist but structures are empty
    #   partial          — only one of KM/BP has a valid structure
    #   not_detected     — no KM/BP FIT entries at all
    # ══════════════════════════════════════════════════════════════════════
    if has_km and has_bp:
        result.bootguard_status = "structures_found"
    elif has_km or has_bp:
        result.bootguard_status = "partial"
    else:
        result.bootguard_status = "not_detected"

    # Separate flag: were FIT entries present (even if empty)?
    result.bg_entries_present = has_km or has_bp
    
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

# ─── JSON serialization ────────────────────────────────────────────────────

def _result_to_dict(result: FitResult) -> dict:
    """Convert FitResult to a JSON-serializable dict for the GUI."""
    return {
        "found": result.found,
        "entries_count": len(result.entries),
        "entries": [
            {
                "index": i,
                "address": e.address,
                "size": e.size & 0x00FFFFFF,
                "version": e.version,
                "type_code": e.type_code,
                "type_name": FitType(e.type_code).name if e.type_code in FitType._value2member_map_ else f"0x{e.type_code:02X}",
                "checksum_valid": e.checksum_valid,
            }
            for i, e in enumerate(result.entries)
        ],
        "microcodes": [
            {
                "cpuid": f"0x{mc.cpuid:08X}",
                "revision": f"0x{mc.revision:08X}",
                "date": mc.date_str,
                "address": f"0x{mc.address:016X}",
                "size": mc.size,
                "size_formatted": f"{mc.size:,}B" if mc.size else "?",
            }
            for mc in result.microcodes
        ],
        "acms": [
            {
                "address": f"0x{acm.address:016X}",
                "size_bytes": acm.size_bytes,
            }
            for acm in result.acms
        ],
        "bootguard": {
            "status": result.bootguard_status,
            "has_km": result.has_km,
            "has_bp": result.has_bp,
            "entries_present": result.bg_entries_present,
            "needs_fpf_check": result.bootguard_status == "structures_found",
        },
        "summary": result.summary,
    }


# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    import argparse
    from pathlib import Path
    
    parser = argparse.ArgumentParser(description="Intel FIT Table Parser")
    parser.add_argument("input", help="Firmware image file (.bin/.rom)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="Output as JSON (for GUI)")
    parser.add_argument("--base", type=lambda x: int(x, 0), default=None,
                       help="Base physical address (default: auto-detect 4GB mapping)")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        return 1

    data = input_path.read_bytes()

    if args.json:
        import json as _json
        result = parse_fit(data, args.base)
        out = _result_to_dict(result)
        out["file"] = str(input_path)
        out["file_size"] = len(data)
        print(_json.dumps(out, indent=2, default=str))
        return 0 if result.found else 1

    print(f"[*] Parsing FIT from {input_path} ({len(data):,} bytes)")

    result = parse_fit(data, args.base)
    
    if not result.found:
        print("[!] No valid FIT found")
        return 1
    
    print(f"\n=== Intel FIT ({len(result.entries)} entries) ===")
    
    if result.microcodes:
        print(f"\nMicrocodes ({len(result.microcodes)}):")
        for mc in result.microcodes:
            sz = f"{mc.size:,}B" if mc.size else "?"
            print(f"  CPUID={mc.cpuid:08X}  Rev={mc.revision:08X}  "
                  f"Date={mc.date_str}  Size={sz}  @0x{mc.address:016X}")
    
    if result.acms:
        print(f"\nStartup ACMs ({len(result.acms)}):")
        for acm in result.acms:
            print(f"  @0x{acm.address:016X}  size={acm.size_bytes:,} bytes")
    
    print(f"\nBoot Guard: {result.bootguard_status.upper()}")
    if result.has_km:
        print("  Key Manifest: valid structure")
    if result.has_bp:
        print("  Boot Policy:  valid structure")
    if result.bg_entries_present and not (result.has_km and result.has_bp):
        print("  (!) FIT entries exist but structures are empty/placeholder")
    if result.bootguard_status == "structures_found":
        print("  (!) Final status requires PCH fuse check — see FPF registers")
    
    # Print all entries
    if args.verbose:
        print("\nAll FIT entries:")
        for i, e in enumerate(result.entries):
            type_name = FitType(e.type_code).name if e.type_code in FitType._value2member_map_ else f"0x{e.type_code:02X}"
            print(f"  [{i:2d}] Type={type_name:12s}  Addr=0x{e.address:016X}  Size={e.size}  Ver={e.version}")

if __name__ == "__main__":
    main()