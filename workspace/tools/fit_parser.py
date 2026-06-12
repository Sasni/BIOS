#!/usr/bin/env python3
"""
Intel Firmware Interface Table (FIT) Parser
Based on UEFIExtract's FIT parser implementation.
Parses Intel FIT from firmware images for microcode, ACM, Boot Guard detection.
"""

import struct
import warnings
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import IntEnum

# FIT Entry structure (16 bytes)
FIT_ENTRY_SIZE = 16
FIT_SIGNATURE = 0x2020205F5449465F  # "_FIT_   "

# Intel Flash Descriptor (IFD) constants
FLVALSIG = 0x0FF0A55A               # Flash Valid Signature at SPI offset 0x10
IFD_FCBA_OFFSET = 0x30              # FCBA field: SPI offset (descriptor +0x20)
IFD_FRBA_OFFSET = 0x34              # FRBA field: SPI offset (descriptor +0x24)
FLREG_BASE_SHIFT = 16               # FLREGx: limit in bits [30:16] (shift right by 16)
FLREG_MASK = 0x7FFF                 # 15-bit base/limit mask (bits [14:0], up to 128 MB)
IFD_MAX_SECTION_OFFSET = 0x1000     # Descriptor occupies first 4 KB of SPI

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

def parse_flash_descriptor(data: bytes) -> Optional[int]:
    """Parse Intel Flash Descriptor to determine physical base address.

    Detects the IFD via FLVALSIG (0x0FF0A55A) at SPI offset 0x10,
    validates the descriptor map and region table consistency, then
    computes the physical base address of ``data[0]`` under the standard
    top-of-4GB SPI mapping.

    Returns None if the IFD is absent, inconsistent, or contains
    invalid BIOS region data.
    """

    # Minimum size: FLVALSIG at 0x10 + descriptor map + region table
    if len(data) < 0x54:
        return None

    # ── 1) Detect IFD: FLVALSIG at offset 0x10 ───────────────────────────
    #    Offset 0x00–0x0F is reserved (EC pointer on newer platforms).
    #    No signature check at offset 0x00 — only FLVALSIG identifies the IFD.
    if struct.unpack_from('<I', data, 0x10)[0] != FLVALSIG:
        return None

    # ── 2) Read section base addresses from descriptor map ───────────────
    #    FCBA  at SPI 0x30  — Flash Component Base Address
    #    FRBA  at SPI 0x34  — Flash Region Base Address
    #    FMBA  at SPI 0x38  — Flash Master Base Address
    #    FISBA at SPI 0x3C  — ICH Strap Base Address
    #    FMSBA at SPI 0x40  — MCH Strap Base Address
    #
    #    Each is a 32-bit field. The low 8 bits carry the section offset
    #    in 4-byte increments from the descriptor base (SPI 0x00).

    def _read_section_offset(offset: int) -> int:
        """Read a section base address field and return byte offset in SPI."""
        raw = struct.unpack_from('<I', data, offset)[0]
        return (raw & 0xFF) * 4

    fcba  = _read_section_offset(IFD_FCBA_OFFSET)
    frba  = _read_section_offset(IFD_FRBA_OFFSET)
    fmba  = _read_section_offset(0x38)
    fisba = _read_section_offset(0x3C)
    fmsba = _read_section_offset(0x40)

    # ── 3) Validate section offsets ──────────────────────────────────────
    #    All sections must lie within the first 4 KB (the descriptor page).
    #    Offsets should be ordered sensibly and not overlap wildly.
    sections = {
        "FCBA": fcba, "FRBA": frba, "FMBA": fmba,
        "FISBA": fisba, "FMSBA": fmsba,
    }
    for name, off in sections.items():
        if off == 0:
            # Zero offset for optional sections (FMBA, FISBA, FMSBA) is OK;
            # but FCBA and FRBA are mandatory.
            if name in ("FCBA", "FRBA"):
                return None
        elif not (0x30 <= off < IFD_MAX_SECTION_OFFSET):
            return None

    # Ensure region table doesn't overflow the descriptor
    if frba + 4 > IFD_MAX_SECTION_OFFSET:
        return None

    # ── 4) Read all region descriptors (FLREG0–FLREGn) ───────────────────
    #    Typical count: 4 regions (BIOS, ME, GbE, PDR)
    #    We read up to 8 to be future-proof.
    #    Unprogrammed slots contain 0x00000000 or 0xFFFFFFFF.
    _UNPROGRAMMED = {0x00000000, 0xFFFFFFFF}
    regions: List[tuple] = []
    for i in range(8):
        reg_off = frba + i * 4
        if reg_off + 4 > min(len(data), IFD_MAX_SECTION_OFFSET):
            break
        flreg = struct.unpack_from('<I', data, reg_off)[0]
        if flreg in _UNPROGRAMMED:
            regions.append((0, 0))  # unpopulated sentinel
            continue
        # FLREGx layout per Intel spec:
        #   bits [14:0]  = Region Base  (4 KB units)
        #   bits [30:16] = Region Limit (4 KB units)
        base_4k  = flreg & FLREG_MASK
        limit_4k = (flreg >> FLREG_BASE_SHIFT) & FLREG_MASK
        regions.append((base_4k, limit_4k))

    # ── 5) Validate BIOS region (FLREG0) — the only region we require ────
    if len(regions) == 0:
        return None

    bios_base_4k, bios_limit_4k = regions[0]
    if bios_base_4k == 0 and bios_limit_4k == 0:
        return None  # BIOS region not defined
    if bios_base_4k > bios_limit_4k:
        return None  # BIOS region has negative size
    bios_end = (bios_limit_4k + 1) * 4096
    if bios_end > 0x1_0000_0000:
        return None  # exceeds 4 GB address space

    # ── 6) Soft-validate remaining regions (warn, don't reject) ──────────
    for i, (base, limit) in enumerate(regions):
        if base == 0 and limit == 0:
            continue  # unpopulated
        if base > limit:
            warnings.warn(
                f"IFD FLREG{i}: base (0x{base:04X}) > limit (0x{limit:04X}); "
                f"region skipped"
            )
            continue
        r_start = base * 4096
        r_end   = (limit + 1) * 4096
        if r_end > 0x1_0000_0000:
            warnings.warn(
                f"IFD FLREG{i}: region extends beyond 4 GB; skipped"
            )
            continue
        # Check for overlap with preceding populated regions
        for j in range(i):
            pb, pl = regions[j]
            if pb == 0 and pl == 0:
                continue
            p_start = pb * 4096
            p_end   = (pl + 1) * 4096
            if r_start < p_end and p_start < r_end:
                warnings.warn(
                    f"IFD FLREG{i} overlaps FLREG{j}: "
                    f"[0x{r_start:08X}–0x{r_end:08X}] vs "
                    f"[0x{p_start:08X}–0x{p_end:08X}]"
                )

    # ── 7) Compute physical base ─────────────────────────────────────────
    #    The IFD is only present in full-SPI dumps, so len(data) IS the
    #    flash size.  The Flash Descriptor tells us where the BIOS region
    #    lives within SPI, but NOT the total flash size — deriving flash
    #    size from bios_end alone would be wrong (GbE/PDR may follow BIOS).
    #
    #    Cross-validate: if the BIOS region extends beyond len(data), the
    #    dump is truncated; use the maximum region end across ALL regions
    #    as a safer lower bound.
    max_region_end = bios_end
    for base, limit in regions[1:]:
        if base == 0 and limit == 0:
            continue
        region_end = (limit + 1) * 4096
        if region_end > max_region_end:
            max_region_end = region_end

    if max_region_end > len(data):
        warnings.warn(
            f"IFD regions extend beyond image end "
            f"(0x{max_region_end:X} > 0x{len(data):X}); "
            f"dump may be truncated, using region limit as lower bound"
        )

    flash_size = max(len(data), max_region_end)
    physical_base = 0x1_0000_0000 - flash_size

    return physical_base


def parse_fit(data: bytes, base_address: int | None = None) -> FitResult:
    """
    Parse Intel FIT from firmware image.

    The FIT is located in the last 4KB of the 4GB address space.
    In a firmware dump, the FIT pointer is at offset (size - 0x40).

    Args:
        data: Firmware image bytes.
        base_address: Base physical address where image is mapped.
            None (default): auto-detect — tries in order:
            1. Parse the Intel Flash Descriptor (IFD) at offset 0x10 to
               read the BIOS region base/limit from FLREG0.  Works for
               full-SPI dumps (8–64 MB) on all platforms.
            2. Assume standard SPI mapping at top of 4 GB
               (base = 4 GB - image_size).  Correct for most full-SPI
               dumps.
            3. Fall back to base = 0 (linear dump).

    Limitations:
        The IFD-based detection (method 1) requires a full-SPI dump that
        includes the Flash Descriptor at the beginning of the image.
        BIOS-region-only dumps do not contain the IFD and fall through
        to methods 2/3, which may produce an incorrect base.  For those,
        pass an explicit ``--base``.
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

    # ── Resolve base_address ──────────────────────────────────────────────────

    explicit_base = base_address is not None

    if base_address is None:
        # Phase 1: Try Intel Flash Descriptor (IFD) — precise for full-SPI dumps
        ifd_base = parse_flash_descriptor(data)
        if ifd_base is not None:
            if ifd_base <= fit_phys < ifd_base + len(data):
                base_address = ifd_base
                fit_offset = fit_phys - ifd_base
            # else: IFD base doesn't contain FIT pointer — fall through to Phase 2

    if base_address is None:
        # Phase 2: Try standard heuristics
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
    
    # ── Boot Guard tracking ──────────────────────────────────────────────
    # Separate "entry present" from "structure valid" — a FIT entry can
    # exist as an empty placeholder (all FFs / zeros) while a different
    # entry of the same type holds valid data.  Final status depends on
    # the best entry of each type, not the last one seen.
    km_entry = False
    bp_entry = False
    km_valid = False  # at least one KM entry has valid structure
    bp_valid = False  # at least one BP entry has valid structure
    
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
            km_entry = True
            # Try to validate the Key Manifest structure at the entry address.
            # A valid KM starts with a non-zero tag/version — all-FF or
            # all-zero means the FIT entry exists but KM was never provisioned.
            km_phys = entry.address
            if image_base <= km_phys < image_end:
                km_off = km_phys - image_base
                if km_off + 8 <= len(data):
                    km_tag = struct.unpack_from('<I', data, km_off)[0]
                    if km_tag not in (0, 0xFFFFFFFF):
                        km_valid = True  # never reset: once valid, stays valid

        elif tcode == FitType.BP:
            bp_entry = True
            bp_phys = entry.address
            if image_base <= bp_phys < image_end:
                bp_off = bp_phys - image_base
                if bp_off + 8 <= len(data):
                    bp_tag = struct.unpack_from('<I', data, bp_off)[0]
                    if bp_tag not in (0, 0xFFFFFFFF):
                        bp_valid = True

    result.has_km = km_valid
    result.has_bp = bp_valid

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
    #   partial          — only one of KM/BP has a valid structure
    #   entries_present  — FIT entries exist but structures are empty
    #   not_detected     — no KM/BP FIT entries at all
    # ══════════════════════════════════════════════════════════════════════
    if km_valid and bp_valid:
        result.bootguard_status = "structures_found"
    elif km_valid or bp_valid:
        result.bootguard_status = "partial"
    elif km_entry or bp_entry:
        result.bootguard_status = "entries_present"
    else:
        result.bootguard_status = "not_detected"

    # Were FIT entries of type KM/BP present (even if empty placeholders)?
    result.bg_entries_present = km_entry or bp_entry
    
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
    ``parse_fit(data)`` (base_address=None) for new code — it uses
    Flash Descriptor (IFD) parsing for full-SPI dumps and falls back
    to heuristics for BIOS-region-only dumps.

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