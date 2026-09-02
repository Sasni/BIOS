#!/usr/bin/env python3
"""
Flash Descriptor Security Audit
Parses Intel Flash Descriptor (IFD) and audits SPI flash security
against NIST SP 800-147 §4.3 (Non-Bypassability).

Checks:
  - Master Access Table (who can write to BIOS region)
  - Descriptor lock status
  - Descriptor checksum integrity
  - Region layout and component info
"""

import struct
import sys
from pathlib import Path
from typing import Optional

from fit_parser import (
    audit_flash_descriptor,
    IfdSecurityReport,
    _ifd_report_to_dict,
)


def _format_masters(masters: list[int]) -> str:
    """Format master IDs to human-readable names."""
    names = {0: "None", 1: "CPU", 2: "ME", 3: "EC", 4: "GbE", 5: "IE"}
    return ", ".join(names.get(m, f"Master{m}") for m in masters) if masters else "None"


def _print_report(report: IfdSecurityReport, verbose: bool = False) -> None:
    """Print a human-readable IFD security audit report."""

    print(f"\n{'='*60}")
    print(f"  Intel Flash Descriptor Security Audit")
    print(f"{'='*60}")

    if report.status == "not_detected":
        print(f"\n  [!] IFD NOT DETECTED")
        print(f"  {report.summary}")
        return

    # Status badge
    status_labels = {
        "compliant":     "+ PASS — NIST 800-147 §4.3",
        "partial":       "~ PARTIAL — some protections missing",
        "non_compliant": "! FAIL — NIST 800-147 §4.3 non-bypassability violation",
    }
    label = status_labels.get(report.status, report.status)
    print(f"\n  Verdict: {label}")

    # ── Regions ──────────────────────────────────────────────────────────
    populated = [r for r in report.regions if r.is_populated]
    if populated:
        print(f"\n  ── SPI Regions ({len(populated)} defined) ──")
        for r in populated:
            print(f"  [{r.index}] {r.name:6s}  offset=0x{r.offset:08X}  size={r.size//1024:>5,} KB  "
                  f"(0x{r.size:X})")

    # ── Master Access ────────────────────────────────────────────────────
    if report.master_access:
        print(f"\n  ── Master Access Permissions ──")
        print(f"  {'Region':8s}  {'Read':30s}  {'Write':30s}")
        print(f"  {'-'*8}  {'-'*30}  {'-'*30}")
        for ma in report.master_access:
            read_str  = _format_masters(ma.read_masters)
            write_str = _format_masters(ma.write_masters)
            print(f"  {ma.region_name:8s}  {read_str:30s}  {write_str:30s}")

    # ── Components ───────────────────────────────────────────────────────
    if report.components:
        print(f"\n  ── Flash Components ──")
        for i, c in enumerate(report.components):
            print(f"  Component {i}: {c.density_mb} MB  ({c.number_of_components} chip(s) on bus)")

    # ── Security Details ─────────────────────────────────────────────────
    print(f"\n  ── Security Details ──")
    lock_icon = "+" if report.descriptor_locked else "!"
    print(f"  [{lock_icon}] Descriptor Locked:     {report.descriptor_locked}")
    chk_icon = "+" if report.descriptor_checksum_valid else "!"
    print(f"  [{chk_icon}] Descriptor Checksum:    {'Valid' if report.descriptor_checksum_valid else 'INVALID'}")

    me_icon  = "!" if report.bios_writable_by_me else "+"
    ec_icon  = "!" if report.bios_writable_by_ec else "+"
    print(f"  [{me_icon}] ME write to BIOS:        {'YES — VIOLATION' if report.bios_writable_by_me else 'No'}")
    print(f"  [{ec_icon}] EC write to BIOS:        {'YES — VIOLATION' if report.bios_writable_by_ec else 'No'}")

    bypass_icon = "+" if report.non_bypassability_pass else "!"
    print(f"  [{bypass_icon}] Non-Bypassability (§4.3): {'PASS' if report.non_bypassability_pass else 'FAIL'}")

    # ── Issues ───────────────────────────────────────────────────────────
    if report.issues:
        print(f"\n  ── Issues Found ──")
        for issue in report.issues:
            print(f"  ! {issue}")

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n  Summary: {report.summary}")
    print(f"  Flash size: {report.flash_size:,} bytes ({report.flash_size//(1024*1024)} MB)")
    if report.physical_base:
        print(f"  Physical base: 0x{report.physical_base:016X}")

    if verbose and report.status != "not_detected":
        print(f"\n  ── Raw Region Details ──")
        for r in report.regions:
            status = "populated" if r.is_populated else "empty"
            print(f"  [{r.index}] {r.name:6s}  base_4k=0x{r.base_4k:04X}  "
                  f"limit_4k=0x{r.limit_4k:04X}  {status}")

    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Intel Flash Descriptor Security Audit (NIST SP 800-147 §4.3)"
    )
    parser.add_argument("input", help="Firmware image file (.bin/.rom)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="Output as JSON (for GUI)")

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}", file=sys.stderr)
        return 1

    data = input_path.read_bytes()

    if args.json:
        import json as _json
        report = audit_flash_descriptor(data)
        out = _ifd_report_to_dict(report)
        out["file"] = str(input_path)
        out["file_size"] = len(data)
        print(_json.dumps(out, indent=2, default=str))
        return 0 if report.status != "not_detected" else 1

    print(f"[*] Flash Descriptor Security Audit")
    print(f"[*] File: {input_path} ({len(data):,} bytes)")

    report = audit_flash_descriptor(data)
    _print_report(report, verbose=args.verbose)

    if report.status == "not_detected":
        return 1
    elif report.status == "non_compliant":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
