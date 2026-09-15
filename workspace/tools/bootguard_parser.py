#!/usr/bin/env python3
"""
Intel BootGuard Parser for SPI dumps.

Parses from a raw SPI image:
  - BootGuard ACM header (Authenticated Code Module)
  - Key Manifest (__KEYM__)
  - Boot Policy Manifest (__ACBP__ + __IBBS__ + __PMSG__ elements)
  - IBB hash computation (SHA1/256/384/512/SM3) over BPM IBB segments
  - AMI v2 protected-range hash file entries + verification

Address mapping: SPI image is mapped at top of 4GB (base = 0x1_0000_0000 - file_size).
Verified against LongSoft-style BootGuard parser output (Dell CBX3 / LA-C451P).
"""

import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

TAG_KEYM = b"__KEYM__"
TAG_ACBP = b"__ACBP__"

# AMI protected-range hash entry GUIDs (as stored, LE-mixed bytes)
AMI_PR_GUIDS = [
    bytes.fromhex("441fc9cbbca45b4a8696703451d0b053"),
    bytes.fromhex("0b8244fdabf1c041ae4e0c55556eb9bd"),
]

IBB_HASH_OFFSETS = [  # (name, hashlib name)
    ("SHA1", "sha1"),
    ("SHA256", "sha256"),
    ("SHA384", "sha384"),
    ("SHA512", "sha512"),
    ("SM3", "sm3"),
]


@dataclass
class AcmHeader:
    offset: int
    module_type: int
    module_subtype: int
    header_size: int
    header_version: int
    chipset_id: int
    flags: int
    module_vendor: int
    date: int
    module_size: int
    acm_svn: int
    ses_svn: int
    code_control_flags: int
    error_entry_point: int
    gdt_max: int
    gdt_base: int
    segment_sel: int
    entry_point: int
    key_size: int
    scratch_size: int


@dataclass
class ProtectedRange:
    guid_offset: int
    guid: bytes
    hash_stored: bytes
    address: int
    size: int
    hash_computed: str = ""
    match: bool = False


@dataclass
class BootGuardReport:
    file_size: int
    map_base: int = 0
    acm: AcmHeader | None = None
    km_offset: int = -1
    km: dict = field(default_factory=dict)
    bpm_offset: int = -1
    bpm: dict = field(default_factory=dict)
    ibb_hashes: dict = field(default_factory=dict)
    ibb_hash_match: bool = False
    protected_ranges: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def _bcd(b: int) -> int:
    return ((b >> 4) & 0xF) * 10 + (b & 0xF)


def _acm_date(raw: int) -> str:
    """ACM date u32 LE: byte0=day BCD, byte1=month BCD, u16 year BCD."""
    year_bcd = _bcd((raw >> 24) & 0xFF) * 100 + _bcd((raw >> 16) & 0xFF)
    return f"{_bcd(raw & 0xFF):02d}.{_bcd((raw >> 8) & 0xFF):02d}.{year_bcd:04d}"


def parse_acm_header(data: bytes, off: int) -> Optional[AcmHeader]:
    """ACM v3 header (BootGuard), fields per Intel ACM layout, verified vs
    LongSoft-style parser output (LA-C451P: HeaderSize 0x284 = 0xa1 words)."""
    if off + 0x68 > len(data):
        return None
    mt, ms = struct.unpack_from("<HH", data, off + 0)
    hs_words, hv, cid, fl = struct.unpack_from("<IIHH", data, off + 4)
    ven, dt = struct.unpack_from("<II", data, off + 16)
    msz_words, asvn, ssvn = struct.unpack_from("<IHH", data, off + 24)
    ccf, eep = struct.unpack_from("<II", data, off + 32)
    gmax, gbase = struct.unpack_from("<II", data, off + 40)
    ssel, _rsv = struct.unpack_from("<HH", data, off + 48)
    ep, _rsv2, ks, ss = struct.unpack_from("<IIII", data, off + 52)
    return AcmHeader(off, mt, ms, hs_words * 4, hv, cid, fl, ven,
                     _acm_date(dt), msz_words * 4, asvn, ssvn, ccf, eep,
                     gmax, gbase, ssel, ep, ks, ss)


def _digest(algo: str, blob: bytes) -> str | None:
    try:
        return hashlib.new(algo, blob).hexdigest().upper()
    except (ValueError, TypeError):
        return None


def parse_bpm(data: bytes, bpm_off: int, report: BootGuardReport) -> None:
    """Parse __ACBP__ BPM: header fields + __IBBS__ segments + IBB hashes."""
    bpm = data[bpm_off:bpm_off + 0x200]
    if not bpm.startswith(TAG_ACBP):
        return
    ver = bpm[8]
    rev = bpm[9]
    bpsvn = bpm[10]
    acmsvn = bpm[11]
    nem = struct.unpack_from("<H", bpm, 12)[0]
    d = {"version": f"{ver:02X}h", "bpm_revision": f"{rev:02X}h",
         "bpsvn": f"{bpsvn:02X}h", "acmsvn": f"{acmsvn:02X}h",
         "nem_data_size": f"{nem:04X}h"}
    i = bpm.find(b"__IBBS__")
    if i >= 0:
        ibbs = bpm[i:]
        flags = struct.unpack_from("<I", ibbs, 12)[0]
        mchbar = struct.unpack_from("<Q", ibbs, 16)[0]
        vtdbar = struct.unpack_from("<Q", ibbs, 24)[0]
        d["ibbs"] = {"flags": f"{flags:08X}h", "mch_bar": f"{mchbar:016X}h",
                     "vtd_bar": f"{vtdbar:016X}h"}
        # IBB hash stored right after header (fixed at IBBS+0x64 per BPM 1.0)
        ibbs_off = bpm_off + i
        stored = data[ibbs_off + 0x64: ibbs_off + 0x64 + 32]
        cnt_off = ibbs_off + 0x84
        cnt = struct.unpack_from("<I", data, cnt_off)[0]
        recs = _seg_records(data, cnt_off, cnt)
        segs = [{"flags": f"{fl:04X}h", "address": f"{base:08X}h",
                 "size": f"{sz:08X}h"} for base, sz, fl in recs]
        d["ibbs"]["segments_count"] = cnt
        d["ibbs"]["segments"] = segs
        # Compute IBB hashes over concatenated segment data (file offsets)
        blob = b"".join(
            data[b - report.map_base: b - report.map_base + sz]
            for b, sz in _seg_list(data, cnt_off, cnt))
        for name, algo in IBB_HASHES:
            h = _digest(algo, blob)
            if h:
                report.ibb_hashes[name] = h
        report.ibb_hash_match = blob and report.ibb_hashes.get("SHA256", "").lower() == stored.hex()
        d["ibbs"]["stored_ibb_hash"] = stored.hex().upper()
    i2 = bpm.find(b"__PMSG__")
    if i2 >= 0:
        d["post_ibb_msg"] = "present"
    report.bpm = d


IBB_HASHES = [("SHA1", "sha1"), ("SHA256", "sha256"), ("SHA384", "sha384"),
              ("SHA512", "sha512"), ("SM3", "sm3")]


def _seg_records(data: bytes, cnt_off: int, cnt: int):
    """Full records (base, size, flags) with 2-byte padding auto-detect."""
    p = cnt_off + 4
    for try_off in (4, 5, 6, 8, 2):
        base, size = struct.unpack_from("<II", data, cnt_off + try_off)
        if base >= 0xF0000000 and size < len(data):
            p = cnt_off + try_off
            break
    out = []
    for _ in range(min(cnt, 16)):
        base, size, flags, _r = struct.unpack_from("<IIHH", data, p)
        out.append((base, size, flags))
        p += 12
    return out


def _seg_list(data: bytes, cnt_off: int, cnt: int):
    return [(b, s) for b, s, _f in _seg_records(data, cnt_off, cnt)]


def report_map_base(data: bytes) -> int:
    return 0x1_0000_0000 - len(data)


def parse_key_manifest(data: bytes, off: int) -> dict:
    d = {"tag": "__KEYM__"}
    if off + 0x40 > len(data):
        return d
    d["version"] = f"{data[off+8]:02X}h"
    d["km_version"] = f"{data[off+9]:02X}h"
    d["km_svn"] = f"{data[off+10]:02X}h"
    d["km_id"] = f"{data[off+11]:02X}h"
    # KM hash of BP public key = SHA256 of BPM pubkey (element __PMSG__ key)
    return d


def parse_protected_ranges(data: bytes) -> list:
    ranges = []
    for guid in AMI_PR_GUIDS:
        start = 0
        while True:
            idx = data.find(guid, start)
            if idx < 0:
                break
            start = idx + 1
            if idx + 68 > len(data):
                continue
            h = data[idx + 28: idx + 60]
            addr, size = struct.unpack_from("<II", data, idx + 60)
            # Sanity filter: valid entries sit at top of 4GB (or are empty
            # placeholders with addr 0); reject random in-module GUID hits.
            empty = (addr == 0 and size in (0, 0xFFFFFFFF))
            if not empty and not (size and report_map_base(data) <= addr
                                  < 0x1_0000_0000
                                  and addr - report_map_base(data) + size
                                  <= len(data)):
                continue
            pr = ProtectedRange(idx, guid, h, addr, size)
            if size and 0 < addr < 0x1_0000_0000:
                off = addr - report_map_base(data)
                if 0 <= off and off + size <= len(data):
                    pr.hash_computed = hashlib.sha256(
                        data[off: off + size]).hexdigest().upper()
                    pr.match = pr.hash_computed == h.hex().upper()
            ranges.append(pr)
    return ranges


def scan(data: bytes) -> BootGuardReport:
    rep = BootGuardReport(file_size=len(data))
    rep.map_base = report_map_base(data)
    # Prefer the FIT-declared ACM if the FIT parser is available
    acm_off = -1
    try:
        from fit_parser import parse_fit  # tools dir is on sys.path via bioskit
        fr = parse_fit(data)
        if fr.found:
            for e in fr.acms:
                acm_off = e.address - rep.map_base
                break
    except Exception:
        acm_off = -1
    if acm_off < 0:
        # Fallback: scan for BootGuard ACM header (ModuleType=2, Subtype=3, sane header size)
        for off in range(0, len(data) - 0x400, 4):
            mt, ms, hs = struct.unpack_from("<HHH", data, off)
            if mt == 2 and ms == 3 and 0x10 <= hs <= 0x100:
                _, _, _, _, _, _, ven, dt, msz = struct.unpack_from("<8H", data, off)
                if ven == 0x8086 and msz * 4 in (0x8000, 0x10000, 0x20000):
                    acm_off = off
                    break
    if acm_off >= 0:
        rep.acm = parse_acm_header(data, acm_off)
    km = data.find(TAG_KEYM)
    bpm = data.find(TAG_ACBP)
    rep.km_offset = km
    rep.bpm_offset = bpm
    if km >= 0:
        rep.km = parse_key_manifest(data, km)
    if bpm >= 0:
        parse_bpm(data, bpm, rep)
    rep.protected_ranges = parse_protected_ranges(data)
    return rep


def _to_dict(rep: BootGuardReport) -> dict:
    d = {"file_size": rep.file_size, "map_base": f"{rep.map_base:08X}h"}
    if rep.acm:
        a = rep.acm
        d["acm"] = {"offset": f"{a.offset:X}h", "module_type": f"{a.module_type:04X}h",
                    "module_subtype": f"{a.module_subtype:04X}h",
                    "header_size": f"{a.header_size:08X}h",
                    "header_version": f"{a.header_version:08X}h",
                    "chipset_id": f"{a.chipset_id:08X}h", "flags": f"{a.flags:04X}h",
                    "module_vendor": f"{a.module_vendor:04X}h", "date": a.date,
                    "module_size": f"{a.module_size:08X}h",
                    "acm_svn": f"{a.acm_svn:04X}h", "ses_svn": f"{a.ses_svn:04X}h",
                    "entry_point": f"{a.entry_point:08X}h",
                    "key_size": f"{a.key_size:04X}h",
                    "scratch_space_size": f"{a.scratch_size:04X}h"}
    if rep.km_offset >= 0:
        d["key_manifest"] = dict(rep.km, offset=f"{rep.km_offset:X}h")
    if rep.bpm:
        d["bpm"] = dict(rep.bpm, offset=f"{rep.bpm_offset:X}h")
        d["ibb_hashes"] = dict(rep.ibb_hashes)
        d["ibb_hash_match"] = rep.ibb_hash_match
    if rep.protected_ranges:
        d["protected_ranges"] = [
            {"guid_offset": f"{r.guid_offset:X}h",
             "address": f"{r.address:08X}h", "size": f"{r.size:X}h",
             "hash_stored": r.hash_stored.hex().upper(),
             "hash_computed": r.hash_computed,
             "match": r.match} for r in rep.protected_ranges]
    d["notes"] = rep.notes
    return d


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Intel BootGuard parser (ACM/KM/BPM/AMI protected ranges)")
    ap.add_argument("input")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    p = Path(args.input)
    if not p.exists():
        print(f"[!] File not found: {p}")
        return 1
    data = p.read_bytes()
    rep = scan(data)
    if args.json:
        print(json.dumps(_to_dict(rep), indent=2))
        return 0
    print(f"[*] BootGuard scan: {p} ({len(data):,} bytes, map base 0x{rep.map_base:08X}h)")
    if rep.acm:
        a = rep.acm
        print(f"\nBootGuard ACM found at base {a.offset:X}h")
        print(f"  ModuleType: {a.module_type:04X}h  Subtype: {a.module_subtype:04X}h")
        print(f"  HeaderSize: {a.header_size:08X}h  Version: {a.header_version:08X}h")
        print(f"  ChipsetId: {a.chipset_id:08X}h  Flags: {a.flags:04X}h")
        print(f"  ModuleVendor: {a.module_vendor:04X}h  Date: {a.date}")
        print(f"  ModuleSize: {a.module_size:08X}h  AcmSvn: {a.acm_svn:04X}h  SeSvn: {a.ses_svn:04X}h")
        print(f"  EntryPoint: {a.entry_point:08X}h  KeySize: {a.key_size:04X}h  Scratch: {a.scratch_size:04X}h")
    else:
        print("[!] No BootGuard ACM found")
    if rep.bpm:
        print(f"\nBoot Policy Manifest (__ACBP__) at {rep.bpm_offset:X}h")
        for k, v in rep.bpm.items():
            if k == "ibbs":
                ib = v
                print(f"  IBBS: flags={ib['flags']}  MchBar={ib['mch_bar']}  VtdBar={ib['vtd_bar']}")
                print(f"  IBB segments ({ib['segments_count']}):")
                for s in ib["segments"]:
                    print(f"    Flags={s['flags']}  Addr={s['address']}  Size={s['size']}")
                print(f"  Stored IBB hash: {ib['stored_ibb_hash']}")
            else:
                print(f"  {k}: {v}")
        print("Computed IBB hashes:")
        for name, h in rep.ibb_hashes.items():
            print(f"  {name}: {h}")
        print(f"  IBB hash match vs BPM: {'YES' if rep.ibb_hash_match else 'NO'}")
    if rep.protected_ranges:
        print("\nAMI v2 protected ranges hash file:")
        for r in rep.protected_ranges:
            print(f"  Address: {r.address:08X}h, Size: {r.size:X}h")
            print(f"    Hash stored:  {r.hash_stored.hex().upper()}")
            if r.size:
                print(f"    Hash computed:{r.hash_computed}  {'MATCH' if r.match else 'MISMATCH'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())