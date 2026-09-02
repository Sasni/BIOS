#!/usr/bin/env python3
"""
UEFI SecureBoot Auditor
Parses SecureBoot variables (PK, KEK, db, dbx) from AMI Aptio V NVRAM
and audits the platform's SecureBoot configuration against
NIST SP 800-147 §4.1 + NIST SP 800-155.

Requires: nvar_parser.py (included in project)
Optional: cryptography >= 41.0 (for X.509 certificate parsing)
"""

import struct
import sys
import uuid as _uuid
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass, field

from nvar_parser import parse_nvar, NVARVariable, NVARStore

# ── Optional X.509 certificate parsing ───────────────────────────────────

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    X509_AVAILABLE = True
except ImportError:
    X509_AVAILABLE = False

# ── UEFI Well-Known GUIDs (spec §8.2) ────────────────────────────────────

def _guid_str_to_le(guid_str: str) -> bytes:
    """Convert UEFI GUID string to 16-byte little-endian representation.

    UEFI GUID format:  aabbccdd-eeff-gghh-iijj-kkllmmnnoopp
    Stored as:         dd cc bb aa ff ee hh gg ii jj kk ll mm nn oo pp
    """
    u = _uuid.UUID(guid_str)
    return u.bytes_le

EFI_GLOBAL_VARIABLE_GUID_BIN  = _guid_str_to_le("8be4df61-93ca-11d2-aa0d-00e098032b8c")
EFI_IMAGE_SECURITY_DB_GUID_BIN = _guid_str_to_le("d719b2cb-3d3a-4596-a3bc-dad00e67656f")

# Signature type GUIDs (binary LE)
SIG_TYPE_NAMES = {
    _guid_str_to_le("a5c059a1-94e4-4aa7-87b5-ab155c2bf072"): "EFI_CERT_X509_GUID",
    _guid_str_to_le("c1c41626-504c-4092-aca9-41f936934328"): "EFI_CERT_SHA256_GUID",
    _guid_str_to_le("3c5766ea-269c-4354-b40e-c8d0ba65be5b"): "EFI_CERT_RSA2048_GUID",
    _guid_str_to_le("826ca512-ad10-4b53-966d-138743bea0df"): "EFI_CERT_SHA1_GUID",
    _guid_str_to_le("3bd2a492-0c5a-4c30-8e82-bbc8a885cf53"): "EFI_CERT_X509_SHA256_GUID",
    _guid_str_to_le("4aafd29d-68df-49ee-8aa9-347d375665a7"): "EFI_CERT_PKCS7_GUID",
}

# UEFI Owner GUIDs
KNOWN_OWNERS = {
    _guid_str_to_le("77fa9abd-0359-4d32-bd60-28f4e78f784b"): "Microsoft Corporation",
    _guid_str_to_le("77fa9abd-0359-4d32-bd60-28f4e78f784c"): "Microsoft Windows Production PCA 2011",
    _guid_str_to_le("e2a8a0e0-9f4f-4a0e-8e9b-3b3b5e5d5a1b"): "Canonical Ltd.",
}

# Variable lookup: (name, guid_bin) pairs
SB_VAR_LOOKUP = [
    ("SecureBoot",   EFI_GLOBAL_VARIABLE_GUID_BIN),   # bool: 0=off, 1=on
    ("SetupMode",    EFI_GLOBAL_VARIABLE_GUID_BIN),   # bool: 1=no PK enrolled
    ("AuditMode",    EFI_GLOBAL_VARIABLE_GUID_BIN),   # bool: 1=audit mode
    ("DeployedMode", EFI_GLOBAL_VARIABLE_GUID_BIN),   # bool: 1=deployed mode
    ("PK",           EFI_GLOBAL_VARIABLE_GUID_BIN),   # Platform Key
    ("KEK",          EFI_GLOBAL_VARIABLE_GUID_BIN),   # Key Exchange Keys
    ("db",           EFI_IMAGE_SECURITY_DB_GUID_BIN), # Allowed Signatures
    ("dbx",          EFI_IMAGE_SECURITY_DB_GUID_BIN), # Forbidden Signatures
]


# ── Dataclasses ──────────────────────────────────────────────────────────

@dataclass
class EfiSignatureData:
    """One entry in an EFI_SIGNATURE_LIST."""
    owner: str                      # GUID string of signature owner
    data_raw: bytes                 # raw signature data bytes
    # Parsed X.509 fields (None when cryptography unavailable or not X.509)
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_valid_from: Optional[str] = None
    cert_valid_to: Optional[str] = None
    cert_serial: Optional[str] = None
    cert_fingerprint_sha1: Optional[str] = None
    cert_key_algorithm: Optional[str] = None
    cert_key_size: Optional[int] = None


@dataclass
class EfiSignatureList:
    """One EFI_SIGNATURE_LIST (a list of signatures of the same type)."""
    signature_type: str             # human-readable type (e.g. "EFI_CERT_X509_GUID")
    signature_type_guid: str        # GUID string
    signature_header: bytes         # raw header bytes
    entries: List[EfiSignatureData] = field(default_factory=list)


@dataclass
class SecureBootReport:
    """Complete SecureBoot audit result."""
    found: bool = False
    secure_boot_enabled: bool = False
    setup_mode: bool = False
    audit_mode: bool = False
    deployed_mode: bool = False
    platform_mode: str = "unknown"          # "Setup" | "User" | "Audit" | "Deployed"
    pk: List[EfiSignatureList] = field(default_factory=list)
    kek: List[EfiSignatureList] = field(default_factory=list)
    db: List[EfiSignatureList] = field(default_factory=list)
    dbx: List[EfiSignatureList] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    compliance_level: str = "not_detected"   # "compliant" | "partial" | "non_compliant" | "not_detected"
    summary: str = ""


# ── Variable Lookup ──────────────────────────────────────────────────────

def _find_var(stores: List[NVARStore], name: str, guid_bin: bytes) -> Optional[NVARVariable]:
    """Find an NVAR variable by (name, GUID) across all stores."""
    for store in stores:
        for var in store.variables:
            if var.name == name and var.guid == guid_bin:
                return var
    return None


def _read_bool_var(stores: List[NVARStore], name: str) -> Optional[bool]:
    """Read a boolean UEFI variable (1 byte, 0 or 1)."""
    var = _find_var(stores, name, EFI_GLOBAL_VARIABLE_GUID_BIN)
    if var is not None and var.data_size >= 1:
        # Need to read data from the original dump
        return None  # We don't have the raw data here; data is in the variable itself
    return None


# ── EFI_SIGNATURE_LIST Parser ────────────────────────────────────────────

def _guid_bytes_to_str(guid: bytes) -> str:
    """Convert 16-byte LE GUID to standard string format."""
    if len(guid) != 16:
        return guid.hex().upper()
    return str(_uuid.UUID(bytes_le=guid)).upper()


def _parse_efi_signature_list(data: bytes, offset: int = 0) -> Tuple[Optional[EfiSignatureList], int]:
    """Parse one EFI_SIGNATURE_LIST from data.

    Returns (EfiSignatureList or None, bytes_consumed).
    Returns None if data is too short for a valid header.
    """
    if offset + 28 > len(data):
        return None, 0

    sig_type_raw = data[offset:offset + 16]
    sig_type_guid = _guid_bytes_to_str(sig_type_raw)
    sig_type_name = SIG_TYPE_NAMES.get(sig_type_raw, f"UNKNOWN_{sig_type_guid[:8]}")

    list_size = struct.unpack_from('<I', data, offset + 16)[0]
    header_size = struct.unpack_from('<I', data, offset + 20)[0]
    entry_size = struct.unpack_from('<I', data, offset + 24)[0]

    if list_size < 28:
        return None, 0
    if offset + list_size > len(data):
        return None, 0

    sig_header = data[offset + 28 : offset + 28 + header_size]

    # Entries start after header (28) + signature_header
    entries_start = offset + 28 + header_size
    entries_data_size = list_size - 28 - header_size

    if entry_size == 0 or entries_data_size == 0:
        # Empty list (allowed)
        sl = EfiSignatureList(
            signature_type=sig_type_name,
            signature_type_guid=sig_type_guid,
            signature_header=sig_header,
        )
        return sl, list_size

    num_entries = entries_data_size // entry_size
    entries: List[EfiSignatureData] = []

    for i in range(num_entries):
        entry_off = entries_start + i * entry_size
        if entry_off + entry_size > len(data):
            break

        owner_raw = data[entry_off:entry_off + 16]
        owner_guid = _guid_bytes_to_str(owner_raw)
        owner_name = KNOWN_OWNERS.get(owner_raw, owner_guid)

        sig_data = data[entry_off + 16 : entry_off + entry_size]

        entry = EfiSignatureData(
            owner=owner_name,
            data_raw=sig_data,
        )

        # Try X.509 parsing if available and applicable
        if X509_AVAILABLE and sig_type_name in ("EFI_CERT_X509_GUID",):
            _parse_x509_cert(entry, sig_data)

        entries.append(entry)

    sl = EfiSignatureList(
        signature_type=sig_type_name,
        signature_type_guid=sig_type_guid,
        signature_header=sig_header,
        entries=entries,
    )
    return sl, list_size


def _parse_x509_cert(entry: EfiSignatureData, der_data: bytes) -> None:
    """Try to parse DER-encoded X.509 certificate data. Updates entry in place."""
    try:
        cert = x509.load_der_x509_certificate(der_data)
    except Exception:
        return

    # Subject
    try:
        entry.cert_subject = cert.subject.rfc4514_string()
    except Exception:
        pass

    # Issuer
    try:
        entry.cert_issuer = cert.issuer.rfc4514_string()
    except Exception:
        pass

    # Validity
    try:
        entry.cert_valid_from = cert.not_valid_before_utc.isoformat()
    except Exception:
        pass
    try:
        entry.cert_valid_to = cert.not_valid_after_utc.isoformat()
    except Exception:
        pass

    # Serial number
    try:
        entry.cert_serial = f"{cert.serial_number:X}"
    except Exception:
        pass

    # Fingerprint (SHA-1)
    try:
        fp = cert.fingerprint(_hashes.SHA1())
        entry.cert_fingerprint_sha1 = fp.hex().upper()
    except Exception:
        pass

    # Key algorithm and size
    try:
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            entry.cert_key_algorithm = "RSA"
            entry.cert_key_size = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            entry.cert_key_algorithm = "EC"
            entry.cert_key_size = pubkey.key_size
        else:
            entry.cert_key_algorithm = type(pubkey).__name__
    except Exception:
        pass


# ── Variable Data Access ─────────────────────────────────────────────────

def _get_var_data(data: bytes, var: NVARVariable) -> bytes:
    """Read variable payload from the full dump."""
    if var.data_offset + var.data_size <= len(data):
        return data[var.data_offset:var.data_offset + var.data_size]
    return b''


# ── Main Audit Function ──────────────────────────────────────────────────

def audit_secureboot(dump_data: bytes) -> SecureBootReport:
    """Audit SecureBoot configuration from a BIOS dump.

    Args:
        dump_data: Full BIOS dump bytes.

    Returns:
        SecureBootReport with parsed variables, mode, and compliance verdict.
    """
    report = SecureBootReport()

    # Parse NVAR
    nvar_result = parse_nvar(dump_data)
    if not nvar_result.found or not nvar_result.stores:
        report.summary = "No NVAR variable stores found — SecureBoot variables not available (non-AMI platform or corrupted dump?)"
        return report

    stores = nvar_result.stores

    # ── Read mode booleans ───────────────────────────────────────────────
    sb_var = _find_var(stores, "SecureBoot", EFI_GLOBAL_VARIABLE_GUID_BIN)
    sm_var = _find_var(stores, "SetupMode", EFI_GLOBAL_VARIABLE_GUID_BIN)
    am_var = _find_var(stores, "AuditMode", EFI_GLOBAL_VARIABLE_GUID_BIN)
    dm_var = _find_var(stores, "DeployedMode", EFI_GLOBAL_VARIABLE_GUID_BIN)

    if sb_var and sb_var.data_size >= 1:
        sb_data = _get_var_data(dump_data, sb_var)
        report.secure_boot_enabled = len(sb_data) >= 1 and sb_data[0] == 1

    if sm_var and sm_var.data_size >= 1:
        sm_data = _get_var_data(dump_data, sm_var)
        report.setup_mode = len(sm_data) >= 1 and sm_data[0] == 1

    if am_var and am_var.data_size >= 1:
        am_data = _get_var_data(dump_data, am_var)
        report.audit_mode = len(am_data) >= 1 and am_data[0] == 1

    if dm_var and dm_var.data_size >= 1:
        dm_data = _get_var_data(dump_data, dm_var)
        report.deployed_mode = len(dm_data) >= 1 and dm_data[0] == 1

    # Determine platform mode
    if report.setup_mode:
        report.platform_mode = "Setup"
    elif report.deployed_mode:
        report.platform_mode = "Deployed"
    elif report.audit_mode:
        report.platform_mode = "Audit"
    elif report.secure_boot_enabled:
        report.platform_mode = "User"
    else:
        report.platform_mode = "User"  # User mode with SecureBoot off

    # ── Parse signature databases ────────────────────────────────────────
    for var_name in ("PK", "KEK", "db", "dbx"):
        guid_bin = EFI_GLOBAL_VARIABLE_GUID_BIN if var_name in ("PK", "KEK") else EFI_IMAGE_SECURITY_DB_GUID_BIN
        var = _find_var(stores, var_name, guid_bin)

        sig_lists: List[EfiSignatureList] = []
        if var is not None:
            var_data = _get_var_data(dump_data, var)
            offset = 0
            while offset < len(var_data):
                sl, consumed = _parse_efi_signature_list(var_data, offset)
                if sl is None or consumed == 0:
                    break
                sig_lists.append(sl)
                offset += consumed

        setattr(report, var_name.lower(), sig_lists)

    report.found = (
        len(report.pk) > 0 or len(report.kek) > 0 or
        len(report.db) > 0 or len(report.dbx) > 0 or
        sb_var is not None or sm_var is not None
    )

    # ── Audit checks ─────────────────────────────────────────────────────
    issues: List[str] = []

    # PK check
    pk_empty = all(len(sl.entries) == 0 for sl in report.pk)
    pk_missing = len(report.pk) == 0
    if pk_missing or pk_empty:
        issues.append("PK (Platform Key) is missing or empty — SecureBoot cannot be enabled")
    elif report.setup_mode:
        issues.append("SetupMode=1 despite PK being present — PK may be invalid or corrupted")

    # db check
    db_empty = all(len(sl.entries) == 0 for sl in report.db)
    db_missing = len(report.db) == 0
    if (db_missing or db_empty) and report.secure_boot_enabled:
        issues.append("db (Signature Database) is empty — no OS will boot with SecureBoot ON")
    elif db_missing or db_empty:
        issues.append("db (Signature Database) is empty — no bootloaders enrolled")

    # dbx check
    dbx_empty = all(len(sl.entries) == 0 for sl in report.dbx)
    dbx_missing = len(report.dbx) == 0
    if dbx_missing or dbx_empty:
        issues.append("dbx (Forbidden Signatures) is missing or empty — known-revoked bootloaders not blocked")

    # Certificate-level checks (when X.509 available)
    for sig_list in report.pk + report.kek + report.db:
        for entry in sig_list.entries:
            if entry.cert_key_size and entry.cert_key_size < 2048 and entry.cert_key_algorithm == "RSA":
                issues.append(f"RSA key < 2048 bits ({entry.cert_key_size}-bit) in {entry.cert_subject or '?'}")
            if entry.cert_key_size and entry.cert_key_size < 256 and entry.cert_key_algorithm == "EC":
                issues.append(f"EC key < 256 bits ({entry.cert_key_size}-bit) in {entry.cert_subject or '?'}")

    report.issues = issues

    # ── Compliance verdict ───────────────────────────────────────────────
    if not report.found:
        report.compliance_level = "not_detected"
        report.summary = "No SecureBoot variables found — platform may not support UEFI SecureBoot or NVRAM is corrupted"
    elif pk_missing or pk_empty:
        report.compliance_level = "non_compliant"
        report.summary = f"SecureBoot {report.platform_mode} mode — PK missing/empty, cannot enable"
    elif report.secure_boot_enabled and dbx_missing:
        report.compliance_level = "partial"
        report.summary = f"SecureBoot ON ({report.platform_mode}) — dbx missing, revoked bootloaders not blocked"
    elif report.secure_boot_enabled and not dbx_missing and not db_missing:
        report.compliance_level = "compliant"
        report.summary = f"SecureBoot ON ({report.platform_mode}) — PK, KEK, db, dbx present"
    elif not report.secure_boot_enabled and not pk_missing:
        report.compliance_level = "partial"
        report.summary = f"SecureBoot OFF ({report.platform_mode}) — keys present but SecureBoot disabled"
    else:
        report.compliance_level = "partial"
        report.summary = f"SecureBoot {report.platform_mode} — non-standard configuration"

    return report


# ── JSON Serialization ───────────────────────────────────────────────────

def _report_to_dict(report: SecureBootReport) -> dict:
    """Convert SecureBootReport to JSON-serializable dict."""
    def _sig_list_to_dict(sl: EfiSignatureList) -> dict:
        entries = []
        for e in sl.entries:
            entry = {
                "owner": e.owner,
                "data_hex": e.data_raw.hex()[:64] + ("..." if len(e.data_raw) > 32 else ""),
                "data_size": len(e.data_raw),
            }
            if e.cert_subject:
                entry["cert_subject"] = e.cert_subject
            if e.cert_issuer:
                entry["cert_issuer"] = e.cert_issuer
            if e.cert_valid_from:
                entry["cert_valid_from"] = e.cert_valid_from
            if e.cert_valid_to:
                entry["cert_valid_to"] = e.cert_valid_to
            if e.cert_serial:
                entry["cert_serial"] = e.cert_serial
            if e.cert_fingerprint_sha1:
                entry["cert_fingerprint_sha1"] = e.cert_fingerprint_sha1
            if e.cert_key_algorithm:
                entry["cert_key_algorithm"] = e.cert_key_algorithm
            if e.cert_key_size:
                entry["cert_key_size"] = e.cert_key_size
            entries.append(entry)
        return {
            "signature_type": sl.signature_type,
            "signature_type_guid": sl.signature_type_guid,
            "entries_count": len(sl.entries),
            "entries": entries,
        }

    return {
        "found": report.found,
        "secure_boot_enabled": report.secure_boot_enabled,
        "setup_mode": report.setup_mode,
        "audit_mode": report.audit_mode,
        "deployed_mode": report.deployed_mode,
        "platform_mode": report.platform_mode,
        "pk": [_sig_list_to_dict(sl) for sl in report.pk],
        "kek": [_sig_list_to_dict(sl) for sl in report.kek],
        "db": [_sig_list_to_dict(sl) for sl in report.db],
        "dbx": [_sig_list_to_dict(sl) for sl in report.dbx],
        "x509_available": X509_AVAILABLE,
        "issues": report.issues,
        "compliance_level": report.compliance_level,
        "summary": report.summary,
    }


# ─── CLI ──────────────────────────────────────────────────────────────────

def _print_report(report: SecureBootReport, verbose: bool = False) -> None:
    """Print a human-readable SecureBoot audit report."""

    print(f"\n{'='*60}")
    print(f"  UEFI SecureBoot Audit")
    print(f"{'='*60}")

    if not report.found:
        print(f"\n  [!] No SecureBoot variables detected")
        print(f"  {report.summary}")
        return

    # ── Status ───────────────────────────────────────────────────────────
    print(f"\n  Platform Mode: {report.platform_mode}")
    sb_state = "ON" if report.secure_boot_enabled else "OFF"
    print(f"  SecureBoot:    {sb_state}")
    print(f"  SetupMode:     {'YES' if report.setup_mode else 'no'}")
    print(f"  AuditMode:     {'YES' if report.audit_mode else 'no'}")
    print(f"  DeployedMode:  {'YES' if report.deployed_mode else 'no'}")

    status_labels = {
        "compliant":     "+ COMPLIANT",
        "partial":       "~ PARTIAL",
        "non_compliant": "! NON-COMPLIANT",
        "not_detected":  "? NOT DETECTED",
    }
    label = status_labels.get(report.compliance_level, report.compliance_level)
    print(f"\n  Verdict: {label}")

    # ── Databases ────────────────────────────────────────────────────────
    for db_name, db_label in [("pk", "PK (Platform Key)"), ("kek", "KEK (Key Exchange Keys)"),
                               ("db", "db (Allowed Signatures)"), ("dbx", "dbx (Forbidden Signatures)")]:
        sig_lists = getattr(report, db_name)
        print(f"\n  ── {db_label} ──")
        if not sig_lists:
            print(f"  (empty)")
            continue
        for sl in sig_lists:
            print(f"  Type: {sl.signature_type}  [{len(sl.entries)} entries]")
            for e in sl.entries:
                line = f"    Owner: {e.owner}"
                if e.cert_subject:
                    line += f"\n      Subject:  {e.cert_subject}"
                if e.cert_issuer:
                    line += f"\n      Issuer:   {e.cert_issuer}"
                if e.cert_valid_to:
                    line += f"\n      Valid to: {e.cert_valid_to}"
                if e.cert_fingerprint_sha1:
                    line += f"\n      SHA-1:    {e.cert_fingerprint_sha1}"
                if e.cert_key_algorithm:
                    ks = f"{e.cert_key_size}-bit" if e.cert_key_size else ""
                    line += f"\n      Key:      {e.cert_key_algorithm} {ks}"
                if not e.cert_subject:
                    line += f"\n      Data:     {e.data_raw[:32].hex().upper()}..."
                print(line)

    # ── Issues ───────────────────────────────────────────────────────────
    if report.issues:
        print(f"\n  ── Issues ──")
        for issue in report.issues:
            print(f"  ! {issue}")

    if not X509_AVAILABLE:
        print(f"\n  [!] cryptography library not installed — X.509 certificates not parsed")
        print(f"  [i] Install with: pip install cryptography")

    print(f"\n  Summary: {report.summary}")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="UEFI SecureBoot Auditor (NIST SP 800-147 §4.1 + SP 800-155)"
    )
    parser.add_argument("input", help="Firmware image file (.bin/.rom)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="Output as JSON (for GUI)")
    parser.add_argument("--no-x509", action="store_true",
                       help="Skip X.509 certificate parsing (even if cryptography available)")

    args = parser.parse_args()

    # Honour --no-x509 even when cryptography is installed
    global X509_AVAILABLE
    if args.no_x509:
        X509_AVAILABLE = False

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}", file=sys.stderr)
        return 1

    data = input_path.read_bytes()

    if args.json:
        import json as _json
        report = audit_secureboot(data)
        out = _report_to_dict(report)
        out["file"] = str(input_path)
        out["file_size"] = len(data)
        print(_json.dumps(out, indent=2, default=str))
        return 0 if report.found else 1

    print(f"[*] UEFI SecureBoot Audit")
    print(f"[*] File: {input_path} ({len(data):,} bytes)")
    if not X509_AVAILABLE:
        print(f"[*] X.509 parsing: unavailable (install 'cryptography' for full details)")

    report = audit_secureboot(data)
    _print_report(report, verbose=args.verbose)

    if report.compliance_level == "non_compliant":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
