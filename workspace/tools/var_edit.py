#!/usr/bin/env python3
"""
UEFI Variable Editor (offline) — read/write single UEFI variables in BIOS dumps.

Formaty (format-agnostic, wspólna składnia):
  NVAR  — AMI Aptio V         (nvar_parser.py)
  VSS   — Insyde H2O          ($VSS / VSS2, wpisy AA55)
  EVSA  — Phoenix SCT (używane też przez Lenovo/AMI) — wpisy EC/ED/EE/EF/83

Inspiracja składnią UefiVarTool (GeographicCone/UefiVarTool, GPLv3) /
setup_var.efi (datasone, MIT) — reimplementacja czysta (clean-room), dla
dumpów OFFLINE:

  UVT (live, EFI shell):   Setup:0x40(1)=0x01
  To narzędzie (offline):  AMITSESetup@0x0301E9:0x00(1)=0x01

Operacje adresują obszar DANYCH sparsowanej zmiennej (bajty, które
reset_variable_data() w reset_nvram.py czyści / które raportuje --list):

  <VarName>[@<RecordOffset>]:<Offset>[(<Size>)][=<Value>]

  VarName       sparsowana nazwa zmiennej (case-sensitive), np. AMITSESetup,
                Setup, PlatformLang, SecureBootSetup
  RecordOffset  opcjonalny bezwzględny offset rekordu w pliku — wymagany przy
                duplikatach nazw (np. 2x SecureBootSetup / 2x Setup w NVAR)
  Offset        pozycja w obszarze DANYCH zmiennej (0 = pierwszy bajt danych)
  Size          bajty, domyślnie 1; zapis max 8 (jak UVT); odczyt cała zmienna
  Value         0x hex albo dziesiętnie; zapis little-endian; brak = odczyt

Formaty VSS/EVSA (użyte przy parsowaniu, wyprowadzone z dumpów i źródeł
publicznych — habr 281242/281469, "Устройство NVRAM", CodeRush):
  VSS  — nagłówek store ($VSS + StoreSize u32), wpisy zaczynają się markerem
         AA55; pola względem wpisu: Attributes u32@+4, NameSize u32@
         (+8|+36), DataSize u32@(+12|+40), GUID 16B, nazwa UTF-16LE
         (rozmiar z NameSize, z terminatorem); dane zaraz po nazwie.
         Wariant z rezerwą 28 B (nazwa@+60) vs standard (nazwa@+32) —
         wykrywany automatycznie per store (wybór wg najdłuższego ciągłego
         marszu wpisów).
  EVSA — nagłówek store to wpis typu 0xEC (4B: Type/Checksum/Size=0x14) +
         "EVSA"(4) + Attributes(4) + StoreSize(4) + reserved(4). Wpisy:
         0xED|0xE1 GUID (GuidId + GUID), 0xEE|0xE2 nazwa (VarId + UCS2),
         0xEF|0xE3 dane (GuidId, VarId, Attributes, Data), 0x83 usunięte.
         Atrybut 0x10000000 w danych = rozszerzony wpis z DataSize.
         Zmiana danych w wpisie EVSA wymaga przeliczenia sumy kontrolnej
         wpisu (bajt @+1): dodawanie mod-256 całego wpisu (bez bajtu sumy).
         UWAGA: ta konwencja jest wyprowadzona ze źródła publicznego i
         NIE została jeszcze zwalidowana na żywym dumpie EVSA (w lokalnym
         zbiorze brak obrazu z danymi — jest tylko po resecie). Przed
         flashowaniem wyniku na kluczowej maszynie warto zweryfikować.

Model bezpieczeństwa (jak UVT + offline):
  - odczyty zawsze bezpieczne, nie potrzebują pliku wyjściowego
  - zapisy NIGDY nie modyfikują pliku wejściowego: wymagają -o/--output
    (albo --simulate, które drukuje plan i nic nie pisze)
  - walidacja zapisów: bajty zmienione tylko wewnątrz wykrytych obszarów
    (region NVAR / magazyny VSS/EVSA); dump jest ponownie parsowany,
    a wartość odczytywana po zapisie (readback)
  - stopka CRC32 regionu NVAR przeliczana, jeśli istnieje; dla wpisów EVSA
    przeliczana suma kontrolna wpisu
  - --plan zapisuje rozwiązane operacje jako skrypt do ponownego --apply

`execute()` to jedyny pipeline używany przez CLI (main) i GUI Flask
(app.py /api/var/*) — GUI nie duplikuje logiki bezpieczeństwa.

Ograniczenia:
  - parsowanie NVAR jest heurystyczne (patrz nvar_parser.py); duplikaty nazw
    i nakładające się rekordy istnieją na realnych dumpach — zawsze potwierdź
    cel przez --list i preferuj @<RecordOffset>.
  - VSS: warianty buildów Insyde mogą różnić się nagłówkiem store; marsz
    wpisów kończy się (z notką) na nieznanym/niepewnym wpisie.
  - EVSA: parsowanie wg layoutu Phoenix (artykuł habr); oczekuje walidacji na
    żywym dumpie — na lokalnym zbiorze są tylko magazyny po resecie.
  - Offsety odnoszą się do obszaru DANYCH (tego, który --list raportuje jako
    "data"). Część buildów AMI trzyma bajty atrybutów/wskaźnika GUID zaraz za
    terminatorem nazwy, więc właściwy payload może zaczynać się na +1/+2 —
    zweryfikuj odczytem przed mapowaniem wartości IFR VarOffset na to
    narzędzie.

Przykłady:
  python var_edit.py dump.bin --list
  python var_edit.py dump.bin AMITSESetup:0x0(16)              # odczyt 16 B
  python var_edit.py dump.bin SecureBootSetup@0x030365:0x0     # duplikat
  python var_edit.py dump.bin Setup:0x40(1)=0x01 --simulate    # sucho
  python var_edit.py dump.bin Setup:0x40(1)=0x01 -o out.bin    # realny patch
  python var_edit.py dump.bin --plan plan.txt Setup:0x40(1)=0x01
  python var_edit.py dump.bin --apply plan.txt -o out.bin      # replay planu
"""

import re
import sys
import struct
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Tuple

from nvar_parser import parse_nvar, NVARVariable, NVARParseResult
from reset_nvram import _update_nvram_crc32

# ── Operation syntax ──────────────────────────────────────────────────────
#
#   Name[@0xRECORD]:0xOFF[(SIZE)][=0xVALUE]
#   Offsets/values: hex z 0x albo dziesiętnie. Size: dziesiętnie lub 0x.
#   SIZE domyślnie 1 bajt; brak VALUE → operacja odczytu.

_OP_RE = re.compile(
    r"^(?P<name>[^:]+?)(?:@(?P<rec>0x[0-9A-Fa-f]+|\d+))?"
    r":(?P<off>0x[0-9A-Fa-f]+|\d+)"
    r"(?:\((?P<size>0x[0-9A-Fa-f]+|\d+)\))?"
    r"(?:=(?P<val>0x[0-9A-Fa-f]+|\d+))?$"
)

MAX_VALUE_SIZE = 8

VSS_SIGNATURES = (b"$VSS", b"VSS2", b"$VSS2")
EVSA_SIGNATURE = b"EVSA"

FMT_NVAR = "NVAR"
FMT_VSS = "VSS"
FMT_EVSA = "EVSA"


def eprint(*args, **kwargs):
    """Print an error to stderr so bioskit.py surfaces it without -v."""
    print(*args, file=sys.stderr, **kwargs)


class OpError(Exception):
    """Raised for operation-level problems (parse, resolution, bounds)."""


# ── Variable record model ──────────────────────────────────────────────────

@dataclass
class VarRec:
    """Unified, format-agnostic handle to one UEFI variable record."""
    fmt: str                      # FMT_NVAR / FMT_VSS / FMT_EVSA
    offset: int                   # absolute file offset of the record start
    name: str                     # parsed name (case-sensitive)
    data_offset: int              # absolute offset of the DATA area start
    data_size: int                # size of the DATA area
    total_size: int               # whole record size (header+name+data)
    guid: Optional[bytes] = None
    attrs: Optional[int] = None   # EFI attributes (VSS/EVSA); NVAR: None
    state: int = 0xFFFFFF         # NVAR state / active marker
    store_start: int = 0          # containing store span (bounds checks)
    store_end: int = 0
    checksum_pos: Optional[int] = None    # EVSA: byte @record+1
    checksum_cover: Tuple[int, int] = (0, 0)  # EVSA: coverage of the checksum


@dataclass
class StoresContext:
    """Parsing context across every supported store format in one dump."""
    found: bool = False
    formats: List[str] = field(default_factory=list)
    nvar: Optional[NVARParseResult] = None
    vss_stores: List[Tuple[int, int, int]] = field(default_factory=list)
    evsa_stores: List[Tuple[int, int, int, int]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def region_start(self) -> Optional[int]:
        if self.nvar and self.nvar.found:
            return self.nvar.region_start
        if self.vss_stores:
            return min(s[0] for s in self.vss_stores)
        if self.evsa_stores:
            return min(s[1] for s in self.evsa_stores)  # store entry start
        return None

    @property
    def region_end(self) -> Optional[int]:
        if self.nvar and self.nvar.found:
            return self.nvar.region_end
        if self.vss_stores:
            return max(s[0] + s[1] for s in self.vss_stores)
        if self.evsa_stores:
            return max(s[1] + s[0] for s in self.evsa_stores)  # start+size
        return None


def _num(text: str, what: str) -> int:
    """Parse a decimal or 0x-hex number."""
    try:
        return int(text, 0) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        raise OpError(f"invalid {what}: '{text}' (use decimal or 0x hex)")


def parse_op(text: str) -> dict:
    """Parse a single operation string into a dict."""
    m = _OP_RE.match(text.strip())
    if not m:
        raise OpError(f"cannot parse operation: '{text}'")
    op = {
        "name": m.group("name").strip(),
        "rec": _num(m.group("rec"), "record offset") if m.group("rec") else None,
        "offset": _num(m.group("off"), "offset"),
        "size": _num(m.group("size"), "size") if m.group("size") else 1,
        "value": _num(m.group("val"), "value") if m.group("val") else None,
    }
    if not op["name"]:
        raise OpError(f"empty variable name in: '{text}'")
    if op["rec"] is not None and op["rec"] < 0:
        raise OpError(f"negative record offset in: '{text}'")
    if op["offset"] < 0:
        raise OpError(f"negative data offset in: '{text}'")
    # Writes are capped at 8 bytes (UEFI SetVariable-safe granularity, like
    # UVT); reads may span the whole variable data area.
    max_size = MAX_VALUE_SIZE if op["value"] is not None else 0x10000
    if not 1 <= op["size"] <= max_size:
        raise OpError(
            f"size {op['size']} out of range 1..{max_size} in: '{text}'")
    if op["value"] is not None:
        if op["value"] < 0:
            raise OpError(f"negative value in: '{text}'")
        if op["value"] >= 1 << (8 * op["size"]):
            raise OpError(
                f"value 0x{op['value']:X} does not fit in {op['size']} "
                f"byte(s) in: '{text}'")
    return op


def parse_script(lines: List[str]) -> List[dict]:
    """Parse plan-script lines (same grammar, '#' comments, blank ignored)."""
    ops = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        ops.append(parse_op(line))
    return ops


def read_script(path: Path) -> List[dict]:
    if not path.exists():
        raise OpError(f"plan file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-16")   # shell-style UTF-16 LE
    return parse_script(text.splitlines())


# ── Store discovery ────────────────────────────────────────────────────────

def _u16(data: bytes, pos: int) -> int:
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    return struct.unpack_from("<I", data, pos)[0]


def find_vss_stores(data: bytes) -> List[Tuple[int, int, int]]:
    """Find VSS stores: (sig_offset, store_size, first_marker_offset).

    VSS header: sig (4) + StoreSize u32 (4) + meta; variable records start
    with the AA55 marker somewhere in the first 0x400 bytes after the sig.
    """
    found = []
    for sig in VSS_SIGNATURES:
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos == -1:
                break
            start = pos + 1
            if pos + 8 > len(data):
                continue
            size = _u32(data, pos + 4)
            if not (0x100 <= size <= len(data)) or pos + size > len(data):
                continue
            m = data.find(b"\xaa\x55", pos + 0x10,
                          min(pos + 0x400, pos + size))
            if m == -1 or m + 16 > pos + size:
                continue
            found.append((pos, size, m))
    # Dedupe overlapping detections (same store caught under two signatures)
    unique = []
    for f in found:
        if not any(f[0] <= u[0] < f[0] + f[1] and u[0] != f[0]
                   for u in unique):
            unique.append(f)
    return unique


def find_evsa_stores(data: bytes) -> List[Tuple[int, int, int, int]]:
    """Find EVSA stores: (store_size, store_entry_start, sig_off, data_off).

    Phoenix layout: pre-header u32 = {Type 0xEC, Checksum u8, Size u16}
    immediately before the 'EVSA' signature; then Attributes u32, StoreSize
    u32 (invalidated to 0xFFFFFFFF on reset dumps → skipped), reserved u32.
    """
    found = []
    pos = -1
    while True:
        pos = data.find(EVSA_SIGNATURE, pos + 1)
        if pos == -1:
            break
        if pos < 4:
            continue
        entry = pos - 4
        if data[entry] != 0xEC:          # store entry Type
            continue
        if _u16(data, entry + 2) != 0x14:  # store entry Size = 20
            continue
        store_size = _u32(data, pos + 8)   # after sig(4)+attrs(4)
        if store_size == 0xFFFFFFFF:       # reset-invalidated store
            continue
        if not (0x100 <= store_size <= len(data)) or entry + store_size > len(data):
            continue
        found.append((store_size, entry, pos, entry + 0x14))
    return found


# ── Name decoding ──────────────────────────────────────────────────────────

def _decode_utf16_name(raw: bytes, prefix: str, offset: int) -> str:
    """Decode a UTF-16LE name; fall back to a synthetic readable tag."""
    try:
        s = raw.decode("utf-16-le", errors="replace")
    except Exception:
        s = ""
    s = s.rstrip("\x00")
    if not s:
        return f"{prefix}_0x{offset:04X}"
    printable = "".join(ch if 0x20 <= ord(ch) < 0x7F else f"\\x{ord(ch):02X}"
                        for ch in s)
    if len(printable) * 3 < len(s) * 2:     # mostly garbage → synthetic
        return f"{prefix}_0x{offset:04X}"
    return printable[:60]


# ── VSS variable parser ────────────────────────────────────────────────────

_VSS_LAYOUTS = (
    {"ns": 36, "ds": 40, "name": 60, "guid": 44},   # lenovo/Insyde wariant
    {"ns": 8, "ds": 12, "name": 32, "guid": 16},    # "standard" (habr)
)


def _parse_vss_store(data: bytes, sig_off: int, size: int,
                     marker: int) -> Tuple[List[VarRec], str]:
    """Walk VSS variable records from *marker* to the end of the store.

    Each record (offsets relative to the AA55 marker):
      +0 AA55 (2) + state/reserved (2) | Attributes u32@+4 | reserved 28 B |
      NameSize u32 | DataSize u32 | GUID 16 B | Name UTF-16LE | Data
    Two known layouts differ only in where NameSize/DataSize/GUID/name sit
    (variant A: name@+60; variant B: name@+32, no 28-byte reserved gap).
    Both are tried per store; the one yielding the longer consistent walk
    wins.
    """
    store_end = sig_off + size

    def try_layout(layout) -> Tuple[List[VarRec], int, int, str]:
        recs = []
        m = marker
        note = ""
        while m + layout["name"] + 8 <= store_end:
            if data[m] in (0x00, 0xFF) and data[m + 1] in (0x00, 0xFF):
                break
            ns = _u32(data, m + layout["ns"])
            ds = _u32(data, m + layout["ds"])
            name_start = m + layout["name"]
            if not (2 <= ns <= 0x400 and ns % 2 == 0):
                break
            if name_start + ns + ds > store_end:
                break
            if ds > store_end - (name_start + ns):
                break
            raw_name = data[name_start:name_start + ns]
            name = _decode_utf16_name(raw_name, "vss", m)
            data_off = name_start + ns
            rec_end = data_off + ds
            if rec_end > store_end:
                break
            guid = data[m + layout["guid"]:m + layout["guid"] + 16]
            recs.append(VarRec(
                fmt=FMT_VSS, offset=m, name=name,
                data_offset=data_off, data_size=ds,
                total_size=rec_end - m,
                guid=guid, attrs=_u32(data, m + 4),
                store_start=sig_off, store_end=store_end,
            ))
            m = rec_end
            if rec_end >= store_end:
                break
            # Next record usually starts exactly at rec_end. If not, treat a
            # long run of 0x00/0xFF as the erased tail (store end reached),
            # otherwise look for the next plausible record header a bit
            # further on (small inter-record slack or deleted records).
            nxt = data.find(b"\xaa\x55", m, min(m + 0x400, store_end))
            if nxt == m:
                continue
            if nxt == -1 or nxt + layout["name"] + 8 > store_end:
                break
            if data[m:nxt] and all(b in (0x00, 0xFF) for b in data[m:nxt]):
                m = nxt
                continue
            ns2 = _u32(data, nxt + layout["ns"])
            ds2 = _u32(data, nxt + layout["ds"])
            if not (2 <= ns2 <= 0x400 and ns2 % 2 == 0):
                break
            if nxt + layout["name"] + ns2 + ds2 > store_end:
                break
            m = nxt
        if m < store_end and not all(
                b in (0x00, 0xFF) for b in data[m:store_end]):
            note = (f"VSS store 0x{sig_off:06X}: walk stopped at "
                    f"0x{m:06X} (unparsed tail to 0x{store_end:06X})")
        return recs, m, len(recs), note

    best = ([], marker, "")
    for layout in _VSS_LAYOUTS:
        recs, m, n, note = try_layout(layout)
        if len(recs) > len(best[0]):
            best = (recs, m, note)
    recs, walked_to, note = best
    if not recs and note == "":
        note = (f"VSS store 0x{sig_off:06X}: no parseable variable records "
                f"(marker 0x{marker:06X})")
    return recs, note


def parse_vss_variables(data: bytes) -> Tuple[List[VarRec], List[Tuple[int, int, int]], List[str]]:
    """Parse all VSS stores in a dump."""
    recs: List[VarRec] = []
    notes: List[str] = []
    stores = find_vss_stores(data)
    for sig_off, size, marker in stores:
        r, _note = _parse_vss_store(data, sig_off, size, marker)
        recs.extend(r)
        if _note:
            notes.append(_note)
    return recs, stores, notes


# ── EVSA variable parser ───────────────────────────────────────────────────

_EVSA_TYPES = {
    0xED: "guid", 0xE1: "guid",
    0xEE: "name", 0xE2: "name",
    0xEF: "data", 0xE3: "data",
    0x83: "deleted",
}


def parse_evsa_variables(data: bytes) -> Tuple[List[VarRec], List[Tuple[int, int, int, int]], List[str]]:
    """Parse all EVSA stores in a dump (Phoenix layout, see module doc)."""
    recs: List[VarRec] = []
    notes: List[str] = []
    stores = find_evsa_stores(data)
    for size, entry, sig_off, data_off in stores:
        store_end = entry + size
        names: dict = {}
        guids: dict = {}
        m = data_off
        while m + 6 <= store_end:
            typ = data[m]
            etype = _EVSA_TYPES.get(typ)
            if etype is None:
                # tolerate zero/FF padding only; otherwise stop the walk
                if data[m:m + 6] in (b"\x00" * 6, b"\xff" * 6):
                    break
                break
            esize = _u16(data, m + 2)
            if esize < 6 or m + esize > store_end:
                break
            if etype == "guid":
                gid = _u16(data, m + 4)
                if esize >= 22:
                    guids[gid] = data[m + 6:m + 22]
                m += esize
            elif etype == "name":
                vid = _u16(data, m + 4)
                names[vid] = _decode_utf16_name(
                    data[m + 6:m + esize], "evsa", m)
                m += esize
            elif etype == "deleted":
                m += esize
            else:  # data
                gid = _u16(data, m + 4)
                vid = _u16(data, m + 6)
                attrs = _u32(data, m + 8)
                ext = bool(attrs & 0x10000000)
                if ext:
                    if m + 16 > m + esize:
                        break
                    ds = _u32(data, m + 12)
                    data_off_abs = m + 16
                    rec_end = data_off_abs + ds
                else:
                    ds = esize - 12
                    data_off_abs = m + 12
                    rec_end = m + esize
                if ds < 0 or rec_end > store_end:
                    break
                name = names.get(vid)
                if not name:
                    name = f"evsa_{vid:04X}"
                recs.append(VarRec(
                    fmt=FMT_EVSA, offset=m, name=name,
                    data_offset=data_off_abs, data_size=ds,
                    total_size=rec_end - m,
                    guid=guids.get(gid), attrs=attrs,
                    store_start=entry, store_end=store_end,
                    checksum_pos=m + 1,
                    checksum_cover=(m, rec_end),
                ))
                m = rec_end
        if m < store_end and not all(
                b in (0x00, 0xFF) for b in data[m:store_end]):
            notes.append(f"EVSA store 0x{entry:06X}: walk stopped at "
                         f"0x{m:06X} (unparsed tail to 0x{store_end:06X})")
    return recs, stores, notes


# ── Unified listing ────────────────────────────────────────────────────────

def list_nvar(data: bytes) -> Tuple[StoresContext, List[VarRec]]:
    """Parse every supported store and return (context, all records).

    The name is kept for backward compatibility with app.py; the result now
    spans NVAR + VSS + EVSA.
    """
    ctx = StoresContext()
    records: List[VarRec] = []

    nvar_result = parse_nvar(data)
    if nvar_result.found:
        ctx.nvar = nvar_result
        ctx.formats.append(FMT_NVAR)
        for v in nvar_result.variables:
            records.append(VarRec(
                fmt=FMT_NVAR, offset=v.offset, name=v.name,
                data_offset=v.data_offset, data_size=v.data_size,
                total_size=v.total_size, guid=v.guid, state=v.state,
                store_start=nvar_result.region_start,
                store_end=nvar_result.region_end,
            ))

    vss_recs, vss_stores, vss_notes = parse_vss_variables(data)
    if vss_stores:
        ctx.formats.append(FMT_VSS)
        ctx.vss_stores = vss_stores
        records.extend(vss_recs)
        ctx.notes.extend(vss_notes)

    evsa_recs, evsa_stores, evsa_notes = parse_evsa_variables(data)
    if evsa_stores:
        ctx.formats.append(FMT_EVSA)
        ctx.evsa_stores = evsa_stores
        records.extend(evsa_recs)
        ctx.notes.extend(evsa_notes)

    # De-duplicate by absolute record offset (store walkers may overlap)
    seen = set()
    unique = []
    for r in records:
        if r.offset not in seen:
            seen.add(r.offset)
            unique.append(r)
    records = unique

    if records:
        ctx.found = True
    else:
        # No variable records anywhere — but maybe the stores themselves
        # exist (e.g. a reset dump). Still treat as found only with records,
        # so callers get a clear error instead of an empty listing.
        raise OpError(
            "no supported variable store with data found in this dump "
            "(NVAR/VSS/EVSA). If this is a reset/cleared dump, the store "
            "exists but variables were wiped — see reset_nvram / analyze.")

    ctx.formats = sorted(set(ctx.formats), key=lambda f: FMT_NVAR != f)
    return ctx, records


# ── Variable resolution ────────────────────────────────────────────────────

def resolve_var(records: List[VarRec], op: dict) -> VarRec:
    """Pick the record an operation targets.

    Resolution order:
      1. explicit absolute record offset (op['rec']) — exact and unambiguous
      2. unique name match
      3. error listing all candidates (duplicate names are common)
    """
    if op["rec"] is not None:
        for v in records:
            if v.offset == op["rec"]:
                return v
        raise OpError(f"no record at absolute offset "
                      f"0x{op['rec']:06X} (see --list)")

    matches = [v for v in records if v.name == op["name"]]
    if not matches:
        raise OpError(f"variable '{op['name']}' not found (see --list)")
    if len(matches) > 1:
        detail = "\n".join(
            f"    [{v.fmt}] {v.name} @0x{v.offset:06X}  "
            f"data={v.data_size}B  "
            f"{('guid=' + v.guid.hex()) if v.guid else ''}"
            for v in matches)
        raise OpError(
            f"variable name '{op['name']}' is ambiguous — {len(matches)} "
            f"records match; pick one with @0x<offset>:\n{detail}")
    return matches[0]


def _var_span(v: VarRec) -> Tuple[int, int]:
    """Absolute (start, end) of the addressable DATA area of a record."""
    start = v.data_offset
    end = min(v.data_offset + v.data_size, v.offset + v.total_size)
    if end <= start and v.total_size > 0:
        end = min(v.offset + v.total_size, start)  # degenerate; keep >= start
    return start, max(start, end)


def read_value(data: bytes, v: VarRec, offset: int, size: int) -> bytes:
    start, end = _var_span(v)
    if offset + size > end - start:
        raise OpError(
            f"read out of bounds: offset 0x{offset:X} size {size} on "
            f"'{v.name}' @0x{v.offset:06X} (data area {end - start}B, "
            f"0x{start:06X}–0x{end:06X}); max offset "
            f"0x{max(0, end - start - 1):X}")
    return bytes(data[start + offset:start + offset + size])


def write_value(data: bytearray, v: VarRec, offset: int, size: int,
                value: int) -> Tuple[int, bytes, bytes]:
    """Patch *size* bytes at *offset* of v's data area with LE *value*.

    Returns (absolute_offset, old_bytes, new_bytes).
    """
    start, end = _var_span(v)
    if offset + size > end - start:
        raise OpError(
            f"write out of bounds: offset 0x{offset:X} size {size} on "
            f"'{v.name}' @0x{v.offset:06X} (data area {end - start}B, "
            f"0x{start:06X}–0x{end:06X})")
    abs_off = start + offset
    old = bytes(data[abs_off:abs_off + size])
    new = value.to_bytes(size, "little")
    data[abs_off:abs_off + size] = new
    return abs_off, old, new


# ── Output helpers ─────────────────────────────────────────────────────────

def fmt_op(op: dict, resolved: VarRec) -> str:
    """Render a resolved operation back into script syntax (round-trip)."""
    head = f"{op['name']}@0x{resolved.offset:06X}:0x{op['offset']:X}"
    if op["size"] != 1:
        head += f"({op['size']})"
    if op["value"] is not None:
        head += f"=0x{op['value']:X}"
    return head


def hexdump(data: bytes, base: int, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    +0x{base + i:04X}  {hx:<47s}  {asc}")
    return "\n".join(lines)


# ── Checksum recomputation (EVSA entries) ─────────────────────────────────

def _recompute_evsa_checksum(patch: bytearray, v: VarRec) -> bool:
    """EVSA record checksum: additive mod-256 over the whole entry,
    checksum byte excluded, chosen so the byte sum ≡ 0 (mod 256).

    Convention derived from public Phoenix EVSA documentation; not yet
    validated against a live store (see module docstring).
    """
    if v.checksum_pos is None:
        return False
    cs, ce = v.checksum_cover
    total = 0
    for i in range(cs, ce):
        if i == v.checksum_pos:
            continue
        total += patch[i]
    patch[v.checksum_pos] = (-total) & 0xFF
    return True


# ── Single execution pipeline (CLI + GUI) ─────────────────────────────────

def _allowed_spans(ctx: StoresContext) -> List[Tuple[int, int]]:
    spans = []
    if ctx.nvar and ctx.nvar.found:
        spans.append((ctx.nvar.region_start, ctx.nvar.region_end))
    for sig_off, size, _m in ctx.vss_stores:
        spans.append((sig_off, sig_off + size))
    for size, entry, _sig, _do in ctx.evsa_stores:
        spans.append((entry, entry + size))
    return spans


def execute(data: bytes, ops: List[dict], *, output_path: Optional[Path] = None,
            simulate: bool = False, plan_path: Optional[Path] = None) -> dict:
    """Run a list of parsed operations against a BIOS dump.

    Shared by the CLI (var_edit.py main) and the web GUI (app.py
    /api/var/write) so safety logic exists exactly once.

    Returns a dict:
      ok            bool — False on any fatal error (error field set)
      error         str | None
      messages      list[str] — ordered human-readable per-op lines
      writes        list of {op, var, abs_off, old, new, label}
      reads         list of {op, var, value, raw, label}
      plan_lines    list[str] — re-playable resolved write ops
      plan_path     str | None (when plan_path given and writes exist)
      region        (start, end) | None
      crc_updated   bool
      checksums     int — number of EVSA entry checksums recomputed
      changed_bytes int
      output_path   str | None (set only when a file was written)
      output_sha256 str | None
    """
    result = {
        "ok": False, "error": None,
        "messages": [], "writes": [], "reads": [],
        "plan_lines": [], "plan_path": None,
        "region": None, "crc_updated": False, "checksums": 0,
        "changed_bytes": 0, "output_path": None, "output_sha256": None,
    }

    try:
        ctx, records = list_nvar(data)
    except OpError as e:
        result["error"] = str(e)
        return result

    # Resolve all ops up-front (fails fast on ambiguous/unknown names)
    try:
        resolved = [resolve_var(records, op) for op in ops]
    except OpError as e:
        result["error"] = str(e)
        return result

    writes = [op for op in ops if op["value"] is not None]
    has_writes = bool(writes)
    if has_writes and not simulate and output_path is None and plan_path is None:
        result["error"] = ("Write operations require -o/--output, "
                           "--simulate, or --plan")
        return result

    patch = bytearray(data)
    changes = []           # (abs_off, old, new)
    planned_lines = []

    for op, v in zip(ops, resolved):
        try:
            if op["value"] is None:
                # ── Read ──
                raw = read_value(patch, v, op["offset"], op["size"])
                le = int.from_bytes(raw, "little")
                if op["size"] == 1:
                    val_s = f"{le:#04x}"
                else:
                    val_s = f"0x{le:0{2 * op['size']}X}"
                label = f"{fmt_op(op, v)}  ->  {val_s}  ({raw.hex(' ')})"
                result["messages"].append(label)
                result["reads"].append(
                    {"op": op, "var_offset": v.offset, "value": le,
                     "raw_hex": raw.hex(), "label": label})
            else:
                # ── Write (planned or applied) ──
                abs_off, old, new = write_value(
                    patch, v, op["offset"], op["size"], op["value"])
                old_int = int.from_bytes(old, "little")
                new_int = op["value"]
                planned_lines.append(
                    f"{fmt_op(op, v)}   # was 0x{old_int:0{2 * op['size']}X}")
                changes.append((abs_off, old, new))
                verb = "[simulate]" if simulate else "[patch]"
                label = (f"{verb}    {fmt_op(op, v)}   "
                         f"(0x{old_int:0{2 * op['size']}X} -> "
                         f"0x{new_int:0{2 * op['size']}X})")
                result["messages"].append(label)
                result["writes"].append(
                    {"op": op, "var_offset": v.offset, "abs_off": abs_off,
                     "old_hex": old.hex(), "new_hex": new.hex(), "label": label})
        except OpError as e:
            result["error"] = str(e)
            return result

    result["writes_count"] = len(changes)
    result["reads_count"] = len(result["reads"])
    result["region"] = (ctx.region_start, ctx.region_end)
    result["plan_lines"] = planned_lines

    # Plan file (before applying, so --simulate also saves)
    if plan_path and planned_lines:
        Path(plan_path).write_text(
            "# BIOS var_edit plan — re-apply with --apply\n"
            f"# source sha256: {hashlib.sha256(data).hexdigest()}\n"
            + "\n".join(planned_lines) + "\n",
            encoding="utf-8")
        result["plan_path"] = str(plan_path)

    if simulate:
        return result
    if not changes:
        result["ok"] = True
        return result

    # ── Apply: store-bound validation, checksums, readback ───────────────
    spans = _allowed_spans(ctx)
    diffs = [(i, data[i], patch[i]) for i in range(len(data))
             if data[i] != patch[i]]
    outside = [(i, a, b) for i, a, b in diffs
               if not any(s <= i < e for s, e in spans)]
    if outside:
        result["error"] = (
            f"{len(outside)} changed byte(s) OUTSIDE any parsed store "
            f"(NVAR/VSS/EVSA spans) — refusing to write output; first at "
            f"0x{outside[0][0]:06X}")
        return result

    # NVAR CRC32 footer update (only when an NVAR region is present)
    if ctx.nvar and ctx.nvar.found and ctx.nvar.region_start is not None:
        result["crc_updated"] = _update_nvram_crc32(
            patch, ctx.nvar.region_start, ctx.nvar.region_end)

    # EVSA record checksums (one recompute per touched record)
    touched_records = {}
    for op, v in zip(ops, resolved):
        if v.fmt == FMT_EVSA and v.checksum_pos is not None and op["value"] is not None:
            touched_records[v.offset] = v
    for v in touched_records.values():
        if _recompute_evsa_checksum(patch, v):
            result["checksums"] += 1

    result["changed_bytes"] = len(diffs)

    # Re-parse patched dump and read back every written value
    try:
        _, records2 = list_nvar(bytes(patch))
    except OpError as e:
        result["error"] = f"re-parse after patch failed: {e}"
        return result
    for op, v in zip(ops, resolved):
        if op["value"] is None:
            continue
        if v.offset not in [x.offset for x in records2]:
            result["error"] = f"record @0x{v.offset:06X} vanished after patch!"
            return result
        target = next(x for x in records2 if x.offset == v.offset)
        rb = read_value(bytes(patch), target, op["offset"], op["size"])
        if int.from_bytes(rb, "little") != op["value"]:
            result["error"] = (f"readback mismatch for {fmt_op(op, v)}: "
                               f"got 0x{int.from_bytes(rb, 'little'):X}")
            return result

    if output_path is not None:
        Path(output_path).write_bytes(patch)
        result["output_path"] = str(output_path)
        result["output_sha256"] = hashlib.sha256(patch).hexdigest()

    result["ok"] = True
    return result


# ── CLI ──────────────────────────────────────────────────────────────────

def _fmt_row(v: VarRec) -> str:
    extra = ""
    if v.guid:
        extra += f"  guid={v.guid.hex()}"
    if v.attrs is not None:
        extra += f"  attrs=0x{v.attrs:X}"
    if v.state != 0xFFFFFF:
        extra += f"  state=0x{v.state:06X}"
    return (f"0x{v.offset:06X}  [{v.fmt:4s}]  {v.name[:40]:40s}  "
            f"size={v.total_size:5d}  data={v.data_size:6d}{extra}")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="UEFI Variable Editor (offline) — read/write single "
                    "UEFI variables (NVAR/VSS/EVSA) in BIOS dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Operations (read = no value, write = with '='):
  AMITSESetup:0x0(16)               read 16 bytes at data offset 0
  AMITSESetup:0x0(4)=0x01020304     write 4 bytes little-endian
  SecureBootSetup@0x030365:0x0      disambiguate duplicate name by record
                                    offset (see --list)
  '#' comments and blank lines are ignored in plan files.

Formats: NVAR (AMI Aptio V), VSS (Insyde H2O), EVSA (Phoenix SCT).
  --list shows every parsed variable with its format tag.

Examples:
  %(prog)s dump.bin --list
  %(prog)s dump.bin AMITSESetup:0x0(16)
  %(prog)s dump.bin Setup:0x40(1)=0x01 --simulate
  %(prog)s dump.bin Setup:0x40(1)=0x01 -o patched.bin
  %(prog)s dump.bin --apply plan.txt -o patched.bin
"""
    )
    parser.add_argument("input", help="Path to BIOS dump (.bin)")
    parser.add_argument("ops", nargs="*", metavar="OP",
                        help="Variable operations (see epilog)")
    parser.add_argument("--list", action="store_true",
                        help="List parsed NVAR/VSS/EVSA variables and exit")
    parser.add_argument("-o", "--output",
                        help="Output dump path (required for writes; "
                             "input file is never modified)")
    parser.add_argument("-s", "--simulate", action="store_true",
                        help="Do not write any file — show the plan only")
    parser.add_argument("--apply", metavar="PLAN",
                        help="Read operations from a plan/script file")
    parser.add_argument("--plan", metavar="PLAN",
                        help="Save resolved operations to a re-playable script")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show hex context for reads/writes")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        eprint(f"[!] File not found: {args.input}")
        return 1

    data = input_path.read_bytes()

    # Parse ops (from argv or from --apply plan file)
    if args.apply:
        try:
            ops = read_script(Path(args.apply))
        except OpError as e:
            eprint(f"[!] {e}")
            return 1
    else:
        try:
            ops = [parse_op(t) for t in args.ops]
        except OpError as e:
            eprint(f"[!] {e}")
            return 1

    if args.list:
        try:
            result, variables = list_nvar(data)
        except OpError as e:
            eprint(f"[!] {e}")
            return 1
        for v in variables:
            print("    " + _fmt_row(v))
        region = ""
        if result.region_start is not None:
            region = (f", region 0x{result.region_start:06X}–"
                      f"0x{result.region_end:06X}")
        print(f"[*] {len(variables)} variable record(s) in "
              f"{','.join(result.formats)} format(s){region}")
        if result.notes:
            for n in result.notes:
                print(f"[!] {n}")
        return 0

    if not ops:
        parser.print_help()
        return 1

    output_path = Path(args.output) if args.output else None
    plan_path = Path(args.plan) if args.plan else None

    # Friendly early error when writes would silently do nothing
    writes = [op for op in ops if op["value"] is not None]
    if writes and output_path is None and not args.simulate and not args.plan:
        try:
            _, variables = list_nvar(data)
        except OpError as e:
            eprint(f"[!] {e}")
            return 1
        try:
            resolved = [resolve_var(variables, op) for op in ops]
        except OpError as e:
            eprint(f"[!] {e}")
            return 1
        eprint("[!] Write operations require -o/--output, --simulate, or --plan:")
        for op, v in zip(ops, resolved):
            if op["value"] is not None:
                print(f"    {fmt_op(op, v)}")
        return 1

    res = execute(data, ops, output_path=output_path,
                  simulate=args.simulate, plan_path=plan_path)

    for m in res["messages"]:
        print(m)

    if res["error"]:
        eprint(f"[!] {res['error']}")
        return 1

    if plan_path and res["plan_lines"]:
        print(f"[*] Plan saved: {res['plan_path']} "
              f"({len(res['plan_lines'])} writes)")

    if args.simulate:
        print(f"[*] Simulate only — no file written. "
              f"{res['writes_count']} byte-range change(s).")
        return 0

    if not res["writes_count"]:
        return 0

    # Plan-only mode (--plan without -o): author a script, touch no dump
    if output_path is None:
        print(f"[*] Plan only — no output dump written. Re-apply with "
              f"--apply {res['plan_path']}")
        return 0

    crc_parts = []
    crc_parts.append("NVAR CRC32 footer updated" if res["crc_updated"]
                     else "no NVAR CRC32 footer (not updated)")
    if res["checksums"]:
        crc_parts.append(f"{res['checksums']} EVSA checksum(s) recomputed")
    print(f"[+] Patched {res['writes_count']} byte-range(s) "
          f"({res['changed_bytes']} bytes changed total); "
          + "; ".join(crc_parts))
    print("[+] Readback verified for all writes.")
    print(f"[+] Written: {res['output_path']}")
    print(f"    SHA256: {res['output_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
