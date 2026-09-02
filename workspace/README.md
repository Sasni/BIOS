# BIOS Analysis Toolkit - Open Source Knowledge Base

## Overview

BIOS Analysis Toolkit — open-source tools for analyzing, identifying, and repairing BIOS/UEFI firmware dumps.

- **Web GUI** (`app.py`) — drag & drop .bin files, hex viewer, analysis, diff, NVRAM reset
- **CLI** (`bioskit.py`) — unified command-line entry point for all tools
- **10 tools** — parse, diff, identify, batch, AMI extract, FIT parser, NVRAM reset, patches
- **2 NVRAM formats** — AMI Aptio V (NVAR) + Insyde H2O (VSS)

## Quick Start

```bash
# CLI entry point
python bioskit.py parse bios.bin
python bioskit.py diff original.bin repaired.bin
python bioskit.py nvram corrupted.bin -o repaired.bin
python bioskit.py var dump.bin AMITSESetup:0x0(16)           # read a variable
python bioskit.py var dump.bin Setup:0x40(1)=0x01 -o out.bin # write (offline)

# Or use the Web GUI
python app.py
# → http://localhost:5000 — drag & drop .bin files
```

### Tools

| Tool | Description |
|------|-------------|
| `parse_bios` | Analyze BIOS dump: regions, SMBIOS, UEFI volumes, FIT, AMI modules, NVRAM |
| `diff_bios` | Compare before/after repair BIOS dumps |
| `batch_process` | Batch process directory of BIOS dumps into model database |
| `identify_bios` | Identify unknown BIOS dump against known models |
| `db_manager` | Database management (list, stats, export, dedup) |
| `fit_parser` | Parse Intel Firmware Interface Table (FIT) |
| `bios_finder` | Search BIOS setup variables from IFR text |
| `ami_parser` | Extract modules from AMI BIOS (AMIBIOSC format, LH5 decompression) |
| `reset_nvram` | Reset corrupted NVRAM to factory defaults (AMI NVAR + Insyde VSS) |
| `var_edit` | Read/write single NVAR variables offline — UVT-style `Name:Offset(Size)=Value` grammar, simulate mode, re-playable plan files |
| `me_clean_patch` | Apply ME region clean patch |

## Directory Structure

```
workspace/
├── app.py                    # Flask Web GUI
├── bioskit.py                # CLI entry point
├── requirements.txt
├── data/
│   ├── raw/                  # .bin files (gitignored)
│   ├── parsed/               # Analysis JSON (gitignored)
│   └── models/               # bios_models.json — the knowledge base
├── tools/
│   ├── parse_bios.py         # Main analyzer: regions, SMBIOS, UEFI, FIT, AMI, NVRAM
│   ├── diff_bios.py          # Before/after repair comparison
│   ├── batch_process.py      # Batch processor → model database
│   ├── identify_bios.py      # Identify unknown BIOS against model DB
│   ├── db_manager.py         # Database management (list, stats, export)
│   ├── fit_parser.py         # Intel FIT: microcode, ACM, Boot Guard
│   ├── bios_finder.py        # Search BIOS setup variables from IFR
│   ├── ami_parser.py         # AMI BIOS module extractor (LH5 decompression)
│   ├── reset_nvram.py        # NVRAM reset: AMI NVAR + Insyde VSS
│   ├── var_edit.py           # Single-variable read/write: NVAR+VSS+EVSA (offline)
│   └── patches/              # Documented repair patches
├── static/
│   ├── css/style.css
│   └── js/bios-ui.js         # Vanilla JS frontend
├── templates/
│   └── index.html
└── docs/
    ├── region-map.md
    ├── unlock-methods.md
    └── spi-chips.md
```

## Data Flow

```
BIOS .bin files
       │
       ▼
┌──────────────────┐
│  parse_bios.py   │  →  data/parsed/*.analysis.json
│  (regions, UEFI,       (vendor, model, board, SMBIOS,
│   SMBIOS, FIT,          regions, NVRAM, AMI modules)
│   NVRAM, strings)  │
└──────────────────┘
       │
       ├──────────────────────────┐
       ▼                          ▼
┌──────────────────┐    ┌──────────────────┐
│  batch_process   │    │  reset_nvram.py  │
│  → models DB     │    │  → repaired .bin │
└──────────────────┘    └──────────────────┘
       │
       ▼
┌──────────────────┐    ┌──────────────────┐
│  diff_bios.py    │    │  ami_parser.py   │
│  before/after    │    │  AMI module      │
│  → diff.json     │    │  extraction      │
└──────────────────┘    └──────────────────┘

Web GUI (app.py): drag & drop → Info → Hex → Diff → Fix
```

## Model Database Schema (bios_models.json)

```json
{
  "vendor": "Lenovo",
  "model": "ThinkPad T14 Gen 3",
  "bios_version": "1.23",
  "bios_date": "2023/05/15",
  "board_id": "21AJ",
  "spi_chip": "W25Q256JV",
  "size_mb": 32.0,
  "sha256": "abc123...",
  "regions": [
    {"name": "ME", "offset": "0x00001000", "size": 3145728, "sha256": "...", "entropy": 7.9},
    {"name": "BIOS", "offset": "0x00300000", "size": 29360128, "sha256": "...", "entropy": 7.2},
    {"name": "GBE", "offset": "0x00700000", "size": 65536, "sha256": "...", "entropy": 4.1}
  ],
  "notes": "KBC unlock via ITE 8227E",
  "source_file": "T14G3_1.23.bin",
  "analysis_date": "2024-01-15T10:30:00"
}
```

## Privacy / Redaction

**parse_bios.py automatically redacts:**
- Serial Numbers → `REDACTED`
- UUIDs → `REDACTED`
- MAC Addresses → Only shows candidates, not stored in model DB
- Windows Product Keys → Not extracted

**Never commit to git:**
- Raw .bin files in `data/raw/`
- Analysis files with `--no-redact` flag
- Any file containing real serials/UUIDs/MACs

## Documenting Repair Patterns

When you have before/after pairs:

1. Run `diff_bios.py original.bin repaired.bin`
2. Examine the diff regions - these are the **exact bytes changed**
3. Document in `docs/unlock-methods.md`:

```markdown
### Lenovo ThinkPad T14 Gen 3 (21AJ) - Password Unlock via KBC

**Method:** ITE 8227E KBC unlock
**Changed Regions:**
- NVRAM offset 0x1A3000: 0x00→0xFF (password hash cleared)
- EC RAM offset 0x400: Keyboard controller unlock sequence

**Patch Script:** `tools/patches/t14g3_kbc_unlock.py`
```

## Supported Formats

| Format | Vendor | Detection |
|--------|--------|-----------|
| NVAR | AMI Aptio V | `NVAR` signature, per-variable parsing |
| VSS | Insyde H2O | `$VSS` signature, store-based clearing |
| AMIBIOSC | AMI (legacy) | Module extraction with LH5 decompression |
| Intel FIT | Intel | Firmware Interface Table (microcode, ACM, Boot Guard) |
| Intel IFD | Intel | Flash Descriptor (ME, BIOS, GbE regions) |

## Extending the Tools

### Adding a New Vendor Detector

Edit `extract_smbios_info()` in `parse_bios.py`, add to `vendor_patterns`:

```python
(r'NewVendor\s+BIOS', 'NEWVENDOR', 90),  # regex, name, confidence score
```

### Adding a New NVRAM Format

Add detection in `reset_nvram.py` following the pattern of `parse_vss_stores()`:

```python
def parse_xyz_stores(data: bytes) -> List[VSSStore]:
    """Find XYZ variable stores."""
    # Find signature, parse header, return store list
```

## Contributing

1. Add your BIOS dumps to `data/raw/` (locally, redacted)
2. Run `batch_process.py` to populate database
3. Document findings in `docs/`
4. Submit PR with new model entries (JSON only, no binaries)

## Legal Notice

- Only analyze BIOS dumps you legally own/obtained
- Do not share copyrighted BIOS binaries
- Redact all PII (serials, UUIDs, MACs, keys) before sharing analysis
- This toolkit is for educational and repair purposes only