# BIOS Analysis Toolkit - Open Source Knowledge Base

## Overview

This toolkit enables building an open-source database of BIOS structures, regions, and repair patterns. It consists of:

- **parse_bios.py** - Analyzes BIOS dumps, extracts regions, metadata
- **diff_bios.py** - Compares before/after repair dumps to find exact changes
- **batch_process.py** - Processes multiple BIOS dumps into a model database
- **identify_bios.py** - Identifies unknown BIOS dumps against known models

## Quick Start

```bash
# 1. Analyze a single BIOS dump
python tools/parse_bios.py path/to/bios.bin

# 2. Compare before/after repair
python tools/diff_bios.py original.bin repaired.bin

# 3. Batch process a directory of BIOS dumps
python tools/batch_process.py path/to/bios_dumps/

# 4. Identify an unknown BIOS
python tools/identify_bios.py unknown.bin --analyze-first
```

## Directory Structure

```
workspace/
├── data/
│   ├── raw/           # Original .bin files (gitignored)
│   ├── parsed/        # Analysis JSON outputs
│   └── models/        # bios_models.json - the knowledge base
├── tools/
│   ├── parse_bios.py      # Main analyzer
│   ├── diff_bios.py       # Before/after diff
│   ├── batch_process.py   # Batch processor
│   └── identify_bios.py   # Model identification
├── docs/
│   ├── region-map.md      # Known region layouts per vendor
│   ├── unlock-methods.md  # Documented unlock/repair methods
│   └── spi-chips.md       # SPI flash chip database
└── scripts/
    └── (utility scripts)
```

## Data Flow

```
BIOS .bin files
       │
       ▼
┌──────────────────┐
│  parse_bios.py   │  →  data/parsed/*.analysis.json
│  (extract regions,          (FFS volumes, ME, GbE, NVRAM,
│   metadata, SMBIOS)         SMBIOS, strings, metadata)
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  batch_process.py│  →  data/models/bios_models.json
│  (aggregate into              (ModelEntry: vendor, model,
│   model database)             version, regions, hashes)
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  diff_bios.py    │  →  data/parsed/*.diff.json
│  (before/after   │     (Exact byte changes,
│   comparison)    │      patch scripts)
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  identify_bios.py│  →  Match unknown dumps
│  (lookup against │     to known models
│   database)      │
└──────────────────┘
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

## Extending the Tools

### Adding New Region Detectors

Edit `parse_bios.py`, add to `detect_*_region()` functions:

```python
def detect_custom_region(data: bytes) -> Optional[Dict]:
    positions = find_all(data, b'CUSTOM_SIG')
    return {"detected": len(positions) > 0, "positions": positions}
```

Then register in `analyze_bios()`.

### Adding UEFI Module Parsing

For deeper UEFI analysis, integrate `uefi-firmware-parser`:

```bash
pip install uefi-firmware-parser
```

```python
from uefi_firmware import AutoParser
parser = AutoParser(data)
for module in parser.firmware.modules:
    print(module.name, module.guid, module.size)
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