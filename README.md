# BIOS Analysis Toolkit

Open-source tools for analyzing, identifying, and repairing BIOS/UEFI firmware dumps.

- **Web GUI** (`app.py`) — drag & drop .bin files, hex viewer, analysis, diff, NVRAM reset
- **CLI** (`bioskit.py`) — unified command-line entry point
- **10 tools** — parse, diff, identify, batch, AMI extract, FIT parser, NVRAM reset, patches
- **2 NVRAM formats** — AMI Aptio V (NVAR) + Insyde H2O (VSS)

## Quick Start

```bash
git clone https://github.com/Sasni/BIOS.git
cd BIOS/workspace
pip install -r requirements.txt

# CLI
python bioskit.py parse bios.bin
python bioskit.py diff original.bin repaired.bin
python bioskit.py nvram corrupted.bin -o repaired.bin

# Web GUI
python app.py
# → http://localhost:5000
```

## Tools

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
| `reset_nvram` | Reset corrupted NVRAM to factory defaults (AMI NVAR + Insyde VSS + EVSA) |
| `me_clean_patch` | Apply ME region clean patch |

## Supported Formats

| Format | Vendor | Detection |
|--------|--------|-----------|
| NVAR | AMI Aptio V | `NVAR` signature, per-variable parsing |
| VSS | Insyde H2O | `$VSS` signature, store-based clearing |
| EVSA | AMI | 42B header, DataSize invalidation |
| AMIBIOSC | AMI (legacy) | Module extraction with LH5 decompression |
| Intel FIT | Intel | Firmware Interface Table (microcode, ACM, Boot Guard) |
| Intel IFD | Intel | Flash Descriptor (ME, BIOS, GbE regions) |

## Features

- **NVRAM reset** — targeted variable clearing (`--target`, `--keep`, `--state`) + donor recovery (`--donor`)
- **FIT parser** — auto-detection of `base_address` via Flash Descriptor, Boot Guard structure validation
- **FPT dead zones** — detection of zeroed FV blocks in Insyde H2O
- **Batch processing** — build model database from multiple dumps
- **Automated redaction** — serials, UUIDs, MACs auto-redacted in analysis output

## Directory Structure

```
workspace/
├── app.py              # Flask Web GUI
├── bioskit.py          # CLI entry point
├── requirements.txt
├── data/
│   ├── raw/            # .bin files (gitignored)
│   ├── parsed/         # Analysis JSON (gitignored)
│   └── models/         # bios_models.json — knowledge base
├── tools/
│   ├── parse_bios.py
│   ├── diff_bios.py
│   ├── batch_process.py
│   ├── identify_bios.py
│   ├── db_manager.py
│   ├── fit_parser.py
│   ├── bios_finder.py
│   ├── ami_parser.py
│   ├── reset_nvram.py
│   └── patches/
├── static/
│   ├── css/style.css
│   └── js/bios-ui.js
├── templates/
│   └── index.html
└── docs/
    ├── region-map.md
    ├── unlock-methods.md
    └── spi-chips.md
```

## Privacy / Redaction

`parse_bios.py` automatically redacts serial numbers, UUIDs, and MAC addresses.

**Never commit to git:** raw .bin files, analysis with `--no-redact`, or any file containing real serials/UUIDs/MACs.

## License

MIT

## Legal Notice

- Only analyze BIOS dumps you legally own/obtained
- Do not share copyrighted BIOS binaries
- This toolkit is for educational and repair purposes only
