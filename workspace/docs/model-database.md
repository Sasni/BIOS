# Model Catalog (facts only)

The repo ships a compact **hardware model catalog** at
`data/models/model_catalog.tsv` — 589 entries (vendor, model name, motherboard
board ID). It contains **only factual, independently-verifiable data**:

| Column | Meaning |
|--------|---------|
| `vendor`    | Lenovo / Dell / HP / Acer / Microsoft / Samsung / GigaByte |
| `model`     | Human-readable model name (e.g. `ThinkPad X1 Carbon`) |
| `board_id`  | Motherboard PCB ID (e.g. `LA-G891P`, `NM-D742`, `6050A3260801-MB-A01`) |

| Vendor | Entries |
|--------|---------|
| Dell   | 364 |
| Lenovo | 146 |
| HP     | 48  |
| Acer   | 25  |
| GigaByte / Microsoft / Samsung | 2 each |

## Why a TSV and why so small?

- **22.5 KB** total. One line per model, tab-separated — trivially diffable,
  auditable, and loadable by anything (Python, awk, grep, spreadsheet).
- No internal lookup keys, no binaries, no serial numbers.

## Regenerating

```bash
python tools/import_model_catalog.py --source-dir "PATH_TO_VENDOR_DB" \
                                     --output data/models/model_catalog.tsv
```

`--source-dir` points at a directory containing the per-vendor `.db` files
(`Lenovo.db`, `Dell.db`, `HP.db`, `Acer.db`, `Microsoft.db`, `Samsung.db`,
`GigaByte.db`). The importer is idempotent and de-duplicates on
(vendor, model, board_id).

## Using it — `sigscan`

```bash
python bioskit.py sigscan bios.bin          # or: python tools/sigscan.py bios.bin
python tools/sigscan.py bios.bin --json --min-len 6 --top 10
```

For each catalog entry it searches the dump for two strings, ranked by
specificity:

1. **model** — most reliable; appears in the SMBIOS/DMI "System Product Name"
   region (around `0x400000` on 16MB BIOS-region dumps).
2. **board_id** — usually only inside compressed UEFI volumes, so rarely
   raw-visible.

## Known limitations (verified against real dumps)

- **8MB dumps are usually the ME/descriptor chip** — no model strings, so
  `sigscan` correctly returns nothing. Identify from the 16/32MB BIOS-region
  dump instead.
- **Board IDs live inside compressed UEFI volumes.** To match them you must
  search decompressed content (parse_bios / ami_parser output), not raw bytes.
- **The catalog is a point-in-time snapshot.** Newer models (e.g. Latitude
  7430, EliteBook 840 G9) are not yet present.
- **No ASUS/MSI** entries (no corresponding `.db` in the source data).

## Licensing / provenance

The catalog contains only **facts**: vendor names, product names and motherboard
board IDs. These are publicly observable hardware identifiers (board IDs are
printed on the PCB silkscreen and appear in public schematics/boardviews), not
creative expression, so re-listing them is not a copyright issue.

It deliberately **excludes** the vendor tool's internal signature strings, which
are the tool author's own technical choices and the part most plausibly
protected as a database/compilation. Those can be re-exported with
`--include-signatures` **only** if you hold the rights to that data.

Do **not** commit any license keys or proprietary binaries alongside this data.
