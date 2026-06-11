# Region Map Reference

## Intel Flash Descriptor Layout (Typical)

| Region | Offset | Size | Description |
|--------|--------|------|-------------|
| Descriptor | 0x000000 | 4 KB | Flash Descriptor (IFD) |
| ME (Management Engine) | 0x001000 | ~3 MB | Intel ME/TXE firmware |
| BIOS/UEFI | 0x300000 | Rest | Main BIOS/UEFI firmware |
| GbE (Gigabit Ethernet) | 0x700000 | 64 KB | LAN/MAC configuration |
| PDR (Platform Data) | 0x800000 | Variable | Platform-specific data |

**Note:** Offsets vary by platform (consumer vs workstation, chipset generation).

---

## Vendor-Specific Layouts

### Lenovo (ThinkPad / IdeaPad / Legion)

| Region | Typical Offset | Notes |
|--------|---------------|-------|
| ME | 0x1000 | Often 1.5-5 MB depending on ME version |
| BIOS | 0x300000 / 0x400000 | Main firmware |
| NVRAM | Variable | Often in BIOS region |
| EC | Separate chip / BIOS region | Embedded Controller firmware |
| DMI/SMBIOS | In BIOS region | Type 0,1,2,3,4,11,17,32,41 structures |
| KBC | In EC / separate | Keyboard Controller (ITE/NPCE) |

**Special:** Many modern Lenovo use "KBC Unlock" via ITE 8227E / NPCE68BPA0DX - modifies EC RAM, not SPI directly.

---

### Dell (Latitude / Precision / Inspiron / XPS)

| Region | Typical Offset | Notes |
|--------|---------------|-------|
| ME | 0x1000 | Standard Intel |
| BIOS | 0x300000 | Main firmware |
| NVRAM | In BIOS region | Contains Service Tag, Asset Tag |
| PFR | In BIOS region | Platform Firmware Resilience |
| Manufacturing Mode | NVRAM | Offset varies by model |

**Special:** "Manufacturing Mode Active" fix - clears specific NVRAM variable. Service Tag stored in DMI Type 1 + NVRAM.

---

### HP (EliteBook / ProBook / ZBook)

| Region | Typical Offset | Notes |
|--------|---------------|-------|
| ME | 0x1000 | Standard |
| BIOS | 0x300000 / 0x400000 | Split sometimes (2x chips) |
| MPM | In BIOS/EC | Mobile Platform Management |
| Sure Start | In BIOS | HP's firmware resilience |
| NVRAM | In BIOS | Serial, UUID, MAC, Asset Tag |

**Special:** MPM Lock / Endpoint Security Controller - requires specific byte pattern clear in NVRAM/EC.

---

### ASUS (ROG / VivoBook / ZenBook / Prime)

| Region | Typical Offset | Notes |
|--------|---------------|-------|
| ME | 0x1000 | Standard |
| BIOS | 0x300000 | AMI Aptio V usually |
| NVRAM | In BIOS | Standard UEFI variables |
| ASUS-specific | In BIOS | DMI extensions, fan profiles |

**Special:** AMI Aptio BIOS - uses standard IFR forms for setup.

---

### Acer / Predator / Nitro

| Region | Typical Offset | Notes |
|--------|---------------|-------|
| ME | 0x1000 | Standard |
| BIOS | 0x300000 | InsydeH2O or AMI |
| NVRAM | In BIOS | Insyde H2O variable store |

---

### Microsoft Surface

| Region | Typical Offset | Notes |
|--------|---------------|-------|
| ME | 0x1000 | Custom Microsoft ME |
| BIOS | 0x300000 | Custom UEFI |
| NVRAM | In BIOS | BitLocker keys, TPM data |
| TPM | Separate / In ME | Firmware TPM |

---

### Huawei / MateBook

| Region | Typical Offset | Notes |
|--------|---------------|-------|
| ME | 0x1000 | Standard |
| BIOS | 0x300000 | InsydeH2O |
| NVRAM | In BIOS | Password hints in NVRAM |

---

## Region Entropy Signatures

| Region | Typical Entropy | Notes |
|--------|----------------|-------|
| ME | 7.8 - 8.0 | Highly compressed/encrypted |
| BIOS (code) | 6.5 - 7.5 | Mixed code/data |
| BIOS (compressed) | 7.5 - 7.9 | UEFI modules compressed |
| NVRAM | 3.0 - 5.0 | Sparse, lots of 0xFF/0x00 |
| GbE | 4.0 - 6.0 | MAC + config, partially structured |
| EC | 6.0 - 7.5 | Microcontroller firmware |
| Descriptor | 4.0 - 6.0 | Structured, low entropy |

---

## SMBIOS/DMI Table Types (Common)

| Type | Name | Key Fields |
|------|------|------------|
| 0 | BIOS Information | Vendor, Version, Date, ROM Size |
| 1 | System Information | Manufacturer, Product Name, Serial, UUID, SKU, Family |
| 2 | Base Board | Manufacturer, Product, Version, Serial, Asset Tag |
| 3 | Chassis | Manufacturer, Type, Serial, Asset Tag |
| 4 | Processor | Socket, Type, Family, Manufacturer, ID, Version, Voltage, Speed |
| 11 | OEM Strings | Vendor-specific strings |
| 17 | Memory Device | Locator, Bank, Manufacturer, Serial, Asset Tag, Part Number, Speed |
| 32 | System Boot Information | Boot Status |
| 41 | Onboard Device | Type, Status, Description |
| 126 | Inactive | (End marker) |
| 127 | End-of-Table | (End marker) |

---

## Adding New Region Definitions

Edit `tools/parse_bios.py`:
1. Add detection function: `detect_<name>_region(data)`
2. Register in `analyze_bios()` 
3. Add to `build_region_map()` with standard offsets
4. Document here with vendor-specific offsets

---

## Observed Layouts From Real BIOS Analysis

### Lenovo Legion (stachurki) - 8MB Extracted BIOS Region

| Region | Offset | Size | Notes |
|--------|--------|------|-------|
| BIOS_REGION | 0x000000 | 8 MB | Entire file is BIOS region (no IFD/ME/GBE) |
| UEFI Volumes | Scattered | Variable | Compressed (Tiano/LZMA), high entropy ~7.2 |
| ME Modules | Embedded | ~384/48 bytes | Repeated structures inside BIOS region |

**Observed:** No standard IFD layout - this is an extracted BIOS region from a Lenovo Legion laptop. ME firmware is embedded within BIOS region as modules.

---

### Lenovo Legion (stachurki2) - 16MB Full SPI Dump

| Region | Offset | Size | Notes |
|--------|--------|------|-------|
| Descriptor | 0x000000 | 4 KB | All zeros (0x00) |
| ME Region | 0x001000 | ~3 MB | 0x0016D3-0x15279 (erased to 0xFF after repair) |
| BIOS Region | 0x300000 | ~13 MB | Main firmware, contains UEFI volumes |
| GBE Region | 0x700000 | 64 KB | Standard |

**Observed (Pre-repair):**
- ME region at 0x1000-0x300000 contains active ME firmware
- Repair erases ME region (0x003A61-0x15279) to 0xFF
- Descriptor at 0x4C updated (checksum)

**Observed (Post-repair):**
- ME region clean (0xFF)
- BIOS region modules rewritten

---

### HP (monika walczyk) - 8MB Extracted BIOS Region

| Region | Offset | Size | Notes |
|--------|--------|------|-------|
| BIOS_REGION | 0x000000 | 8 MB | Extracted BIOS region |
| MFS Header | 0x004008 | ~875 bytes | Managed Firmware Service (post-repair) |
| ME Modules | 0x22C020-0x22C428 | 49 bytes each | Repeated, erased to 0xFF |
| ME Firmware | 0x260070-0x2AD08D | ~2 MB | Erased to 0xFF |
| BBL (Boot Block) | 0x201000 | 528 bytes | Boot Block Loader strings |
| PE/COFF Executables | 0x76C000-0x7D0D17 | Variable | EFI applications, rewritten post-repair |

**Observed (Pre-repair):**
- Compressed UEFI volumes throughout (entropy ~6.9)
- ME modules embedded at 0x22C020+

**Observed (Post-repair):**
- MFS header written at 0x4008 (`MFS.>` signature)
- ME region erased to 0xFF (0x22C020-0x2AD08D)
- PE/COFF executables resigned/rewritten

---

### Common Repair Patterns (All Vendors)

| Pattern | Offset Range | Action |
|---------|-------------|--------|
| ME Region Erase | 0x001000-0x300000 | Fill 0xFF (clean state) |
| ME Module Erase | Vendor-specific | 49-byte structs → 0xFF |
| BIOS Volume Rebuild | 0x300000+ | Recompress/replace volumes |
| Checksum Updates | Descriptor, modules | Recalculate |
| MFS Init (HP) | 0x4008 | Write `MFS.>` header |
| BBL Update (HP) | 0x201000 | Clear strings |
| PE/COFF Resign (HP) | 0x76C000+ | Rewrite EFI apps |