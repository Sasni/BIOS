# Documented Unlock / Repair Methods

> **Legal/ethical reminder:** Only apply these to hardware you own or have explicit authorization to repair. Document methods generically (offsets, patterns) - never share specific unlocked BIOS files with someone else's serial/UUID/MAC.

---

## Password Unlock Methods

### 1. NVRAM Variable Clearing (Most Common)

**Principle:** BIOS passwords stored in UEFI NVRAM variables. Clearing specific variables removes password.

| Variable GUID | Variable Name | Action |
|---------------|---------------|--------|
| `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` | `Setup` | Clear password fields |
| `8BE4DF61-93CA-11D2-AA0D-00E098032B8C` | `Password` / `AdminPassword` / `UserPassword` | Delete variable |
| `47C7B227-C42A-48CE-81E1-5AD5D3B9E4A5` | `AMITSESetup` | AMI-specific |
| `E8BF8F7E-2BE8-4FF0-AEAA-9E7D6D7F7B5C` | `InsydeH2O` | Insyde-specific |

**Detection:** Scan NVRAM region for these GUIDs + variable names.

**Patch:** Set variable attributes to 0, data to empty, or delete entire variable store entry.

---

### 2. Lenovo KBC (Keyboard Controller) Unlock

**Models:** ThinkPad T14/T15/X1/L14/E14/P14 Gen 1-3, P15, X1 Carbon 7-9, etc.
**Controller:** ITE 8227E / IT8827E / NPCE68BPA0DX / NPCE795

**Mechanism:**
1. KBC stores password hash in EC RAM (not SPI flash)
2. Unlock sequence sent via KBC command port (0x60/0x64)
3. EC verifies and clears password flag in its RAM
4. On next boot, BIOS reads "unlocked" from EC

**Implementation approach:**
- Modify EC firmware image in BIOS region (if EC stored there)
- Or: Patch EC RAM via KBC commands at runtime (requires OS/BIOS access)
- Patch the EC firmware blob in BIOS region

**Known EC RAM offsets (varies by model):**
| Offset | Function |
|--------|----------|
| 0x100-0x120 | Password hash storage |
| 0x200 | Password status flag (0=locked, 1=unlocked) |
| 0x300 | KBC command buffer |

---

### 3. Dell Manufacturing Mode / Service Tag

**Problem:** Laptop stuck in "Manufacturing Mode" - can't enter Service Tag, BIOS locked.

**Fix:** Clear Manufacturing Mode flag in NVRAM:
- Variable: `MfgMode` / `ManufacturingMode` (GUID: `47C7B227-C42A-48CE-81E1-5AD5D3B9E4A5`)
- Set to 0 / Delete variable

**Service Tag Restore:**
- DMI Type 1 (System Information): Serial Number field
- DMI Type 2 (Base Board): Serial Number field  
- NVRAM variable: `ServiceTag` / `AssetTag`
- Some models: Write to specific SPI offset (e.g., 0x1A0000)

---

### 4. HP MPM Lock / Endpoint Security

**Problem:** "HP Endpoint Security Controller" / "MPM Lock" prevents boot.

**Fix:** Clear specific bytes in NVRAM/EC region:
- Search for pattern: `4D 50 4D 00` ("MPM\0")
- Clear surrounding 16-32 bytes
- Or: Modify EC firmware at offset where MPM flag stored

**Models affected:** EliteBook 840/850 G8-G10, ProBook 440/450 G8-G10, ZBook Fury/G9+

---

### 5. Autopilot / MDM Lock (Lenovo/Dell/HP)

**Problem:** Windows Autopilot enrollment locks BIOS settings.

**Fix:** Clear Autopilot-specific NVRAM variables:
- `AutopilotEnrolled`, `MDMEnrolled`, `DeviceRegistered`
- GUIDs often vendor-specific
- Some require: `Setup` variable → `Autopilot` field = 0

---

## Region Repair Methods

### 1. Intel ME Region Clean/Repair

**When:** ME corruption, "ME FW update required", boot loops.

**Methods:**
| Method | Description | Risk |
|--------|-------------|------|
| ME Cleaner | Use `me_cleaner.py` to strip ME to minimal | Medium - may disable AMT |
| ME Region Restore | Copy known-good ME from same chipset/sku | Low if exact match |
| ME Downgrade | Flash older ME version compatible with BIOS | Medium |
| Full ME Rebuild | Use FITC to rebuild ME with platform data | High - complex |

**Key Tool:** `me_cleaner.py` (GitHub: corna/me_cleaner)
```bash
python me_cleaner.py -S -b bios.bin -o bios_me_cleaned.bin
```

---

### 2. GbE (LAN MAC) Region Repair

**When:** MAC address lost (shows 00:00:00:00:00:00 or FF:FF:FF:FF:FF:FF), no LAN.

**Fix:**
1. Locate GbE region (usually 0x700000, 64KB)
2. Find MAC pattern: 6 bytes at offset 0x00-0x10 in region
3. Restore valid MAC:
   - From sticky label on laptop/motherboard
   - From OUI (first 3 bytes = vendor) + random last 3
   - From matching model donor dump

**Structure (Intel GbE region):**
```
Offset 0x00: MAC Address (6 bytes)
Offset 0x10: Checksum (sometimes)
Offset 0x20: PHY config
Offset 0x40: LED config
...
```

---

### 3. DMI/SMBIOS Restore (Serial, UUID, Board ID)

**When:** Serial shows "To Be Filled By O.E.M.", UUID all zeros, Board ID wrong.

**Method:**
1. Locate SMBIOS tables in BIOS region (scan for `_SM_` / `_SM3_`)
2. Parse tables, find Type 0, 1, 2, 3, 11, 17
3. Modify in-place:
   - Type 0: BIOS Vendor, Version, Date
   - Type 1: Manufacturer, Product Name, **Serial Number**, **UUID**, SKU, Family
   - Type 2: Manufacturer, Product, Version, **Serial**, Asset Tag
   - Type 3: Manufacturer, Serial, Asset Tag
   - Type 11: OEM Strings (sometimes contains Service Tag)
   - Type 17: Memory serial/part numbers

**Checksum:** Each SMBIOS structure has 8-bit checksum at end - must recalculate after edit.

**Tools:** `dmidecode` (Linux) to dump, custom script to patch.

---

### 4. EC (Embedded Controller) Firmware Repair

**When:** Keyboard/touchpad/fan not working, battery not charging, KBC unlock needed.

**Chips:** ITE IT8586/IT8587/IT8987, ENE KB9012/KB9026, NPCE NPCE685/NPCE795

**Methods:**
1. **Extract EC from BIOS:** Many vendors store EC firmware in BIOS region (search for "EC\0" or chip signature)
2. **Patch EC binary:** Fix bugs, enable features, unlock KBC
3. **Reflash:** Either via BIOS flash (if EC in BIOS region) or separate EC flash (dedicated SPI chip)

**Caution:** Wrong EC firmware = brick (no keyboard, no power management).

---

### 5. NVRAM Variable Store Reconstruction

**When:** "Enter BIOS Setup" loop, settings not saved, variables corrupted.

**Structure (UEFI Variable Store):**
```
Header: 
  Signature: "NVRA" / "VARSTORE"
  Size, Format, State, Attributes
Entries:
  GUID (16) + NameSize + DataSize + Attributes + Name + Data + Checksum
```

**Fix:**
1. Extract variable store region
2. Parse entries (UEFI spec)
3. Remove corrupted entries (bad checksum, truncated)
4. Rebuild with valid entries only
5. Update header checksum

---

## Vendor-Specific Algorithms

### Lenovo
- **Consumer (IdeaPad/Yoga/Legion):** Phoenix BIOS - password in NVRAM, readable via pattern
- **ThinkPad (Enterprise):** KBC unlock via ITE/NPCE - no DMI loss
- **B590/B490/ThinkCentre:** Specific DMI format, AES-encrypted DMI

### Dell
- **ACME BIOS:** Specific ID detection, password in NVRAM
- **Manufacturing Mode:** NVRAM flag clear
- **Service Tag:** DMI Type 1+2 + NVRAM + sometimes SPI offset

### HP
- **AMI BIOS:** Standard AMI password variables
- **InsydeH2O:** Insyde-specific variables
- **MPM/Endpoint Security:** EC/NVRAM byte patterns
- **16MB/32MB dual chip:** Merge/split logic

### Acer
- **InsydeH2O:** 2 password algorithms (old/new)
- **Aspire 5745G:** Specific unlock algo

### Microsoft Surface
- **UEFI + Insyde:** Custom variable GUIDs, BitLocker integration

### Huawei
- **InsydeH2O:** Models H9BB, CurieF, RolleF, H98A, H95

---

## Documenting Your Own Findings

When you discover a new method:

1. **Create diff:** `diff_bios.py before.bin after.bin`
2. **Analyze changes:** Look at modified regions, byte patterns
3. **Document:**
```markdown
### [Vendor] [Model] ([Board ID]) - [Issue]

**Symptom:** 
**Root Cause:** 
**Fix Method:** 
**Changed Regions:**
- Offset 0xXXXXXX: 0xYY → 0xZZ (description)
**Patch Script:** `tools/patches/[model]_[issue].py`
**Verification:** 
```

4. **Add to database:** Include in `bios_models.json` with `notes` field
5. **Share pattern** (not the binary) via PR

---

## Real-World Repair Patterns (From Analysis)

### Lenovo Legion (stachurki) - 8MB BIOS Region - ME Clean + Rebuild

**Files:** `lenovo legion stachurki.bin` → `lenovo legion stachurki_rep.bin` (8MB each)
**SHA256 Before:** `f096a6155652ad78325c8016cec3d33829f4b9c9386215799ff503117eb15b6e`
**SHA256 After:**  `5ba88a4e570d92c6f010cdda6b70a31445dba58f181ed9c4b80c9f09bc3113b4`

**Changes:** 2,743,836 bytes (32.7%) across 855 regions
**Pattern:** Massive ME region erase (0xFF fill) + BIOS region rebuild

**Key Changed Regions:**
- Offset 0x000080 (20 bytes): Header modification
- Offset 0x003008 (4 bytes): Checksum/update
- Offset 0x004260-0x006A38: Large compressed data sections rewritten
- Offset 0x01C010-0x036AE4: Repeated 384/48-byte blocks rewritten (ME modules?)
- **Many regions filled with 0xFF** (erased to clean state)

**Interpretation:** ME Cleaner-style operation + BIOS region rebuild with clean ME.

---

### Lenovo Legion (stachurki2) - 16MB Full SPI - ME Clean + Region Erase

**Files:** `lenovo legion stachurki2.bin` → `lenovo legion stachurki2_rep.bin` (16MB each)
**SHA256 Before:** `229bbb1b5b2196594f43b19912aab1ffb5c359ca425f4045929bc2d2ac4556f4`
**SHA256 After:**  `ab2c049e30722019256666a01e8c882dee5ebf3cd7482bdbc5cec357677e2ee3`

**Changes:** 4,588,680 bytes (27.4%) across 144 regions
**Pattern:** Large contiguous blocks erased to 0xFF (ME region cleanup)

**Key Changed Regions:**
- Offset 0x00004C (4 bytes): Filled 0xFF (descriptor checksum)
- Offset 0x0016D3 (9,073 bytes): Data → 0xFF fill
- Offset 0x003A61 (41,587 bytes): **Filled with 0xFF** (ME region start)
- Offset 0x00DCF3-0x015279: Multiple large blocks **Filled with 0xFF** (ME firmware)
- Offset 0x02E020-0x02E638: Repeated 49-byte structures → 0xFF (ME modules)
- Offset 0x0616DB, 0x0AE6DA, 0x0BEBC4: BIOS region modules rewritten
- Offset 0x1960C1 (3.3MB): Large BIOS region section rewritten
- Offset 0x880290 (426KB), 0xA34FAE (66KB), 0xBD0154: ME/BIOS modules
- **Extensive 0xFF fills** = ME region erased to clean state

**Interpretation:** Full SPI dump - ME region (0x003A61-0x15279 ≈ 3MB) erased to clean 0xFF, then BIOS region modules rebuilt.

---

### HP (monika walczyk) - 8MB BIOS Region - Complete Rebuild

**Files:** `monika walczyk hp.bin` → `monika walczyk hp_rep.bin` (8MB each)
**SHA256 Before:** `3ae7839aa40bd098c96ce68cee47fc8e3c2e04a8d213ae9082d4b6d17dbbc100`
**SHA256 After:**  `151ebdfa6c4f9b0128935c8fd4bee20868e98cff33ec2526bcab5d2c2d266722`

**Changes:** 3,000,850 bytes (35.8%) across 262 regions
**Pattern:** Complete BIOS region rebuild with 0xFF erasure

**Key Changed Regions:**
- Offset 0x004008 (875 bytes): Empty → MFS header written (`MFS.>` signature)
- Offset 0x004390-0x08E7B: **Massive 0xFF fills** (erasing compressed volumes)
- Offset 0x18018, 0x18C00, 0x18D18, 0x18DE0: Small structures → 0xFF
- Offset 0x20037, 0x20056: Large sections → 0xFF
- Offset 0x201000 (528 bytes): BBL (Boot Block Loader) strings erased
- Offset 0x20E04C (11KB): Data section rewritten
- Offset 0x210D14, 0x210D94, 0x214A4B, 0x217D7A, 0x218059: **0xFF fills**
- Offset 0x22C020-0x22C428: Repeated 49-byte ME modules → 0xFF
- Offset 0x260070-0x2AD08D: ME region completely erased (2MB+)
- Offset 0x4F0D82-0x6DD000: BIOS volumes rewritten
- Offset 0x76C000-0x7D0D17: PE/COFF Executables (EFI apps) rewritten

**Interpretation:** Complete ME erase (0xFF) + MFS (Managed Firmware Service) initialization + BIOS volume rebuild + EFI executable resigning.

---

### Common Pattern Across All 3 Repairs

| Aspect | stachurki (8MB) | stachurki2 (16MB) | HP (8MB) |
|--------|-----------------|-------------------|----------|
| **ME Region** | Erased (0xFF) | Erased (0xFF, ~3MB) | Erased (0xFF, ~2MB) |
| **BIOS Region** | Rebuilt volumes | Rebuilt volumes | Rebuilt + MFS init |
| **0xFF Fill** | Many small regions | Large contiguous blocks | Massive contiguous blocks |
| **Checksums** | Updated at multiple offsets | Updated | Updated |
| **Compression** | Tiano/LZMA volumes | Tiano/LZMA volumes | Tiano/LZMA + PE/COFF |

### Automated Detection Rules for These Patterns

```python
def detect_me_clean(diff_result):
    \"\"\"Detect if diff matches the ME Clean pattern.\"\"\"
    ff_fills = [r for r in diff_result.diff_regions if 'Filled with 0xFF' in r.description]
    large_ff = [r for r in ff_fills if r.size > 1000]
    me_region_erased = any(0x1000 <= r.offset <= 0x300000 for r in large_ff)
    return len(large_ff) > 5 and me_region_erased

def detect_bios_rebuild(diff_result):
    \"\"\"Detect BIOS region rebuild pattern.\"\"\"
    rewritten = [r for r in diff_result.diff_regions if r.size > 100 and 'String change' in r.description]
    bios_region = [r for r in rewritten if r.offset >= 0x300000]
    return len(bios_region) > 10
```

---

## Patch Templates for Common Repairs

See `tools/patches/` for template and examples.