# SPI Flash Chip Database

> Used for identifying chips, pinouts, capacities, voltages, and programmer compatibility.

---

## Common Laptop SPI Chips (SOIC-8 / WSON-8 / BGA)

### Winbond

| Part Number | Capacity | Package | Voltage | Max Freq | Notes |
|-------------|----------|---------|---------|----------|-------|
| W25Q80BW | 1 MB | SOIC-8 | 3.3V | 104 MHz | Legacy |
| W25Q16JV | 2 MB | SOIC-8 | 3.3V | 104 MHz | Common |
| W25Q32JV | 4 MB | SOIC-8 | 3.3V | 104 MHz | Very common |
| W25Q64JV | 8 MB | SOIC-8 | 3.3V | 104 MHz | Standard |
| W25Q128JV | 16 MB | SOIC-8 | 3.3V | 104 MHz | Common |
| W25Q256JV | 32 MB | SOIC-8 | 3.3V | 104 MHz | Modern laptops |
| W25Q512JV | 64 MB | SOIC-8 | 3.3V | 104 MHz | Rare |
| W25M512JV | 64 MB | SOIC-8 | 3.3V | 104 MHz | Dual die |
| W25N01GV | 128 MB | WSON-8 | 3.3V | 104 MHz | NAND-based SPI |
| W25R128JV | 16 MB | SOIC-8 | 1.8V | 133 MHz | Low voltage |
| W25R256JV | 32 MB | SOIC-8 | 1.8V | 133 MHz | Low voltage |

**ID Codes:** Manufacturer ID `0xEF`, Device IDs: `0x4013` (8M), `0x4014` (16M), `0x4015` (32M), `0x4016` (64M), `0x4017` (128M), `0x4018` (256M), `0x4019` (512M)

---

### Macronix (MXIC)

| Part Number | Capacity | Package | Voltage | Max Freq | Notes |
|-------------|----------|---------|---------|----------|-------|
| MX25L8006E | 1 MB | SOIC-8 | 3.3V | 86 MHz | |
| MX25L1606E | 2 MB | SOIC-8 | 3.3V | 86 MHz | |
| MX25L3206E | 4 MB | SOIC-8 | 3.3V | 104 MHz | |
| MX25L6406E | 8 MB | SOIC-8 | 3.3V | 104 MHz | |
| MX25L12805D | 16 MB | SOIC-8 | 3.3V | 104 MHz | |
| MX25L25605D | 32 MB | SOIC-8 | 3.3V | 104 MHz | |
| MX25L51245G | 64 MB | SOIC-8 | 3.3V | 133 MHz | |
| MX25U12835F | 16 MB | SOIC-8 | 1.8V | 104 MHz | Ultra low power |
| MX25U25635F | 32 MB | SOIC-8 | 1.8V | 104 MHz | Ultra low power |
| MX66L51235F | 64 MB | BGA-24 | 3.3V | 133 MHz | OctaBus |

**ID Codes:** Manufacturer ID `0xC2`, Device IDs: `0x2013` (8M), `0x2014` (16M), `0x2015` (32M), `0x2016` (64M), `0x2017` (128M), `0x2018` (256M)

---

### GigaDevice

| Part Number | Capacity | Package | Voltage | Max Freq | Notes |
|-------------|----------|---------|---------|----------|-------|
| GD25Q80 | 1 MB | SOIC-8 | 3.3V | 104 MHz | Winbond compatible |
| GD25Q16 | 2 MB | SOIC-8 | 3.3V | 104 MHz | |
| GD25Q32 | 4 MB | SOIC-8 | 3.3V | 104 MHz | |
| GD25Q64 | 8 MB | SOIC-8 | 3.3V | 104 MHz | |
| GD25Q128 | 16 MB | SOIC-8 | 3.3V | 104 MHz | |
| GD25Q256 | 32 MB | SOIC-8 | 3.3V | 104 MHz | |
| GD25B256 | 32 MB | SOIC-8 | 3.3V | 133 MHz | Faster |
| GD25LQ128 | 16 MB | SOIC-8 | 1.8V | 104 MHz | Low voltage |
| GD25LQ256 | 32 MB | SOIC-8 | 1.8V | 104 MHz | Low voltage |

**ID Codes:** Manufacturer ID `0xC8`, Device IDs similar to Winbond

---

### ISSI

| Part Number | Capacity | Package | Voltage | Max Freq | Notes |
|-------------|----------|---------|---------|----------|-------|
| IS25LP080D | 1 MB | SOIC-8 | 3.3V | 104 MHz | |
| IS25LP160D | 2 MB | SOIC-8 | 3.3V | 104 MHz | |
| IS25LP320D | 4 MB | SOIC-8 | 3.3V | 104 MHz | |
| IS25LP640D | 8 MB | SOIC-8 | 3.3V | 104 MHz | |
| IS25LP128 | 16 MB | SOIC-8 | 3.3V | 104 MHz | |
| IS25LP256 | 32 MB | SOIC-8 | 3.3V | 104 MHz | |
| IS25WP080 | 1 MB | SOIC-8 | 1.8V | 104 MHz | Low voltage |
| IS25WP256 | 32 MB | SOIC-8 | 1.8V | 104 MHz | Low voltage |

**ID Codes:** Manufacturer ID `0x9D`, Device IDs: `0x6013` (8M), `0x6014` (16M), `0x6015` (32M), `0x6016` (64M), `0x6017` (128M), `0x6018` (256M)

---

### Microchip (SST / Atmel)

| Part Number | Capacity | Package | Voltage | Max Freq | Notes |
|-------------|----------|---------|---------|----------|-------|
| SST25VF080B | 1 MB | SOIC-8 | 3.3V | 50 MHz | Older |
| SST25VF016B | 2 MB | SOIC-8 | 3.3V | 50 MHz | |
| SST25VF032B | 4 MB | SOIC-8 | 3.3V | 50 MHz | |
| SST25VF064C | 8 MB | SOIC-8 | 3.3V | 80 MHz | |
| AT25FF081A | 1 MB | SOIC-8 | 3.3V | 85 MHz | Adesto/Atmel |
| AT25FF321A | 4 MB | SOIC-8 | 3.3V | 85 MHz | |
| AT25SF128A | 16 MB | SOIC-8 | 3.3V | 104 MHz | |
| AT25SF256A | 32 MB | SOIC-8 | 3.3V | 104 MHz | |

**ID Codes:** SST `0xBF` / Atmel `0x1F`

---

### EON / ESMT

| Part Number | Capacity | Package | Voltage | Max Freq | Notes |
|-------------|----------|---------|---------|----------|-------|
| EN25Q80B | 1 MB | SOIC-8 | 3.3V | 104 MHz | |
| EN25Q16 | 2 MB | SOIC-8 | 3.3V | 104 MHz | |
| EN25Q32 | 4 MB | SOIC-8 | 3.3V | 104 MHz | |
| EN25Q64 | 8 MB | SOIC-8 | 3.3V | 104 MHz | |
| EN25Q128 | 16 MB | SOIC-8 | 3.3V | 104 MHz | |
| EN25Q256 | 32 MB | SOIC-8 | 3.3V | 104 MHz | |

**ID Codes:** Manufacturer ID `0x1C`

---

## Programmer Compatibility

### CH341A (Black/Green PCB)
- **Voltage:** 3.3V only (5V mode damages 1.8V chips!)
- **Speed:** ~2 MHz max reliable
- **Support:** Most 3.3V SPI chips up to 32MB
- **Issues:** No 1.8V support, slow, voltage spikes on connect
- **Fix:** Use 3.3V regulator, add series resistors (100Ω), external 3.3V supply

### RT809H / RT809F
- **Voltage:** 1.8V - 3.3V adjustable
- **Speed:** Up to 30 MHz
- **Support:** All common SPI, NAND, eMMC
- **Best for:** Professional repair, 1.8V chips, large capacities

### SVOD3 / SVOD4
- **Voltage:** 1.8V - 3.3V
- **Support:** SPI, NAND, eMMC, UFS
- **Software:** Windows only, Chinese UI

### Bus Pirate v3/v4
- **Voltage:** 3.3V (5V tolerant I/O)
- **Speed:** Up to 8 MHz
- **Support:** Good for debugging, scripting
- **Open source:** Yes

### Raspberry Pi (GPIO Bitbang)
- **Voltage:** 3.3V native
- **Speed:** ~2-4 MHz (flashrom linux_spi)
- **Cost:** $0 if you have Pi
- **Support:** flashrom native

### Dediprog SF100/SF600/SF700
- **Voltage:** 1.2V - 3.6V
- **Speed:** Up to 120 MHz (SF700)
- **Support:** Professional, all chips, API access
- **Price:** $300-1000+

---

## Pinout Reference (SOIC-8 / WSON-8)

```
       1  ══════════  8
       2  ══════════  7
       3  ══════════  6
       4  ══════════  5
```

| Pin | Name | Function |
|-----|------|----------|
| 1 | CS# | Chip Select (Active Low) |
| 2 | DO | Data Out (MISO) |
| 3 | WP# | Write Protect (Active Low) |
| 4 | GND | Ground |
| 5 | DI | Data In (MOSI) |
| 6 | CLK | Serial Clock |
| 7 | HOLD# | Hold (Active Low) / RESET# |
| 8 | VCC | Power (1.8V / 3.3V) |

**Connection to CH341A:**
| CH341A Pin | SPI Signal | Chip Pin |
|------------|------------|----------|
| CS0 | CS# | 1 |
| MISO | DO | 2 |
| (NC) | WP# | 3 - Pull to VCC via 10kΩ |
| GND | GND | 4 |
| MOSI | DI | 5 |
| CLK | CLK | 6 |
| (NC) | HOLD# | 7 - Pull to VCC via 10kΩ |
| VCC/3.3V | VCC | 8 |

**Critical:** For 1.8V chips, use level shifter or RT809H. CH341A 3.3V WILL DAMAGE 1.8V chips.

---

## Chip Identification via Software

### flashrom (Linux)
```bash
# Detect chip
flashrom -p ch341a_spi

# Read
flashrom -p ch341a_spi -r dump.bin

# Write
flashrom -p ch341a_spi -w fixed.bin
```

### Python (using pyftdi or direct USB)
```python
# Read JEDEC ID
# Command 0x9F returns: Manufacturer ID + Memory Type + Capacity
jedec_id = spi.xfer2([0x9F, 0x00, 0x00, 0x00])
mfr_id = jedec_id[1]
mem_type = jedec_id[2]
capacity = jedec_id[3]
```

### JEDEC ID Decoding
```
Manufacturer ID (1 byte) + Memory Type (1 byte) + Capacity (1 byte)

Capacity encoding:
  0x10 = 512 Kb (64 KB)
  0x11 = 1 Mb (128 KB)
  0x12 = 2 Mb (256 KB)
  0x13 = 4 Mb (512 KB)
  0x14 = 8 Mb (1 MB)
  0x15 = 16 Mb (2 MB)
  0x16 = 32 Mb (4 MB)
  0x17 = 64 Mb (8 MB)
  0x18 = 128 Mb (16 MB)
  0x19 = 256 Mb (32 MB)
  0x20 = 512 Mb (64 MB)
```

---

## Common Laptop Chip by Model

| Laptop Series | Typical Chip | Capacity |
|---------------|--------------|----------|
| ThinkPad T480/T490/T14 | W25Q128JV / W25Q256JV | 16/32 MB |
| ThinkPad X1 Carbon 7-9 | W25Q256JV | 32 MB |
| Dell Latitude 5xxx/7xxx | W25Q128JV / MX25L128 | 16 MB |
| Dell Precision 5xxx/7xxx | W25Q256JV | 32 MB |
| HP EliteBook 8xx G8+ | W25Q256JV | 32 MB |
| HP ProBook 4xx G8+ | W25Q128JV / W25Q256JV | 16/32 MB |
| ASUS ROG/ZenBook | MX25L128 / GD25Q128 | 16 MB |
| Acer Predator/Nitro | GD25Q128 / W25Q128 | 16 MB |
| Lenovo IdeaPad/Yoga | W25Q64JV / W25Q128JV | 8/16 MB |
| Microsoft Surface | W25Q256JV (custom) | 32 MB |
| Huawei MateBook | GD25Q128 / W25Q128 | 16 MB |

---

## Adding New Chips

When you encounter an unknown chip:

1. **Read JEDEC ID** with flashrom or programmer
2. **Lookup** in manufacturer datasheet
3. **Add to this table** with:
   - Part number
   - Capacity
   - Package
   - Voltage
   - JEDEC ID bytes
   - Programmer compatibility notes
4. **Test read/write/erase** cycle
5. **Document** any quirks (e.g., "requires 4-byte address mode for >16MB")