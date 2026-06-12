# TODO — BIOS Analysis Toolkit

## Zrobione
- [x] Parser NVAR (TotalSize, State, StoreType, Name)
- [x] Primary + backup store detection
- [x] Celowane czyszczenie (`--target`, `--keep`, `--state`)
- [x] VSS (Insyde H2O) — pełna obsługa: detekcja + reset z zachowaniem sygnatury
- [x] EVSA (AMI EVSA) — detekcja + reset (42B header, inwalidacja DataSize)
- [x] FPT dead zones (Insyde H2O) — wykrywanie bloków zer w FV
- [x] Donor recovery (`--donor`) — odtwarzanie 0x00/0x55 z czystego dumpu
- [x] `--scan-dead` — bramkowanie martwych stref (tylko z Insyde evidence)
- [x] AMI parser (AMIBIOSC + LH5)
- [x] Web GUI — drag & drop, Hex, Diff, Fix
- [x] Poprawiona detekcja vendor/model/board (Dell, ASUS)
- [x] NVRAM detection w parse_bios
- [x] Aptio V detection
- [x] FIT parser: auto-detekcja base_address (zamiast `base=0`)
- [x] FIT parser: fix format string `<QIHBB` (version = uint16)
- [x] FIT parser: usunięty crash na `_build_summary()`
- [x] FIT parser: rozmiar mikrokodu z nagłówka (offset 0x20 — TotalSize)
- [x] FIT parser: Boot Guard — walidacja struktur KM/BP, nie tylko wpisów FIT

## FIT parser — dalszy rozwój
- [ ] FIT checksum validation — pole checksum odczytywane ale nigdy nie weryfikowane
  - Specyfikacja Intela definiuje algorytm sumy kontrolnej dla każdego wpisu
  - Warto dodać walidację z raportowaniem błędów (bad checksum)
- [ ] BIOS_SM / BIOS_SM2 / TPM — typy w enumie FitType, całkowicie ignorowane
  - BIOS_SM (0x07) — Startup Module
  - BIOS_SM2 (0x08) — Startup Module v2
  - TPM (0x0C) — TPM initialization entry
  - Dodać parsowanie adresów + podstawową walidację

## Rozpoznawanie formatów
- [ ] Aptio IV (starszy format)
- [ ] Phoenix BIOS parser
- [ ] Dell-specific extensions
- [ ] Lenovo-specific extensions
- [ ] Insyde H2O — VSS2 pełna obsługa (obecnie wykrywany jako VSS)

## Analiza zmiennych
- [ ] EVSA: parsowanie pojedynczych zmiennych (EE-delimited) — obecnie tylko reset całego store
- [ ] VSS: parsowanie pojedynczych zmiennych — obecnie tylko reset całego store
- [ ] SecureBoot: PK, KEK, db, dbx — podgląd
- [ ] Setup / CpuSetup — podgląd
- [ ] BootOrder / DriverOrder
- [ ] Eksport zmiennych do pliku
- [ ] GUI: tabela zmiennych NVRAM

## Integracja
- [ ] UEFITool / UEFIExtract — parsowanie FV
- [ ] ifrextract — parsowanie IFR
- [ ] Własny parser FFS/FV (ulepszony)
- [ ] Dekompresja Tiano/LZMA wolumenów

## Wykrywanie korupcji
- [ ] Bad checksum
- [ ] Invalid state
- [ ] Duplicate GUID
- [ ] Truncated record
- [ ] Naprawa tylko uszkodzonych zmiennych (zamiast czyszczenia całego store)

## Narzędzia
- [x] **Flash Descriptor parser** — parsowanie FD (offset 0x10) → FLREG0–FLREGn ✅ (zaimplementowano w `fit_parser.py`)
  - potrzebne do poprawnego `base_address` dla FIT na 32+ MB (Alder Lake+)
  - przydatne do wykrywania regionów BIOS/ME/GBE w dumpach
- [ ] VSS2 — dedykowany parser (obecnie VSS i VSS2 dzielą ścieżkę)
- [ ] Transfer DMI między plikami
- [ ] Microcode extraction (poza FIT)
- [ ] Batch reset NVRAM
- [ ] GUI: edytor hex z podświetlaniem struktury NVRAM
- [ ] GUI: historia napraw / undo
