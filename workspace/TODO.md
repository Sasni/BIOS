# TODO — BIOS Analysis Toolkit

## Zrobione
- [x] Parser NVAR (TotalSize, State, StoreType, Name)
- [x] Primary + backup store detection
- [x] Celowane czyszczenie (`--target`, `--keep`, `--state`)
- [x] VSS (Insyde H2O) — podstawowa obsługa
- [x] AMI parser (AMIBIOSC + LH5)
- [x] Web GUI — drag & drop, Hex, Diff, Fix
- [x] Poprawiona detekcja vendor/model/board (Dell, ASUS)
- [x] NVRAM detection w parse_bios
- [x] Aptio V detection

## Rozpoznawanie formatów
- [ ] Aptio IV (starszy format)
- [ ] Phoenix BIOS parser
- [ ] Dell-specific extensions
- [ ] Lenovo-specific extensions

## Analiza zmiennych
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
- [ ] Naprawa tylko uszkodzonych zmiennych

## Narzędzia
- [ ] VSS2 — pełna obsługa
- [ ] Transfer DMI między plikami
- [ ] Microcode extraction (poza FIT)
- [ ] Batch reset NVRAM
- [ ] GUI: edytor hex z podświetlaniem struktury NVRAM
- [ ] GUI: historia napraw / undo
