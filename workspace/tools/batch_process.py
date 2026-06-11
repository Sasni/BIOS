#!/usr/bin/env python3
"""
Batch BIOS Processor - Processes multiple BIOS dumps through the analysis pipeline.
"""

import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed

# ─── Data Classes ─────────────────────────────────────────────────────────

@dataclass
class ModelEntry:
    vendor: str
    model: str
    bios_version: str
    bios_date: str
    board_id: str
    spi_chip: str = ""
    size_mb: float = 0.0
    sha256: str = ""
    regions: List[Dict] = None
    notes: str = ""
    source_file: str = ""
    analysis_date: str = ""
    
    def __post_init__(self):
        if self.regions is None:
            self.regions = []
        if not self.analysis_date:
            self.analysis_date = datetime.utcnow().isoformat()

# ─── Database Operations ──────────────────────────────────────────────────

DB_PATH = Path(__file__).parent.parent / "data" / "models" / "bios_models.json"

def load_database() -> List[ModelEntry]:
    if not DB_PATH.exists():
        return []
    try:
        data = json.loads(DB_PATH.read_text())
        return [ModelEntry(**item) for item in data]
    except Exception as e:
        print(f"[!] Error loading database: {e}")
        return []

def save_database(models: List[ModelEntry]) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = [asdict(m) for m in models]
    DB_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print(f"[+] Database saved: {len(models)} models -> {DB_PATH}")

def find_model(models: List[ModelEntry], vendor: str, model: str, bios_version: str) -> Optional[ModelEntry]:
    for m in models:
        if (m.vendor.lower() == vendor.lower() and 
            m.model.lower() == model.lower() and 
            m.bios_version == bios_version):
            return m
    return None

def add_or_update_model(models: List[ModelEntry], entry: ModelEntry) -> List[ModelEntry]:
    existing = find_model(models, entry.vendor, entry.model, entry.bios_version)
    if existing:
        # Update
        idx = models.index(existing)
        models[idx] = entry
        print(f"[~] Updated: {entry.vendor} {entry.model} {entry.bios_version}")
    else:
        models.append(entry)
        print(f"[+] Added: {entry.vendor} {entry.model} {entry.bios_version}")
    return models

# ─── Analysis Integration ─────────────────────────────────────────────────

def run_parse_bios(bin_path: Path, output_dir: Path) -> Path:
    """Run parse_bios.py on a single file."""
    output_path = output_dir / f"{bin_path.stem}.analysis.json"
    cmd = [
        sys.executable,
        str(Path(__file__).parent / "parse_bios.py"),
        str(bin_path),
        "-o", str(output_path)
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"parse_bios failed: {result.stderr}")
    return output_path

def analysis_to_model(analysis_path: Path, bin_path: Path) -> ModelEntry:
    """Convert analysis JSON to ModelEntry."""
    data = json.loads(analysis_path.read_text())
    
    # Extract region info
    regions = []
    for r in data.get("regions", []):
        regions.append({
            "name": r["name"],
            "offset": f"0x{r['offset']:08X}",
            "size": r["size"],
            "sha256": r["sha256"],
            "entropy": r["entropy"]
        })
    
    return ModelEntry(
        vendor=data.get("detected_vendor", "Unknown"),
        model=data.get("detected_model", "Unknown"),
        bios_version=data.get("bios_version", "Unknown"),
        bios_date=data.get("bios_date", "Unknown"),
        board_id=data.get("board_id", "Unknown"),
        spi_chip="",  # Would need manual input or detection
        size_mb=round(data.get("file_size", 0) / 1024 / 1024, 2),
        sha256=data.get("sha256", ""),
        regions=regions,
        source_file=bin_path.name,
    )

# ─── Batch Processing ─────────────────────────────────────────────────────

def process_single(bin_path: Path, parsed_dir: Path, models: List[ModelEntry]) -> ModelEntry:
    print(f"\n[*] Processing: {bin_path.name}")
    analysis_path = run_parse_bios(bin_path, parsed_dir)
    model = analysis_to_model(analysis_path, bin_path)
    models = add_or_update_model(models, model)
    save_database(models)
    return model

def batch_process(input_dir: Path, parsed_dir: Path, workers: int = 1) -> None:
    """Process all .bin files in input directory."""
    bin_files = list(input_dir.glob("*.bin"))
    if not bin_files:
        print(f"[!] No .bin files found in {input_dir}")
        return
    
    print(f"[*] Found {len(bin_files)} BIOS files to process")
    
    models = load_database()
    parsed_dir.mkdir(parents=True, exist_ok=True)
    
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(process_single, f, parsed_dir, models): f for f in bin_files}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] Error processing {futures[future].name}: {e}")
    else:
        for bin_file in bin_files:
            try:
                process_single(bin_file, parsed_dir, models)
            except Exception as e:
                print(f"[!] Error processing {bin_file.name}: {e}")
    
    print(f"\n[+] Batch complete. Database: {len(models)} models")

# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Batch process BIOS dumps into model database")
    parser.add_argument("input_dir", help="Directory containing .bin files")
    parser.add_argument("-p", "--parsed-dir", default="data/parsed", help="Output directory for analysis JSON")
    parser.add_argument("-w", "--workers", type=int, default=1, help="Parallel workers (1 for sequential)")
    parser.add_argument("--db", help="Custom database path")
    
    args = parser.parse_args()
    
    global DB_PATH
    if args.db:
        DB_PATH = Path(args.db)
    
    input_dir = Path(args.input_dir)
    parsed_dir = Path(args.parsed_dir)
    
    if not input_dir.exists():
        print(f"[!] Input directory not found: {input_dir}")
        sys.exit(1)
    
    batch_process(input_dir, parsed_dir, args.workers)

if __name__ == "__main__":
    main()