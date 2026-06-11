#!/usr/bin/env python3
"""
Database Manager - Manage the BIOS model database.
"""

import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict

DB_PATH = Path(__file__).parent.parent / "data" / "models" / "bios_models.json"

def load_db() -> List[Dict]:
    if not DB_PATH.exists():
        return []
    return json.loads(DB_PATH.read_text())

def save_db(data: List[Dict]) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    DB_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))

def cmd_list(args) -> None:
    models = load_db()
    if not models:
        print("Database is empty.")
        return
    
    print(f"{'Vendor':<20} {'Model':<30} {'Version':<12} {'Date':<12} {'Size':>6} {'Board':<10}")
    print("-" * 95)
    for m in models:
        print(f"{m.get('vendor',''):<20} {m.get('model',''):<30} {m.get('bios_version',''):<12} "
              f"{m.get('bios_date',''):<12} {m.get('size_mb',0):>6.1f}MB {m.get('board_id',''):<10}")
    print(f"\nTotal: {len(models)} models")

def cmd_stats(args) -> None:
    models = load_db()
    if not models:
        print("Database is empty.")
        return
    
    vendors = {}
    total_size = 0
    for m in models:
        v = m.get('vendor', 'Unknown')
        vendors[v] = vendors.get(v, 0) + 1
        total_size += m.get('size_mb', 0)
    
    print(f"Total models: {len(models)}")
    print(f"Total size:   {total_size:.1f} MB")
    print(f"Avg size:     {total_size/len(models):.1f} MB")
    print(f"\nBy vendor:")
    for v, c in sorted(vendors.items(), key=lambda x: -x[1]):
        print(f"  {v:<20}: {c}")

def cmd_export(args) -> None:
    models = load_db()
    if not models:
        print("Database is empty.")
        return
    
    output = Path(args.output) if args.output else Path("bios_models_export.json")
    # Export without internal fields
    export_data = []
    for m in models:
        export_data.append({
            "vendor": m.get("vendor"),
            "model": m.get("model"),
            "bios_version": m.get("bios_version"),
            "bios_date": m.get("bios_date"),
            "board_id": m.get("board_id"),
            "spi_chip": m.get("spi_chip"),
            "size_mb": m.get("size_mb"),
            "regions": m.get("regions"),
            "notes": m.get("notes"),
        })
    output.write_text(json.dumps(export_data, indent=2, ensure_ascii=False))
    print(f"[+] Exported {len(models)} models to {output}")

def cmd_dedup(args) -> None:
    models = load_db()
    if not models:
        print("Database is empty.")
        return
    
    # Deduplicate by vendor+model+version
    seen = {}
    unique = []
    for m in models:
        key = (m.get("vendor"), m.get("model"), m.get("bios_version"))
        if key not in seen:
            seen[key] = m
            unique.append(m)
        else:
            # Keep the one with more regions
            if len(m.get("regions", [])) > len(seen[key].get("regions", [])):
                seen[key] = m
                unique[-1] = m
    
    removed = len(models) - len(unique)
    if removed > 0:
        save_db(unique)
        print(f"[+] Removed {removed} duplicates. {len(unique)} models remaining.")
    else:
        print("No duplicates found.")

def cmd_remove(args) -> None:
    models = load_db()
    if not models:
        print("Database is empty.")
        return
    
    # Find matching models
    matches = []
    for i, m in enumerate(models):
        if (args.vendor and m.get("vendor", "").lower() != args.vendor.lower()):
            continue
        if (args.model and m.get("model", "").lower() != args.model.lower()):
            continue
        if (args.version and m.get("bios_version") != args.version):
            continue
        matches.append((i, m))
    
    if not matches:
        print("No matching models found.")
        return
    
    print("Matches:")
    for i, (idx, m) in enumerate(matches):
        print(f"  {i+1}. {m.get('vendor')} {m.get('model')} {m.get('bios_version')} (index {idx})")
    
    if args.force or input("\nRemove these? (y/N): ").lower() == 'y':
        # Remove in reverse order to keep indices valid
        for idx, _ in sorted(matches, key=lambda x: -x[0]):
            models.pop(idx)
        save_db(models)
        print(f"[+] Removed {len(matches)} model(s)")

def main():
    parser = argparse.ArgumentParser(description="BIOS Model Database Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # list
    subparsers.add_parser("list", help="List all models")
    
    # stats
    subparsers.add_parser("stats", help="Show database statistics")
    
    # export
    p_export = subparsers.add_parser("export", help="Export database to JSON")
    p_export.add_argument("-o", "--output", help="Output file path")
    
    # dedup
    subparsers.add_parser("dedup", help="Remove duplicate entries")
    
    # remove
    p_remove = subparsers.add_parser("remove", help="Remove models matching criteria")
    p_remove.add_argument("--vendor", help="Vendor name")
    p_remove.add_argument("--model", help="Model name")
    p_remove.add_argument("--version", help="BIOS version")
    p_remove.add_argument("-f", "--force", action="store_true", help="Don't prompt")
    
    args = parser.parse_args()
    
    commands = {
        "list": cmd_list,
        "stats": cmd_stats,
        "export": cmd_export,
        "dedup": cmd_dedup,
        "remove": cmd_remove,
    }
    
    commands[args.command](args)

if __name__ == "__main__":
    main()