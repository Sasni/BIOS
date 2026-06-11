#!/usr/bin/env python3
"""
BIOS Identify Tool - Identifies unknown BIOS dumps against known model database.
"""

import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

# ─── Data Classes ─────────────────────────────────────────────────────────

@dataclass
class MatchResult:
    model_entry: Dict
    score: float
    matched_fields: List[str]
    details: str

# ─── Database Loading ─────────────────────────────────────────────────────

DB_PATH = Path(__file__).parent.parent / "data" / "models" / "bios_models.json"

def load_database() -> List[Dict]:
    if not DB_PATH.exists():
        return []
    try:
        return json.loads(DB_PATH.read_text())
    except Exception as e:
        print(f"[!] Error loading database: {e}")
        return []

# ─── Matching Logic ───────────────────────────────────────────────────────

def calculate_match_score(analysis: Dict, model: Dict) -> Tuple[float, List[str], str]:
    """Calculate match score between analysis and model entry."""
    score = 0.0
    matched = []
    details = []
    
    # Exact SHA256 match (highest confidence)
    if analysis.get("sha256") == model.get("sha256"):
        score += 100.0
        matched.append("sha256")
        details.append("Exact SHA256 match")
        return score, matched, "; ".join(details)
    
    # Vendor match
    if analysis.get("detected_vendor", "").lower() == model.get("vendor", "").lower():
        score += 30.0
        matched.append("vendor")
        details.append(f"Vendor: {model.get('vendor')}")
    
    # Model match (fuzzy)
    analysis_model = analysis.get("detected_model", "").lower()
    model_model = model.get("model", "").lower()
    if analysis_model and model_model:
        if analysis_model == model_model:
            score += 25.0
            matched.append("model_exact")
            details.append(f"Model exact: {model.get('model')}")
        elif analysis_model in model_model or model_model in analysis_model:
            score += 15.0
            matched.append("model_partial")
            details.append(f"Model partial: {model.get('model')}")
    
    # BIOS version match
    if analysis.get("bios_version") == model.get("bios_version") and analysis.get("bios_version") != "Unknown":
        score += 20.0
        matched.append("bios_version")
        details.append(f"BIOS version: {model.get('bios_version')}")
    
    # BIOS date match
    if analysis.get("bios_date") == model.get("bios_date") and analysis.get("bios_date") != "Unknown":
        score += 10.0
        matched.append("bios_date")
        details.append(f"BIOS date: {model.get('bios_date')}")
    
    # Board ID match
    if analysis.get("board_id") == model.get("board_id") and analysis.get("board_id") != "Unknown":
        score += 15.0
        matched.append("board_id")
        details.append(f"Board ID: {model.get('board_id')}")
    
    # File size match
    size_mb = round(analysis.get("file_size", 0) / 1024 / 1024, 2)
    model_size = model.get("size_mb", 0)
    if abs(size_mb - model_size) < 0.1:
        score += 5.0
        matched.append("size")
        details.append(f"Size match: {size_mb}MB")
    
    return score, matched, "; ".join(details)

def identify_bios(analysis_path: Path, top_n: int = 5) -> List[MatchResult]:
    """Identify a BIOS against the database."""
    analysis = json.loads(analysis_path.read_text())
    models = load_database()
    
    if not models:
        print("[!] Database is empty. Run batch_process.py first.")
        return []
    
    print(f"[*] Identifying {analysis_path.name} against {len(models)} models...")
    
    matches = []
    for model in models:
        score, matched, details = calculate_match_score(analysis, model)
        if score > 0:
            matches.append(MatchResult(
                model_entry=model,
                score=score,
                matched_fields=matched,
                details=details
            ))
    
    # Sort by score descending
    matches.sort(key=lambda x: x.score, reverse=True)
    
    return matches[:top_n]

def print_matches(matches: List[MatchResult]) -> None:
    """Pretty print match results."""
    if not matches:
        print("  No matches found.")
        return
    
    print(f"\n{'Rank':>4} {'Score':>6} {'Vendor':<15} {'Model':<25} {'Version':<12} {'Matched Fields'}")
    print("-" * 100)
    
    for i, match in enumerate(matches, 1):
        m = match.model_entry
        print(f"{i:>4} {match.score:>6.1f} {m.get('vendor', ''):<15} {m.get('model', ''):<25} {m.get('bios_version', ''):<12} {', '.join(match.matched_fields)}")
        if match.details:
            print(f"{'':>10}→ {match.details}")

# ─── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Identify unknown BIOS dump against model database")
    parser.add_argument("analysis", help="Analysis JSON from parse_bios.py (or .bin file to analyze first)")
    parser.add_argument("-n", "--top", type=int, default=5, help="Number of top matches to show")
    parser.add_argument("--analyze-first", action="store_true", help="Run parse_bios.py on .bin file first")
    
    args = parser.parse_args()
    
    analysis_path = Path(args.analysis)
    
    # If given a .bin file, analyze it first
    if analysis_path.suffix.lower() == ".bin" or args.analyze_first:
        if not analysis_path.exists():
            print(f"[!] File not found: {analysis_path}")
            sys.exit(1)
        
        print(f"[*] Analyzing {analysis_path} first...")
        import subprocess
        output_path = analysis_path.with_suffix('.analysis.json')
        cmd = [
            sys.executable,
            str(Path(__file__).parent / "parse_bios.py"),
            str(analysis_path),
            "-o", str(output_path)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] Analysis failed: {result.stderr}")
            sys.exit(1)
        analysis_path = output_path
    
    if not analysis_path.exists():
        print(f"[!] Analysis file not found: {analysis_path}")
        sys.exit(1)
    
    matches = identify_bios(analysis_path, args.top)
    print_matches(matches)
    
    # Show best match details
    if matches:
        best = matches[0]
        print(f"\n=== BEST MATCH ===")
        for k, v in best.model_entry.items():
            print(f"  {k}: {v}")

if __name__ == "__main__":
    main()