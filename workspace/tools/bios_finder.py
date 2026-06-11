#!/usr/bin/env python3
"""
BIOS Setting Finder - Extract BIOS setup variables from IFR (Internal Forms Representation)
Based on UEFIExtract's BiosSettingFinder implementation.
Finds BIOS setup variables matching user queries from IFR data.
"""

import re
import sys
import argparse
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import unicodedata

# ─── Data Classes ─────────────────────────────────────────────────────────

@dataclass
class QueryPhrase:
    raw: str
    normalized: str
    tokens: List[str]

@dataclass
class SettingCandidate:
    """A BIOS setting candidate found in IFR"""
    node_name: str = ""
    offset: int = 0
    kind: str = ""          # "Setting", "Checkbox", "Numeric", "Password"
    name: str = ""          # Setting name from IFR
    score: int = 0
    matched_phrase: str = ""
    var_offset: int = 0     # Variable offset (0xXXXX)
    protocol: str = "Unknown"

@dataclass
class IfrNode:
    """Represents a node containing IFR data"""
    name: str
    offset: int
    size: int
    data: bytes
    protocol: str = "Unknown"
    ifr_text: str = ""

# ─── Text Processing Utilities ─────────────────────────────────────────────

def trim(text: str) -> str:
    """Trim whitespace from both ends."""
    return text.strip()

def normalize(text: str) -> str:
    """Normalize text: lowercase, collapse spaces, remove non-alphanumeric."""
    if not text:
        return ""
    result = []
    last_was_space = True
    for ch in text.lower():
        if ch.isalnum():
            result.append(ch)
            last_was_space = False
        elif not last_was_space:
            result.append(' ')
            last_was_space = True
    return trim(''.join(result))

def tokenize(text: str) -> List[str]:
    """Split text into alphanumeric tokens."""
    tokens = []
    current = []
    for ch in text:
        if ch.isalnum():
            current.append(ch)
        elif current:
            tokens.append(''.join(current))
            current = []
    if current:
        tokens.append(''.join(current))
    return tokens

def is_generic_token(token: str) -> bool:
    """Check if token is a generic BIOS term."""
    generic = {
        'lock', 'setting', 'option', 'feature', 'mode',
        'state', 'enable', 'disable', 'support', 'control',
        'menu', 'item', 'value', 'default', 'current',
        'advanced', 'security', 'boot', 'power', 'thermal',
        'chipset', 'system', 'device', 'port', 'interface'
    }
    return token in generic

# ─── Query Parsing ─────────────────────────────────────────────────────────

def parse_query(query: str) -> List[QueryPhrase]:
    """Parse user query into normalized phrases."""
    phrases = []
    current = []
    
    def flush():
        raw = trim(''.join(current))
        current.clear()
        if not raw:
            return
        phrase = QueryPhrase(
            raw=raw,
            normalized=normalize(raw),
            tokens=tokenize(normalize(raw))
        )
        if phrase.normalized and phrase.tokens:
            phrases.append(phrase)
    
    for ch in query:
        if ch in ',;\n\r':
            flush()
        else:
            current.append(ch)
    flush()
    
    if not phrases:
        raw = trim(query)
        norm = normalize(raw)
        tokens = tokenize(norm)
        if norm and tokens:
            phrases.append(QueryPhrase(raw=raw, normalized=norm, tokens=tokens))
    
    return phrases

# ─── Scoring Algorithm ─────────────────────────────────────────────────────

def score_name(normalized_name: str, phrase: QueryPhrase) -> int:
    """Score a setting name against a query phrase."""
    if not normalized_name or not phrase.normalized:
        return 0
    
    # Exact match
    if normalized_name == phrase.normalized:
        return 1400
    
    # Prefix match
    if normalized_name.startswith(phrase.normalized):
        return 1200
    
    # Contains
    if phrase.normalized in normalized_name:
        return 1050
    
    # Token-based scoring
    matched = 0
    generic = 0
    prefix = 0
    
    for token in phrase.tokens:
        pos = normalized_name.find(token)
        if pos == -1:
            continue
        matched += 1
        if is_generic_token(token):
            generic += 1
        if pos == 0 or (pos > 0 and normalized_name[pos-1] == ' '):
            prefix += 1
    
    if matched == 0:
        return 0
    
    score = 110 * matched + 35 * prefix - 90 * generic
    
    if matched == len(phrase.tokens):
        score += 420
    
    if len(phrase.tokens) == 1 and is_generic_token(phrase.tokens[0]):
        score -= 200
    
    return score

def score_candidate(name: str, phrases: List[QueryPhrase]) -> tuple[int, str]:
    """Score a setting name against all query phrases."""
    normalized = normalize(name)
    best_score = 0
    best_phrase = ""
    
    for phrase in phrases:
        score = score_name(normalized, phrase)
        if score > best_score:
            best_score = score
            best_phrase = phrase.raw
    
    return best_score, best_phrase

# ─── IFR Text Extraction ───────────────────────────────────────────────────

# Regex patterns for common IFR output formats
SETTING_REGEX = re.compile(
    r'(Setting|Checkbox|Numeric|Password):\s+(.+?),\s+Variable:\s+0x([0-9A-Fa-f]+)',
    re.IGNORECASE | re.DOTALL
)

NUMERIC_RANGE_REGEX = re.compile(
    r'Numeric:\s+(.+?)\s+\([^)]*\),\s+Variable:\s+0x([0-9A-Fa-f]+)',
    re.IGNORECASE | re.DOTALL
)

def extract_ifr_candidates(
    ifr_text: str,
    phrases: List[QueryPhrase],
    min_score: int = 260
) -> List[SettingCandidate]:
    """Extract BIOS setting candidates from IFR text."""
    candidates = []
    seen = set()
    
    def process_match(match, kind: str, numeric_range: bool):
        if numeric_range:
            name = match.group(1).strip()
            offset_hex = match.group(2)
        else:
            kind = match.group(1).strip()
            name = match.group(2).strip()
            offset_hex = match.group(3)
        
        # Clean name
        name = name.strip()
        while name and name[-1].isspace():
            name = name[:-1]
        
        if not name:
            return
        
        try:
            offset = int(offset_hex, 16)
        except ValueError:
            return
        
        if offset == 0:
            return
        
        score, matched = score_candidate(name, phrases)
        if score < min_score:
            return
        
        # Deduplicate
        dedup_key = f"{kind}:{offset}:{name}"
        if dedup_key in seen:
            return
        seen.add(dedup_key)
        
        candidates.append(SettingCandidate(
            kind=kind,
            name=name,
            offset=offset,
            score=score,
            matched_phrase=matched,
            var_offset=offset
        ))
    
    # Process standard settings
    for match in SETTING_REGEX.finditer(ifr_text):
        process_match(match, "", False)
    
    # Process numeric ranges
    for match in NUMERIC_RANGE_REGEX.finditer(ifr_text):
        process_match(match, "Numeric", True)
    
    # Sort by score (desc), then offset
    candidates.sort(key=lambda c: (-c.score, c.offset, c.name))
    return candidates

# ─── Integration with parse_bios.py ─────────────────────────────────────────

def find_bios_settings(
    analysis_json: Path,
    query: str,
    min_score: int = 260
) -> List[SettingCandidate]:
    """
    Find BIOS settings in an analyzed BIOS dump.
    
    Args:
        analysis_json: Path to .analysis.json from parse_bios.py
        query: Search query (e.g., "secure boot", "password", "virtualization")
        min_score: Minimum score threshold
    """
    import json
    
    with open(analysis_json) as f:
        data = json.load(f)
    
    # This would need actual IFR extraction from the BIOS
    # For now, return empty - integration with IFR parser needed
    return []

# ─── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="BIOS Setting Finder - Search BIOS setup variables from IFR text"
    )
    parser.add_argument("ifr_file", help="IFR text file (output from UEFIExtract ifrscan)")
    parser.add_argument("query", help="Search query (comma-separated phrases)")
    parser.add_argument("-s", "--min-score", type=int, default=260, help="Minimum score")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()
    
    ifr_path = Path(args.ifr_file)
    if not ifr_path.exists():
        print(f"[!] IFR file not found: {ifr_path}")
        return 1
    
    ifr_text = ifr_path.read_text(encoding='utf-8', errors='ignore')
    phrases = parse_query(args.query)
    
    print(f"[*] Searching for: {args.query}")
    print(f"[*] Phrases: {[p.raw for p in phrases]}")
    print(f"[*] IFR size: {len(ifr_text):,} chars")
    
    candidates = extract_ifr_candidates(ifr_text, phrases, args.min_score)
    
    if not candidates:
        print("[!] No BIOS setting candidates found")
        return 0
    
    print(f"\n=== BIOS Setting Candidates ({len(candidates)}) ===")
    print(f"{'Rank':>4} {'Score':>5} {'Kind':<12} {'Offset':>8} {'Name'}")
    print("-" * 80)
    
    for i, c in enumerate(candidates[:50], 1):
        print(f"{i:>4} {c.score:>5} {c.kind:<12} 0x{c.offset:06X}  {c.name}")
        if args.verbose and c.matched_phrase:
            print(f"       → matched: {c.matched_phrase}")
    
    if len(candidates) > 50:
        print(f"... and {len(candidates) - 50} more")
    
    if args.output:
        import json
        out_path = Path(args.output)
        out_data = [
            {
                "kind": c.kind,
                "name": c.name,
                "offset": f"0x{c.offset:X}",
                "score": c.score,
                "matched_phrase": c.matched_phrase,
                "var_offset": f"0x{c.var_offset:X}"
            }
            for c in candidates
        ]
        out_path.write_text(json.dumps(out_data, indent=2))
        print(f"[+] Results saved to {out_path}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())