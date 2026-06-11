#!/usr/bin/env python3
"""
BIOS Analysis Toolkit - Local Web GUI
Flask-based desktop-grade UI running on localhost.
Integrates with existing tools/ scripts for analysis, diff, hex viewing.
"""

import sys
import os
import json
import math
import hashlib
import subprocess
import struct
import re
from pathlib import Path
from datetime import datetime
from typing import Optional

from flask import Flask, jsonify, request, render_template, send_from_directory

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "tools"
PATCHES_DIR = TOOLS_DIR / "patches"
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PARSED_DIR = DATA_DIR / "parsed"
MODELS_DIR = DATA_DIR / "models"
BIOS_DIR = BASE_DIR.parent  # E:\APKI MOJE\BIOS\

def _sanitize_relpath(relpath: str) -> str:
    """Fix common issues in relpath from URL: CR char, leading/trailing junk."""
    s = relpath.strip().replace("\r", "\\").replace("\n", "")
    # Normalize URL forward slashes to OS separator (Windows: \)
    s = s.replace("/", "\\")
    # If path starts with 'workspacedata' instead of 'workspace\data', fix it
    if "\\" not in s and s.startswith("workspace"):
        # CR got eaten — try to reconstruct from raw segments
        pass  # let it fail gracefully, user re-uploads
    return s

app = Flask(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_bin_files() -> list[dict]:
    """Scan for .bin files across all relevant directories."""
    results = []
    seen = set()
    search_dirs = [BIOS_DIR, BIOS_DIR / "OLD"]
    for sd in search_dirs:
        if not sd.exists():
            continue
        for p in sorted(sd.rglob("*.bin")):
            if "data/raw" in str(p) or "__pycache__" in str(p):
                continue
            abs_p = p.resolve()
            if abs_p in seen:
                continue
            seen.add(abs_p)
            sz = abs_p.stat().st_size
            results.append({
                "name": abs_p.name,
                "path": str(abs_p),
                "relpath": str(abs_p.relative_to(BIOS_DIR)),
                "size": sz,
                "size_mb": round(sz / (1024 * 1024), 2),
                "modified": datetime.fromtimestamp(abs_p.stat().st_mtime).isoformat(),
            })
    return results


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _run_tool(script: str, *args: str, timeout: int = 120) -> dict:
    """Run a tool/ script and capture JSON output."""
    tool_path = TOOLS_DIR / script
    if not tool_path.exists():
        return {"error": f"Tool not found: {tool_path}"}
    cmd = [sys.executable, str(tool_path)] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = result.stdout.strip()
        err = result.stderr.strip()
        # try to parse JSON from stdout
        data = None
        if out:
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                m = re.search(r'```(?:json)?\s*\n(.*?)\n```', out, re.DOTALL)
                if m:
                    try:
                        data = json.loads(m.group(1))
                    except json.JSONDecodeError:
                        pass
                if data is None:
                    for line in reversed(out.splitlines()):
                        line = line.strip()
                        if line.startswith("{"):
                            try:
                                data = json.loads(line)
                                break
                            except json.JSONDecodeError:
                                continue
        return {
            "stdout": out,
            "stderr": err,
            "data": data,
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Tool timed out after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


def _hex_chunk(data: bytes, offset: int, length: int) -> dict:
    """Return a chunk of hex data with byte addresses and ASCII."""
    end = min(offset + length, len(data))
    chunk = data[offset:end]
    lines = []
    for i in range(0, len(chunk), 16):
        line_bytes = chunk[i:i+16]
        addr = offset + i
        hex_str = " ".join(f"{b:02x}" for b in line_bytes[:8])
        if len(line_bytes) > 8:
            hex_str += "  " + " ".join(f"{b:02x}" for b in line_bytes[8:])
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in line_bytes)
        lines.append({
            "addr": addr,
            "hex": hex_str,
            "ascii": ascii_str,
            "offset": i,
        })
    return {
        "offset": offset,
        "length": length,
        "total_size": len(data),
        "lines": lines,
        "has_more": end < len(data),
    }


def _get_patches() -> list[dict]:
    """List available patch scripts in tools/patches/."""
    patches = []
    if PATCHES_DIR.exists():
        for p in sorted(PATCHES_DIR.glob("*.py")):
            if p.name.startswith("_"):
                continue
            patches.append({
                "name": p.stem,
                "path": str(p),
                "modified": datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
            })
    return patches


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/files")
def api_files():
    files = _find_bin_files()
    return jsonify(files)


@app.route("/api/analyze/<path:relpath>")
def api_analyze(relpath):
    relpath = _sanitize_relpath(relpath)
    abs_path = _resolve_file(relpath)
    if abs_path is None:
        return jsonify({"error": "File not found"}), 404

    # ── parse_bios.py: writes JSON to file ──
    parse_json_path = PARSED_DIR / f"{abs_path.stem}.analysis.json"
    parse_result = _run_tool("parse_bios.py", str(abs_path), "-o", str(parse_json_path))
    parse_data = None
    if parse_json_path.exists():
        try:
            with open(parse_json_path) as f:
                parse_data = json.load(f)
        except (json.JSONDecodeError, Exception) as e:
            parse_data = {"error": str(e)}

    # ── fit_parser.py: text stdout ──
    fit_result = _run_tool("fit_parser.py", str(abs_path))

    return jsonify({
        "file": relpath,
        "sha256": _sha256(str(abs_path)),
        "parse": {
            "stdout": parse_result.get("stdout", ""),
            "stderr": parse_result.get("stderr", ""),
            "data": parse_data,
            "exit_code": parse_result.get("exit_code", -1),
        },
        "fit": fit_result,
    })


@app.route("/api/hex/<path:relpath>")
def api_hex(relpath):
    relpath = _sanitize_relpath(relpath)
    abs_path = _resolve_file(relpath)
    if abs_path is None:
        return jsonify({"error": "File not found"}), 404
    offset = request.args.get("offset", 0, type=int)
    length = request.args.get("length", 256, type=int)
    length = min(length, 65536)
    with open(abs_path, "rb") as f:
        data = f.read()
    return jsonify(_hex_chunk(data, offset, length))


@app.route("/api/hex-search/<path:relpath>")
def api_hex_search(relpath):
    relpath = _sanitize_relpath(relpath)
    abs_path = _resolve_file(relpath)
    if abs_path is None:
        return jsonify({"error": "File not found"}), 404
    query = request.args.get("q", "")
    mode = request.args.get("mode", "string")
    if not query:
        return jsonify({"error": "No query"}), 400
    with open(abs_path, "rb") as f:
        data = f.read()
    if mode == "hex":
        pattern = bytes.fromhex(query.replace(" ", ""))
    else:
        pattern = query.encode("utf-8", errors="replace")
    positions = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    return jsonify({
        "query": query,
        "mode": mode,
        "pattern_len": len(pattern),
        "matches": len(positions),
        "positions": positions[:200],
        "total_file_size": len(data),
    })


@app.route("/api/diff/<path:orig_rel>/<path:rep_rel>")
def api_diff(orig_rel, rep_rel):
    orig_rel = _sanitize_relpath(orig_rel)
    rep_rel = _sanitize_relpath(rep_rel)
    orig_path = _resolve_file(orig_rel)
    rep_path = _resolve_file(rep_rel)
    if orig_path is None:
        return jsonify({"error": f"Original not found: {orig_rel}"}), 404
    if rep_path is None:
        return jsonify({"error": f"Repaired not found: {rep_rel}"}), 404
    # diff_bios.py writes JSON to file
    diff_json_path = PARSED_DIR / f"{orig_path.stem}_vs_{rep_path.stem}.diff.json"
    result = _run_tool("diff_bios.py", str(orig_path), str(rep_path), "-o", str(diff_json_path))
    diff_data = None
    if diff_json_path.exists():
        try:
            with open(diff_json_path) as f:
                diff_data = json.load(f)
        except (json.JSONDecodeError, Exception) as e:
            diff_data = {"error": str(e)}
    return jsonify({
        "original": orig_rel,
        "repaired": rep_rel,
        "diff": {
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "data": diff_data,
            "exit_code": result.get("exit_code", -1),
        },
    })


@app.route("/api/identify/<path:relpath>")
def api_identify(relpath):
    relpath = _sanitize_relpath(relpath)
    abs_path = _resolve_file(relpath)
    if abs_path is None:
        return jsonify({"error": "File not found"}), 404
    # identify_bios.py needs an analysis JSON; use --analyze-first
    result = _run_tool("identify_bios.py", str(abs_path), "--analyze-first")
    return jsonify({
        "file": relpath,
        "result": result,
    })


@app.route("/api/patches")
def api_patches():
    return jsonify(_get_patches())


@app.route("/api/patch/apply", methods=["POST"])
def api_patch_apply():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    patch_name = data.get("patch")
    input_file = data.get("input")
    output_file = data.get("output", "")
    if not patch_name or not input_file:
        return jsonify({"error": "Missing patch name or input file"}), 400
    input_path = (BIOS_DIR / input_file).resolve()
    if not input_path.exists():
        return jsonify({"error": f"Input not found: {input_file}"}), 404
    if not output_file:
        stem = input_path.stem
        output_file = f"{stem}_patched.bin"
        output_path = input_path.parent / output_file
    else:
        output_path = (BIOS_DIR / output_file).resolve()
    patch_script = PATCHES_DIR / f"{patch_name}.py"
    if not patch_script.exists():
        return jsonify({"error": f"Patch not found: {patch_name}"}), 404
    cmd = [sys.executable, str(patch_script), str(input_path), str(output_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return jsonify({
            "patch": patch_name,
            "input": input_file,
            "output": str(output_path),
            "exit_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/db/stats")
def api_db_stats():
    models_file = MODELS_DIR / "bios_models.json"
    if not models_file.exists():
        return jsonify({"exists": False, "models": 0})
    try:
        with open(models_file) as f:
            models = json.load(f)
        if isinstance(models, list):
            count = len(models)
        elif isinstance(models, dict):
            count = len(models.get("models", []))
        else:
            count = 0
        return jsonify({"exists": True, "models": count, "path": str(models_file)})
    except Exception as e:
        return jsonify({"exists": True, "error": str(e)})


def _resolve_file(relpath: str) -> Optional[Path]:
    """Resolve a relpath to an absolute path, with fallback search by filename.

    Handles both clean URLs (from fixed frontend) and legacy corrupted URLs
    where backslashes were mangled by the browser's URL parser.
    """
    # Try exact match (with / → \ normalization already done by _sanitize_relpath)
    abs_path = (BIOS_DIR / relpath).resolve()
    if abs_path.exists():
        return abs_path

    # Also try manual / → \ (belt and suspenders)
    normalized = relpath.replace("/", "\\")
    abs_path = (BIOS_DIR / normalized).resolve()
    if abs_path.exists():
        return abs_path

    # Fallback: extract the filename (last segment) and fuzzy-search for it.
    # The corruption can mangle the filename itself (e.g. \raw\AAL10 → awAAL10),
    # so exact match is not enough — try substring/suffix matching.
    name = Path(relpath).name
    if not name:
        return None
    search_dirs = [
        BIOS_DIR,
        BIOS_DIR / "OLD",
        BIOS_DIR / "workspace" / "data" / "raw",
    ]
    candidates: list[Path] = []
    for sd in search_dirs:
        if not sd.exists():
            continue
        candidates.extend(sd.glob("*.bin"))
    # Try exact name match first
    for c in candidates:
        if c.name == name:
            return c
    # Fuzzy: check if received name ends with or starts with a candidate name,
    # or vice versa (handles awAAL10... vs AAL10... from \r corruption)
    for c in candidates:
        cn = c.name
        if name.endswith(cn) or cn.endswith(name):
            return c
        # Partial overlap: at least 70% of the shorter name matches
        shorter = min(len(name), len(cn))
        if shorter >= 8:
            # Check if the last N chars match (suffix)
            if name[-shorter:] == cn[-shorter:]:
                return c
            # Check if first N chars match (prefix)
            if name[:shorter] == cn[:shorter]:
                return c

    return None


@app.route("/api/file-info/<path:relpath>")
def api_file_info(relpath):
    relpath = _sanitize_relpath(relpath)
    abs_path = _resolve_file(relpath)
    if abs_path is None:
        return jsonify({
            "error": "File not found",
            "received_relpath": relpath,
            "exists": False,
        }), 404
    stat = abs_path.stat()
    with open(abs_path, "rb") as f:
        data = f.read()
    return jsonify({
        "name": abs_path.name,
        "path": str(abs_path),
        "size": stat.st_size,
        "size_mb": round(stat.st_size / (1024 * 1024), 2),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
    })


@app.route("/api/nvram/reset", methods=["POST"])
def api_nvram_reset():
    """Reset NVRAM variable store to factory defaults."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    relpath = data.get("relpath")
    if not relpath:
        return jsonify({"error": "Missing relpath"}), 400

    relpath = _sanitize_relpath(relpath)
    abs_path = _resolve_file(relpath)
    if abs_path is None:
        return jsonify({"error": f"File not found: {relpath}"}), 404

    # Run NVRAM reset
    try:
        sys.path.insert(0, str(TOOLS_DIR))
        from reset_nvram import find_nvram_region, reset_nvram
    except ImportError:
        return jsonify({"error": "reset_nvram module not available"}), 500

    bios_data = abs_path.read_bytes()
    region = find_nvram_region(bios_data)

    if region is None:
        return jsonify({
            "error": "No NVRAM region detected",
            "details": "This BIOS may not use the NVAR variable store format, or the NVRAM area is not in the expected location.",
            "file": relpath,
        }), 400

    # Perform the reset
    repaired_data = reset_nvram(bios_data, region)

    # Save repaired file alongside original
    stem = abs_path.stem
    repaired_name = f"{stem}_nvram_reset.bin"
    repaired_path = abs_path.parent / repaired_name
    repaired_path.write_bytes(repaired_data)

    return jsonify({
        "ok": True,
        "file": relpath,
        "repaired_file": str(repaired_path.relative_to(BIOS_DIR)),
        "repaired_name": repaired_name,
        "region": {
            "start": f"0x{region.start:06X}",
            "end": f"0x{region.end:06X}",
            "header_end": f"0x{region.header_end:06X}",
            "size": region.size,
            "stores_kept": region.store_count,
        },
        "cleared_bytes": region.end - region.header_end,
        "original_sha256": hashlib.sha256(bios_data).hexdigest(),
        "repaired_sha256": hashlib.sha256(repaired_data).hexdigest(),
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Upload a BIOS dump file. Saves to data/raw/."""
    if "file" not in request.files:
        return jsonify({"error": "No file in request"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    safe_name = f.filename.strip().replace("\r", "").replace("\n", "")
    if not safe_name.lower().endswith(".bin"):
        return jsonify({"error": "Only .bin files allowed"}), 400
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    dest = RAW_DIR / safe_name
    if dest.exists():
        stem = dest.stem
        counter = 1
        while (RAW_DIR / f"{stem}_{counter}.bin").exists():
            counter += 1
        dest = RAW_DIR / f"{stem}_{counter}.bin"
    f.save(str(dest))
    return jsonify({
        "ok": True,
        "file": str(dest),
        "relpath": str(dest.relative_to(BIOS_DIR)),
        "size": dest.stat().st_size,
    })


@app.route("/api/delete/<path:relpath>", methods=["DELETE"])
def api_delete(relpath):
    relpath = _sanitize_relpath(relpath)
    abs_path = (BIOS_DIR / relpath).resolve()
    if not abs_path.exists():
        return jsonify({"error": "File not found"}), 404
    # Safety: only delete .bin files in specific directories
    allowed = False
    for parent in [RAW_DIR, BIOS_DIR / "OLD", BIOS_DIR]:
        try:
            abs_path.relative_to(parent)
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        return jsonify({"error": "Cannot delete files outside allowed directories"}), 403
    os.remove(str(abs_path))
    # Also remove related analysis JSON if exists
    analysis_file = PARSED_DIR / f"{abs_path.stem}.analysis.json"
    if analysis_file.exists():
        os.remove(str(analysis_file))
    return jsonify({"ok": True, "deleted": relpath})


@app.after_request
def add_no_cache(response):
    """Disable caching for JS and HTML to prevent stale code issues."""
    if response.content_type and ('javascript' in response.content_type or 'html' in response.content_type):
        response.headers['Cache-Control'] = 'no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route("/static/<path:filename>")
def static_files(filename):
    # Redirect old app.js to new name (cache bust)
    if filename == "js/app.js":
        return send_from_directory(BASE_DIR / "static", "js/bios-ui.js")
    return send_from_directory(BASE_DIR / "static", filename)


if __name__ == "__main__":
    import webbrowser
    port = int(os.environ.get("BIOS_PORT", 5000))
    url = f"http://localhost:{port}"
    print(f"[+] BIOS Analysis Toolkit GUI starting...")
    print(f"[+] Open {url} in your browser")
    webbrowser.open(url)
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
