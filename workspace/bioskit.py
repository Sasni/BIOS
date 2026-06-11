#!/usr/bin/env python3
"""
BIOS Toolkit - Unified CLI Entry Point
Extended with UEFIExtract-inspired tools
"""

import sys
import subprocess
import logging
import argparse
from pathlib import Path
from typing import NamedTuple

# ─── Logger ────────────────────────────────────────────────────────────────────

_log = logging.getLogger(__name__)
_log.addHandler(logging.NullHandler())  # silent by default; caller configures

# ─── Constants ────────────────────────────────────────────────────────────────

EXIT_OK = 0
EXIT_ERR = 1

TOOLS_DIR = Path(__file__).resolve().parent / "tools"


class ToolDef(NamedTuple):
    script: str
    subdir: str | None = None


# Single source of truth: CLI name → ToolDef
TOOL_MAP: dict[str, ToolDef] = {
    "parse":    ToolDef("parse_bios"),
    "diff":     ToolDef("diff_bios"),
    "batch":    ToolDef("batch_process"),
    "identify": ToolDef("identify_bios"),
    "db":       ToolDef("db_manager"),
    "fit":      ToolDef("fit_parser"),
    "find":     ToolDef("bios_finder"),
    "patch":    ToolDef("me_clean_patch", "patches"),
    "nvram":    ToolDef("reset_nvram"),
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_safe_tool_name(name: str) -> bool:
    """Reject names that could escape the tools directory."""
    if not name:
        return False
    dangerous = {"..", "/", "\\", "\0"}
    for ch in dangerous:
        if ch in name:
            return False
    if not name.replace("_", "").replace("-", "").isalnum():
        return False
    return True


def run_tool(tool_name: str, args: list[str], subdir: str | None = None,
             verbose: bool = False) -> int:
    """Run a subtool script from the tools/ directory (or a subdirectory).

    Args:
        tool_name: Base filename without .py extension.
        args: Positional arguments forwarded to the tool.
        subdir: Optional subdirectory inside tools/ (e.g. "patches").
        verbose: If False, suppress subtool stdout; stderr shown only on failure.

    Returns:
        Exit code from the subprocess.
    """
    if not _is_safe_tool_name(tool_name):
        _log.error("Unsafe tool name: %s", tool_name)
        return EXIT_ERR

    tools_base = TOOLS_DIR.resolve()
    if subdir:
        tool_path = (tools_base / subdir / f"{tool_name}.py").resolve()
    else:
        tool_path = (tools_base / f"{tool_name}.py").resolve()

    # Ensure the resolved path is still inside the tools directory
    try:
        tool_path.relative_to(tools_base)
    except ValueError:
        _log.error("Tool path escapes tools directory: %s", tool_path)
        return EXIT_ERR

    if not tool_path.exists():
        _log.error("Tool not found: %s", tool_name)
        return EXIT_ERR

    cmd = [sys.executable, str(tool_path)] + args
    try:
        result = subprocess.run(
            cmd,
            timeout=300,
            stdout=None if verbose else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
        )
        if result.stderr:
            if verbose:
                sys.stderr.write(result.stderr)
            elif result.returncode != 0:
                _log.error("%s: %s", tool_name, result.stderr.strip()[:500])
        return result.returncode
    except subprocess.TimeoutExpired:
        _log.error("Tool timed out after 300s: %s", tool_name)
        return EXIT_ERR
    except FileNotFoundError:
        _log.error("Python interpreter not found: %s", sys.executable)
        return EXIT_ERR
    except OSError as exc:
        _log.error("Failed to run tool %s: %s", tool_name, exc)
        return EXIT_ERR


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="BIOS Analysis Toolkit - Open Source BIOS Knowledge Base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Core Tools:
  parse      Analyze BIOS dump (regions, metadata, SMBIOS, UEFI volumes, FIT)
  diff       Compare before/after repair BIOS dumps
  batch      Batch process directory of BIOS dumps into model database
  identify   Identify unknown BIOS dump against known models
  db         Database management (list, stats, export, dedup, remove)

Advanced Tools:
  fit        Parse Intel Firmware Interface Table (FIT) - microcode, ACM, Boot Guard
  find       BIOS Setting Finder - search BIOS setup variables from IFR text
  patch      Apply documented BIOS patch to a dump
  nvram      Reset corrupted NVRAM to factory defaults

Examples:
  bioskit parse bios.bin
  bioskit diff original.bin repaired.bin
  bioskit batch ./bios_dumps/
  bioskit identify unknown.bin --analyze-first
  bioskit db --stats
  bioskit fit bios.bin --verbose
  bioskit find ifr_output.txt "secure boot, password"
  bioskit patch lenovo_legion_me_clean bios.bin bios_patched.bin
  bioskit nvram corrupted_bios.bin -o repaired_bios.bin
        """
    )

    parser.add_argument(
        "tool",
        choices=list(TOOL_MAP.keys()),
        help="Tool to run",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to the tool",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show subtool output (by default suppressed)",
    )

    args = parser.parse_args()

    if args.tool not in TOOL_MAP:
        parser.print_help()
        return EXIT_ERR

    tool_def = TOOL_MAP[args.tool]
    tool_args = [a for a in args.args if a != "--"]
    return run_tool(tool_def.script, tool_args, tool_def.subdir, verbose=args.verbose)


if __name__ == "__main__":
    import argparse as _ap  # already imported at module level, reuse for parse
    # Pre-parse just -v/--verbose to set log level before main()
    pre_parser = _ap.ArgumentParser(add_help=False)
    pre_parser.add_argument("-v", "--verbose", action="store_true")
    pre_args, _ = pre_parser.parse_known_args()

    logging.basicConfig(
        level=logging.DEBUG if pre_args.verbose else logging.WARNING,
        format="[!] %(levelname)s: %(message)s",
    )
    sys.exit(main())
