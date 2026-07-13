"""Stage 4: Recover kernel symbols.

Decision tree:
1. Try readelf -sW on vmlinux (unstripped)
2. If stripped, try vmlinux-to-elf (which recovers from embedded kallsyms)
3. After recovery, check BTF for structure offsets
4. If still no symbols, mark as failed
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from ..utils.btf_utils import REQUIRED_STRUCTS, extract_struct_offsets
from ..utils.elf_utils import (
    has_btf_section,
    has_symbols,
    read_symbol_table,
)

logger = logging.getLogger(__name__)


def _run_cmd(cmd: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _try_readelf_symbols(vmlinux_path: Path) -> dict[str, int]:
    """Method 1: Try reading symbols directly from unstripped vmlinux."""
    logger.info("Method 1: Trying readelf on vmlinux...")
    if not has_symbols(vmlinux_path):
        logger.info("vmlinux appears stripped, skipping readelf method")
        return {}

    symbols = read_symbol_table(vmlinux_path)
    if len(symbols) > 50:  # Meaningful threshold
        logger.info("readelf found %d symbols", len(symbols))
        return symbols

    logger.info("readelf found too few symbols (%d), trying next method", len(symbols))
    return {}


def _try_vmlinux_to_elf_recovery(vmlinux_path: Path, output_dir: Path) -> dict[str, int]:
    """Method 2: Try vmlinux-to-elf which recovers symbols from embedded kallsyms."""
    logger.info("Method 2: Trying vmlinux-to-elf for kallsyms recovery...")

    recovered_vmlinux = output_dir / "vmlinux_recovered"

    proc = _run_cmd(
        ["vmlinux-to-elf", str(vmlinux_path), str(recovered_vmlinux)],
        timeout=300,
    )
    if proc.returncode != 0:
        logger.warning("vmlinux-to-elf failed: %s", proc.stderr)
        return {}

    if not recovered_vmlinux.exists():
        logger.warning("vmlinux-to-elf produced no output")
        return {}

    # Now try reading symbols from the recovered vmlinux
    symbols = read_symbol_table(recovered_vmlinux)
    if len(symbols) > 50:
        logger.info("vmlinux-to-elf recovered %d symbols", len(symbols))
        return symbols

    logger.info("vmlinux-to-elf recovered too few symbols (%d)", len(symbols))
    return {}


def _try_kallsyms_extraction(vmlinux_path: Path) -> dict[str, int]:
    """Method 3: Try extracting kallsyms data directly from the binary.

    This uses pyelftools to read the symbol table instead of the
    external `nm` command.
    """
    logger.info("Method 3: Trying direct kallsyms extraction...")

    symbols: dict[str, int] = {}

    # Use pyelftools to read symbol table instead of nm
    from ..utils.elf_utils import read_symbol_table

    try:
        all_symbols = read_symbol_table(vmlinux_path)
        if len(all_symbols) > 50:
            logger.info("pyelftools extracted %d symbols", len(all_symbols))
            return all_symbols
    except Exception as e:
        logger.debug("pyelftools symbol extraction failed: %s", e)

    return {}


def recover_symbols(vmlinux_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Execute the symbol recovery decision tree.

    Args:
        vmlinux_path: Path to the vmlinux ELF file.
        output_dir: Directory for recovery outputs.

    Returns:
        dict with keys: symbols, has_btf, btf_structs, symbol_count, recovery_method
    """
    vmlinux = Path(vmlinux_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "symbols": {},
        "has_btf": False,
        "btf_structs": {},
        "symbol_count": 0,
        "recovery_method": "none",
    }

    if not vmlinux.exists():
        logger.error("vmlinux not found: %s", vmlinux)
        return result

    # Decision tree
    symbols: dict[str, int] = {}
    method = "none"

    # Method 1: Direct readelf
    symbols = _try_readelf_symbols(vmlinux)
    if symbols:
        method = "readelf"
    else:
        # Method 2: vmlinux-to-elf recovery
        symbols = _try_vmlinux_to_elf_recovery(vmlinux, out_dir)
        if symbols:
            method = "vmlinux-to-elf"
        else:
            # Method 3: Direct kallsyms extraction
            symbols = _try_kallsyms_extraction(vmlinux)
            if symbols:
                method = "kallsyms"

    if not symbols:
        logger.error("All symbol recovery methods failed for %s", vmlinux)
        result["recovery_method"] = "failed"
        return result

    result["symbols"] = symbols
    result["symbol_count"] = len(symbols)
    result["recovery_method"] = method

    logger.info("Symbol recovery complete: %d symbols via %s", len(symbols), method)

    # Check BTF section
    result["has_btf"] = has_btf_section(vmlinux)
    if result["has_btf"]:
        logger.info("BTF section found, extracting struct offsets...")
        btf_structs = extract_struct_offsets(vmlinux, REQUIRED_STRUCTS)
        result["btf_structs"] = btf_structs
        total_fields = sum(len(fields) for fields in btf_structs.values())
        logger.info("BTF: extracted offsets for %d structs, %d total fields",
                     len(btf_structs), total_fields)
    else:
        logger.warning("No BTF section found, struct offsets will need manual specification")

    return result


def run(prev_result: dict[str, Any], work_dir: str | Path) -> dict[str, Any]:
    """Main entry point for symbol recovery stage.

    Args:
        prev_result: Result from kernel_extract stage with 'vmlinux_path' key.
        work_dir: Working directory.

    Returns:
        dict with keys: symbols, has_btf, btf_structs, symbol_count, recovery_method
    """
    work = Path(work_dir)
    recovery_dir = work / "symbol_recovery"

    vmlinux_path = prev_result.get("vmlinux_path")
    if not vmlinux_path:
        logger.error("No vmlinux_path from previous stage")
        return {
            "symbols": {},
            "has_btf": False,
            "btf_structs": {},
            "symbol_count": 0,
            "recovery_method": "failed",
        }

    return recover_symbols(vmlinux_path, recovery_dir)
