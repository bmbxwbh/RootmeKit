"""ELF file analysis utilities for vmlinux introspection."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Architecture mapping from ELF e_machine values
_ELF_ARCH_MAP: dict[int, str] = {
    0x3E: "x86_64",
    0xB7: "aarch64",
    0x28: "arm",
}

# Known _stext-like symbols for KIMAGE_TEXT_BASE determination
_STEXT_SYMBOLS = (
    "_stext",
    "_text",
    "stext",
    "__init_begin",
)


def _run_cmd(cmd: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def parse_elf_headers(vmlinux_path: str | Path) -> dict[str, Any]:
    """Parse ELF headers and return architecture, entry point, and section list.

    Returns:
        dict with keys: arch (str), entry_point (int), sections (list[str]),
        bits (int, 32 or 64), endian (str 'little' or 'big')
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        raise FileNotFoundError(f"vmlinux not found: {vmlinux}")

    result: dict[str, Any] = {
        "arch": "unknown",
        "entry_point": 0,
        "sections": [],
        "bits": 64,
        "endian": "little",
    }

    # Use readelf -h to get header info
    proc = _run_cmd(["readelf", "-hW", str(vmlinux)])
    if proc.returncode != 0:
        logger.error("readelf -hW failed: %s", proc.stderr)
        return result

    header = proc.stdout

    # Parse Machine
    m = re.search(r"Machine:\s+(.+)", header)
    if m:
        machine = m.group(1).strip()
        if "AArch64" in machine or "aarch64" in machine:
            result["arch"] = "aarch64"
        elif "ARM" in machine:
            result["arch"] = "arm"
        elif "Advanced Micro Devices X86-64" in machine or "x86-64" in machine:
            result["arch"] = "x86_64"

    # Parse Class (32/64 bit)
    m = re.search(r"Class:\s+ELF(\d+)", header)
    if m:
        result["bits"] = int(m.group(1))

    # Parse Data (endian)
    m = re.search(r"Data:\s+.+(little|big)", header, re.IGNORECASE)
    if m:
        result["endian"] = m.group(1).lower()

    # Parse Entry point
    m = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", header)
    if m:
        result["entry_point"] = int(m.group(1), 16)

    # Get section list
    proc = _run_cmd(["readelf", "-SW", str(vmlinux)])
    if proc.returncode == 0:
        sections: list[str] = []
        for line in proc.stdout.splitlines():
            m = re.search(r"\]\s+(\S+)\s+", line)
            if m and m.group(1) not in ("Name", ""):
                sections.append(m.group(1))
        result["sections"] = sections

    logger.info("ELF headers: arch=%s, bits=%d, entry=0x%x, sections=%d",
                result["arch"], result["bits"], result["entry_point"],
                len(result["sections"]))
    return result


def read_symbol_table(vmlinux_path: str | Path) -> dict[str, int]:
    """Read symbol table from vmlinux using readelf.

    Returns:
        dict mapping symbol_name -> VMA address
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        raise FileNotFoundError(f"vmlinux not found: {vmlinux}")

    symbols: dict[str, int] = {}

    # Try readelf -sW first (wider output, no line wrapping)
    proc = _run_cmd(["readelf", "-sW", str(vmlinux)])
    if proc.returncode != 0:
        logger.warning("readelf -sW failed: %s", proc.stderr)
        # Try nm as fallback
        proc = _run_cmd(["nm", "-D", str(vmlinux)])
        if proc.returncode != 0:
            logger.error("nm -D also failed: %s", proc.stderr)
            return symbols

        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    addr = int(parts[0], 16)
                    name = parts[2]
                    symbols[name] = addr
                except (ValueError, IndexError):
                    continue
        return symbols

    # Parse readelf output
    # Format: Num: Value Size Type Bind Vis Ndx Name
    for line in proc.stdout.splitlines():
        # Match lines with symbol info
        m = re.match(
            r"\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)",
            line,
        )
        if m:
            try:
                addr = int(m.group(1), 16)
                sym_type = m.group(2)
                name = m.group(3)
                # Only include FUNC, OBJECT, NOTYPE (skip SECTION, FILE, etc.)
                if sym_type in ("FUNC", "OBJECT", "NOTYPE"):
                    symbols[name] = addr
            except (ValueError, IndexError):
                continue

    logger.info("Read %d symbols from %s", len(symbols), vmlinux.name)
    return symbols


def has_symbols(vmlinux_path: str | Path) -> bool:
    """Check if vmlinux has a symbol table (not stripped)."""
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return False

    proc = _run_cmd(["readelf", "-sW", str(vmlinux)])
    if proc.returncode != 0:
        return False

    # Count meaningful symbol entries
    count = 0
    for line in proc.stdout.splitlines():
        m = re.match(
            r"\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+(FUNC|OBJECT)\s+",
            line,
        )
        if m:
            count += 1

    logger.debug("Symbol count (FUNC+OBJECT): %d", count)
    return count > 10  # Arbitrary threshold; stripped kernels have ~0


def has_btf_section(vmlinux_path: str | Path) -> bool:
    """Check if vmlinux has a .BTF section."""
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return False

    proc = _run_cmd(["readelf", "-SW", str(vmlinux)])
    if proc.returncode != 0:
        return False

    for line in proc.stdout.splitlines():
        if ".BTF" in line:
            logger.debug("Found .BTF section in %s", vmlinux.name)
            return True

    logger.debug("No .BTF section found in %s", vmlinux.name)
    return False


def find_kimage_base(symbols: dict[str, int]) -> int | None:
    """Find KIMAGE_TEXT_BASE from known symbols like _stext or _text.

    Returns:
        The base address, or None if no suitable symbol is found.
    """
    for sym_name in _STEXT_SYMBOLS:
        if sym_name in symbols:
            addr = symbols[sym_name]
            logger.info("KIMAGE_TEXT_BASE = 0x%x (from %s)", addr, sym_name)
            return addr

    # Try searching with prefix patterns
    for name, addr in symbols.items():
        for sym in _STEXT_SYMBOLS:
            if name == sym:
                logger.info("KIMAGE_TEXT_BASE = 0x%x (from %s)", addr, name)
                return addr

    logger.warning("Could not determine KIMAGE_TEXT_BASE from symbols")
    return None


def detect_va_bits(vmlinux_path: str | Path) -> int | None:
    """Detect VA_BITS from kernel Image header or known PAGE_OFFSET patterns.

    For arm64 kernels:
    - Checks the kernel image header for VA_BITS info
    - Falls back to heuristics based on symbol addresses

    Returns:
        VA_BITS value (typically 39, 48, etc.), or None if undetectable.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return None

    # Method 1: Check if we can find VA_BITS from kernel config embedded in vmlinux
    proc = _run_cmd(["strings", str(vmlinux)])
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            if "CONFIG_ARM64_VA_BITS=" in line:
                m = re.search(r"CONFIG_ARM64_VA_BITS=(\d+)", line)
                if m:
                    va_bits = int(m.group(1))
                    logger.info("VA_BITS = %d (from embedded config)", va_bits)
                    return va_bits

    # Method 2: Heuristic from symbol addresses
    # If we have symbols, check the highest address to guess VA_BITS
    symbols = read_symbol_table(vmlinux_path)
    if symbols:
        max_addr = max(symbols.values())
        if max_addr > 0:
            # For arm64 with VA_BITS=48, kernel addresses are in the range
            # 0xFFFF000000000000 - 0xFFFFFFFFFFFFFFFF
            # For VA_BITS=39, kernel addresses are in lower ranges
            if max_addr > 0xFFFF000000000000:
                # Definitely 48-bit or more
                va_bits = 48
            elif max_addr > 0x800000000000:
                va_bits = 39
            elif max_addr > 0xFFFFFF8000000000:
                va_bits = 48
            else:
                # Try to compute from top bit position
                bit_len = max_addr.bit_length()
                if bit_len >= 48:
                    va_bits = 48
                elif bit_len >= 39:
                    va_bits = 39
                else:
                    va_bits = None

            if va_bits:
                logger.info("VA_BITS = %d (heuristic from max symbol addr 0x%x)",
                            va_bits, max_addr)
                return va_bits

    # Method 3: Default for arm64 GKI (most common is 48)
    logger.warning("Could not detect VA_BITS, defaulting to 48 for arm64")
    return 48


def extract_kernel_version(vmlinux_path: str | Path) -> str | None:
    """Extract kernel version string from vmlinux.

    Searches for 'Linux version' strings in the binary.

    Returns:
        Version string (e.g. '6.1.75-android14-11-g1d7c5bb06c7a'), or None.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return None

    # Use strings + grep for "Linux version"
    proc = _run_cmd(
        ["strings", str(vmlinux)],
        timeout=300,  # vmlinux can be large
    )
    if proc.returncode != 0:
        logger.error("strings command failed: %s", proc.stderr)
        return None

    # Find Linux version string
    for line in proc.stdout.splitlines():
        if "Linux version" in line:
            # Extract the version number
            m = re.search(r"Linux version (\S+)", line)
            if m:
                version = m.group(1)
                logger.info("Kernel version: %s", version)
                return version

    # Fallback: try with longer minimum string length
    proc = _run_cmd(["strings", "-n", "20", str(vmlinux)], timeout=300)
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            m = re.search(r"Linux version (\S+)", line)
            if m:
                version = m.group(1)
                logger.info("Kernel version (long strings): %s", version)
                return version

    logger.warning("Could not extract kernel version from %s", vmlinux.name)
    return None


def detect_arch(vmlinux_path: str | Path) -> str:
    """Detect architecture from ELF header.

    Returns:
        Architecture string: 'aarch64', 'arm', or 'x86_64'. Defaults to 'aarch64'.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        logger.warning("vmlinux not found, defaulting to aarch64")
        return "aarch64"

    proc = _run_cmd(["readelf", "-hW", str(vmlinux)])
    if proc.returncode != 0:
        logger.warning("readelf failed, defaulting to aarch64")
        return "aarch64"

    m = re.search(r"Machine:\s+(.+)", proc.stdout)
    if m:
        machine = m.group(1).strip()
        if "AArch64" in machine or "aarch64" in machine:
            return "aarch64"
        if "ARM" in machine:
            return "arm"
        if "x86-64" in machine or "X86-64" in machine:
            return "x86_64"

    logger.warning("Could not detect arch from ELF header, defaulting to aarch64")
    return "aarch64"
