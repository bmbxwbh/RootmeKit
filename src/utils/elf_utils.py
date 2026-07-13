"""ELF file analysis utilities for vmlinux introspection.

Uses pyelftools (Python-native) instead of external readelf/nm/strings
to avoid dependency on binutils being installed on the runner.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

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


def _extract_printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings from binary data.

    Replaces the `strings` command with a pure Python implementation.

    Args:
        data: Raw binary data.
        min_length: Minimum length of strings to return.

    Returns:
        List of printable ASCII strings found in the data.
    """
    result: list[str] = []
    current: list[int] = []

    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
        else:
            if len(current) >= min_length:
                result.append(bytes(current).decode("ascii"))
            current = []

    # Don't forget the last string
    if len(current) >= min_length:
        result.append(bytes(current).decode("ascii"))

    return result


def _open_elf(vmlinux_path: str | Path):
    """Open an ELF file for reading with pyelftools.

    Returns:
        A tuple of (file_handle, ELFFile object).

    Usage:
        f, elf = _open_elf(path)
        try:
            ... use elf ...
        finally:
            f.close()
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        raise FileNotFoundError(f"vmlinux not found: {vmlinux}")
    f = open(vmlinux, "rb")
    try:
        elf = ELFFile(f)
    except Exception:
        f.close()
        raise
    return f, elf


def parse_elf_headers(vmlinux_path: str | Path) -> dict[str, Any]:
    """Parse ELF headers and return architecture, entry point, and section list.

    Uses pyelftools instead of readelf.

    Returns:
        dict with keys: arch (str), entry_point (int), sections (list[str]),
        bits (int, 32 or 64), endian (str 'little' or 'big')
    """
    result: dict[str, Any] = {
        "arch": "unknown",
        "entry_point": 0,
        "sections": [],
        "bits": 64,
        "endian": "little",
    }

    try:
        f, elf = _open_elf(vmlinux_path)
    except (FileNotFoundError, Exception) as e:
        logger.error("Failed to open ELF file: %s", e)
        return result

    try:
        # Architecture from e_machine
        machine = elf.header.e_machine
        arch = _ELF_ARCH_MAP.get(machine, "unknown")
        if arch == "unknown":
            # Try matching by name
            machine_name = elf.header.get("e_machine", "")
            if isinstance(machine_name, str):
                if "AArch64" in machine_name or "aarch64" in machine_name:
                    arch = "aarch64"
                elif "ARM" in machine_name:
                    arch = "arm"
                elif "x86-64" in machine_name or "X86-64" in machine_name:
                    arch = "x86_64"
        result["arch"] = arch

        # Class (32/64 bit)
        result["bits"] = elf.elfclass

        # Endianness
        result["endian"] = elf.little_endian and "little" or "big"

        # Entry point
        result["entry_point"] = elf.header.e_entry

        # Section list
        sections: list[str] = []
        for section in elf.iter_sections():
            name = section.name
            if name:
                sections.append(name)
        result["sections"] = sections

        logger.info("ELF headers: arch=%s, bits=%d, entry=0x%x, sections=%d",
                     result["arch"], result["bits"], result["entry_point"],
                     len(result["sections"]))
    except Exception as e:
        logger.error("Error parsing ELF headers: %s", e)
    finally:
        f.close()

    return result


def read_symbol_table(vmlinux_path: str | Path) -> dict[str, int]:
    """Read symbol table from vmlinux using pyelftools.

    Replaces readelf -sW and nm -D.

    Returns:
        dict mapping symbol_name -> VMA address
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        raise FileNotFoundError(f"vmlinux not found: {vmlinux}")

    symbols: dict[str, int] = {}

    try:
        f, elf = _open_elf(vmlinux_path)
    except (FileNotFoundError, Exception) as e:
        logger.warning("Failed to open ELF file: %s", e)
        return symbols

    try:
        # Iterate over all symbol table sections (.symtab, .dynsym, etc.)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                # Skip null symbols and symbols with empty names
                name = symbol.name
                if not name:
                    continue

                # Get symbol type
                sym_type = symbol.entry.st_info.type
                # STT_FUNC = 2, STT_OBJECT = 1, STT_NOTYPE = 0
                if sym_type not in ("STT_FUNC", "STT_OBJECT", "STT_NOTYPE"):
                    # Also handle numeric values
                    try:
                        type_val = symbol.entry.st_info.type
                        if isinstance(type_val, int):
                            if type_val not in (0, 1, 2):
                                continue
                        else:
                            continue
                    except Exception:
                        continue

                addr = symbol.entry.st_value
                if addr != 0:
                    symbols[name] = addr
    except Exception as e:
        logger.warning("Error reading symbol table: %s", e)
    finally:
        f.close()

    logger.info("Read %d symbols from %s", len(symbols), vmlinux.name)
    return symbols


def has_symbols(vmlinux_path: str | Path) -> bool:
    """Check if vmlinux has a symbol table (not stripped).

    Uses pyelftools instead of readelf.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return False

    count = 0

    try:
        f, elf = _open_elf(vmlinux_path)
    except Exception:
        return False

    try:
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                sym_type = symbol.entry.st_info.type
                # Only count FUNC and OBJECT symbols
                if sym_type in ("STT_FUNC", "STT_OBJECT"):
                    count += 1
                elif isinstance(sym_type, int) and sym_type in (1, 2):
                    count += 1
    except Exception:
        pass
    finally:
        f.close()

    logger.debug("Symbol count (FUNC+OBJECT): %d", count)
    return count > 10  # Arbitrary threshold; stripped kernels have ~0


def has_btf_section(vmlinux_path: str | Path) -> bool:
    """Check if vmlinux has a .BTF section.

    Uses pyelftools instead of readelf.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return False

    try:
        f, elf = _open_elf(vmlinux_path)
    except Exception:
        return False

    try:
        for section in elf.iter_sections():
            if section.name == ".BTF":
                logger.debug("Found .BTF section in %s", vmlinux.name)
                f.close()
                return True
    except Exception:
        pass
    finally:
        if not f.closed:
            f.close()

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

    Uses Python-native string extraction instead of `strings` command.

    For arm64 kernels:
    - Checks the kernel image for embedded CONFIG_ARM64_VA_BITS
    - Falls back to heuristics based on symbol addresses

    Returns:
        VA_BITS value (typically 39, 48, etc.), or None if undetectable.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return None

    # Method 1: Check if we can find VA_BITS from kernel config embedded in vmlinux
    # Use Python-native string extraction instead of `strings` command
    try:
        with open(vmlinux, "rb") as f:
            data = f.read()

        for s in _extract_printable_strings(data, min_length=10):
            if "CONFIG_ARM64_VA_BITS=" in s:
                m = re.search(r"CONFIG_ARM64_VA_BITS=(\d+)", s)
                if m:
                    va_bits = int(m.group(1))
                    logger.info("VA_BITS = %d (from embedded config)", va_bits)
                    return va_bits
    except OSError as e:
        logger.debug("Failed to read vmlinux for VA_BITS detection: %s", e)

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

    Uses Python-native string extraction instead of `strings` command.

    Returns:
        Version string (e.g. '6.1.75-android14-11-g1d7c5bb06c7a'), or None.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        return None

    # Use Python-native string extraction instead of `strings` command
    try:
        with open(vmlinux, "rb") as f:
            data = f.read()

        # Try with default min_length first
        for s in _extract_printable_strings(data, min_length=10):
            if "Linux version" in s:
                m = re.search(r"Linux version (\S+)", s)
                if m:
                    version = m.group(1)
                    logger.info("Kernel version: %s", version)
                    return version

        # Fallback: try with longer minimum string length
        for s in _extract_printable_strings(data, min_length=20):
            if "Linux version" in s:
                m = re.search(r"Linux version (\S+)", s)
                if m:
                    version = m.group(1)
                    logger.info("Kernel version (long strings): %s", version)
                    return version

    except OSError as e:
        logger.error("Failed to read vmlinux for kernel version: %s", e)
        return None

    logger.warning("Could not extract kernel version from %s", vmlinux.name)
    return None


def detect_arch(vmlinux_path: str | Path) -> str:
    """Detect architecture from ELF header.

    Uses pyelftools instead of readelf.

    Returns:
        Architecture string: 'aarch64', 'arm', or 'x86_64'. Defaults to 'aarch64'.
    """
    vmlinux = Path(vmlinux_path)
    if not vmlinux.exists():
        logger.warning("vmlinux not found, defaulting to aarch64")
        return "aarch64"

    try:
        f, elf = _open_elf(vmlinux_path)
    except Exception:
        logger.warning("Failed to open ELF file, defaulting to aarch64")
        return "aarch64"

    try:
        machine = elf.header.e_machine
        arch = _ELF_ARCH_MAP.get(machine, "unknown")
        if arch != "unknown":
            return arch

        # Try by name
        machine_name = elf.header.get("e_machine", "")
        if isinstance(machine_name, str):
            if "AArch64" in machine_name or "aarch64" in machine_name:
                return "aarch64"
            if "ARM" in machine_name:
                return "arm"
            if "x86-64" in machine_name or "X86-64" in machine_name:
                return "x86_64"
    except Exception:
        pass
    finally:
        f.close()

    logger.warning("Could not detect arch from ELF header, defaulting to aarch64")
    return "aarch64"
