"""BTF (BPF Type Format) parsing utilities for structure offset extraction.

Uses pyelftools for DWARF fallback and shutil.which instead of
the external `which` command. Keeps pahole as primary tool since
it's installed by the workflow, but gracefully handles its absence.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)

# Required structures for exploit generation
REQUIRED_STRUCTS = ("task_struct", "cred", "pipe_buffer", "mm_struct", "page")


def _run_cmd(cmd: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def extract_struct_offsets(
    vmlinux_path: str | Path,
    struct_names: tuple[str, ...] | list[str] | None = None,
) -> dict[str, dict[str, int]]:
    """Use pahole to extract structure field offsets from BTF.

    Falls back to pyelftools-based DWARF parsing if pahole is unavailable.

    Args:
        vmlinux_path: Path to vmlinux ELF file.
        struct_names: List of struct names to extract. Defaults to REQUIRED_STRUCTS.

    Returns:
        dict: struct_name -> {field_name: byte_offset}
    """
    vmlinux = Path(vmlinux_path)
    if struct_names is None:
        struct_names = REQUIRED_STRUCTS

    result: dict[str, dict[str, int]] = {}

    if not vmlinux.exists():
        logger.error("vmlinux not found: %s", vmlinux)
        return result

    # Check if pahole is available using shutil.which instead of `which` command
    pahole_path = shutil.which("pahole")
    if pahole_path is None:
        logger.warning("pahole not found in PATH; falling back to pyelftools for BTF/DWARF")
        # Use pyelftools-based fallback
        for struct_name in struct_names:
            offsets = _extract_struct_from_dwarf_pyelftools(vmlinux, struct_name)
            if offsets:
                result[struct_name] = offsets
            else:
                logger.warning("No offsets extracted for struct %s", struct_name)
                result[struct_name] = {}
        logger.info("Extracted offsets for %d structs (pyelftools fallback)", len(result))
        return result

    # pahole is available, use it
    logger.debug("pahole found at: %s", pahole_path)

    # Check pahole version
    proc = _run_cmd([pahole_path, "--version"])
    if proc.returncode == 0:
        logger.debug("pahole version: %s", proc.stdout.strip())

    for struct_name in struct_names:
        offsets = _extract_single_struct_pahole(vmlinux, struct_name, pahole_path)
        if offsets:
            result[struct_name] = offsets
        else:
            # Fallback to pyelftools
            logger.info("pahole failed for %s, trying pyelftools fallback", struct_name)
            offsets = _extract_struct_from_dwarf_pyelftools(vmlinux, struct_name)
            if offsets:
                result[struct_name] = offsets
            else:
                logger.warning("No offsets extracted for struct %s", struct_name)
                result[struct_name] = {}

    logger.info("Extracted offsets for %d structs", len(result))
    return result


def _extract_single_struct_pahole(vmlinux: Path, struct_name: str, pahole_path: str) -> dict[str, int]:
    """Extract field offsets for a single struct using pahole.

    Returns:
        dict mapping field_name -> byte_offset
    """
    offsets: dict[str] = {}

    # Use pahole -C <struct_name> to get struct layout
    proc = _run_cmd(
        [pahole_path, "-C", struct_name, str(vmlinux)],
        timeout=60,
    )

    if proc.returncode != 0:
        logger.debug("pahole -C %s failed: %s", struct_name, proc.stderr.strip())
        # Try with --format_path to specify BTF section
        proc = _run_cmd(
            [pahole_path, "--btf_format_path", str(vmlinux), "-C", struct_name],
            timeout=60,
        )
        if proc.returncode != 0:
            logger.debug("pahole with --btf_format_path also failed: %s",
                         proc.stderr.strip())
            return offsets

    output = proc.stdout

    # Parse pahole output
    in_struct = False

    for line in output.splitlines():
        stripped = line.strip()

        if f"struct {struct_name}" in stripped and "{" in stripped:
            in_struct = True
            continue

        if in_struct and "}" in stripped:
            in_struct = False
            continue

        if not in_struct:
            continue

        # Parse field line - various formats from pahole:
        # type name;                    /* offset size */
        # type *name;                   /* offset size */
        # type name[N];                 /* offset size */
        # Also handles bitfields:
        # int field:1;                  /* offset:8 bits:0 */

        # Standard field with offset comment
        m = re.match(
            r".*?\b(\w+)\s*;.*?/\*\s*(\d+)\s+\d+\s*\*/",
            stripped,
        )
        if m:
            field_name = m.group(1)
            offset = int(m.group(2))
            offsets[field_name] = offset
            continue

        # Bitfield
        m = re.match(
            r".*?\b(\w+)\s*:\s*\d+\s*;.*?/\*\s*offset:(\d+)\s+bits:\d+\s*\*/",
            stripped,
        )
        if m:
            field_name = m.group(1)
            offset = int(m.group(2)) // 8  # Convert bits to bytes
            offsets[field_name] = offset
            continue

    if offsets:
        logger.debug("Extracted %d fields for %s via pahole", len(offsets), struct_name)

    return offsets


def _extract_struct_from_dwarf_pyelftools(vmlinux: Path, struct_name: str) -> dict[str, int]:
    """Fallback: extract struct offsets from DWARF info using pyelftools.

    This replaces the previous readelf-based DWARF parsing.
    Returns partial results at best.
    """
    offsets: dict[str, int] = {}

    try:
        f = open(vmlinux, "rb")
    except OSError as e:
        logger.debug("Failed to open vmlinux for DWARF: %s", e)
        return offsets

    try:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            logger.debug("No DWARF info in %s", vmlinux.name)
            return offsets

        dwarf_info = elf.get_dwarf_info()
        for compilation_unit in dwarf_info.iter_CUs():
            top_die = compilation_unit.get_top_DIE()
            for die in top_die.iter_children():
                if die.tag == "DW_TAG_structure_type":
                    # Check if this is the struct we're looking for
                    die_name = die.attributes.get("DW_AT_name")
                    if die_name and die_name.value == struct_name:
                        for member in die.iter_children():
                            if member.tag == "DW_TAG_member":
                                member_name_attr = member.attributes.get("DW_AT_name")
                                member_loc = member.attributes.get("DW_AT_data_member_location")
                                if member_name_attr and member_loc is not None:
                                    # DW_AT_data_member_location can be an int or a DWARF expr
                                    loc_val = member_loc.value
                                    if isinstance(loc_val, int):
                                        offsets[member_name_attr.value] = loc_val
                                    elif isinstance(loc_val, bytes):
                                        # Simple DWARF expression: usually just a DW_OP_plus_uconst
                                        # For simplicity, try to parse common forms
                                        if len(loc_val) == 1 and loc_val[0] == 0x00:
                                            # DW_OP_lit0
                                            offsets[member_name_attr.value] = 0
                                        elif len(loc_val) == 2 and loc_val[0] == 0x23:
                                            # DW_OP_plus_uconst followed by ULEB128
                                            offsets[member_name_attr.value] = loc_val[1]
                        if offsets:
                            return offsets
    except Exception as e:
        logger.debug("pyelftools DWARF parsing failed for %s: %s", struct_name, e)
    finally:
        f.close()

    return offsets


def extract_enum_values(vmlinux_path: str | Path) -> dict[str, int]:
    """Extract useful enum values from BTF/DWARF if available.

    Returns:
        dict mapping enum_value_name -> integer value
    """
    vmlinux = Path(vmlinux_path)
    result: dict[str, int] = {}

    if not vmlinux.exists():
        return result

    # Use pahole to list enums (if available)
    pahole_path = shutil.which("pahole")
    if pahole_path is None:
        logger.debug("pahole not found, cannot extract enums")
        return result

    proc = _run_cmd([pahole_path, "--enums", str(vmlinux)], timeout=60)
    if proc.returncode != 0:
        logger.debug("pahole --enums failed: %s", proc.stderr.strip())
        return result

    # Parse enum output
    # Format: enum name { VALUE1 = 0, VALUE2 = 1, ... };
    current_enum = ""
    for line in proc.stdout.splitlines():
        m = re.match(r"enum (\w+)\s*\{", line)
        if m:
            current_enum = m.group(1)
            continue

        if current_enum:
            # Parse individual enum values
            for entry in line.split(","):
                m = re.match(r"\s*(\w+)\s*=\s*(\d+)", entry)
                if m:
                    name = m.group(1)
                    value = int(m.group(2))
                    result[name] = value

        if "}" in line:
            current_enum = ""

    logger.info("Extracted %d enum values", len(result))
    return result
