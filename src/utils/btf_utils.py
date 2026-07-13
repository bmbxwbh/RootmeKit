"""BTF (BPF Type Format) parsing utilities for structure offset extraction."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Any

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

    # Check if pahole is available
    proc = _run_cmd(["which", "pahole"])
    if proc.returncode != 0:
        logger.warning("pahole not found in PATH; BTF struct offsets unavailable")
        return result

    # Check pahole version
    proc = _run_cmd(["pahole", "--version"])
    if proc.returncode == 0:
        logger.debug("pahole version: %s", proc.stdout.strip())

    for struct_name in struct_names:
        offsets = _extract_single_struct(vmlinux, struct_name)
        if offsets:
            result[struct_name] = offsets
        else:
            logger.warning("No offsets extracted for struct %s", struct_name)
            result[struct_name] = {}

    logger.info("Extracted offsets for %d structs", len(result))
    return result


def _extract_single_struct(vmlinux: Path, struct_name: str) -> dict[str, int]:
    """Extract field offsets for a single struct using pahole.

    Returns:
        dict mapping field_name -> byte_offset
    """
    offsets: dict[str, int] = {}

    # Use pahole -C <struct_name> to get struct layout
    proc = _run_cmd(
        ["pahole", "-C", struct_name, str(vmlinux)],
        timeout=60,
    )

    if proc.returncode != 0:
        logger.debug("pahole -C %s failed: %s", struct_name, proc.stderr.strip())
        # Try with --format_path to specify BTF section
        proc = _run_cmd(
            ["pahole", "--btf_format_path", str(vmlinux), "-C", struct_name],
            timeout=60,
        )
        if proc.returncode != 0:
            logger.debug("pahole with --btf_format_path also failed: %s",
                         proc.stderr.strip())
            return offsets

    output = proc.stdout

    # Parse pahole output
    # Example format:
    # struct task_struct {
    #     void *             stack;                /*     0     8 */
    #     ...
    #     const struct cred *   cred;              /*   744     8 */
    # }
    #
    # We want to extract field name and byte offset

    current_offset = 0
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
            current_offset = offset
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
            current_offset = offset
            continue

        # Union member
        m = re.match(
            r".*?\b(\w+)\s*;.*?/\*\s*(\d+)\s+\d+\s*\*/",
            stripped,
        )
        if m:
            field_name = m.group(1)
            offset = int(m.group(2))
            offsets[field_name] = offset

    if offsets:
        logger.debug("Extracted %d fields for %s", len(offsets), struct_name)
    else:
        # Fallback: try using readelf to parse DWARF info if available
        offsets = _extract_struct_from_dwarf(vmlinux, struct_name)

    return offsets


def _extract_struct_from_dwarf(vmlinux: Path, struct_name: str) -> dict[str, int]:
    """Fallback: extract struct offsets from DWARF info using readelf.

    This is a best-effort fallback when pahole is unavailable.
    Returns partial results at best.
    """
    offsets: dict[str, int] = {}

    proc = _run_cmd(["readelf", "--debug-dump=info", str(vmlinux)])
    if proc.returncode != 0:
        return offsets

    # Very basic DWARF parsing - look for DW_TAG_member entries
    # within the target struct. This is incomplete but may give some results.
    in_target = False
    current_member: str | None = None

    for line in proc.stdout.splitlines():
        if f"DW_AT_name.*:.*{struct_name}" in line or f'DW_AT_name    : "{struct_name}"' in line:
            in_target = True
            continue

        if in_target and "DW_TAG_member" in line:
            current_member = None
            continue

        if in_target and current_member is None:
            m = re.search(r'DW_AT_name\s*:\s*"(\w+)"', line)
            if m:
                current_member = m.group(1)

        if in_target and current_member and "DW_AT_data_member_location" in line:
            m = re.search(r"DW_AT_data_member_location:\s*(\d+)", line)
            if m:
                offsets[current_member] = int(m.group(1))
                current_member = None

        if in_target and "DW_TAG_structure_type" in line and struct_name not in line:
            in_target = False

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

    # Use pahole to list enums
    proc = _run_cmd(["pahole", "--enums", str(vmlinux)], timeout=60)
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
