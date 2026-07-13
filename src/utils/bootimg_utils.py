"""Android boot image handling utilities."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Android boot image magic
_BOOT_MAGIC = b"ANDROID!"
_BOOT_MAGIC_SIZE = 8


def _run_cmd(cmd: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def detect_bootimg_type(path: str | Path) -> str | None:
    """Detect the type of a boot image by checking ANDROID! magic and header version.

    Returns:
        One of: 'boot', 'init_boot', 'vendor_boot', or None if not a boot image.
    """
    path = Path(path)
    if not path.exists():
        logger.warning("Boot image path does not exist: %s", path)
        return None

    # Check filename hints first
    name_lower = path.name.lower()
    if "init_boot" in name_lower or "initboot" in name_lower:
        return "init_boot"
    if "vendor_boot" in name_lower or "vendorboot" in name_lower:
        return "vendor_boot"
    if "boot" in name_lower:
        return "boot"

    # Read header and check magic
    try:
        with open(path, "rb") as f:
            magic = f.read(_BOOT_MAGIC_SIZE)
    except OSError as e:
        logger.error("Failed to read boot image: %s", e)
        return None

    if magic != _BOOT_MAGIC:
        logger.debug("Not an Android boot image (magic=%s)", magic[:8])
        return None

    # Read header version (offset varies, but for v0-v3 it's at a fixed location)
    # For header v0-v2: the header version field is not standardized in the same way
    # For header v3+: the header version is part of the structured header
    # We'll rely on filename + magic for now; detailed parsing would require
    # the full boot_img_hdr structure
    try:
        with open(path, "rb") as f:
            f.seek(40)  # Offset of header_version in boot_img_hdr_v0
            header_data = f.read(4)
            if len(header_data) >= 4:
                # header_version is a uint32 at this offset for v0-v2
                import struct
                header_version = struct.unpack("<I", header_data)[0]
                if header_version >= 4:
                    # v4+ usually means init_boot is separate
                    logger.debug("Boot header version: %d", header_version)
    except Exception:
        pass

    # Default to 'boot' if magic matches
    return "boot"


def unpack_bootimg(boot_img_path: str | Path, output_dir: str | Path) -> Path | None:
    """Unpack a boot image using unpackbootimg or mkbootimg tools.

    Args:
        boot_img_path: Path to the boot image file.
        output_dir: Directory to unpack into.

    Returns:
        Path to the extracted kernel file, or None on failure.
    """
    boot_img = Path(boot_img_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not boot_img.exists():
        logger.error("Boot image not found: %s", boot_img)
        return None

    # Try unpackbootimg first
    proc = _run_cmd(
        ["unpackbootimg", "-i", str(boot_img), "-o", str(out_dir)],
    )
    if proc.returncode == 0:
        # unpackbootimg creates a directory named after the image
        # Look for the kernel file
        kernel_candidates = list(out_dir.glob("**/kernel")) + list(out_dir.glob("**/kernel.img"))
        if kernel_candidates:
            kernel_path = kernel_candidates[0]
            logger.info("Unpacked boot image, kernel at: %s", kernel_path)
            return kernel_path

    # Try mkbootimg's unpack variant
    proc = _run_cmd(
        ["mkbootimg", "--unpack", str(boot_img)],
    )
    if proc.returncode == 0:
        kernel_candidates = list(out_dir.glob("kernel")) + list(out_dir.glob("kernel.img"))
        if kernel_candidates:
            return kernel_candidates[0]

    # Manual extraction as fallback: skip boot header to get kernel
    # Boot image header is typically 1648 bytes (v0) or 1580 bytes (v1-2)
    # We try several known header sizes
    logger.info("Trying manual kernel extraction from boot image")
    header_sizes = [1648, 1580, 1660, 4096]
    for hs in header_sizes:
        kernel_out = out_dir / "kernel"
        try:
            with open(boot_img, "rb") as f_in:
                _header = f_in.read(hs)
                kernel_data = f_in.read()
                with open(kernel_out, "wb") as f_out:
                    f_out.write(kernel_data)
            if kernel_out.stat().st_size > 0:
                logger.info("Extracted kernel with header size %d: %s", hs, kernel_out)
                return kernel_out
        except OSError as e:
            logger.debug("Header size %d failed: %s", hs, e)
            continue

    logger.error("Failed to unpack boot image: %s", boot_img)
    return None


def find_boot_images(unpack_dir: str | Path) -> dict[str, Path]:
    """Find boot.img, init_boot.img in an unpacked ROM directory.

    Returns:
        dict mapping image type to its path. Keys: 'boot', 'init_boot', 'vendor_boot'.
    """
    unpack = Path(unpack_dir)
    result: dict[str, Path] = {}

    if not unpack.exists():
        logger.warning("Unpack directory does not exist: %s", unpack)
        return result

    # Search for boot images by name
    patterns = {
        "boot": ["boot.img", "boot", "BOOT.img"],
        "init_boot": ["init_boot.img", "init_boot", "INIT_BOOT.img"],
        "vendor_boot": ["vendor_boot.img", "vendor_boot", "VENDOR_BOOT.img"],
    }

    for img_type, names in patterns.items():
        for name in names:
            # Direct match
            candidate = unpack / name
            if candidate.exists():
                result[img_type] = candidate
                break
            # Recursive search
            candidates = list(unpack.glob(f"**/{name}"))
            if candidates:
                result[img_type] = candidates[0]
                break

    logger.info("Found boot images: %s", {k: str(v) for k, v in result.items()})
    return result


def detect_rom_type(rom_path: str | Path) -> str:
    """Detect ROM format.

    Returns:
        One of: 'payload' (has payload.bin), 'ozip' (.ozip extension, OPPO),
        'pac' (Samsung), 'boot_img' (direct boot image), 'unknown'.
    """
    rom = Path(rom_path)

    if not rom.exists():
        logger.error("ROM path does not exist: %s", rom)
        return "unknown"

    # Check by extension
    if rom.suffix.lower() == ".ozip":
        logger.info("Detected ROM type: ozip (OPPO)")
        return "ozip"

    if rom.suffix.lower() == ".pac":
        logger.info("Detected ROM type: pac (Samsung)")
        return "pac"

    # Check if it's a direct boot image
    if detect_bootimg_type(rom) is not None:
        logger.info("Detected ROM type: boot_img (direct boot image)")
        return "boot_img"

    # Check if it's a directory with payload.bin
    if rom.is_dir():
        payload_bin = rom / "payload.bin"
        if payload_bin.exists():
            logger.info("Detected ROM type: payload (directory with payload.bin)")
            return "payload"
        # Check recursively
        payload_candidates = list(rom.glob("**/payload.bin"))
        if payload_candidates:
            logger.info("Detected ROM type: payload (nested payload.bin)")
            return "payload"

    # Check if it's a zip file that might contain payload.bin
    if rom.suffix.lower() in (".zip", ".rar", ".7z"):
        # Try listing the zip contents
        if rom.suffix.lower() == ".zip":
            proc = _run_cmd(["unzip", "-l", str(rom)])
            if proc.returncode == 0 and "payload.bin" in proc.stdout:
                logger.info("Detected ROM type: payload (zip containing payload.bin)")
                return "payload"

    logger.warning("Could not determine ROM type for: %s", rom)
    return "unknown"
