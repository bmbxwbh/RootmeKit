"""Android boot image handling utilities.

Uses Python-native implementations instead of external tools:
- zipfile instead of unzip
- Custom Android boot image parser instead of unpackbootimg/mkbootimg
"""

from __future__ import annotations

import logging
import struct
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Android boot image magic
_BOOT_MAGIC = b"ANDROID!"
_BOOT_MAGIC_SIZE = 8


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
                header_version = struct.unpack("<I", header_data)[0]
                if header_version >= 4:
                    # v4+ usually means init_boot is separate
                    logger.debug("Boot header version: %d", header_version)
    except Exception:
        pass

    # Default to 'boot' if magic matches
    return "boot"


def _parse_boot_header_v0v1(data: bytes) -> dict[str, Any] | None:
    """Parse Android boot image header v0/v1.

    The v0 header is 1648 bytes. v1 adds 4 fields (1648 + 16 = 1664).
    v2 adds 2 more fields (1664 + 8 = 1672).

    Returns:
        Parsed header dict, or None if parsing fails.
    """
    if len(data) < 1648:
        return None

    # v0/v1/v2 common fields (first 40 bytes + rest)
    (
        kernel_size,
        kernel_addr,
        ramdisk_size,
        ramdisk_addr,
        second_size,
        second_addr,
        tags_addr,
        page_size,
        header_version,
        os_version,
    ) = struct.unpack_from("<10I", data, 8)

    return {
        "header_version": header_version,
        "kernel_size": kernel_size,
        "kernel_addr": kernel_addr,
        "ramdisk_size": ramdisk_size,
        "ramdisk_addr": ramdisk_addr,
        "second_size": second_size,
        "second_addr": second_addr,
        "tags_addr": tags_addr,
        "page_size": page_size,
        "os_version": os_version,
    }


def _parse_boot_header_v3(data: bytes) -> dict[str, Any] | None:
    """Parse Android boot image header v3.

    v3 header is simpler: 1580 bytes.
    No second loader, no DTB, no tags.

    Returns:
        Parsed header dict, or None if parsing fails.
    """
    if len(data) < 1580:
        return None

    (
        kernel_size,
        ramdisk_size,
        os_version,
        header_version,
        reserved,
    ) = struct.unpack_from("<5I", data, 8)

    return {
        "header_version": header_version,
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "page_size": 4096,  # v3 always uses 4096
        "second_size": 0,
        "os_version": os_version,
    }


def _parse_boot_header_v4(data: bytes) -> dict[str, Any] | None:
    """Parse Android boot image header v4.

    v4 header is even simpler and always paired with init_boot.
    Signature may follow the header.

    Returns:
        Parsed header dict, or None if parsing fails.
    """
    if len(data) < 100:
        return None

    (
        kernel_size,
        ramdisk_size,
        os_version,
        header_version,
        reserved,
    ) = struct.unpack_from("<5I", data, 8)

    return {
        "header_version": header_version,
        "kernel_size": kernel_size,
        "ramdisk_size": ramdisk_size,
        "page_size": 4096,  # v4 always uses 4096
        "second_size": 0,
        "os_version": os_version,
    }


def _page_align(size: int, page_size: int) -> int:
    """Round up size to the next page boundary."""
    return (size + page_size - 1) & ~(page_size - 1)


def _unpack_bootimg_python(boot_img: Path, out_dir: Path) -> Path | None:
    """Unpack a boot image using pure Python.

    Parses the Android boot image header to find the kernel section,
    then extracts it without needing unpackbootimg or mkbootimg.

    Args:
        boot_img: Path to the boot image file.
        out_dir: Directory to extract into.

    Returns:
        Path to the extracted kernel file, or None on failure.
    """
    try:
        with open(boot_img, "rb") as f:
            data = f.read()
    except OSError as e:
        logger.error("Failed to read boot image: %s", e)
        return None

    if len(data) < 8 or data[:8] != _BOOT_MAGIC:
        logger.error("Not an Android boot image (bad magic)")
        return None

    # Read header version to determine header format
    header_version = struct.unpack_from("<I", data, 40)[0]

    # Parse header based on version
    header: dict[str, Any] | None = None
    header_size = 0

    if header_version <= 2:
        # v0/v1/v2 header sizes
        if header_version == 0:
            header_size = 1648
        elif header_version == 1:
            header_size = 1664
        else:  # v2
            header_size = 1672
        header = _parse_boot_header_v0v1(data[:header_size])
    elif header_version == 3:
        header_size = 1580
        header = _parse_boot_header_v3(data[:header_size])
    elif header_version >= 4:
        header_size = 100  # approximate, v4 is small
        header = _parse_boot_header_v4(data[:header_size])
    else:
        logger.error("Unknown boot header version: %d", header_version)
        return None

    if header is None:
        logger.error("Failed to parse boot image header")
        return None

    logger.info("Boot image header v%d: kernel_size=%d, ramdisk_size=%d, page_size=%d",
                header["header_version"], header["kernel_size"],
                header["ramdisk_size"], header["page_size"])

    kernel_size = header["kernel_size"]
    page_size = header["page_size"]

    if kernel_size == 0:
        logger.error("Kernel size is 0 in boot image header")
        return None

    # Calculate kernel offset: right after the header, page-aligned
    kernel_offset = _page_align(header_size, page_size)

    if kernel_offset + kernel_size > len(data):
        logger.error("Kernel section extends beyond file (offset=%d, size=%d, file=%d)",
                     kernel_offset, kernel_size, len(data))
        return None

    # Extract kernel
    kernel_data = data[kernel_offset:kernel_offset + kernel_size]
    kernel_out = out_dir / "kernel"

    try:
        with open(kernel_out, "wb") as f:
            f.write(kernel_data)
    except OSError as e:
        logger.error("Failed to write kernel file: %s", e)
        return None

    logger.info("Extracted kernel from boot image (v%d, %d bytes): %s",
                header["header_version"], kernel_size, kernel_out)
    return kernel_out


def unpack_bootimg(boot_img_path: str | Path, output_dir: str | Path) -> Path | None:
    """Unpack a boot image to extract the kernel.

    Uses pure Python implementation (no external unpackbootimg/mkbootimg required).

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

    # Use Python-native boot image parser
    kernel_path = _unpack_bootimg_python(boot_img, out_dir)
    if kernel_path and kernel_path.exists() and kernel_path.stat().st_size > 0:
        logger.info("Unpacked boot image, kernel at: %s", kernel_path)
        return kernel_path

    # Try Samsung/other vendor formats — scan for kernel magic signatures
    # ARM64 Linux kernel Image starts with these bytes
    _ARM64_IMAGE_MAGIC = b"\x6d\x7d\x6d\x6e"  # "mdm\0" at offset 4 in ARM64 Image header
    _ARM64_IMAGE_MAGIC2 = b"\x00\x00\x00\x00\x6d\x7d"  # Alternative: zeros then magic
    # GZIP magic
    _GZIP_MAGIC = b"\x1f\x8b"
    # LZ4 magic
    _LZ4_MAGIC = b"\x04\x22\x4d\x18"
    # XZ magic
    _XZ_MAGIC = b"\xfd\x37\x7a\x58\x5a\x00"

    logger.info("Standard ANDROID! boot image parser failed, scanning for kernel signatures...")
    try:
        with open(boot_img, "rb") as f:
            data = f.read(min(boot_img.stat().st_size, 2 * 1024 * 1024))  # Read first 2MB

        # Dump first 64 bytes for debugging
        logger.info("Boot image first 32 bytes: %s", data[:32].hex())
        logger.info("Boot image first 16 bytes raw: %s", data[:16])

        # Strategy: scan through the file looking for known kernel signatures
        scan_offsets = []

        # Check for Samsung PIT/Vendor boot format — kernel may start at a fixed offset
        # Try common page-aligned offsets
        for offset in range(0, min(len(data), 65536), 512):
            chunk = data[offset:offset + 8]
            if len(chunk) < 4:
                continue
            # ARM64 Image header: bytes [4:8] should be 0x644d5241 ("ARM\x64" in LE) or similar
            if chunk[0:4] == _GZIP_MAGIC:
                scan_offsets.append(("gzip", offset))
            elif chunk[0:4] == _LZ4_MAGIC:
                scan_offsets.append(("lz4", offset))
            elif chunk[0:6] == _XZ_MAGIC:
                scan_offsets.append(("xz", offset))
            # ARM64 kernel: at offset+4, check for magic 0x644d5241
            elif len(data) > offset + 8:
                arm_magic = data[offset + 4:offset + 8]
                if arm_magic == b"\x41\x52\x4d\x64":  # "ARMd" = ARM64 Image magic
                    scan_offsets.append(("arm64_image", offset))

        if scan_offsets:
            logger.info("Found kernel signatures at: %s", scan_offsets[:5])

            # Use the first match
            ktype, koffset = scan_offsets[0]

            # For compressed kernels, extract from that offset to end of file
            with open(boot_img, "rb") as f:
                f.seek(koffset)
                kernel_data = f.read()

            kernel_out = out_dir / "kernel"
            with open(kernel_out, "wb") as f:
                f.write(kernel_data)

            logger.info("Extracted %s kernel at offset %d (%d bytes): %s",
                        ktype, koffset, len(kernel_data), kernel_out)
            return kernel_out

    except Exception as e:
        logger.error("Kernel signature scan failed: %s", e)

    # Fallback: Manual extraction with known header sizes
    # This is the old approach kept as a secondary fallback
    logger.info("Kernel signature scan failed, trying manual header-size extraction")
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

    Uses Python-native zipfile instead of unzip command.

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
    if rom.suffix.lower() == ".zip":
        # Use Python's zipfile module instead of unzip command
        try:
            with zipfile.ZipFile(rom, "r") as zf:
                namelist = zf.namelist()
                if any("payload.bin" in name for name in namelist):
                    logger.info("Detected ROM type: payload (zip containing payload.bin)")
                    return "payload"
        except (zipfile.BadZipFile, OSError) as e:
            logger.debug("Failed to read zip file: %s", e)

    logger.warning("Could not determine ROM type for: %s", rom)
    return "unknown"
