"""Stage 3: Extract kernel from boot image.

Unpacks the boot image to get the raw kernel Image,
then converts it to ELF vmlinux for analysis.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..utils.bootimg_utils import unpack_bootimg
from ..utils.elf_utils import detect_arch, extract_kernel_version, has_symbols

logger = logging.getLogger(__name__)


def _run_cmd(cmd: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def extract_kernel(boot_img_path: str | Path, output_dir: str | Path) -> Path | None:
    """Unpack boot.img and get the raw kernel Image.

    Args:
        boot_img_path: Path to the boot image file.
        output_dir: Directory to extract into.

    Returns:
        Path to the raw kernel Image file, or None on failure.
    """
    boot_img = Path(boot_img_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not boot_img.exists():
        logger.error("Boot image not found: %s", boot_img)
        return None

    logger.info("Extracting kernel from boot image: %s", boot_img)

    kernel_path = unpack_bootimg(boot_img, out_dir)
    if kernel_path and kernel_path.exists():
        logger.info("Raw kernel extracted: %s", kernel_path)
        return kernel_path

    # Fallback: try direct extraction with vmlinux-to-elf which can also unpack
    logger.info("Trying vmlinux-to-elf direct extraction...")
    output_elf = out_dir / "vmlinux"
    proc = _run_cmd(["vmlinux-to-elf", str(boot_img), str(output_elf)])
    if proc.returncode == 0 and output_elf.exists():
        logger.info("Direct vmlinux-to-elf extraction succeeded: %s", output_elf)
        return output_elf

    logger.error("Failed to extract kernel from boot image")
    return None


def convert_to_elf(kernel_image_path: str | Path, output_dir: str | Path) -> Path | None:
    """Convert raw kernel Image to ELF vmlinux using vmlinux-to-elf.

    Args:
        kernel_image_path: Path to the raw kernel Image.
        output_dir: Directory to write the ELF vmlinux.

    Returns:
        Path to the ELF vmlinux file, or None on failure.
    """
    kernel = Path(kernel_image_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not kernel.exists():
        logger.error("Kernel image not found: %s", kernel)
        return None

    output_elf = out_dir / "vmlinux"

    # Check if it's already an ELF file
    try:
        with open(kernel, "rb") as f:
            magic = f.read(4)
        if magic == b"\x7fELF":
            logger.info("Kernel is already an ELF file, copying to output")
            shutil.copy2(kernel, output_elf)
            return output_elf
    except OSError:
        pass

    # Convert using vmlinux-to-elf
    logger.info("Converting kernel Image to ELF: %s -> %s", kernel, output_elf)
    proc = _run_cmd(["vmlinux-to-elf", str(kernel), str(output_elf)], timeout=300)

    if proc.returncode != 0:
        logger.error("vmlinux-to-elf failed: %s", proc.stderr)
        return None

    if not output_elf.exists():
        logger.error("vmlinux-to-elf produced no output")
        return None

    logger.info("ELF vmlinux created: %s (%d bytes)",
                output_elf, output_elf.stat().st_size)
    return output_elf


def _is_gki_kernel(
    kernel_version: str | None,
    init_boot_img_path: str | Path | None,
) -> bool:
    """Determine if this is a GKI (Generic Kernel Image) kernel.

    GKI detection heuristics:
    - If init_boot.img exists -> GKI (introduced with GKI)
    - If kernel version >= 6.1 -> GKI (6.1+ is always GKI)
    """
    # If init_boot.img exists, it's definitely GKI
    if init_boot_img_path is not None:
        init_boot = Path(init_boot_img_path) if isinstance(init_boot_img_path, str) else init_boot_img_path
        if init_boot.exists():
            logger.info("GKI detected: init_boot.img present")
            return True

    # Check kernel version
    if kernel_version:
        m = re.match(r"(\d+)\.(\d+)", kernel_version)
        if m:
            major = int(m.group(1))
            minor = int(m.group(2))
            if major > 6 or (major == 6 and minor >= 1):
                logger.info("GKI detected: kernel version %s >= 6.1", kernel_version)
                return True

    logger.info("Not detected as GKI kernel")
    return False


def run(prev_result: dict[str, Any], work_dir: str | Path) -> dict[str, Any]:
    """Main entry point for kernel extraction stage.

    Args:
        prev_result: Result from rom_unpack stage with 'boot_img_path' and
                     'init_boot_img_path' keys.
        work_dir: Working directory.

    Returns:
        dict with keys: 'vmlinux_path', 'kernel_version', 'kernel_is_gki', 'arch'
    """
    work = Path(work_dir)
    extract_dir = work / "kernel_extracted"

    boot_img_path = prev_result.get("boot_img_path")
    init_boot_img_path = prev_result.get("init_boot_img_path")

    result: dict[str, Any] = {
        "vmlinux_path": None,
        "kernel_version": None,
        "kernel_is_gki": False,
        "arch": "aarch64",
    }

    if not boot_img_path:
        logger.error("No boot image path provided from previous stage")
        return result

    # Step 1: Extract raw kernel from boot image
    kernel_image = extract_kernel(boot_img_path, extract_dir)
    if kernel_image is None:
        logger.error("Failed to extract kernel from boot image")
        return result

    # If init_boot.img exists, also extract its kernel (it's the actual GKI kernel)
    if init_boot_img_path:
        init_boot = Path(init_boot_img_path) if isinstance(init_boot_img_path, str) else init_boot_img_path
        if init_boot.exists():
            init_extract_dir = extract_dir / "init_boot"
            init_kernel = extract_kernel(init_boot, init_extract_dir)
            if init_kernel:
                logger.info("Using init_boot kernel (GKI) as primary kernel")
                kernel_image = init_kernel

    # Step 2: Convert to ELF
    vmlinux_path = convert_to_elf(kernel_image, extract_dir)
    if vmlinux_path is None:
        logger.error("Failed to convert kernel to ELF")
        return result

    result["vmlinux_path"] = vmlinux_path

    # Step 3: Extract kernel version
    kernel_version = extract_kernel_version(vmlinux_path)
    result["kernel_version"] = kernel_version

    # Step 4: Detect architecture
    arch = detect_arch(vmlinux_path)
    result["arch"] = arch

    # Step 5: GKI detection
    result["kernel_is_gki"] = _is_gki_kernel(kernel_version, init_boot_img_path)

    logger.info(
        "Kernel extraction complete: vmlinux=%s, version=%s, arch=%s, gki=%s",
        vmlinux_path, kernel_version, arch, result["kernel_is_gki"],
    )

    return result
