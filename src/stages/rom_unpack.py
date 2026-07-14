"""Stage 1-2: Download and unpack ROM.

Downloads the ROM from the provided URL, detects the ROM format,
and unpacks it to extract boot images.

Uses mature external tools:
  - payload-dumper-go: extract partition images from OTA payload.bin
  - magiskboot: unpack boot.img / init_boot.img to raw kernel
  - vmlinux-to-elf: convert raw kernel Image to ELF with symbols
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _run_cmd(
    cmd: list[str],
    *,
    timeout: int = 600,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.info("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def _tool_available(name: str) -> bool:
    """Check if an external tool is available on PATH."""
    path = shutil.which(name)
    if path:
        return True
    # Also check common locations that may not be in PATH
    for p in ["/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"]:
        candidate = Path(p) / name
        if candidate.exists() and candidate.is_file():
            return True
    return False


def _tool_path(name: str) -> str | None:
    """Find the full path of an external tool."""
    path = shutil.which(name)
    if path:
        return path
    for p in ["/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"]:
        candidate = Path(p) / name
        if candidate.exists() and candidate.is_file():
            return str(candidate)
    return None


def download_rom(rom_url: str, cache_dir: str | Path) -> Path:
    """Download ROM using Python urllib, return local path.

    Args:
        rom_url: URL to download the ROM from.
        cache_dir: Directory to cache the downloaded file.

    Returns:
        Path to the downloaded ROM file.
    """
    import urllib.request
    import urllib.parse

    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)

    # Determine filename from URL
    parsed = urllib.parse.urlparse(rom_url)
    filename = Path(parsed.path).name or "rom_download"
    local_path = cache / filename

    # Skip download if already cached
    if local_path.exists() and local_path.stat().st_size > 0:
        logger.info("ROM already cached at: %s", local_path)
        return local_path

    logger.info("Downloading ROM from: %s", rom_url)

    # Use Python's urllib — no dependency on curl/wget
    try:
        urllib.request.urlretrieve(rom_url, str(local_path))
    except Exception as e:
        # Fallback: try with subprocess curl if available
        curl_path = shutil.which("curl")
        if curl_path:
            logger.info("urllib failed (%s), trying curl...", e)
            proc = subprocess.run(
                [curl_path, "-L", "-o", str(local_path), rom_url],
                timeout=3600,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"curl download failed (exit {proc.returncode})") from e
        else:
            raise RuntimeError(f"Failed to download ROM: {e}") from e

    if not local_path.exists() or local_path.stat().st_size == 0:
        raise RuntimeError(f"Downloaded ROM file is empty or missing: {local_path}")

    logger.info("ROM downloaded to: %s (%d bytes)", local_path, local_path.stat().st_size)
    return local_path


# ---------------------------------------------------------------------------
# payload.bin extraction — using payload-dumper-go (preferred) or Python fallback
# ---------------------------------------------------------------------------

def _extract_payload_with_dumper_go(payload_bin: Path, output_dir: Path, partitions: list[str]) -> bool:
    """Extract partition images using payload-dumper-go.

    Args:
        payload_bin: Path to payload.bin file.
        output_dir: Output directory for extracted images.
        partitions: List of partition names to extract.

    Returns:
        True if extraction succeeded.
    """
    dumper = _tool_path("payload-dumper-go")
    if not dumper:
        logger.warning("payload-dumper-go not available, will use Python fallback")
        return False

    # payload-dumper-go -o <output_dir> -p <part1,part2,...> <payload.bin>
    part_arg = ",".join(partitions)
    try:
        proc = _run_cmd(
            [dumper, "-o", str(output_dir), "-p", part_arg, str(payload_bin)],
            timeout=3600,
        )
        if proc.returncode != 0:
            logger.error("payload-dumper-go failed: %s", proc.stderr)
            return False
        logger.info("payload-dumper-go output:\n%s", proc.stdout[-2000:] if len(proc.stdout) > 2000 else proc.stdout)
        return True
    except Exception as e:
        logger.error("payload-dumper-go exception: %s", e)
        return False


def _extract_payload_python(payload_bin: Path, output_dir: Path, partitions: list[str]) -> bool:
    """Extract partition images using Python-native payload parser (fallback).

    Returns:
        True if extraction succeeded.
    """
    from ..utils.payload_utils import extract_payload_partitions

    try:
        extract_payload_partitions(
            str(payload_bin),
            str(output_dir),
            partition_names=partitions,
        )
        return True
    except Exception as e:
        logger.error("Python payload parser failed: %s", e)
        return False


def _find_payload_bin(rom_path: Path, output_dir: Path) -> Path | None:
    """Find payload.bin from ROM path. Extracts from zip if needed.

    Returns:
        Path to payload.bin or None if not found.
    """
    if rom_path.is_dir():
        candidates = list(rom_path.glob("**/payload.bin"))
        return candidates[0] if candidates else None

    if rom_path.suffix.lower() == ".zip":
        # Extract payload.bin from zip
        zip_dir = output_dir / "zip_extract"
        zip_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Extracting payload.bin from zip: %s", rom_path)
        with zipfile.ZipFile(rom_path, "r") as zf:
            # Find payload.bin entry
            payload_entries = [n for n in zf.namelist() if n.endswith("payload.bin")]
            if not payload_entries:
                return None
            # Extract just the payload.bin
            for entry in payload_entries:
                zf.extract(entry, zip_dir)
            return zip_dir / payload_entries[0]

    # Assume it's payload.bin directly
    if rom_path.exists():
        return rom_path

    return None


def _unpack_payload(rom_path: Path, output_dir: Path, kernel_partition: str | None = None) -> Path:
    """Unpack payload.bin using payload-dumper-go (preferred) or Python fallback.

    Args:
        rom_path: Path to the ROM file.
        output_dir: Directory for extraction output.
        kernel_partition: Which partition contains the kernel.
            "init_boot" for Android 13+ GKI, "boot" for older devices.
            None means auto-detect (try init_boot -> boot -> vendor_boot).

    Returns:
        Path to the directory containing extracted images.
    """
    payload_dir = output_dir / "payload_extract"
    payload_dir.mkdir(parents=True, exist_ok=True)

    # Find payload.bin
    payload_bin = _find_payload_bin(rom_path, output_dir)
    if payload_bin is None or not payload_bin.exists():
        raise FileNotFoundError("payload.bin not found in ROM")

    # Determine which partitions to extract
    if kernel_partition:
        partition_names = [kernel_partition]
    else:
        partition_names = ["init_boot", "boot", "vendor_boot"]

    logger.info("Extracting partitions %s from payload: %s", partition_names, payload_bin)

    # Try payload-dumper-go first (mature, handles all compression)
    success = _extract_payload_with_dumper_go(payload_bin, payload_dir, partition_names)

    # Fallback to Python-native parser
    if not success:
        logger.info("Falling back to Python-native payload parser")
        success = _extract_payload_python(payload_bin, payload_dir, partition_names)

    if not success:
        raise RuntimeError("All payload extraction methods failed")

    return payload_dir


# ---------------------------------------------------------------------------
# boot.img unpacking — using magiskboot (preferred) or Python fallback
# ---------------------------------------------------------------------------

def _unpack_bootimg_magiskboot(boot_img: Path, out_dir: Path) -> Path | None:
    """Unpack boot image using magiskboot.

    magiskboot unpack extracts: kernel, ramdisk.cpio, etc.
    The kernel file is the raw (decompressed) kernel Image.

    Returns:
        Path to the extracted kernel file, or None if failed.
    """
    magiskboot = _tool_path("magiskboot")
    if not magiskboot:
        logger.warning("magiskboot not available, will use Python fallback")
        return None

    # magiskboot unpack works in the current directory
    work_dir = out_dir / "magiskboot_unpack"
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        proc = _run_cmd(
            [magiskboot, "unpack", "-n", "-h", str(boot_img)],
            cwd=work_dir,
            timeout=120,
        )
        # magiskboot returns 0 for valid boot images
        if proc.returncode not in (0, 2):
            logger.error("magiskboot unpack failed (rc=%d): %s", proc.returncode, proc.stderr)
            return None

        logger.info("magiskboot output:\n%s", proc.stdout)

        # magiskboot extracts 'kernel' file (decompressed)
        kernel_file = work_dir / "kernel"
        if kernel_file.exists() and kernel_file.stat().st_size > 0:
            # Copy to standard location
            dest = out_dir / "kernel"
            shutil.copy2(kernel_file, dest)
            logger.info("magiskboot extracted kernel: %s (%d bytes)", dest, dest.stat().st_size)
            return dest

        logger.error("magiskboot did not produce kernel file")
        return None

    except Exception as e:
        logger.error("magiskboot exception: %s", e)
        return None


def _unpack_bootimg_python(boot_img: Path, out_dir: Path) -> Path | None:
    """Unpack boot image using Python-native parser (fallback).

    Returns:
        Path to the extracted kernel file, or None if failed.
    """
    from ..utils.bootimg_utils import unpack_bootimg as unpack_boot_image

    try:
        return unpack_boot_image(boot_img, out_dir)
    except Exception as e:
        logger.error("Python boot image parser failed: %s", e)
        return None


def unpack_boot_img(boot_img: Path, out_dir: Path) -> Path | None:
    """Unpack boot image to extract kernel, using magiskboot (preferred) or Python fallback.

    Returns:
        Path to the extracted raw kernel Image file.
    """
    logger.info("Unpacking boot image: %s", boot_img)

    # Try magiskboot first — it handles all formats and compression natively
    kernel_path = _unpack_bootimg_magiskboot(boot_img, out_dir)
    if kernel_path:
        return kernel_path

    # Fallback to Python-native parser
    logger.info("Falling back to Python-native boot image parser")
    return _unpack_bootimg_python(boot_img, out_dir)


# ---------------------------------------------------------------------------
# ROM type detection
# ---------------------------------------------------------------------------

def detect_rom_type(rom_path: Path) -> str:
    """Detect ROM type from file magic/extension."""
    if rom_path.is_dir():
        return "directory"

    name = rom_path.name.lower()

    if name.endswith(".ozip"):
        return "ozip"
    if name.endswith(".pac"):
        return "pac"

    # Check if it's a boot image directly
    try:
        with open(rom_path, "rb") as f:
            magic = f.read(16)
        if magic[:8] == b"ANDROID!":
            return "boot_img"
        # ARM64 Image header
        if len(magic) >= 8 and magic[4:8] == b"\x41\x52\x4d\x64":
            return "raw_kernel"
    except Exception:
        pass

    # Default: treat .zip as payload-based OTA
    if name.endswith(".zip"):
        return "payload"

    return "unknown"


def find_boot_images(directory: Path) -> dict[str, Path]:
    """Find boot.img and init_boot.img in a directory tree."""
    result: dict[str, Path] = {}
    for f in directory.glob("**/*"):
        name = f.name.lower()
        if name == "init_boot.img":
            result["init_boot"] = f
        elif name == "boot.img":
            result["boot"] = f
        elif name == "vendor_boot.img":
            result["vendor_boot"] = f
    return result


# ---------------------------------------------------------------------------
# Main unpack logic
# ---------------------------------------------------------------------------

def _unpack_ozip(rom_path: Path, output_dir: Path) -> Path:
    """Decrypt OPPO ozip and treat as payload."""
    decrypted_dir = output_dir / "ozip_decrypt"
    decrypted_dir.mkdir(parents=True, exist_ok=True)
    decrypted_zip = decrypted_dir / rom_path.with_suffix(".zip").name

    proc = _run_cmd(["ozip-decrypt", str(rom_path), str(decrypted_zip)], timeout=600)
    if proc.returncode != 0:
        proc = _run_cmd(["python3", "-m", "oppo_ozip", str(rom_path), str(decrypted_zip)], timeout=600)
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to decrypt ozip: {proc.stderr}")

    return _unpack_payload(decrypted_zip, output_dir)


def _unpack_pac(rom_path: Path, output_dir: Path) -> Path:
    """Unpack Samsung PAC file."""
    pac_dir = output_dir / "pac_extract"
    pac_dir.mkdir(parents=True, exist_ok=True)

    proc = _run_cmd(["samfirm", "extract", "-i", str(rom_path), "-o", str(pac_dir)], timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to unpack PAC file: {proc.stderr}")

    return pac_dir


def unpack_rom(rom_path: str | Path, output_dir: str | Path, kernel_partition: str | None = None) -> dict[str, Any]:
    """Unpack ROM based on detected type.

    Args:
        rom_path: Path to the ROM file or directory.
        output_dir: Directory to extract into.
        kernel_partition: Which partition contains the kernel.

    Returns:
        dict with keys: 'rom_type', 'unpack_dir', 'boot_img_path', 'init_boot_img_path'
    """
    rom = Path(rom_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rom_type = detect_rom_type(rom)
    logger.info("Detected ROM type: %s", rom_type)

    result: dict[str, Any] = {
        "rom_type": rom_type,
        "unpack_dir": None,
        "boot_img_path": None,
        "init_boot_img_path": None,
    }

    if rom_type == "payload":
        unpack_dir = _unpack_payload(rom, out_dir, kernel_partition=kernel_partition)
        result["unpack_dir"] = unpack_dir
    elif rom_type == "ozip":
        unpack_dir = _unpack_ozip(rom, out_dir)
        result["unpack_dir"] = unpack_dir
    elif rom_type == "pac":
        unpack_dir = _unpack_pac(rom, out_dir)
        result["unpack_dir"] = unpack_dir
    elif rom_type == "boot_img":
        dest = out_dir / rom.name
        if rom != dest:
            shutil.copy2(rom, dest)
        result["unpack_dir"] = out_dir
        result["boot_img_path"] = dest
        return result
    elif rom_type == "raw_kernel":
        dest = out_dir / "kernel"
        shutil.copy2(rom, dest)
        result["unpack_dir"] = out_dir
        return result
    else:
        # Last resort: try as a zip file
        if rom.suffix.lower() == ".zip":
            try:
                unpack_dir = _unpack_payload(rom, out_dir, kernel_partition=kernel_partition)
                result["unpack_dir"] = unpack_dir
                result["rom_type"] = "payload"
            except Exception as e:
                logger.error("Fallback zip unpack also failed: %s", e)
                return result
        else:
            return result

    # Find boot images in unpacked directory
    if result["unpack_dir"]:
        boot_images = find_boot_images(result["unpack_dir"])
        result["boot_img_path"] = boot_images.get("boot")
        result["init_boot_img_path"] = boot_images.get("init_boot")

    return result


def run(device_config: dict[str, Any], work_dir: str | Path) -> dict[str, Any]:
    """Main entry point for ROM download and unpack stage.

    Downloads the file first, then auto-detects type from the actual
    downloaded filename extension:
      - .img/.bin → boot/init_boot image (skip ROM extraction)
      - .zip/.ozip/.pac → ROM (full extraction pipeline)

    Args:
        device_config: Device configuration dict with 'rom_url' or 'url' key.
            Optional 'kernel_partition' key.
        work_dir: Working directory for downloads and extraction.

    Returns:
        dict with keys: 'boot_img_path', 'init_boot_img_path', 'rom_type'
    """
    work = Path(work_dir)
    cache_dir = work / "cache"
    unpack_dir = work / "unpacked"

    rom_url = device_config.get("rom_url") or device_config.get("url")
    if not rom_url:
        raise ValueError("device_config must contain 'rom_url' or 'url'")

    kernel_partition = device_config.get("kernel_partition")

    # Stage 1: Download
    rom_path = download_rom(rom_url, cache_dir)

    # Auto-detect from downloaded file extension
    file_ext = rom_path.suffix.lower().lstrip(".")
    if file_ext in ("img", "bin"):
        logger.info("Detected boot image file: %s (skipping ROM unpack)", rom_path.name)
        img_name = rom_path.name.lower()
        if "init_boot" in img_name:
            return {
                "boot_img_path": None,
                "init_boot_img_path": str(rom_path),
                "rom_type": "boot_img",
            }
        else:
            return {
                "boot_img_path": str(rom_path),
                "init_boot_img_path": None,
                "rom_type": "boot_img",
            }

    # Stage 2: Unpack ROM
    result = unpack_rom(rom_path, unpack_dir, kernel_partition=kernel_partition)

    logger.info(
        "ROM unpack complete: type=%s, boot=%s, init_boot=%s",
        result["rom_type"],
        result.get("boot_img_path"),
        result.get("init_boot_img_path"),
    )

    return {
        "boot_img_path": result.get("boot_img_path"),
        "init_boot_img_path": result.get("init_boot_img_path"),
        "rom_type": result["rom_type"],
    }
