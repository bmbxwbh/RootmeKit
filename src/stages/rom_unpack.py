"""Stage 1-2: Download and unpack ROM.

Downloads the ROM from the provided URL, detects the ROM format,
and unpacks it to extract boot images.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from ..utils.bootimg_utils import detect_rom_type, find_boot_images
from ..utils.payload_utils import extract_payload_partitions

logger = logging.getLogger(__name__)


def _run_cmd(
    cmd: list[str],
    *,
    timeout: int = 600,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


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


def _unpack_payload(rom_path: Path, output_dir: Path) -> Path:
    """Unpack payload.bin using Python-native payload parser.

    Returns:
        Path to the directory containing extracted images.
    """
    payload_dir = output_dir / "payload_extract"
    payload_dir.mkdir(parents=True, exist_ok=True)

    # Find payload.bin
    payload_bin: Path | None = None
    if rom_path.is_dir():
        candidates = list(rom_path.glob("**/payload.bin"))
        if candidates:
            payload_bin = candidates[0]
    elif rom_path.suffix.lower() == ".zip":
        # Extract zip first
        zip_dir = output_dir / "zip_extract"
        zip_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Extracting zip: %s", rom_path)
        with zipfile.ZipFile(rom_path, "r") as zf:
            zf.extractall(zip_dir)
        candidates = list(zip_dir.glob("**/payload.bin"))
        if candidates:
            payload_bin = candidates[0]
    else:
        payload_bin = rom_path

    if payload_bin is None or not payload_bin.exists():
        raise FileNotFoundError("payload.bin not found in ROM")

    logger.info("Extracting payload using Python-native parser: %s", payload_bin)
    extract_payload_partitions(
        str(payload_bin),
        str(payload_dir),
        partition_names=["init_boot", "boot"],
    )

    return payload_dir


def _unpack_ozip(rom_path: Path, output_dir: Path) -> Path:
    """Decrypt OPPO ozip and treat as payload.

    Returns:
        Path to the extracted payload directory.
    """
    logger.info("Decrypting OPPO ozip: %s", rom_path)

    # Try oppo_ozip_decrypt or ozip_decrypt
    decrypted_dir = output_dir / "ozip_decrypt"
    decrypted_dir.mkdir(parents=True, exist_ok=True)
    decrypted_zip = decrypted_dir / rom_path.with_suffix(".zip").name

    # Try ozip_decrypt tool
    proc = _run_cmd(
        ["ozip-decrypt", str(rom_path), str(decrypted_zip)],
        timeout=600,
    )
    if proc.returncode != 0:
        # Try Python-based decrypt
        proc = _run_cmd(
            ["python3", "-m", "oppo_ozip", str(rom_path), str(decrypted_zip)],
            timeout=600,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to decrypt ozip: {proc.stderr}")

    # Now treat the decrypted zip as a payload ROM
    return _unpack_payload(decrypted_zip, output_dir)


def _unpack_pac(rom_path: Path, output_dir: Path) -> Path:
    """Unpack Samsung PAC file.

    Returns:
        Path to the directory containing extracted images.
    """
    pac_dir = output_dir / "pac_extract"
    pac_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Unpacking Samsung PAC: %s", rom_path)
    # Samsung PAC files can be extracted with samfirm or similar tools
    proc = _run_cmd(
        ["samfirm", "extract", "-i", str(rom_path), "-o", str(pac_dir)],
        timeout=1800,
    )
    if proc.returncode != 0:
        # Try with parse_pac or manual extraction
        logger.warning("samfirm failed, trying manual PAC extraction")
        proc = _run_cmd(
            ["python3", "-m", "pacparser", str(rom_path), str(pac_dir)],
            timeout=1800,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to unpack PAC file: {proc.stderr}")

    return pac_dir


def unpack_rom(rom_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Unpack ROM based on detected type.

    Args:
        rom_path: Path to the ROM file or directory.
        output_dir: Directory to extract into.

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
        unpack_dir = _unpack_payload(rom, out_dir)
        result["unpack_dir"] = unpack_dir
    elif rom_type == "ozip":
        unpack_dir = _unpack_ozip(rom, out_dir)
        result["unpack_dir"] = unpack_dir
    elif rom_type == "pac":
        unpack_dir = _unpack_pac(rom, out_dir)
        result["unpack_dir"] = unpack_dir
    elif rom_type == "boot_img":
        # Direct boot image - just copy to output dir
        dest = out_dir / rom.name
        if rom != dest:
            shutil.copy2(rom, dest)
        result["unpack_dir"] = out_dir
        result["boot_img_path"] = dest
        return result
    else:
        logger.error("Unknown ROM type, cannot unpack: %s", rom)
        # Last resort: try as a zip file
        if rom.suffix.lower() == ".zip":
            try:
                unpack_dir = _unpack_payload(rom, out_dir)
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

    Args:
        device_config: Device configuration dict with 'rom_url' key.
        work_dir: Working directory for downloads and extraction.

    Returns:
        dict with keys: 'boot_img_path', 'init_boot_img_path', 'rom_type'
    """
    work = Path(work_dir)
    cache_dir = work / "cache"
    unpack_dir = work / "unpacked"

    rom_url = device_config.get("rom_url")
    if not rom_url:
        raise ValueError("device_config must contain 'rom_url'")

    # Stage 1: Download
    rom_path = download_rom(rom_url, cache_dir)

    # Stage 2: Unpack
    result = unpack_rom(rom_path, unpack_dir)

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
