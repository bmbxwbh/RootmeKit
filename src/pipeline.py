"""Main pipeline orchestrator for RootmeKit.

Coordinates all stages: ROM unpack, kernel extract, symbol recovery,
offset calculation, codegen, and static site copy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .stages.codegen import run as codegen_run
from .stages.kernel_extract import run as kernel_extract_run
from .stages.offset_calc import run as offset_calc_run
from .stages.rom_unpack import run as rom_unpack_run
from .stages.site_build import run as site_build_run
from .stages.symbol_recovery import run as symbol_recovery_run

logger = logging.getLogger(__name__)


@dataclass
class BuildResult:
    """Holds all results from each pipeline stage."""

    device_name: str = ""
    display_name: str = ""
    rom_type: str = ""
    boot_img_path: str | None = None
    init_boot_img_path: str | None = None
    vmlinux_path: str | None = None
    kernel_version: str | None = None
    kernel_is_gki: bool = False
    arch: str = "aarch64"
    symbols: dict[str, int] = field(default_factory=dict)
    symbol_count: int = 0
    recovery_method: str = "none"
    has_btf: bool = False
    btf_structs: dict[str, dict[str, int]] = field(default_factory=dict)
    target_h_path: str | None = None
    offsets_h_path: str | None = None
    memory_type: str = "dma_heap"
    offset_sources: dict[str, str] = field(default_factory=dict)
    confidence_report: dict[str, Any] = field(default_factory=dict)
    exploit_c_path: str | None = None
    preload_so_path: str | None = None
    failed: bool = False
    failure_stage: str | None = None
    failure_reason: str | None = None


@dataclass
class DeviceConfig:
    """Parsed from YAML config for a single device.

    Only rom_url is required. name is auto-generated
    from the ROM filename if not provided.
    """

    name: str
    display_name: str
    rom_url: str
    manual_offsets: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceConfig:
        """Create DeviceConfig from a dict (parsed from YAML).

        Auto-generates name from rom_url if not provided.
        """
        rom_url = data.get("rom_url", "")
        # Auto-generate name from ROM URL filename
        filename = rom_url.split("/")[-1].split("?")[0] if rom_url else "unknown"
        # Clean filename to be a valid directory name
        import re
        auto_name = re.sub(r"[^a-zA-Z0-9_-]", "_", filename.rstrip(".zip").rstrip(".ozip").rstrip(".pac"))
        if not auto_name:
            auto_name = "device"

        name = data.get("name") or auto_name
        display_name = name.replace("_", " ")

        # Parse manual_offsets from string to int
        manual_offsets: dict[str, int] = {}
        raw_offsets = data.get("manual_offsets", {})
        if raw_offsets:
            for k, v in raw_offsets.items():
                if isinstance(v, str):
                    try:
                        manual_offsets[k] = int(v, 0)  # supports 0x hex and decimal
                    except ValueError:
                        logger.warning("Invalid manual offset value for %s: %s", k, v)
                elif isinstance(v, int):
                    manual_offsets[k] = v

        return cls(
            name=name,
            display_name=display_name,
            rom_url=rom_url,
            manual_offsets=manual_offsets,
        )


def run_device(device_config: DeviceConfig, work_dir: str | Path) -> BuildResult:
    """Run all stages for one device.

    Handles failures gracefully - marks the device as failed but
    does not crash the pipeline.

    Args:
        device_config: Device configuration.
        work_dir: Working directory for this device.

    Returns:
        BuildResult with all stage outputs or failure information.
    """
    work = Path(work_dir)
    device_work = work / "devices" / device_config.name
    device_work.mkdir(parents=True, exist_ok=True)

    result = BuildResult(
        device_name=device_config.name,
        display_name=device_config.display_name,
    )

    logger.info("=" * 60)
    logger.info("Processing device: %s (%s)", device_config.name, device_config.display_name)
    logger.info("=" * 60)

    # ── Stage 1-2: ROM Download & Unpack ──────────────────────────────
    try:
        logger.info("[Stage 1-2] Downloading and unpacking ROM...")
        device_dict = {
            "rom_url": device_config.rom_url,
        }
        unpack_result = rom_unpack_run(device_dict, device_work)
        result.rom_type = unpack_result.get("rom_type", "unknown")
        result.boot_img_path = str(unpack_result["boot_img_path"]) if unpack_result.get("boot_img_path") else None
        result.init_boot_img_path = str(unpack_result["init_boot_img_path"]) if unpack_result.get("init_boot_img_path") else None

        if not result.boot_img_path:
            raise RuntimeError("No boot image found after ROM unpack")
    except Exception as e:
        logger.error("[Stage 1-2] FAILED: %s", e)
        result.failed = True
        result.failure_stage = "rom_unpack"
        result.failure_reason = str(e)
        return result

    # ── Stage 3: Kernel Extraction ────────────────────────────────────
    try:
        logger.info("[Stage 3] Extracting kernel...")
        extract_result = kernel_extract_run(unpack_result, device_work)
        result.vmlinux_path = str(extract_result["vmlinux_path"]) if extract_result.get("vmlinux_path") else None
        result.kernel_version = extract_result.get("kernel_version")
        result.kernel_is_gki = extract_result.get("kernel_is_gki", False)
        result.arch = extract_result.get("arch", "aarch64")

        if not result.vmlinux_path:
            raise RuntimeError("No vmlinux produced from kernel extraction")
    except Exception as e:
        logger.error("[Stage 3] FAILED: %s", e)
        result.failed = True
        result.failure_stage = "kernel_extract"
        result.failure_reason = str(e)
        return result

    # ── Stage 4: Symbol Recovery ──────────────────────────────────────
    try:
        logger.info("[Stage 4] Recovering symbols...")
        sym_result = symbol_recovery_run(extract_result, device_work)
        result.symbols = sym_result.get("symbols", {})
        result.symbol_count = sym_result.get("symbol_count", 0)
        result.recovery_method = sym_result.get("recovery_method", "none")
        result.has_btf = sym_result.get("has_btf", False)
        result.btf_structs = sym_result.get("btf_structs", {})
    except Exception as e:
        logger.error("[Stage 4] FAILED: %s", e)
        result.failed = True
        result.failure_stage = "symbol_recovery"
        result.failure_reason = str(e)
        return result

    # ── Stage 5: Offset Calculation ──────────────────────────────────
    try:
        logger.info("[Stage 5] Calculating offsets...")
        # Merge previous results for offset calculation
        combined_prev = {
            **unpack_result,
            **extract_result,
            **sym_result,
            "manual_offsets": device_config.manual_offsets,
            "device_name": device_config.name,
        }
        offset_result = offset_calc_run(combined_prev, device_work)
        result.target_h_path = str(offset_result["target_h_path"]) if offset_result.get("target_h_path") else None
        result.offsets_h_path = str(offset_result["offsets_h_path"]) if offset_result.get("offsets_h_path") else None
        result.memory_type = offset_result.get("memory_type", "dma_heap")
        result.offset_sources = offset_result.get("offset_sources", {})
        result.confidence_report = offset_result.get("confidence_report", {})
    except Exception as e:
        logger.error("[Stage 5] FAILED: %s", e)
        result.failed = True
        result.failure_stage = "offset_calc"
        result.failure_reason = str(e)
        return result

    # ── Stage 6: Code Generation ─────────────────────────────────────
    try:
        logger.info("[Stage 6] Generating exploit code...")
        codegen_prev = {
            **offset_result,
            "kernel_version": result.kernel_version,
            "arch": result.arch,
            "kernel_is_gki": result.kernel_is_gki,
        }
        codegen_result = codegen_run(
            codegen_prev, device_work, {
                "name": device_config.name,
                "display_name": device_config.display_name,
            },
        )
        result.exploit_c_path = str(codegen_result["exploit_c_path"]) if codegen_result.get("exploit_c_path") else None
        result.preload_so_path = str(codegen_result["preload_so_path"]) if codegen_result.get("preload_so_path") else None
    except Exception as e:
        logger.error("[Stage 6] FAILED: %s", e)
        result.failed = True
        result.failure_stage = "codegen"
        result.failure_reason = str(e)
        return result

    logger.info("All stages completed successfully for %s", device_config.name)
    return result


def _generate_build_report(
    results: dict[str, BuildResult],
    report_path: Path,
) -> Path:
    """Generate a markdown build report summarizing all devices."""
    lines: list[str] = [
        "# RootmeKit Build Report",
        "",
        f"Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Summary",
        "",
        f"| Device | Status | Kernel | Arch | Symbols | Recovery | Memory |",
        f"|--------|--------|--------|------|---------|----------|--------|",
    ]

    for name, r in results.items():
        status = "OK" if not r.failed else f"FAILED ({r.failure_stage})"
        kernel = r.kernel_version or "unknown"
        sym_count = str(r.symbol_count)
        lines.append(
            f"| {r.display_name} | {status} | {kernel} | {r.arch} | "
            f"{sym_count} | {r.recovery_method} | {r.memory_type} |"
        )

    lines.append("")
    lines.append("## Details")
    lines.append("")

    for name, r in results.items():
        lines.append(f"### {r.display_name} (`{name}`)")
        lines.append("")
        if r.failed:
            lines.append(f"- **Status**: FAILED at stage `{r.failure_stage}`")
            lines.append(f"- **Reason**: {r.failure_reason}")
        else:
            lines.append(f"- **ROM type**: {r.rom_type}")
            lines.append(f"- **Kernel version**: {r.kernel_version}")
            lines.append(f"- **GKI**: {r.kernel_is_gki}")
            lines.append(f"- **Architecture**: {r.arch}")
            lines.append(f"- **Symbol count**: {r.symbol_count}")
            lines.append(f"- **Recovery method**: {r.recovery_method}")
            lines.append(f"- **BTF available**: {r.has_btf}")
            lines.append(f"- **Memory type**: {r.memory_type}")

            if r.confidence_report:
                lines.append(f"- **Symbol confidence**: {r.confidence_report.get('symbol_recovery_confidence', 'unknown')}")
                lines.append(f"- **Offset confidence**: {r.confidence_report.get('offset_confidence', 'unknown')}")

        lines.append("")

    report_path.write_text("\n".join(lines))
    logger.info("Build report written to: %s", report_path)
    return report_path


def run_all(config_path: str | Path, work_dir: str | Path) -> dict[str, Any]:
    """Parse config, run all devices, copy static site.

    Args:
        config_path: Path to the YAML config file.
        work_dir: Working directory for the entire build.

    Returns:
        dict with 'site_dir', 'build_report', 'results' keys.
    """
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)

    # Parse config
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_file}")

    with open(config_file) as f:
        config = yaml.safe_load(f)

    devices_config = config.get("devices", [])
    if not devices_config:
        logger.warning("No devices found in config file: %s", config_file)
        return {"site_dir": None, "build_report": None, "results": {}}

    logger.info("Found %d devices in config", len(devices_config))

    # Parse device configs
    device_configs = [DeviceConfig.from_dict(d) for d in devices_config]

    # Run each device through the pipeline
    results: dict[str, BuildResult] = {}
    for dc in device_configs:
        logger.info("Starting build for device: %s", dc.name)
        result = run_device(dc, work)
        results[dc.name] = result

    # Copy static site
    site_result = site_build_run({}, work)

    # Generate build report
    report_path = work / "BUILD_REPORT.md"
    _generate_build_report(results, report_path)

    # Summary
    succeeded = sum(1 for r in results.values() if not r.failed)
    failed = sum(1 for r in results.values() if r.failed)
    logger.info("Build complete: %d succeeded, %d failed out of %d devices",
                succeeded, failed, len(results))

    return {
        "site_dir": str(site_result.get("site_dir", "")),
        "build_report": str(report_path),
        "results": results,
    }
