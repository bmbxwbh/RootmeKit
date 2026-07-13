"""CLI entry point for RootmeKit.

Uses argparse for simplicity (no click dependency).

Subcommands:
  build        - Full build pipeline (used by GitHub Action)
  parse-config - Parse and validate config, output device list
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

from .pipeline import DeviceConfig, run_all

logger = logging.getLogger("rootmekit")


def _setup_logging(verbose: bool = False) -> None:
    """Configure logging for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _cmd_build(args: argparse.Namespace) -> int:
    """Execute the full build pipeline."""
    _setup_logging(getattr(args, "verbose", False))

    config_path = Path(args.config)
    work_dir = Path(args.work_dir)
    output_dir = Path(args.output_dir)

    logger.info("RootmeKit build starting")
    logger.info("Config: %s", config_path)
    logger.info("Work dir: %s", work_dir)
    logger.info("Output dir: %s", output_dir)

    try:
        result = run_all(config_path, work_dir)
    except FileNotFoundError as e:
        logger.error("Config file not found: %s", e)
        return 1
    except Exception as e:
        logger.error("Build failed with error: %s", e)
        return 1

    # Copy site to output directory if specified
    site_dir = result.get("site_dir")
    if site_dir and Path(site_dir).exists():
        import shutil
        output_site = output_dir / "site"
        if output_site.exists():
            shutil.rmtree(output_site)
        shutil.copytree(Path(site_dir), output_site)
        logger.info("Site copied to: %s", output_site)

    # Copy preload.so files to output directory
    import shutil
    results = result.get("results", {})
    for name, r in results.items():
        if not r.failed and r.preload_so_path:
            device_output = output_dir / name
            device_output.mkdir(parents=True, exist_ok=True)
            src = Path(r.preload_so_path)
            if src.exists():
                shutil.copy2(src, device_output / "preload.so")
                logger.info("preload.so copied to: %s", device_output / "preload.so")

    # Print summary
    succeeded = sum(1 for r in results.values() if not r.failed)
    failed = sum(1 for r in results.values() if r.failed)

    logger.info("=" * 60)
    logger.info("BUILD SUMMARY")
    logger.info("=" * 60)
    logger.info("Total devices: %d", len(results))
    logger.info("Succeeded: %d", succeeded)
    logger.info("Failed: %d", failed)

    for name, r in results.items():
        status = "OK" if not r.failed else f"FAILED ({r.failure_stage}: {r.failure_reason})"
        logger.info("  %s: %s", name, status)

    if result.get("build_report"):
        logger.info("Build report: %s", result["build_report"])

    return 0 if failed == 0 else 1


def _cmd_parse_config(args: argparse.Namespace) -> int:
    """Parse and validate config, output device list as JSON."""
    _setup_logging(getattr(args, "verbose", False))

    config_path = Path(args.config)
    if not config_path.exists():
        logger.error("Config file not found: %s", config_path)
        return 1

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error("Failed to parse YAML config: %s", e)
        return 1

    devices = config.get("devices", [])
    if not devices:
        logger.warning("No devices found in config")
        print(json.dumps({"devices": [], "count": 0}, indent=2))
        return 0

    # Validate each device config
    validated: list[dict[str, Any]] = []
    errors: list[str] = []

    for i, device in enumerate(devices):
        if "rom_url" not in device:
            errors.append(f"Device #{i+1}: missing 'rom_url' field")
            continue

        dc = DeviceConfig.from_dict(device)
        validated.append({
            "name": dc.name,
            "display_name": dc.display_name,
            "rom_url": dc.rom_url,
            "has_manual_offsets": bool(dc.manual_offsets),
            "manual_offset_count": len(dc.manual_offsets),
        })

    output = {
        "devices": validated,
        "count": len(validated),
        "errors": errors,
    }

    print(json.dumps(output, indent=2))
    return 0 if not errors else 1


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="rootmekit",
        description="RootmeKit - Automated Android Root Exploit Generation",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (debug) output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── build ─────────────────────────────────────────────────────────
    build_parser = subparsers.add_parser(
        "build",
        help="Full build pipeline (used by GitHub Action)",
    )
    build_parser.add_argument(
        "--config",
        default="config/devices.yaml",
        help="Path to devices config YAML (default: config/devices.yaml)",
    )
    build_parser.add_argument(
        "--work-dir",
        default="/tmp/rootmekit_build",
        help="Working directory for build artifacts (default: /tmp/rootmekit_build)",
    )
    build_parser.add_argument(
        "--output-dir",
        default="output/",
        help="Output directory for final site (default: output/)",
    )

    # ── parse-config ──────────────────────────────────────────────────
    parse_parser = subparsers.add_parser(
        "parse-config",
        help="Parse and validate config, output device list",
    )
    parse_parser.add_argument(
        "--config",
        default="config/devices.yaml",
        help="Path to devices config YAML (default: config/devices.yaml)",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    cmd_map = {
        "build": _cmd_build,
        "parse-config": _cmd_parse_config,
    }

    handler = cmd_map.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
