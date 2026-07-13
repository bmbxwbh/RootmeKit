"""Stage 7: Copy static site files.

The web page (site/exploit.html) is static and pre-deployed.
This stage simply copies it to the output directory.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def run(all_device_results: dict[str, dict[str, Any]], work_dir: str | Path) -> dict[str, Any]:
    """Copy static site files to the output directory.

    Args:
        all_device_results: Dict mapping device_name -> combined stage results.
        work_dir: Working directory.

    Returns:
        dict with 'site_dir' path.
    """
    work = Path(work_dir)
    site_dir = work / "site"
    site_dir.mkdir(parents=True, exist_ok=True)

    # Copy static site files from site/ directory
    src_site = Path(__file__).parent.parent.parent / "site"
    if src_site.exists():
        for item in src_site.iterdir():
            if item.is_file():
                shutil.copy2(item, site_dir / item.name)
                logger.debug("Copied %s -> %s", item, site_dir / item.name)

    logger.info("Site build complete: %s", site_dir)
    return {"site_dir": site_dir}
