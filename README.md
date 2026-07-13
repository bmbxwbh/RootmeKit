# RootmeKit

全自动 Android Root 链路生成工具。用户只需提供 ROM 下载链接，GitHub Action 自动构建内核 exploit，发布可执行文件。

## 工作原理

```
ROM 包 → 解包提取内核 → 符号恢复 → 偏移计算 → 生成 exploit → 编译 preload.so
```

浏览器端通过 Firefox JIT Type Confusion (CVE-2026-23274) 获取 shell，加载 `preload.so` 执行内核提权。

## 快速开始

### 1. Fork 本仓库

### 2. 编辑配置文件

编辑 `config/devices.yaml`，填入你的 ROM 下载链接：

```yaml
devices:
  - rom_url: "https://example.com/your-device-ota.zip"
```

只需填 `rom_url`，其余自动检测。可选字段：

```yaml
devices:
  - rom_url: "https://example.com/ota.zip"
    name: "my_device"                     # 可选，默认从文件名生成
    manual_offsets:                        # 可选，自动提取失败时手动指定
      KIMAGE_TEXT_BASE: "0xFFFFFFC080000000"
```

### 3. 触发构建

推送 `config/devices.yaml` 到 `main` 分支，或手动触发 GitHub Action。

### 4. 获取结果

- **preload.so** — 从 GitHub Release 下载
- **exploit 页面** — 访问 GitHub Pages 站点

### 5. 在手机上使用

1. 解锁 Bootloader
2. 安装 Firefox 151.0 (arm64)
3. 在 Firefox 中打开 GitHub Pages 站点
4. 导入从 Release 下载的 `preload.so` 文件
5. 点击"开始 Root"

## 前置条件

| 要求 | 说明 |
|------|------|
| Bootloader 解锁 | 必须解锁，否则无法执行 exploit |
| Firefox 151.0 | 必须使用此版本，其他版本偏移不同 |
| ARM64 设备 | 当前仅支持 ARM64 架构 |

## 支持的设备

GKI 内核设备（Android 13+，内核 6.x）成功率最高。非 GKI 设备（内核 4.x/5.x）取决于能否获取调试信息。

| 类型 | 成功率 | 说明 |
|------|--------|------|
| Pixel / 通用 GKI 6.6 | 高 | 符号和 BTF 可自动提取 |
| OnePlus / Xiaomi GKI | 较高 | GKI 内核核心不变 |
| 非 GKI 4.19 + 有 BTF | 中 | 结构体偏移需验证 |
| 非 GKI 无调试信息 | 低 | 需手动提供偏移 |
| Samsung (RKP/KNOX) | 不支持 | 硬件级安全拦截 |

## 流水线阶段

| 阶段 | 说明 |
|------|------|
| 1. ROM 下载 | 从 URL 下载 ROM 包 |
| 2. ROM 解包 | 自动检测格式，提取 boot.img |
| 3. 内核提取 | 从 boot.img 提取 vmlinux |
| 4. 符号恢复 | readelf → vmlinux-to-elf → BTF 三级降级 |
| 5. 偏移计算 | 计算内核符号偏移和内存布局 |
| 6. 代码生成 | 渲染 exploit.c + 交叉编译 preload.so |
| 7. 打包输出 | 复制静态站点 + 生成构建报告 |

## 项目结构

```
rootmekit/
├── site/exploit.html          # 固定的浏览器 exploit 页面
├── config/devices.yaml        # 用户配置（只填 ROM URL）
├── src/                       # Python 构建流水线
├── templates/exploit/         # C 代码模板
├── data/                      # Firefox 偏移 + 内核配置数据库
└── .github/workflows/build.yml
```

## 免责声明

本工具仅供学习和研究用途，仅限对用户自有设备使用。使用者需自行承担所有风险和责任。
