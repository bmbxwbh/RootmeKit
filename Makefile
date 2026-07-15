API ?= 35
OUTDIR ?= build/bin
CODEGEN_DIR ?= build/codegen
NDK_ROOT ?= $(ANDROID_NDK_HOME)
NDK_PREBUILT := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64
NDK_CC := $(NDK_PREBUILT)/bin/clang
SYSROOT := $(NDK_PREBUILT)/sysroot

PRELOAD := $(OUTDIR)/preload.so
DEVICE ?= RedmiK80Ultra

COMMON_CFLAGS := -O2 -Wall -Wno-#warnings -Wno-unused-parameter
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
TARGET_FLAGS := --target=aarch64-linux-android$(API)
LDFLAGS := -shared -fuse-ld=lld -Wl,--lto-O2 -pthread

.PHONY: all clean generate compile deploy info

all: $(PRELOAD)

$(CODEGEN_DIR)/exploit.c:
	@echo "[*] Generating exploit code from ROM data..."
	python3 -m rootmekit --device $(DEVICE) --stage codegen

$(OUTDIR):
	mkdir -p $@

$(PRELOAD): $(CODEGEN_DIR)/exploit.c $(CODEGEN_DIR)/target.h $(CODEGEN_DIR)/offsets.h | $(OUTDIR)
	@echo "[*] Compiling preload.so..."
	$(NDK_CC) $(TARGET_FLAGS) --sysroot=$(SYSROOT) \
	  $(SO_CFLAGS) -I$(CODEGEN_DIR) \
	  $(CODEGEN_DIR)/exploit.c \
	  $(LDFLAGS) -o $@
	@if [ -f "$(NDK_PREBUILT)/bin/llvm-strip" ]; then \
	  $(NDK_PREBUILT)/bin/llvm-strip --strip-all $@; \
	fi
	@echo "[+] Built: $@ ($$(stat -c%s $@) bytes)"

generate: $(CODEGEN_DIR)/exploit.c

compile: $(PRELOAD)

deploy: $(PRELOAD)
	@echo "[*] Deploying to device..."
	adb push $< /data/local/tmp/preload.so
	adb shell chmod 0644 /data/local/tmp/preload.so
	@echo "[+] Deployed. Run with:"
	@echo "    adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true'"

run: deploy
	@echo "[*] Running exploit..."
	adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true'

clean:
	rm -rf build

info:
	@echo "NDK_ROOT=$(NDK_ROOT)"
	@echo "NDK_CC=$(NDK_CC)"
	@echo "DEVICE=$(DEVICE)"
	@echo "PRELOAD=$(PRELOAD)"
