# WinLock demo - Makefile
# x64 stub + builder 用 w64devkit GCC 编译
# x86 stub 用 msys2 mingw32 GCC 编译（可选，仅 'make all-x86' 时需要）
#
# 工具链路径（可按需覆盖，例如：make all-x86 MSYS_MINGW32=/path/to/mingw32）
W64DEVKIT    ?= C:/Home/Develop/w64devkit/bin
MSYS_MINGW32 ?= C:/Home/Develop/msys64/mingw32/bin

# 把两个工具链 bin 都加入 PATH：
# - w64devkit: x64 gcc 的 as/ld 等
# - msys2 mingw32: x86 gcc 的 cc1.exe/as.exe/ld.exe 依赖的 DLL（libgmp-10.dll 等）
#   不加 PATH 的话 x86 gcc 会静默退出（exit 1，无错误输出）
export PATH := $(W64DEVKIT):$(MSYS_MINGW32):$(PATH)

GCC_X64      := gcc
GCC_X86      := $(MSYS_MINGW32)/gcc.exe
OBJCOPY      := objcopy
NM           := nm
RM           := rm -f
MKDIR        := mkdir -p

ROOT     := $(CURDIR)
STUB_DIR := $(ROOT)/stub
BLD_DIR  := $(ROOT)/builder
TST_DIR  := $(ROOT)/test

# 输入样本
SAMPLE   ?= $(ROOT)/../samples/hellogui.exe

# === x64 stub 编译参数（w64devkit gcc） ===
STUB_CFLAGS_X64  := -Wall -Wextra -Wno-cast-function-type -O2 -ffreestanding \
                    -fno-stack-protector -fno-pic -fno-pie \
                    -fno-asynchronous-unwind-tables -fno-exceptions -fno-ident \
                    -mno-red-zone -mno-sse -mno-sse2 \
                    -DWINLOCK_STUB
STUB_LDFLAGS_X64 := -nostdlib -nostartfiles \
                    -Wl,-subsystem,windows -Wl,-e,stub_entry \
                    -Wl,--image-base=0x10000 \
                    -Wl,-T,$(STUB_DIR)/stub.ld \
                    -Wl,--gc-sections -Wl,--build-id=none

# === x86 stub 编译参数（msys2 mingw32 gcc） ===
#   -m32 由 i686-w64-mingw32 工具链隐含提供
#   -mno-red-zone 是 x64-only 选项，x86 省略
#   其余与 x64 一致
STUB_CFLAGS_X86  := -Wall -Wextra -Wno-cast-function-type -O2 -ffreestanding \
                    -fno-stack-protector -fno-pic -fno-pie \
                    -fno-asynchronous-unwind-tables -fno-exceptions -fno-ident \
                    -mno-sse -mno-sse2 \
                    -DWINLOCK_STUB
STUB_LDFLAGS_X86 := -nostdlib -nostartfiles \
                    -Wl,-subsystem,windows -Wl,-e,_stub_entry \
                    -Wl,--image-base=0x10000 \
                    -Wl,-T,$(STUB_DIR)/stub.ld \
                    -Wl,--gc-sections -Wl,--build-id=none

BLD_CFLAGS   := -Wall -Wextra -O2
BLD_LDFLAGS  := -ladvapi32

# 文件
STUB_SRC    := $(STUB_DIR)/stub.c

STUB_OBJ_X64 := $(STUB_DIR)/stub_x64.o
STUB_EXE_X64 := $(STUB_DIR)/stub_x64.exe
STUB_BIN_X64 := $(STUB_DIR)/stub_x64.bin

STUB_OBJ_X86 := $(STUB_DIR)/stub_x86.o
STUB_EXE_X86 := $(STUB_DIR)/stub_x86.exe
STUB_BIN_X86 := $(STUB_DIR)/stub_x86.bin

# 向后兼容：stub.bin = stub_x64.bin
STUB_OBJ     := $(STUB_OBJ_X64)
STUB_EXE     := $(STUB_EXE_X64)
STUB_BIN     := $(STUB_BIN_X64)

BLD_SRC     := $(BLD_DIR)/builder.c
BLD_EXE     := $(BLD_DIR)/builder.exe

# 默认输出
PROTECTED   := $(TST_DIR)/hellogui_locked.exe

.PHONY: all all-x86 clean test run-stub run-protected

# 默认只编 x64 + builder（保持快速）
all: $(STUB_BIN_X64) $(BLD_EXE)
	@echo ""
	@echo "=== Build complete (x64 only) ==="
	@echo "stub_x64.bin: $(STUB_BIN_X64)"
	@echo "builder.exe:  $(BLD_EXE)"
	@echo "Run 'make all-x86' to also build x86 stub."

# 同时编 x64 + x86（需要 msys2 mingw32 工具链）
all-x86: all $(STUB_BIN_X86)
	@echo ""
	@echo "=== Build complete (x64 + x86) ==="
	@echo "stub_x64.bin: $(STUB_BIN_X64)"
	@echo "stub_x86.bin: $(STUB_BIN_X86)"
	@echo "builder.exe:  $(BLD_EXE)"

# 检查 msys2 mingw32 工具链是否可用（编译 x86 stub 前置条件）
check-x86-toolchain:
	@if [ ! -x "$(MSYS_MINGW32)/gcc.exe" ]; then \
		echo "[ERR] msys2 mingw32 gcc not found: $(MSYS_MINGW32)/gcc.exe"; \
		echo "      Install (msys2 shell): pacman -S mingw-w64-i686-gcc"; \
		echo "      Or override path: make all-x86 MSYS_MINGW32=/path/to/mingw32/bin"; \
		exit 1; \
	fi

# === 构建 x64 stub ===
$(STUB_OBJ_X64): $(STUB_SRC) $(ROOT)/config.h
	$(GCC_X64) $(STUB_CFLAGS_X64) -c $< -o $@

$(STUB_EXE_X64): $(STUB_OBJ_X64) $(STUB_DIR)/stub.ld
	$(GCC_X64) $(STUB_CFLAGS_X64) $(STUB_LDFLAGS_X64) $(STUB_OBJ_X64) -o $@

$(STUB_BIN_X64): $(STUB_EXE_X64)
	$(OBJCOPY) -O binary -j .lock $< $@
	@echo === stub_x64.bin layout ===
	@$(NM) $< 2>/dev/null | grep -E "stub_entry|stub_data|STR_" | head -20 || true

# === 构建 x86 stub ===
$(STUB_OBJ_X86): $(STUB_SRC) $(ROOT)/config.h check-x86-toolchain
	$(GCC_X86) $(STUB_CFLAGS_X86) -c $< -o $@

$(STUB_EXE_X86): $(STUB_OBJ_X86) $(STUB_DIR)/stub.ld
	$(GCC_X86) $(STUB_CFLAGS_X86) $(STUB_LDFLAGS_X86) $(STUB_OBJ_X86) -o $@

$(STUB_BIN_X86): $(STUB_EXE_X86)
	$(OBJCOPY) -O binary -j .lock $< $@
	@echo === stub_x86.bin layout ===
	@$(NM) $< 2>/dev/null | grep -E "stub_entry|stub_data|STR_" | head -20 || true

# === 构建 builder ===
$(BLD_EXE): $(BLD_SRC) $(ROOT)/config.h
	$(GCC_X64) $(BLD_CFLAGS) $< -o $@ $(BLD_LDFLAGS)

# === 测试：加壳 hellogui.exe ===
test: $(STUB_BIN_X64) $(BLD_EXE)
	@if [ ! -d "$(TST_DIR)" ]; then $(MKDIR) "$(TST_DIR)"; fi
	"$(BLD_EXE)" "$(SAMPLE)" "$(PROTECTED)"

# === 直接运行加壳后的 exe（需手动输入密码） ===
run-protected: $(PROTECTED)
	"$(PROTECTED)"

# === 仅运行 stub.exe（调试用，会在 stub_entry 早期崩溃，因为 stub_data 没填充） ===
run-stub: $(STUB_EXE_X64)
	"$(STUB_EXE_X64)"

clean:
	$(RM) "$(STUB_OBJ_X64)" "$(STUB_EXE_X64)" "$(STUB_BIN_X64)"
	$(RM) "$(STUB_OBJ_X86)" "$(STUB_EXE_X86)" "$(STUB_BIN_X86)"
	$(RM) "$(BLD_EXE)" "$(PROTECTED)"
	# 清理旧命名
	$(RM) "$(STUB_DIR)/stub.o" "$(STUB_DIR)/stub.exe" "$(STUB_DIR)/stub.bin"
