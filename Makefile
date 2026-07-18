# WinLock demo - Makefile
# 使用 w64devkit GCC
# 把 w64devkit/bin 加入 PATH，让 gcc 能找到 as/ld 等辅助工具

export PATH := C:/Home/Develop/w64devkit/bin:$(PATH)

GCC      := gcc
OBJCOPY  := objcopy
NM       := nm
RM       := rm -f
MKDIR    := mkdir -p

ROOT     := $(CURDIR)
STUB_DIR := $(ROOT)/stub
BLD_DIR  := $(ROOT)/builder
TST_DIR  := $(ROOT)/test

# 输入样本
SAMPLE   ?= $(ROOT)/../samples/hellogui.exe

# 编译参数
STUB_CFLAGS  := -Wall -Wextra -Wno-cast-function-type -O2 -ffreestanding \
                -fno-stack-protector -fno-pic -fno-pie \
                -fno-asynchronous-unwind-tables -fno-exceptions -fno-ident \
                -mno-red-zone -mno-sse -mno-sse2 \
                -DWINLOCK_STUB
STUB_LDFLAGS := -nostdlib -nostartfiles \
                -Wl,-subsystem,windows -Wl,-e,stub_entry \
                -Wl,--image-base=0x10000 \
                -Wl,-T,$(STUB_DIR)/stub.ld \
                -Wl,--gc-sections -Wl,--build-id=none

BLD_CFLAGS   := -Wall -Wextra -O2
BLD_LDFLAGS  := -ladvapi32

# 文件
STUB_SRC    := $(STUB_DIR)/stub.c
STUB_OBJ    := $(STUB_DIR)/stub.o
STUB_EXE    := $(STUB_DIR)/stub.exe
STUB_BIN    := $(STUB_DIR)/stub.bin

BLD_SRC     := $(BLD_DIR)/builder.c
BLD_EXE     := $(BLD_DIR)/builder.exe

# 默认输出
PROTECTED   := $(TST_DIR)/hellogui_locked.exe

.PHONY: all clean test run-stub run-protected

all: $(STUB_BIN) $(BLD_EXE)
	@echo ""
	@echo "=== Build complete ==="
	@echo "stub.bin:   $(STUB_BIN)"
	@echo "builder.exe: $(BLD_EXE)"

# === 构建 stub ===
$(STUB_OBJ): $(STUB_SRC) $(ROOT)/config.h
	$(GCC) $(STUB_CFLAGS) -c $< -o $@

$(STUB_EXE): $(STUB_OBJ) $(STUB_DIR)/stub.ld
	$(GCC) $(STUB_CFLAGS) $(STUB_LDFLAGS) $(STUB_OBJ) -o $@

$(STUB_BIN): $(STUB_EXE)
	$(OBJCOPY) -O binary -j .lock $< $@
	@echo === stub.bin layout ===
	@$(NM) $< 2>/dev/null | grep -E "stub_entry|stub_data|STR_" | head -20 || true

# === 构建 builder ===
$(BLD_EXE): $(BLD_SRC) $(ROOT)/config.h
	$(GCC) $(BLD_CFLAGS) $< -o $@ $(BLD_LDFLAGS)

# === 测试：加壳 hellogui.exe ===
test: $(STUB_BIN) $(BLD_EXE)
	@if [ ! -d "$(TST_DIR)" ]; then $(MKDIR) "$(TST_DIR)"; fi
	"$(BLD_EXE)" "$(SAMPLE)" "$(PROTECTED)"

# === 直接运行加壳后的 exe（需手动输入密码） ===
run-protected: $(PROTECTED)
	"$(PROTECTED)"

# === 仅运行 stub.exe（调试用，会在 stub_entry 早期崩溃，因为 stub_data 没填充） ===
run-stub: $(STUB_EXE)
	"$(STUB_EXE)"

clean:
	$(RM) "$(STUB_OBJ)" "$(STUB_EXE)" "$(STUB_BIN)" "$(BLD_EXE)" "$(PROTECTED)"
