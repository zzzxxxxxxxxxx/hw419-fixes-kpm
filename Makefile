# Environment-agnostic KPM Makefile.
#   Alpine LXC : make CC=aarch64-alpine-linux-musl-gcc
#   Termux     : make CC=clang        (或装了 cc 的话直接 make)
#
# KP_DIR 默认指向本仓库的 KernelPatch 子模块 (bmax121/KernelPatch)。
# clone 时记得: git clone --recursive / git submodule update --init

ifndef KP_DIR
    KP_DIR = KernelPatch
endif

CC ?= cc

KINCLUDE_DIRS := include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_DIRS := . $(foreach dir,$(KINCLUDE_DIRS),kernel/$(dir))
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/$(dir))

# PIE 会产生 KP 加载器不支持的 GOT 重定位，必须关掉
CFLAGS += -O2 -fno-stack-protector -fno-pic -fno-pie -fno-asynchronous-unwind-tables -fno-unwind-tables

objs := hw_procfix.o

all: hw_procfix.kpm

hw_procfix.kpm: ${objs}
	$(CC) -r -o $@ $^
	objcopy -R .comment -R .eh_frame -R .rela.eh_frame $@ 2>/dev/null || true

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
