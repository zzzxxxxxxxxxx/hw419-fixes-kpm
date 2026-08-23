# Environment-agnostic KPM Makefile.
#   Alpine LXC : make CC=aarch64-alpine-linux-musl-gcc
#   Termux     : make CC=clang        (或装了 cc 的话直接 make)

ifndef KP_DIR
    KP_DIR = ./KPM-Headers
endif

CC ?= cc

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/$(dir))

# PIE 会产生 KP 加载器不支持的 GOT 重定位，必须关掉
CFLAGS += -O2 -fno-stack-protector -fno-pic -fno-pie -fno-asynchronous-unwind-tables -mbranch-protection=none

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
