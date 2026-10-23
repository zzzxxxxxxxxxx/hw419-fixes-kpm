# hw419-fixes-kpm

> 华为/HarmonyOS 4.19 vendor 内核的 KernelPatch 修补模块（KPM，
> 内核模块名为 `hw419-fixes`）：
> 修复 bwrap/runc/crun 的 procfs `EBUSY`，并规避 KernelPatch 残留 seccomp
> filter 对旧内核未实现 syscall 注入的 SIGSYS。

- 适用设备：已验证 GOT-W29（骁龙平台，`4.19.157-perf+`），理论适用同源内核
- 依赖：[KernelPatch](https://github.com/bmax121/KernelPatch) / APatch / FolkPatch
- 许可：GPL-2.0

---

## procfs EBUSY

在 Huawei/HarmonyOS 内核的 LXC 中运行 bubblewrap：

```console
# bwrap --unshare-all --new-session --proc /proc -- /bin/bash
bwrap: Can't mount proc on /newroot/proc: Resource busy
```

所有使用原子 `clone(CLONE_NEWUSER | CLONE_NEWPID)` 的工具均受影响。

### 根因

Vendor 内核恢复了旧的 `pid_ns_prepare_proc` 机制：新 PID namespace 的第一个
进程诞生时，`alloc_pid()` 会在 clone 发起者上下文中 `kern_mount()` 一个内部
procfs。原子创建 user+PID namespace 时，内部 superblock 因而属于父进程的
`init_user_ns`，子进程稍后请求 `sget_userns(新 userns)` 时返回 `-EBUSY`。

`proc_mount` 中还有一条 HarmonyOS containerd cmdline 后门，会按
`pidns->user_ns` 创建 superblock。KPM 将：

```asm
bl   __pi_memcmp
cbz  w0, +0x74       ; 340003a0
```

改为无条件跳转：

```asm
b    +0x74           ; 1400001d
```

修复后的不变式是：pidns P 的 procfs superblock 一律属于 `P->user_ns`。

## KernelPatch seccomp 兼容

真机使用 KernelPatch `0.13.8 (d08)`。其 `commit_common_su()` 在切换 root
凭据时只执行：

```c
thi->flags &= ~_TIF_SECCOMP;
seccomp->mode = SECCOMP_MODE_DISABLED;
// seccomp_filter_release(task);
```

这里没有释放或清空 `seccomp.filter`。只读诊断 KPM 在 APatch su 进程中读到：

```text
mode=0 filter=ffffffc395a68d40
```

因此从 `/proc/status` 看到的 `Seccomp: 0` 只表示 mode 被关闭，旧 Android
seccomp 链仍保留。进程之后再安装 Codex 的过滤器时，内核会重新遍历这条旧链。

在同一环境中，即使用一个最终动作仅为 `SECCOMP_RET_ALLOW` 的最小过滤器：

- `#434` 正常执行
- `#435`（clone3）、`#437`（openat2）、`#439`（faccessat2）返回
  `SYS_SECCOMP` SIGSYS

同一个 `kernel.patched` 在 QEMU 中不加载 APatch/KernelPatch 时，`#439` 正常
返回 `ENOSYS`。因此问题来自 KernelPatch su 关闭 seccomp mode 时遗留的旧
filter 链，不是基础内核镜像或 Codex 的 BPF 规则。

NoHello `v1.8.3.7` 也曾 hook `__seccomp_filter`，会叠加这一故障；但移除
NoHello 后，残留 filter 链仍会单独触发 SIGSYS。

### 修复策略

本模块只对 `0..434` 范围之外的 syscall、或 `sys_call_table` 中严格指向
`sys_ni_syscall` / `__arm64_sys_ni_syscall` 的 syscall 生效：

1. 校验 `el0_svc_common+0x70` 的 `cmp w20,#434` 指令；
2. 在 `__secure_computing` 入口读取 `pt_regs->syscallno`；
3. 命中未实现 syscall 时跳过 seccomp 计算；
4. syscall 随后进入正常的 ni-syscall 路径并返回 `-ENOSYS`；
5. musl 收到 `ENOSYS` 后回退到旧 syscall。

已实现的系统调用不绕过。

> **不要在线卸载 NoHello。** 它同时 hook `el0_svc_common`、
> `__seccomp_filter`、`copy_process`、`exit_mmap`、`free_pgd_range` 和 mmap
> 路径。实测 unload 时其他 CPU 仍从旧 trampoline 返回，出现非法 PC 的
> `SP/PC alignment exception` 并 panic。应通过 APatch 配置停止加载并重启。

## 编译

依赖本机/交叉 aarch64 gcc 或 clang，以及 KernelPatch 子模块：

```sh
git submodule update --init
make CC=aarch64-alpine-linux-musl-gcc
```

Makefile 必须保留 `-fno-pic -fno-pie`，否则会产生 KP 加载器不支持的 GOT
重定位。

## 使用

通过 APatch/FolkPatch 的 KPM 加载通道载入。

| 操作 | 方式 |
|---|---|
| 状态查询 | CTL0；返回 proc/seccomp 状态、跳过次数和错误码 |
| 应用 / 还原 | CTL1；非 0 应用两者，0 还原两者 |
| 卸载 | KPM unload；自动移除 hook 并恢复 proc_mount 原指令 |

| 加载参数 | 作用 |
|---|---|
| `no-proc` | 只启用 seccomp 兼容 |
| `no-seccomp` | 只启用 procfs 修复 |
| `off` | 只加载，不自动应用 |

## 安全设计

- `proc_mount` 通过 kallsyms 解析，并对周边指令做三重模式校验；
- 使用 KernelPatch `hotpatch()`，由内核 stop_machine 和 icache 同步；
- seccomp 兼容 hook 位于 `__secure_computing`，卸载时移除；
- 只处理目标内核确实没有实现的 syscall；
- 内核版本不是 4.19 时拒绝安装 seccomp 部分。

## 已知限制

- procfs 补丁依赖本逆向确认的 4.19 vendor 布局；不匹配时安全失败。
- NoHello 的内部实现为 embedded pre-init，公开仓库版本与真机版本不一致；
  KPM 对其运行时行为做兼容，不依赖其私有 ABI。
- 同一 vendor 内核的 `unshare(CLONE_NEWNET)` ENOMEM 是独立问题，本模块未处理。
