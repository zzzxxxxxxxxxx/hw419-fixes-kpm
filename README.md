# hw-procfix-kpm

> 修复华为/HarmonyOS 4.19 vendor 内核上 bwrap / runc / crun 等容器工具报
> `Can't mount proc on /newroot/proc: Resource busy` 的 KernelPatch 模块 (KPM)。

- 适用设备：已验证 GOT-W29（骁龙平台，`4.19.157-perf+`），理论适用同源内核
- 依赖：[KernelPatch](https://github.com/bmax121/KernelPatch) / APatch / FolkPatch 环境
- 许可：GPL-2.0

---

## 问题现象

在 Huawei/HarmonyOS 内核的 LXC 里运行 bubblewrap：

```console
# bwrap --unshare-all --new-session --proc /proc -- /bin/bash
bwrap: Can't mount proc on /newroot/proc: Resource busy
```

所有使用**原子 `clone(CLONE_NEWUSER | CLONE_NEWPID)`** 编排的工具全部中招
（bwrap、runc、crun、youki……）；而 util-linux/busybox 的 `unshare` 分步式编排侥幸幸免。

## 根因分析（逆向 boot.elf + GPL 源码比对结论）

原版 4.19 上游没有这些问题，以下均为 vendor 私改：

### 改动① 复活了上古机制 `pid_ns_prepare_proc`

`kernel/pid.c::alloc_pid()` 增加钩子——每个新 PID namespace 的第一个进程诞生时，
内核自动 `kern_mount()` 一个**内部 procfs 实例**（上游多年前已删除该机制）。

关键缺陷：这个内部挂载发生在 **clone 发起者（父进程）的上下文**里，
其 superblock 属主 = 父进程当时的 userns。

### 改动② `is_containerd()` cmdline 后门

`fs/proc/root.c::proc_mount()` 嗅探 cmdline 是否以 `/system/bin/containerd`
（HarmonyOS 微容器运行时）开头：

- 命中 → superblock 以 **pidns 属主 userns** 创建
- 未命中 → 普通 `sget()`，superblock 以 **挂载者当前 userns** 创建

### EBUSY 因果链

```text
bwrap 父进程（init_user_ns）
   │ clone(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID)   ← 一次原子建仨
   ▼
copy_process()
   ├── 建 U_new；P_new 属主 = U_new
   ├── alloc_pid: 第一个进程诞生
   │     └─ 🪝 pid_ns_prepare_proc(P_new)              ← 改动①
   │          └─ kern_mount(proc)，此刻 current =【父进程】
   │               is_containerd? cmdline="bwrap…" ≠ containerd
   │               ⇒ 内部 proc sb【属主 = init_user_ns】 ⚠️
   ▼
bwrap 子进程（U_new ∩ P_new）
   └─ mount -t proc
        → sget_userns(请求者 = U_new)
        → P_new 已有 sb 属主 init ≠ U_new
        ⇒ -EBUSY 💥
```

分步式编排（先切 userns 再 fork 出 reaper）因 reaper 诞生时 current 已在新
userns 而天然匹配，所以 `unshare(1)` 不受影响——这也是部分工具"时好时坏"
错觉的来源。

## 修复原理

目标不变式：

> **pidns P 的 procfs superblock，无论谁先挂载，属主一律 = P->user_ns。**

`proc_mount` 中 `is_containerd` 判定尾部是一条条件跳转：

```asm
bl   __pi_memcmp        ; cmdline == "/system/bin/containerd" ?
cbz  w0, +0x74          ; 相等才走"按 pidns 属主建 sb"分支    ← 补丁点
; ...不相等路径: 按【挂载者】userns 建 sb → 隐患源头
+0x74:
  sget_userns(ns->user_ns)   ; containerd 分支
```

KPM 把 `cbz w0,+0x74`（`340003A0`）替换为无条件跳转 `b +0x74`（`1400001D`）。
由于该指令**只在挂载者 userns ≠ pidns 属主时才会到达**，补丁后：

| 场景 | 补丁前 | 补丁后 |
|---|---|---|
| 原子 clone(USER\|PID) + 子进程挂 proc | EBUSY 💥 | sb 归属主 → 匹配 ✅ |
| HarmonyOS 自家 containerd | 走属主分支 | 行为不变 ✅ |
| 同 userns 挂载 | 等值快路径 | 不经过此指令，不变 ✅ |
| 权限不足挂载（EPERM 类检查） | EPERM | 全部保留 ✅ |

## 编译

依赖交叉/本机 aarch64 gcc 或 clang，以及 [KernelPatch](https://github.com/bmax121/KernelPatch)
的 KPM 头文件（以 git 子模块形式引用
  [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch)，clone 时加 `--recursive`
  或 `git submodule update --init`）。

```sh
make
```

> 注意必须带 `-fno-pic -fno-pie`：默认 PIE 会产生 KP 加载器不支持的
> `R_AARCH64_ADR_GOT_PAGE / LD64_GOT_LO12_NC` 重定位，导致加载失败。
> Makefile 已内置。

## 使用

通过 APatch/FolkPatch 的 KPM 加载通道载入。

控制接口：

| 操作 | 方式 |
|---|---|
| 状态查询 | CTL0 |
| 应用 / 还原 | CTL1（参数非 0 = 应用，0 = 还原） |
| 卸载并自动还原指令 | KPM unload |

模块卸载或重启后补丁消失，可加入开机自启。

## 安全设计

- 运行时通过 kallsyms 解析 `proc_mount`，免疫 KASLR；
- 打补丁前做三重指令上下文校验（前一条必须是 `bl memcmp`、跳转目标必须是
  `mov x0,x23; bl kfree` 序列），任何不匹配直接拒绝加载，不会盲写内核；
- 使用 KP 核心 `hotpatch()`（内部走内核原生 `aarch64_insn_patch_text()`，
  stop_machine + icache 同步）；
- 卸载无损还原原指令。

## 验证矩阵（GOT-W29 实测）

| 测试 | 结果 |
|---|---|
| `--unshare-user --unshare-pid`（原必死组合） | ✅ |
| `--unshare-all` 全量隔离 | ✅ PID 1 reaper / PID 2 shell 结构正确 |
| 各命名空间单独 unshare ×6 | ✅ |
| 退出码穿透（中间进程转发） | ✅ exit 42 正确传递 |

## 已知限制

- 仅针对本逆向确认的 4.19 vendor 布局；其他内核版本靠运行时模式校验兜底，
  不匹配则拒绝工作（安全失败）。
- 同一 vendor 内核还存在 `unshare(CLONE_NEWNET)` 单独返回 ENOMEM 的独立问题
  （clone 路径正常），本模块未涉及；受影响工具需避免在 unshare() 里携带
  `CLONE_NEWNET`。

## 附：Codex 沙箱 SIGSYS 备忘（4.19 vendor 内核 + Alpine/musl）

> 2026-09 在同一台 GOT-W29 上的排查记录，供后续迁移/升级环境时参考。

Codex CLI 0.154.0（aarch64-musl）在 `workspace-write` 沙箱内运行任何需要 PATH 查找的命令，
都会报 `Bad system call` 并以 exit 159 结束（SIGSYS = 31）。

**触发机制**：Codex 在“沙箱内禁用网络”时会额外安装一层 seccomp 过滤器，而该过滤器对本
内核不支持的新系统调用使用 `SECCOMP_RET_TRAP`，而非返回 `ENOSYS` 让 libc 回退：

- `faccessat2`（aarch64 #439，Linux 5.8+）：musl 的 `euidaccess` / `faccessat(AT_EACCESS)`
  会优先调用它；bash 的 PATH 查找、`command -v`、`[[ -r/-w/-x ]]` 全部命中，进程在内核
  有机会返回 ENOSYS 之前就被 SIGSYS 杀死。
- `clone3`（aarch64 #435，Linux 5.3+）：musl 创建线程时会优先尝试，多线程程序同样被杀。

**实测证据**：沙箱内静态探针捕获到 `si_code=1 (SYS_SECCOMP) syscall=439 arch=0xC00000B7
(aarch64)`；同一调用在沙箱外返回 `ENOSYS`，musl 正常回退到老的 `faccessat`，因此问题不在
内核，而在 seccomp 策略。

**规避方式**：让沙箱的网络策略为 enabled，该 seccomp 过滤器就不会安装，bwrap 文件沙箱仍
然生效：

```toml
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
network_access = true
```

实测 `Seccomp: 0`，裸 `ls` / `command -v` / `[[ -r ]]` 恢复正常；`/etc`、`~/.codex` 仍为
只读，工作区可写。注意 Android/HarmonyOS 的按 UID 网络策略会让 bwrap user namespace 内的
`socket()` 返回 EPERM，所以沙箱内实际仍然没有外网。

**建议上游修复**：对内核不支持的新 syscall 应返回 `ENOSYS`（`SECCOMP_RET_ERRNO`），而不是
`SECCOMP_RET_TRAP`。
