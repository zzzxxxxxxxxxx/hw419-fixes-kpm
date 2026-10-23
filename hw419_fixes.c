/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hw419-fixes — KPM for Huawei 4.19.157-perf+ (GOT-W29)
 *
 * Fixes:
 *   1. bwrap/runc/crun "Can't mount proc ... Resource busy"
 *   2. SIGSYS/exit 159 when userspace seccomp traps syscalls that are absent
 *      from this 4.19 kernel (notably faccessat2 and clone3).
 *
 * Root cause (reverse-engineered from boot.elf + shipped GPL source):
 *   alloc_pid() -> pid_ns_prepare_proc() kern_mounts an internal procfs
 *   instance for every new PID namespace. That mount runs in the CLONER's
 *   context, so with atomic clone(CLONE_NEWUSER|CLONE_NEWPID) the internal
 *   superblock ends up owned by init_user_ns. The sandboxed child later mounts
 *   proc requesting sget_userns(its own userns) -> owner mismatch -> -EBUSY.
 *
 * Fix: patch ONE branch inside proc_mount so the containerd ownership branch
 * (sb owned by pidns->user_ns) is taken whenever mounter userns differs from
 * pidns owner:
 *
 *   ...838031c: bl   __pi_memcmp
 *   ...8380320: cbz  w0, +0x74   340003a0   ; tag match -> containerd path
 *   ...8380394: mov  x0,x23 ; bl kfree      ; containerd path entry
 *
 *   cbz w0,+0x74  ==>  b +0x74       (340003a0 -> 1400001d)
 *
 * Invariant after patch: a procfs superblock for pidns P is ALWAYS created
 * with user_ns = P->user_ns, whoever mounts it first. Same-userns mounts keep
 * the equality fast-path; HarmonyOS containerd behavior unchanged.
 *
 * seccomp compatibility:
 *   Newer seccomp policies may return SECCOMP_RET_TRAP for syscall numbers
 *   unknown to 4.19. musl then receives SIGSYS instead of ENOSYS and cannot
 *   fall back to the legacy syscall. Hook __secure_computing and skip
 *   filtering when nr is outside the vendor's 0..434 syscall range, or when its
 *   sys_call_table entry is exactly sys_ni_syscall / its arm64 wrapper.
 *   No syscall body is bypassed: dispatch still enters the ni-syscall stub
 *   and returns -ENOSYS.
 */

#include <common.h>
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <log.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <hotpatch.h>
#include <hook.h>

KPM_NAME("hw419-fixes");
KPM_VERSION("1.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ox-alpha");
KPM_DESCRIPTION("Fix Huawei procfs ownership and 4.19 seccomp SIGSYS compatibility");

#define TAG "[hw419-fixes] "

#define logi(fmt, ...) logki(TAG fmt, ##__VA_ARGS__)
#define loge(fmt, ...) logke(TAG fmt, ##__VA_ARGS__)

/* kf_ storages: tentative definitions resolved at init via kallsyms */
int kfunc_def(snprintf)(char *buf, size_t size, const char *fmt, ...);
char *kfunc_def(strstr)(const char *s1, const char *s2);

/* arm64 instruction encodings, verified against GOT-W29 boot.elf 4.19.157-perf+
 * (proc_mount @ link addr 0xffffff8008380258) */
#define INSN_CBZ_W0_74  0x340003A0u /* cbz w0, +0x74 : memcmp(tag)==0 */
#define INSN_B_74       0x1400001Du /* b   +0x74     : unconditional */
#define INSN_MOV_X0_X23 0xAA1703E0u /* containerd block: mov x0,x23 ; bl kfree */
#define SCAN_WORDS      0x60        /* site sits at +0xC8 in this build */
#define BRANCH_WORDS    29          /* +0x74 bytes */

static uint32_t *g_site;
static uint32_t g_orig;
static bool g_applied;

/* hotpatch() takes pointers to the new instruction words */
static uint32_t g_insn_new = INSN_B_74;
static uint32_t g_insn_restore;

/* seccomp compatibility state */
static void *g_secure_computing;
static void *g_el0_svc_common;
static uintptr_t *g_sys_call_table;
static uintptr_t g_sys_ni_syscall;
static uintptr_t g_sys_ni_syscall_wrapper;
static unsigned int g_nr_syscalls;
static bool g_seccomp_applied;
static unsigned long long g_seccomp_skips;
static int g_seccomp_last_rc;

/*
 * GOT-W29 4.19.157 el0_svc_common+0x70:
 *   cmp w20, #0x1b2 ; b.hi -> sys_ni_syscall
 * The vendor syscall range ends at #434, so #435 and above are absent even
 * though newer KernelPatch UAPI headers define __NR_syscalls as 451.
 */
#define HW419_NR_SYSCALLS      435u
#define EL0_NR_CHECK_OFFSET    0x70u
#define INSN_CMP_W20_434       0x7106CA9Fu

static int find_site(void)
{
	if (!kallsyms_lookup_name) {
		loge("no kallsyms_lookup_name\n");
		return -1;
	}

	unsigned long pm = kallsyms_lookup_name("proc_mount");
	if (!pm) {
		loge("proc_mount not found via kallsyms\n");
		return -1;
	}
	logi("proc_mount @ %px\n", (void *)pm);

	uint32_t *base = (uint32_t *)pm;
	for (int i = 4; i < SCAN_WORDS; i++) {
		uint32_t w = base[i];

		if (w != INSN_CBZ_W0_74)
			continue;

		uint32_t prev = base[i - 1];
		uint32_t dst  = base[i + BRANCH_WORDS];         /* +0x74 */
		uint32_t dst2 = base[i + BRANCH_WORDS + 1];
		bool ok_bl  = (prev & 0xFC000000u) == 0x94000000u; /* bl memcmp */
		bool ok_dst = dst == INSN_MOV_X0_X23 &&            /* mov x0,x23*/
			      (dst2 & 0xFC000000u) == 0x94000000u; /* bl kfree */

		if (!ok_bl || !ok_dst)
			continue;

		g_site = &base[i];
		logi("patch site @ %px (proc_mount+%#lx)\n",
		     (void *)g_site, (unsigned long)(i * 4));
		return 0;
	}

	loge("pattern not found; kernel layout mismatch?\n");
	return -2;
}

static int apply_proc_patch(void)
{
	int rc;

	if (g_applied)
		return 0;
	if (!g_site && find_site())
		return -1;

	g_orig = *g_site;
	g_insn_restore = g_orig;
	rc = hotpatch((void **)&g_site, &g_insn_new, 1);
	if (rc) {
		loge("hotpatch failed: %d\n", rc);
		return rc;
	}

	g_applied = true;
	logi("patched %08x -> %08x : procfs sb now always owned by pidns->user_ns\n",
	     g_orig, INSN_B_74);
	return 0;
}

static void restore_proc_patch(void)
{
	if (!g_applied || !g_site)
		return;

	g_insn_restore = g_orig;
	hotpatch((void **)&g_site, &g_insn_restore, 1);
	g_applied = false;
	logi("original instruction restored (%08x)\n", g_orig);
}

static int resolve_seccomp_symbols(void)
{
	if (!kallsyms_lookup_name) {
		loge("seccomp: no kallsyms_lookup_name\n");
		return -1;
	}

	if (!g_secure_computing)
		g_secure_computing = (void *)kallsyms_lookup_name("__secure_computing");
	if (!g_el0_svc_common)
		g_el0_svc_common = (void *)kallsyms_lookup_name("el0_svc_common");
	if (!g_sys_call_table)
		g_sys_call_table = (uintptr_t *)kallsyms_lookup_name("sys_call_table");
	if (!g_sys_ni_syscall)
		g_sys_ni_syscall = kallsyms_lookup_name("sys_ni_syscall");
	if (!g_sys_ni_syscall_wrapper)
		g_sys_ni_syscall_wrapper =
			kallsyms_lookup_name("__arm64_sys_ni_syscall");

	if (!g_secure_computing || !g_el0_svc_common || !g_sys_call_table ||
	    (!g_sys_ni_syscall && !g_sys_ni_syscall_wrapper)) {
		loge("seccomp: missing symbols filter=%px svc=%px table=%px ni=%px wrapper=%px\n",
		     g_secure_computing, g_el0_svc_common, g_sys_call_table,
		     (void *)g_sys_ni_syscall, (void *)g_sys_ni_syscall_wrapper);
		return -2;
	}

	if (*(volatile uint32_t *)((uintptr_t)g_el0_svc_common +
				   EL0_NR_CHECK_OFFSET) != INSN_CMP_W20_434) {
		loge("seccomp: el0_svc_common syscall-bound check mismatch\n");
		return -4;
	}
	g_nr_syscalls = HW419_NR_SYSCALLS;
	return 0;
}

/*
 * Called before __secure_computing. A syscall-table entry equal to
 * sys_ni_syscall or __arm64_sys_ni_syscall is unimplemented by this kernel,
 * so bypassing seccomp can only change the result from SIGSYS/EPERM to the
 * conventional -ENOSYS.
 */
static void seccomp_before(hook_fargs1_t *args, void *udata)
{
	struct pt_regs *regs = current_pt_regs();
	int nr = regs ? regs->syscallno : -1;
	uintptr_t entry;

	(void)udata;
	if (nr < 0)
		return;

	if ((unsigned int)nr < g_nr_syscalls) {
		entry = *(volatile uintptr_t *)&g_sys_call_table[nr];
		if (entry != g_sys_ni_syscall &&
		    entry != g_sys_ni_syscall_wrapper)
			return;
	}

	args->skip_origin = 1;
	args->ret = 0;
	/* Diagnostic counter only; a lost update under race is harmless. */
	g_seccomp_skips++;
}

static int apply_seccomp_compat(void)
{
	hook_err_t rc;

	if (g_seccomp_applied)
		return 0;

	/* __secure_computing's ABI and pt_regs layout are specific to Linux 4.19. */
	if ((kver >> 16) != 4 || ((kver >> 8) & 0xff) != 19) {
		g_seccomp_last_rc = -3;
		loge("seccomp: unsupported kernel version %#x\n", kver);
		return g_seccomp_last_rc;
	}

	if (resolve_seccomp_symbols()) {
		g_seccomp_last_rc = -2;
		return g_seccomp_last_rc;
	}

	rc = hook_wrap1(g_secure_computing, seccomp_before, NULL, NULL);
	if (rc != HOOK_NO_ERR) {
		g_seccomp_last_rc = -(int)rc;
		loge("seccomp: hook __secure_computing failed: %d\n", (int)rc);
		return g_seccomp_last_rc;
	}

	g_seccomp_last_rc = 0;
	g_seccomp_applied = true;
	logi("seccomp: normalized unimplemented syscalls to ENOSYS\n");
	return 0;
}

static void restore_seccomp_compat(void)
{
	if (!g_seccomp_applied || !g_secure_computing)
		return;

	hook_unwrap(g_secure_computing, seccomp_before, NULL);
	g_seccomp_applied = false;
	logi("seccomp: __secure_computing hook removed\n");
}

static long hw419_fixes_init(const char *args, const char *event,
			    void *__user reserved)
{
	bool disable_proc;
	bool disable_seccomp;
	int proc_rc = 0;
	int seccomp_rc = 0;

	(void)reserved;
	kfunc_lookup_name(snprintf);
	kfunc_lookup_name(strstr);

	logi("init event=%s args=%s\n", event, args ? args : "");
	disable_proc = args && kf_strstr &&
		       (kf_strstr(args, "off") || kf_strstr(args, "no-proc"));
	disable_seccomp = args && kf_strstr &&
			  (kf_strstr(args, "off") || kf_strstr(args, "no-seccomp"));

	if (disable_proc && disable_seccomp) {
		logi("auto-apply disabled by args\n");
		return 0;
	}

	if (!disable_proc)
		proc_rc = apply_proc_patch();
	if (!disable_seccomp)
		seccomp_rc = apply_seccomp_compat();

	/*
	 * Keep either fix available if the other one cannot be installed. The
	 * status control reports both results; loading both disabled is success.
	 */
	if (!disable_proc && !disable_seccomp && proc_rc && seccomp_rc)
		return proc_rc;
	if (disable_proc)
		return seccomp_rc;
	if (disable_seccomp)
		return proc_rc;
	return 0;
}

static long hw419_fixes_ctl0(const char *args, char *__user out_msg, int outlen)
{
	char buf[256];

	(void)args;
	(void)outlen;
	if (kf_snprintf)
		kf_snprintf(buf, sizeof(buf),
			    "proc_applied=%d site=%px orig=%08x cur=%08x "
			    "seccomp_applied=%d skips=%llu seccomp_rc=%d",
			    (int)g_applied, (void *)g_site, g_orig,
			    g_site ? *g_site : 0, (int)g_seccomp_applied,
			    g_seccomp_skips, g_seccomp_last_rc);
	else
		buf[0] = '\0';
	buf[sizeof(buf) - 1] = '\0';
	compat_copy_to_user(out_msg, buf, sizeof(buf));
	return 0;
}

static long hw419_fixes_ctl1(void *a1, void *a2, void *a3)
{
	int proc_rc;
	int seccomp_rc;

	(void)a2;
	(void)a3;
	/* ctl1(1) apply/re-apply both fixes, ctl1(0) restore both */
	if ((long)a1) {
		proc_rc = apply_proc_patch();
		seccomp_rc = apply_seccomp_compat();
		if (proc_rc && seccomp_rc)
			return proc_rc;
		return 0;
	}
	restore_seccomp_compat();
	restore_proc_patch();
	return 0;
}

static long hw419_fixes_exit(void *__user reserved)
{
	(void)reserved;
	restore_seccomp_compat();
	restore_proc_patch();
	return 0;
}

KPM_INIT(hw419_fixes_init);
KPM_CTL0(hw419_fixes_ctl0);
KPM_CTL1(hw419_fixes_ctl1);
KPM_EXIT(hw419_fixes_exit);
