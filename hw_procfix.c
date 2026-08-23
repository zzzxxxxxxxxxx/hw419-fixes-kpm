/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hw-procfix — KPM for Huawei 4.19.157-perf+ (GOT-W29)
 *
 * Fixes: bwrap/runc/crun "Can't mount proc ... Resource busy"
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
#include <hotpatch.h>

KPM_NAME("hw-procfix");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ox-alpha");
KPM_DESCRIPTION("Fix Huawei procfs sb ownership (bwrap EBUSY)");

#define TAG "[hw-procfix] "

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

static int apply_patch(void)
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

static void restore_patch(void)
{
	if (!g_applied || !g_site)
		return;

	g_insn_restore = g_orig;
	hotpatch((void **)&g_site, &g_insn_restore, 1);
	g_applied = false;
	logi("original instruction restored (%08x)\n", g_orig);
}

static long hw_procfix_init(const char *args, const char *event,
			    void *__user reserved)
{
	kfunc_lookup_name(snprintf);
	kfunc_lookup_name(strstr);

	logi("init event=%s args=%s\n", event, args ? args : "");
	if (args && kf_strstr && kf_strstr(args, "off")) {
		logi("auto-apply disabled by args\n");
		return 0;
	}
	return apply_patch();
}

static long hw_procfix_ctl0(const char *args, char *__user out_msg, int outlen)
{
	char buf[128];

	if (kf_snprintf)
		kf_snprintf(buf, sizeof(buf),
			    "applied=%d site=%px orig=%08x cur=%08x",
			    (int)g_applied, (void *)g_site, g_orig,
			    g_site ? *g_site : 0);
	else
		buf[0] = '\0';
	buf[sizeof(buf) - 1] = '\0';
	compat_copy_to_user(out_msg, buf, sizeof(buf));
	return 0;
}

static long hw_procfix_ctl1(void *a1, void *a2, void *a3)
{
	/* ctl1(1) apply/re-apply, ctl1(0) restore */
	if ((long)a1)
		return apply_patch();
	restore_patch();
	return 0;
}

static long hw_procfix_exit(void *__user reserved)
{
	restore_patch();
	return 0;
}

KPM_INIT(hw_procfix_init);
KPM_CTL0(hw_procfix_ctl0);
KPM_CTL1(hw_procfix_ctl1);
KPM_EXIT(hw_procfix_exit);
