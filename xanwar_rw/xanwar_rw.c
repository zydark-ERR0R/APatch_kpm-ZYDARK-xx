/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "xanwar_rw.h"

#include <kpmodule.h>
#include <kputils.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#include <uapi/asm-generic/errno.h>

#include "../kpm_utils.h"

KPM_NAME("xanwar_rw");
KPM_VERSION("1.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("XAnouar");
KPM_DESCRIPTION("Cross-process memory r/w via prctl hook");

#define logkm(fmt, ...) printk("xanwar_rw: " fmt, ##__VA_ARGS__)

// ======================== Kernel symbols ========================
static int (*kf_access_process_vm)(struct task_struct* task, unsigned long addr,
                                    void* buf, int len, unsigned int gup_flags) = NULL;

static uintptr_t g_prctl_fp = 0;

// ======================== prctl hook ========================
static void before_prctl(hook_fargs4_t *fargs, void *udata) {
    struct pt_regs *regs = (struct pt_regs *)fargs->arg0;
    if (!regs) return;

    unsigned long option = regs->regs[0];
    if (option != NA_PRCTL_MAGIC) return;

    struct na_cmd* cmd = (struct na_cmd*)regs->regs[1];
    if (!cmd) {
        regs->regs[0] = -1;
        fargs->skip_origin = 1;
        return;
    }

    if (cmd->op == NA_CMD_GET_PID) {
        cmd->result = (cmd->pid == 0) ? -1 : 0;
        regs->regs[0] = 0;
        fargs->skip_origin = 1;
        return;
    }

    if (cmd->pid == 0) {
        cmd->result = -1;
        regs->regs[0] = -1;
        fargs->skip_origin = 1;
        return;
    }

    struct task_struct* task = kf_find_task_by_vpid((pid_t)cmd->pid);
    if (!task) {
        cmd->result = -1;
        regs->regs[0] = -1;
        fargs->skip_origin = 1;
        return;
    }

    unsigned int sz = cmd->size;
    if (sz > NA_MAX_RW_SIZE) sz = NA_MAX_RW_SIZE;

    switch (cmd->op) {
        case NA_CMD_READ_MEM: {
            int ret = kf_access_process_vm(task, (unsigned long)cmd->addr,
                                           cmd->data, (int)sz, 0x10);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        case NA_CMD_WRITE_MEM: {
            int ret = kf_access_process_vm(task, (unsigned long)cmd->addr,
                                           cmd->data, (int)sz, 0x10 | 0x01);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        default:
            cmd->result = -1;
            break;
    }

    regs->regs[0] = 0;
    fargs->skip_origin = 1;
}

// ======================== Init / Exit ========================
static long xanwar_rw_init(const char* args, const char* event, void* __user reserved) {
    logkm("init: event=%s\n", event ? event : "?");

    kfunc_lookup_name(access_process_vm);

    if (!kf_access_process_vm) {
        logkm("ERROR: access_process_vm not found\n");
        return -ENOENT;
    }
    logkm("access_process_vm = %p\n", kf_access_process_vm);

    // ======================================================
    // الطريقة 1: ابحث عن sys_call_table عبر kallsyms
    // ======================================================
    uintptr_t sys_call_table = (uintptr_t)kallsyms_lookup_name("sys_call_table");
    logkm("sys_call_table = 0x%lx\n", sys_call_table);

    uintptr_t prctl_fp = 0;

    if (sys_call_table) {
        // __NR_prctl = 167 على arm64
        #define __NR_PRCTL_ARM64 167
        prctl_fp = ((uintptr_t*)sys_call_table)[__NR_PRCTL_ARM64];
        logkm("prctl from sys_call_table = 0x%lx\n", prctl_fp);
    }

    // ======================================================
    // الطريقة 2: إذا فشلت، ابحث عن الأسماء مباشرة
    // ======================================================
    if (!prctl_fp) {
        const char* names[] = { "SyS_prctl", "sys_prctl" };
        for (int i = 0; i < 2; i++) {
            prctl_fp = (uintptr_t)kallsyms_lookup_name(names[i]);
            logkm("try %s -> 0x%lx\n", names[i], prctl_fp);
            if (prctl_fp) break;
        }
    }

    if (!prctl_fp) {
        logkm("ERROR: no prctl symbol found\n");
        return -ENOENT;
    }

    logkm("using prctl fp = 0x%lx\n", prctl_fp);
    g_prctl_fp = prctl_fp;

    hook_err_t err = fp_hook_wrap4(prctl_fp, (hook_chain4_callback)before_prctl, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        logkm("ERROR: fp_hook_wrap4 failed: %d\n", err);
        return -EINVAL;
    }

    logkm("xanwar_rw ready (magic=0x%X)\n", NA_PRCTL_MAGIC);
    return 0;
}

static long xanwar_rw_exit(void* __user reserved) {
    logkm("exit: unhooking prctl\n");
    if (g_prctl_fp) {
        fp_hook_unwrap(g_prctl_fp, (void*)before_prctl, NULL);
    }
    logkm("xanwar_rw unloaded\n");
    return 0;
}

KPM_INIT(xanwar_rw_init);
KPM_EXIT(xanwar_rw_exit);
