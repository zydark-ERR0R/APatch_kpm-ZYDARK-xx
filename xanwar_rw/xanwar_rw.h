/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "xanwar_rw.h"

#include <kpmodule.h>
#include <kputils.h>
#include <hook.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#include "../kpm_utils.h"

KPM_NAME("xanwar_rw");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("XAnouar");
KPM_DESCRIPTION("Cross-process memory r/w via prctl hook");

#define logkm(fmt, ...) printk("xanwar_rw: " fmt, ##__VA_ARGS__)

// ======================== Kernel symbols ========================
static struct task_struct* (*kfunc_find_task_by_vpid)(pid_t nr) = NULL;
static int (*kfunc_access_process_vm)(struct task_struct* task, unsigned long addr,
                                       void* buf, int len, unsigned int gup_flags) = NULL;

// prctl function pointer (from sys_call_table)
static long (*orig_prctl)(const struct pt_regs *regs) = NULL;

// ======================== prctl hook ========================
// KernelPatch fp_hook_wrap passes hook_fargs4_t* for argno=4
static void before_prctl(hook_fargs4_t *fargs, void *udata) {
    // prctl syscall signature: (int option, unsigned long arg2, ...)
    // arm64 passes via pt_regs: regs->regs[0] = option, regs[1] = arg2, ...
    struct pt_regs *regs = (struct pt_regs *)fargs->arg0;
    if (!regs) return;

    unsigned long option = regs->regs[0];
    if (option != NA_PRCTL_MAGIC) return;  // pass through

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

    struct task_struct* task = kfunc_find_task_by_vpid((pid_t)cmd->pid);
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
            // 0x10 = FOLL_FORCE
            int ret = kfunc_access_process_vm(task, (unsigned long)cmd->addr,
                                              cmd->data, (int)sz, 0x10);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        case NA_CMD_WRITE_MEM: {
            // 0x10 = FOLL_FORCE, 0x01 = FOLL_WRITE
            int ret = kfunc_access_process_vm(task, (unsigned long)cmd->addr,
                                              cmd->data, (int)sz, 0x10 | 0x01);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        default:
            cmd->result = -1;
            break;
    }

    regs->regs[0] = 0;          // return success
    fargs->skip_origin = 1;     // don't call original prctl
}

// ======================== Init / Exit ========================
static long xanwar_rw_init(const char* args, const char* event, void* __user reserved) {
    logkm("init: event=%s\n", event ? event : "?");

    // Look up kernel functions
    kfunc_lookup_name(find_task_by_vpid);
    kfunc_lookup_name(access_process_vm);

    if (!kfunc(find_task_by_vpid) || !kfunc(access_process_vm)) {
        logkm("ERROR: required symbols not found\n");
        return -ENOENT;
    }

    // Find sys_call_table to locate prctl function pointer
    uintptr_t *sys_call_table = (uintptr_t*)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) {
        logkm("ERROR: sys_call_table not found\n");
        return -ENOENT;
    }

    // __NR_prctl = 167 on arm64
    #define __NR_PRCTL_ARM64 167
    uintptr_t prctl_fp = sys_call_table[__NR_PRCTL_ARM64];
    if (!prctl_fp) {
        logkm("ERROR: prctl function pointer is null\n");
        return -ENOENT;
    }

    orig_prctl = (void*)prctl_fp;
    logkm("prctl fp = 0x%lx\n", prctl_fp);

    // Hook prctl via fp_hook_wrap (4 args, using before hook only)
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

    if (orig_prctl) {
        fp_hook_unwrap((uintptr_t)orig_prctl,
                       (void*)before_prctl, NULL);
    }

    logkm("xanwar_rw unloaded\n");
    return 0;
}

KPM_INIT(xanwar_rw_init);
KPM_EXIT(xanwar_rw_exit);
