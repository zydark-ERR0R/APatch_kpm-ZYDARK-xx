/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xanwar_rw: Memory read/write KPM for XAnouar Panel
 * Hooks prctl syscall to provide cross-process memory access.
 */

#include "xanwar_rw.h"

#include <kpmodule.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#include "../kpm_utils.h"

KPM_NAME("xanwar_rw");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("XAnouar");
KPM_DESCRIPTION("Cross-process memory read/write via prctl hook");

#define logkm(fmt, ...) printk("xanwar_rw: " fmt, ##__VA_ARGS__)

// ======================== Kernel function pointers ========================
// access_process_vm: reads/writes another process's memory
// find_task_by_vpid: finds task_struct by numeric PID
static struct task_struct* (*kfunc_find_task_by_vpid)(pid_t nr) = NULL;
static int (*kfunc_access_process_vm)(struct task_struct* task, unsigned long addr,
                                       void* buf, int len, unsigned int gup_flags) = NULL;

// ======================== prctl hook ========================
static int before_prctl(unsigned long option, unsigned long arg2,
                        unsigned long arg3, unsigned long arg4,
                        unsigned long arg5) {
    // Only intercept our magic number
    if (option != NA_PRCTL_MAGIC)
        return 0;  // pass through to original prctl

    struct na_cmd* cmd = (struct na_cmd*)arg2;
    if (!cmd) {
        return 1;
    }

    // Handle GET_PID command (not implemented — user must pass pid)
    if (cmd->op == NA_CMD_GET_PID) {
        if (cmd->pid == 0) {
            cmd->result = -1;
        } else {
            cmd->result = 0;
        }
        return 1;
    }

    // For read/write, we need a valid target task
    if (cmd->pid == 0) {
        cmd->result = -1;
        return 1;
    }

    struct task_struct* task = kfunc_find_task_by_vpid((pid_t)cmd->pid);
    if (!task || !task->mm) {
        cmd->result = -1;
        return 1;
    }

    switch (cmd->op) {
        case NA_CMD_READ_MEM: {
            unsigned int sz = cmd->size;
            if (sz > NA_MAX_RW_SIZE) sz = NA_MAX_RW_SIZE;

            int ret = kfunc_access_process_vm(task, (unsigned long)cmd->addr,
                                              cmd->data, (int)sz, FOLL_FORCE);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        case NA_CMD_WRITE_MEM: {
            unsigned int sz = cmd->size;
            if (sz > NA_MAX_RW_SIZE) sz = NA_MAX_RW_SIZE;

            int ret = kfunc_access_process_vm(task, (unsigned long)cmd->addr,
                                              cmd->data, (int)sz,
                                              FOLL_FORCE | FOLL_WRITE);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        default:
            cmd->result = -1;
            break;
    }

    return 1;  // consumed
}

// ======================== Init / Exit ========================
static long xanwar_rw_init(const char* args, const char* event, void* __user reserved) {
    logkm("init: event=%s args=%s\n", event ? event : "?", args ? args : "?");

    // Look up required kernel functions using kallsyms_lookup_name
    kfunc_find_task_by_vpid = (void*)kallsyms_lookup_name("find_task_by_vpid");
    kfunc_access_process_vm = (void*)kallsyms_lookup_name("access_process_vm");

    if (!kfunc_find_task_by_vpid || !kfunc_access_process_vm) {
        logkm("ERROR: required kernel symbols not found\n");
        return -ENOENT;
    }

    logkm("symbols resolved, installing prctl hook...\n");

    // Install prctl syscall hook
    long ret = fp_hook_syscalln(__NR_prctl, 5, before_prctl, 0, 0);
    if (ret != 0) {
        logkm("ERROR: fp_hook_syscalln failed: %ld\n", ret);
        return ret;
    }

    logkm("xanwar_rw ready (magic=0x%X)\n", NA_PRCTL_MAGIC);
    return 0;
}

static long xanwar_rw_exit(void* __user reserved) {
    logkm("exit: unhooking prctl\n");

    fp_unhook_syscalln(__NR_prctl, 5, before_prctl);

    logkm("xanwar_rw unloaded\n");
    return 0;
}

KPM_INIT(xanwar_rw_init);
KPM_EXIT(xanwar_rw_exit);