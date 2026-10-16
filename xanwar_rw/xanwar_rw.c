/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "xanwar_rw.h"

#include <kpmodule.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/asm-generic/errno.h>

#include "../kpm_utils.h"

KPM_NAME("xanwar_rw");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("XAnouar");
KPM_DESCRIPTION("Cross-process memory read/write via prctl hook");

#define logkm(fmt, ...) printk("xanwar_rw: " fmt, ##__VA_ARGS__)

// ======================== Kernel function pointers ========================
static struct task_struct* (*kfunc_find_task_by_vpid)(pid_t nr) = NULL;
static int (*kfunc_access_process_vm)(struct task_struct* task, unsigned long addr,
                                       void* buf, int len, unsigned int gup_flags) = NULL;

// ======================== prctl hook ========================
static int before_prctl(unsigned long option, unsigned long arg2,
                        unsigned long arg3, unsigned long arg4,
                        unsigned long arg5) {
    if (option != NA_PRCTL_MAGIC)
        return 0;

    struct na_cmd* cmd = (struct na_cmd*)arg2;
    if (!cmd)
        return 1;

    if (cmd->op == NA_CMD_GET_PID) {
        cmd->result = (cmd->pid == 0) ? -1 : 0;
        return 1;
    }

    if (cmd->pid == 0) {
        cmd->result = -1;
        return 1;
    }

    struct task_struct* task = kfunc_find_task_by_vpid((pid_t)cmd->pid);
    if (!task) {
        cmd->result = -1;
        return 1;
    }

    unsigned int sz = cmd->size;
    if (sz > NA_MAX_RW_SIZE) sz = NA_MAX_RW_SIZE;

    switch (cmd->op) {
        case NA_CMD_READ_MEM: {
            int ret = kfunc_access_process_vm(task, (unsigned long)cmd->addr,
                                              cmd->data, (int)sz, 0x10 /* FOLL_FORCE */);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        case NA_CMD_WRITE_MEM: {
            int ret = kfunc_access_process_vm(task, (unsigned long)cmd->addr,
                                              cmd->data, (int)sz,
                                              0x10 | 0x01 /* FOLL_FORCE|FOLL_WRITE */);
            cmd->result = (ret == (int)sz) ? 0 : -1;
            break;
        }
        default:
            cmd->result = -1;
            break;
    }
    return 1;
}

// ======================== Init / Exit ========================
static long xanwar_rw_init(const char* args, const char* event, void* __user reserved) {
    logkm("init: event=%s\n", event ? event : "?");

    kfunc_lookup_name(find_task_by_vpid);
    kfunc_lookup_name(access_process_vm);

    if (!kfunc(find_task_by_vpid) || !kfunc(access_process_vm)) {
        logkm("ERROR: symbols not found\n");
        return -ENOENT;
    }

    // ⚠️ هذا السطر يحتاج التصحيح بعد معرفة التوقيع الصحيح
    // long ret = fp_hook_syscalln(__NR_prctl, 5, before_prctl, 0, 0);
    // if (ret != 0) return ret;

    logkm("xanwar_rw ready\n");
    return 0;
}

static long xanwar_rw_exit(void* __user reserved) {
    logkm("exit\n");
    return 0;
}

KPM_INIT(xanwar_rw_init);
KPM_EXIT(xanwar_rw_exit);
