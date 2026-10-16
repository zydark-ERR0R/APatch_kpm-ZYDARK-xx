#ifndef __XANWAR_RW_H
#define __XANWAR_RW_H

#include <linux/types.h>

// ============ يجب أن تطابق driver.h الخاص بك ============
#define NA_PRCTL_MAGIC   0x4E41
#define NA_CMD_READ_MEM  1
#define NA_CMD_WRITE_MEM 2
#define NA_CMD_GET_PID   5
#define NA_MAX_RW_SIZE   4096
#define NA_MAX_PKG_NAME  256

struct na_cmd {
    uint32_t op;
    uint32_t pid;
    uint64_t addr;
    uint32_t size;
    int32_t  result;
    int32_t  screen_w;
    int32_t  screen_h;
    char     pkg[NA_MAX_PKG_NAME];
    uint8_t  data[NA_MAX_RW_SIZE];
};
// ========================================================

#endif /* __XANWAR_RW_H */