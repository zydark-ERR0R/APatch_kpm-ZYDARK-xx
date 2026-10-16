#ifndef __XANWAR_RW_H
#define __XANWAR_RW_H

// لا تستخدم <linux/types.h> هنا لتجنب التعارض مع ktypes.h
// استخدم الأنواع البدائية مباشرة

// ============ يجب أن تطابق driver.h الخاص بك ============
#define NA_PRCTL_MAGIC   0x4E41
#define NA_CMD_READ_MEM  1
#define NA_CMD_WRITE_MEM 2
#define NA_CMD_GET_PID   5
#define NA_MAX_RW_SIZE   4096
#define NA_MAX_PKG_NAME  256

struct na_cmd {
    unsigned int  op;       // uint32_t
    unsigned int  pid;      // uint32_t
    unsigned long addr;     // uint64_t
    unsigned int  size;     // uint32_t
    int           result;   // int32_t
    int           screen_w; // int32_t
    int           screen_h; // int32_t
    char          pkg[NA_MAX_PKG_NAME];
    unsigned char data[NA_MAX_RW_SIZE]; // uint8_t
};
// ========================================================

#endif /* __XANWAR_RW_H */