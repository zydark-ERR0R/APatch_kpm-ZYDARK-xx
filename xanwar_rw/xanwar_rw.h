#ifndef __XANWAR_RW_H
#define __XANWAR_RW_H

#define NA_PRCTL_MAGIC   0x4E41
#define NA_CMD_READ_MEM  1
#define NA_CMD_WRITE_MEM 2
#define NA_CMD_GET_PID   5
#define NA_MAX_RW_SIZE   4096
#define NA_MAX_PKG_NAME  256

struct na_cmd {
    unsigned int  op;
    unsigned int  pid;
    unsigned long addr;
    unsigned int  size;
    int           result;
    int           screen_w;
    int           screen_h;
    char          pkg[NA_MAX_PKG_NAME];
    unsigned char data[NA_MAX_RW_SIZE];
};

#endif
