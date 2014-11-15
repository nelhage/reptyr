#ifndef LINUX_H
#define LINUX_H

#ifdef __linux__
#include <linux/major.h>
#include <linux/net.h>
#include <linux/limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <assert.h>
#include <stddef.h>
#include <termios.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>


#define socketcall_socket SYS_SOCKET
#define socketcall_connect SYS_CONNECT
#define socketcall_sendmsg SYS_SENDMSG

// Define lowercased versions of the socketcall numbers, so that we
// can assemble them with ## in the macro below
#define do_socketcall(child, name, a0, a1, a2, a3, a4)                  \
    ({                                                                  \
        int __ret;                                                      \
        if (ptrace_syscall_numbers((child))->nr_##name) {               \
            __ret = do_syscall((child), name, a0, a1, a2, a3, a4, 0);   \
        } else {                                                        \
            __ret = do_syscall((child), socketcall, socketcall_##name,  \
                               a0, a1, a2, a3, a4);                     \
        }                                                               \
        __ret; })

#endif
#endif
