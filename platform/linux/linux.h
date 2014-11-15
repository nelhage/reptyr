#ifndef LINUX_H
#define LINUX_H

#ifdef __linux__
#include <linux/major.h>
#include <linux/net.h>

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
