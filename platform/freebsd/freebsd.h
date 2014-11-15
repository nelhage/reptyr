#ifndef FREEBSD_H
#define FREEBSD_H

#ifdef __FreeBSD__

#include <stdlib.h>
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <unistd.h>
#include <libprocstat.h>
#include <limits.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>

#define do_socketcall(child, name, a0, a1, a2, a3, a4)                  \
    ({                                                                  \
        int __ret=-1;                                                      \
        if (ptrace_syscall_numbers((child))->nr_##name) {               \
            __ret = do_syscall((child), name, a0, a1, a2, a3, a4, 0);   \
        }                                                               \
        __ret; })

#endif
#endif
