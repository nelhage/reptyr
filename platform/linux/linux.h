/*
 * Copyright (C) 2011 by Nelson Elhage
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

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
