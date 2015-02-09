/*
 * Copyright (C) 2014 Christian Heckendorf <heckendorfc@gmail.com>
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
