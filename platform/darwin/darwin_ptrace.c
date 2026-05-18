/*
 * Copyright (C) 2026 by reptyr contributors
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

#ifdef __APPLE__

#include <errno.h>
#include <string.h>

#include "../../ptrace.h"

static int unsupported(struct ptrace_child *child) {
    if (child)
        child->error = ENOTSUP;
    return -1;
}

struct syscall_numbers *ptrace_syscall_numbers(struct ptrace_child *child) {
    static struct syscall_numbers unsupported_syscalls = {
        .nr_mmap = -1,
        .nr_mmap2 = -1,
        .nr_munmap = -1,
        .nr_getsid = -1,
        .nr_setsid = -1,
        .nr_setpgid = -1,
        .nr_fork = -1,
        .nr_clone = -1,
        .nr_wait4 = -1,
        .nr_signal = -1,
        .nr_rt_sigaction = -1,
        .nr_openat = -1,
        .nr_close = -1,
        .nr_ioctl = -1,
        .nr_dup2 = -1,
        .nr_dup3 = -1,
        .nr_socket = -1,
        .nr_connect = -1,
        .nr_sendmsg = -1,
        .nr_socketcall = -1,
    };
    (void)child;
    return &unsupported_syscalls;
}

int ptrace_wait(struct ptrace_child *child) {
    return unsupported(child);
}

int ptrace_attach_child(struct ptrace_child *child, pid_t pid) {
    memset(child, 0, sizeof(*child));
    child->pid = pid;
    child->state = ptrace_detached;
    child->error = ENOTSUP;
    return -1;
}

int ptrace_finish_attach(struct ptrace_child *child, pid_t pid) {
    memset(child, 0, sizeof(*child));
    child->pid = pid;
    child->state = ptrace_detached;
    child->error = ENOTSUP;
    return -1;
}

int ptrace_detach_child(struct ptrace_child *child) {
    if (child)
        child->state = ptrace_detached;
    return 0;
}

int ptrace_advance_to_state(struct ptrace_child *child, enum child_state desired) {
    (void)desired;
    return unsupported(child);
}

int ptrace_save_regs(struct ptrace_child *child) {
    return unsupported(child);
}

int ptrace_restore_regs(struct ptrace_child *child) {
    return unsupported(child);
}

unsigned long ptrace_remote_syscall(struct ptrace_child *child,
                                    unsigned long sysno,
                                    unsigned long p0, unsigned long p1,
                                    unsigned long p2, unsigned long p3,
                                    unsigned long p4, unsigned long p5) {
    (void)sysno;
    (void)p0;
    (void)p1;
    (void)p2;
    (void)p3;
    (void)p4;
    (void)p5;
    unsupported(child);
    return (unsigned long)-ENOTSUP;
}

int ptrace_memcpy_to_child(struct ptrace_child *child, child_addr_t dst, const void *src, size_t n) {
    (void)dst;
    (void)src;
    (void)n;
    return unsupported(child);
}

int ptrace_memcpy_from_child(struct ptrace_child *child, void *dst, child_addr_t src, size_t n) {
    (void)dst;
    (void)src;
    (void)n;
    return unsupported(child);
}

#endif
