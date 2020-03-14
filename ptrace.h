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
#ifndef PTRACE_H
#define PTRACE_H

#ifdef __powerpc__
#include <asm/ptrace.h>
#endif
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

/*
 * See https://github.com/nelhage/reptyr/issues/25 and
 * https://github.com/nelhage/reptyr/issues/26.
 *
 * Older glibc's don't define PTRACE_{SETOPTIONS,GETEVENTMSG}, (but do
 * in linux/ptrace.h), but on newer systems sys/ptrace.h and
 * linux/ptrace.h conflict. If we were using autoconf or something, we
 * could potentially detect the right headers at configure-time, but
 * I'd like to avoid adding autoconf. These numbers can't ever change
 * for ABI-compatibility reasons, at least.
 */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS   0x4200
#endif
#ifndef PTRACE_GETEVENTMSG
#define PTRACE_GETEVENTMSG  0x4201
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET  0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET  0x4205
#endif

enum child_state {
    ptrace_detached = 0,
    ptrace_at_syscall,
    ptrace_after_syscall,
    ptrace_running,
    ptrace_stopped,
    ptrace_exited
};

struct ptrace_child {
    pid_t pid;
    enum child_state state;
    int personality;
    int status;
    int error;
    unsigned long forked_pid;
    unsigned long saved_syscall;
#ifdef __linux__
#ifdef __arm__
    struct user_regs regs;
#elif defined(__powerpc__)
    struct pt_regs regs;
#else
    struct user_regs_struct regs;
#endif
#elif defined(__FreeBSD__)
	struct reg regs;
#endif
};

struct syscall_numbers {
    long nr_mmap;
    long nr_mmap2;
    long nr_munmap;
    long nr_getsid;
    long nr_setsid;
    long nr_setpgid;
    long nr_fork;
    long nr_clone;
    long nr_wait4;
    long nr_signal;
    long nr_rt_sigaction;
    long nr_openat;
    long nr_close;
    long nr_ioctl;
    long nr_dup2;
    long nr_dup3;
    long nr_socket;
    long nr_connect;
    long nr_sendmsg;
    long nr_socketcall;
};

typedef unsigned long child_addr_t;

int ptrace_wait(struct ptrace_child *child);
int ptrace_attach_child(struct ptrace_child *child, pid_t pid);
int ptrace_finish_attach(struct ptrace_child *child, pid_t pid);
int ptrace_detach_child(struct ptrace_child *child);
int ptrace_wait(struct ptrace_child *child);
int ptrace_advance_to_state(struct ptrace_child *child,
                            enum child_state desired);
int ptrace_save_regs(struct ptrace_child *child);
int ptrace_restore_regs(struct ptrace_child *child);
unsigned long ptrace_remote_syscall(struct ptrace_child *child,
                                    unsigned long sysno,
                                    unsigned long p0, unsigned long p1,
                                    unsigned long p2, unsigned long p3,
                                    unsigned long p4, unsigned long p5);

int ptrace_memcpy_to_child(struct ptrace_child *, child_addr_t, const void*, size_t);
int ptrace_memcpy_from_child(struct ptrace_child *, void*, child_addr_t, size_t);
struct syscall_numbers *ptrace_syscall_numbers(struct ptrace_child *child);

#endif
