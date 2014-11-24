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

#include <sys/ptrace.h>
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
#include <signal.h>

#include "../../ptrace.h"

#include "../platform.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	_min1 < _min2 ? _min1 : _min2; })

static int __ptrace_command(struct ptrace_child *child, int req,
                            void *, int);

#define ptrace_command(cld, req, ...) _ptrace_command(cld, req, ## __VA_ARGS__, NULL, NULL)
#define _ptrace_command(cld, req, addr, data, ...) __ptrace_command((cld), (req), (void*)(addr), (int)(data))


struct ptrace_personality {
    size_t syscall_rv;
    size_t syscall_arg0;
    size_t syscall_arg1;
    size_t syscall_arg2;
    size_t syscall_arg3;
    size_t syscall_arg4;
    size_t syscall_arg5;
    size_t reg_ip;
};


static struct ptrace_personality *personality(struct ptrace_child *child);

#if defined(__amd64__)
#include "arch/amd64.h"
#elif defined(__i386__)
#include "arch/i386.h"
#elif defined(__arm__)
#include "arch/arm.h"
#else
#error Unsupported architecture.
#endif

#ifndef ARCH_HAVE_MULTIPLE_PERSONALITIES
int arch_get_personality(struct ptrace_child *child) {
    return 0;
}

struct syscall_numbers arch_syscall_numbers[] = {
#include "arch/default-syscalls.h"
};
#endif

static struct ptrace_personality *personality(struct ptrace_child *child) {
    return &arch_personality[child->personality];
}

struct syscall_numbers *ptrace_syscall_numbers(struct ptrace_child *child) {
    return &arch_syscall_numbers[child->personality];
}

int ptrace_attach_child(struct ptrace_child *child, pid_t pid) {
    memset(child, 0, sizeof(*child));
    child->pid = pid;

    if (ptrace_command(child, PT_ATTACH, 0, 0) < 0)
        return -1;

    return ptrace_finish_attach(child, pid);
}

int ptrace_finish_attach(struct ptrace_child *child, pid_t pid) {
    memset(child, 0, sizeof(*child));
    child->pid = pid;

    if (ptrace_wait(child) < 0)
        goto detach;

    ptrace_command(child, PT_FOLLOW_FORK, 0, 1);

    if (arch_get_personality(child))
        goto detach;

    kill(pid, SIGCONT);

    return 0;

detach:
    /* Don't clobber child->error */
    ptrace(PT_DETACH, child->pid, (caddr_t)1, 0);
    return -1;
}

int ptrace_detach_child(struct ptrace_child *child) {
    if (ptrace_command(child, PT_DETACH, (caddr_t)1, 0) < 0)
        return -1;
    child->state = ptrace_detached;
    return 0;
}

int ptrace_wait(struct ptrace_child *child) {
    struct ptrace_lwpinfo lwpinfo;
    if (waitpid(child->pid, &child->status, 0) < 0) {
        child->error = errno;
        return -1;
    }
    if (WIFEXITED(child->status) || WIFSIGNALED(child->status)) {
        child->state = ptrace_exited;
    } else if (WIFSTOPPED(child->status)) {
        ptrace_command(child, PT_LWPINFO, &lwpinfo, sizeof(lwpinfo));
        child->state = ptrace_stopped;
        if (lwpinfo.pl_flags & PL_FLAG_FORKED)
            child->forked_pid = lwpinfo.pl_child_pid;
        if (lwpinfo.pl_flags & PL_FLAG_SCE)
            child->state = ptrace_at_syscall;
        if (lwpinfo.pl_flags & PL_FLAG_SCX)
            child->state = ptrace_after_syscall;
    } else {
        child->error = EINVAL;
        return -1;
    }
    return 0;
}

int ptrace_advance_to_state(struct ptrace_child *child,
                            enum child_state desired) {
    int err;
    while (child->state != desired) {
        switch (desired) {
        case ptrace_after_syscall:
            if (WIFSTOPPED(child->status) && WSTOPSIG(child->status) == SIGSEGV) {
                child->error = EAGAIN;
                return -1;
            }
            err = ptrace_command(child, PT_TO_SCX, (caddr_t)1, 0);
            break;
        case ptrace_at_syscall:
            if (WIFSTOPPED(child->status) && WSTOPSIG(child->status) == SIGSEGV) {
                child->error = EAGAIN;
                return -1;
            }
            err = ptrace_command(child, PT_TO_SCE, (caddr_t)1, 0);
            break;
        case ptrace_running:
            return ptrace_command(child, PT_CONTINUE, (caddr_t)1, 0);
        case ptrace_stopped:
            err = kill(child->pid, SIGSTOP);
            if (err < 0)
                child->error = errno;
            break;
        default:
            child->error = EINVAL;
            return -1;
        }
        if (err < 0)
            return err;
        if (ptrace_wait(child) < 0)
            return -1;
    }
    return 0;
}


int ptrace_save_regs(struct ptrace_child *child) {
    if (ptrace_advance_to_state(child, ptrace_at_syscall) < 0)
        return -1;
    if (ptrace_command(child, PT_GETREGS, &child->regs, 0) < 0)
        return -1;
    arch_save_syscall(child);
    arch_fixup_regs(child);
    if (arch_save_syscall(child) < 0)
        return -1;
    return 0;
}

int ptrace_restore_regs(struct ptrace_child *child) {
    int err;
    err = ptrace_command(child, PT_SETREGS, &child->regs, 0);
    if (err < 0)
        return err;
    return arch_restore_syscall(child);
}

unsigned long ptrace_remote_syscall(struct ptrace_child *child,
                                    unsigned long sysno,
                                    unsigned long p0, unsigned long p1,
                                    unsigned long p2, unsigned long p3,
                                    unsigned long p4, unsigned long p5) {
    unsigned long rv;
    if (ptrace_advance_to_state(child, ptrace_at_syscall) < 0)
        return -1;
#define setreg(r, v) arch_set_register(child,personality(child)->r,v)

    //if (arch_set_syscall(child, sysno) < 0)
    //return -1;

    setreg(syscall_rv, sysno);

    setreg(syscall_arg0, p0);
    setreg(syscall_arg1, p1);
    setreg(syscall_arg2, p2);
    setreg(syscall_arg3, p3);
    setreg(syscall_arg4, p4);
    setreg(syscall_arg5, p5);

    if (ptrace_advance_to_state(child, ptrace_after_syscall) < 0)
        return -1;

    rv = arch_get_register(child, personality(child)->syscall_rv);
    if (child->error)
        return -1;

    setreg(reg_ip, *(unsigned long*)((void*)&child->regs +
                                     personality(child)->reg_ip));

#undef setreg

    return rv;
}

int ptrace_memcpy_to_child(struct ptrace_child *child, child_addr_t dst, const void *src, size_t n) {
    int scratch;

    while (n >= sizeof(int)) {
        if (ptrace_command(child, PT_WRITE_D, dst, *((int*)src)) < 0)
            return -1;
        dst += sizeof(int);
        src += sizeof(int);
        n -= sizeof(int);
    }

    if (n) {
        scratch = ptrace_command(child, PT_READ_D, dst);
        if (child->error)
            return -1;
        memcpy(&scratch, src, n);
        if (ptrace_command(child, PT_WRITE_D, dst, scratch) < 0)
            return -1;
    }

    return 0;
}

int ptrace_memcpy_from_child(struct ptrace_child *child, void *dst, child_addr_t src, size_t n) {
    int scratch;

    while (n) {
        scratch = ptrace_command(child, PT_READ_D, src);
        if (child->error) return -1;
        memcpy(dst, &scratch, min(n, sizeof(int)));

        dst += sizeof(int);
        src += sizeof(int);
        if (n >= sizeof(int))
            n -= sizeof(int);
        else
            n = 0;
    }
    return 0;
}

static int __ptrace_command(struct ptrace_child *child, int req,
                            void *addr, int data) {
    long rv;
    errno = 0;
    rv = ptrace(req, child->pid, addr, data);
    child->error = errno;
    return rv;
}


#ifdef BUILD_PTRACE_MAIN
int main(int argc, char **argv) {
    struct ptrace_child child;
    pid_t pid;

    if (argc < 2) {
        printf("Usage: %s pid\n", argv[0]);
        return 1;
    }
    pid = atoi(argv[1]);

    assert(!ptrace_attach_child(&child, pid));
    assert(!ptrace_save_regs(&child));

    printf("mmap = %lx\n", ptrace_remote_syscall(&child, 477, 0,
            4096, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));

    //reset_user_struct(&child.regs);
    assert(!ptrace_restore_regs(&child));
    assert(!ptrace_detach_child(&child));

    return 0;
}
#endif
