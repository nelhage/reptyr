#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <assert.h>

#include "ptrace.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	_min1 < _min2 ? _min1 : _min2; })


#define offsetof(a, b) __builtin_offsetof(a,b)

int ptrace_wait(struct ptrace_child *child);

int ptrace_attach_child(struct ptrace_child *child, pid_t pid) {
    int err = 0;

    memset(child, 0, sizeof child);
    child->pid = pid;

    if ((err = ptrace(PTRACE_ATTACH, pid)) < 0)
        return err;

    ptrace_wait(child);

    if ((err = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)) < 0)
        goto detach;

    return err;

 detach:
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return err;
}

int ptrace_detach_child(struct ptrace_child *child) {
    int err;
    err = ptrace(PTRACE_DETACH, child->pid, 0, 0);
    if (!err)
        child->state = ptrace_detached;
    return err;
}

int ptrace_wait(struct ptrace_child *child) {
    int err;
    if ((err = waitpid(child->pid, &child->status, 0)) < 0)
        return err;
    if (WIFEXITED(child->status) || WIFSIGNALED(child->status)) {
        child->state = ptrace_exited;
    } else if(WIFSTOPPED(child->status)) {
        if (WSTOPSIG(child->status) & 0x80) {
            child->state = (child->state == ptrace_at_syscall) ?
                ptrace_after_syscall : ptrace_at_syscall;
        } else {
            child->state = ptrace_stopped;
        }
    } else {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int ptrace_advance_to_state(struct ptrace_child *child,
                            enum child_state desired) {
    int err;
    while(child->state != desired) {
        switch(desired) {
        case ptrace_at_syscall:
        case ptrace_after_syscall:
            err = ptrace(PTRACE_SYSCALL, child->pid, 0, 0);
            break;
        case ptrace_running:
            return ptrace(PTRACE_CONT, child->pid, 0, 0);
        case ptrace_stopped:
            err = kill(child->pid, SIGSTOP);
            break;
        default:
            errno = EINVAL;
            return -1;
        }
        if (err < 0)
            return err;
        if((err = ptrace_wait(child)) < 0)
            return err;
    }
    return 0;
}


static void reset_user_struct(struct user *user) {
    user->regs.reg_ip -= 2;
    user->regs.reg_ax = user->regs.orig_ax;
}

int ptrace_save_regs(struct ptrace_child *child) {
    int err;
    err = ptrace_advance_to_state(child, ptrace_at_syscall);
    if (err)
        return err;
    err = ptrace(PTRACE_GETREGS, child->pid, 0, &child->user);
    if (!err)
        reset_user_struct(&child->user);
    return err;
}

int ptrace_restore_regs(struct ptrace_child *child) {
    return ptrace(PTRACE_SETREGS, child->pid, 0, &child->user);
}

unsigned long ptrace_remote_syscall(struct ptrace_child *child,
                                    unsigned long sysno,
                                    unsigned long p0, unsigned long p1,
                                    unsigned long p2, unsigned long p3,
                                    unsigned long p4, unsigned long p5) {
    unsigned long rv;
    assert(!ptrace_advance_to_state(child, ptrace_at_syscall));

#define setreg(r, v) do {                                               \
        if (ptrace(PTRACE_POKEUSER, child->pid,                         \
                   offsetof(struct user, regs.r),                       \
                   (v)) < 0) {                                          \
            perror(#r);                                                 \
            exit(1);                                                    \
        }                                                               \
    } while(0)

    setreg(orig_ax, sysno);
    setreg(syscall_arg0, p0);
    setreg(syscall_arg1, p1);
    setreg(syscall_arg2, p2);
    setreg(syscall_arg3, p3);
    setreg(syscall_arg4, p4);
    setreg(syscall_arg5, p5);

    assert(!ptrace_advance_to_state(child, ptrace_after_syscall));

    rv = ptrace(PTRACE_PEEKUSER, child->pid, offsetof(struct user, regs.reg_ax));

    setreg(reg_ax, child->user.regs.orig_ax);
    setreg(reg_ip, child->user.regs.reg_ip);

    #undef setreg

    return rv;
}

int ptrace_memcpy_to_child(struct ptrace_child *child, child_addr_t dst, void *src, size_t n) {
    int err;
    unsigned long scratch;

    while (n >= sizeof(unsigned long)) {
        if ((err = ptrace(PTRACE_POKEDATA, child->pid, dst, *((unsigned long*)src))) < 0)
            return err;
        dst += sizeof(unsigned long);
        src += sizeof(unsigned long);
        n -= sizeof(unsigned long);
    }

    if (n) {
        errno = 0;
        scratch = ptrace(PTRACE_PEEKDATA, child->pid, dst);
        if (errno)
            return -1;
        memcpy(&scratch, src, n);
        if ((err = ptrace(PTRACE_POKEDATA, child->pid, dst, scratch)) < 0)
            return err;
    }

    return 0;
}

int ptrace_memcpy_from_child(struct ptrace_child *child, void *dst, child_addr_t src, size_t n) {
    unsigned long scratch;

    while (n) {
        errno = 0;
        scratch = ptrace(PTRACE_PEEKDATA, child->pid, src);
        if (errno) return -1;
        memcpy(dst, &scratch, min(n, sizeof(unsigned long)));

        dst += sizeof(unsigned long);
        src += sizeof(unsigned long);
        if (n >= sizeof(unsigned long))
            n -= sizeof(unsigned long);
        else
            n = 0;
    }
    return 0;
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

    printf("mmap = %lx\n", ptrace_remote_syscall(&child, mmap_syscall, 0,
                                                 4096, PROT_READ|PROT_WRITE,
                                                 MAP_ANONYMOUS|MAP_PRIVATE, 0, 0));

    reset_user_struct(&child.user);
    assert(!ptrace_restore_regs(&child));
    assert(!ptrace_detach_child(&child));

    return 0;
}
#endif
