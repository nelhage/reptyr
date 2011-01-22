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

#include "ptrace.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	_min1 < _min2 ? _min1 : _min2; })


static long __ptrace_command(struct ptrace_child *child, enum __ptrace_request req,
                             void *, void*);

#define ptrace_command(cld, req, ...) _ptrace_command(cld, req, ## __VA_ARGS__, NULL, NULL)
#define _ptrace_command(cld, req, addr, data, ...) __ptrace_command((cld), (req), (void*)(addr), (void*)(data))

int ptrace_wait(struct ptrace_child *child);

int ptrace_attach_child(struct ptrace_child *child, pid_t pid) {
    memset(child, 0, sizeof child);
    child->pid = pid;
    if (ptrace_command(child, PTRACE_ATTACH) < 0)
        return -1;

    return ptrace_finish_attach(child, pid);
}

int ptrace_finish_attach(struct ptrace_child *child, pid_t pid) {
    memset(child, 0, sizeof child);
    child->pid = pid;

    if (ptrace_wait(child) < 0)
        goto detach;

    if (ptrace_command(child, PTRACE_SETOPTIONS, 0,
                       PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK) < 0)
        goto detach;

    return 0;

 detach:
    /* Don't clobber child->error */
    ptrace(PTRACE_DETACH, child->pid, 0, 0);
    return -1;
}

int ptrace_detach_child(struct ptrace_child *child) {
    if (ptrace_command(child, PTRACE_DETACH, 0, 0) < 0)
        return -1;
    child->state = ptrace_detached;
    return 0;
}

int ptrace_wait(struct ptrace_child *child) {
    if (waitpid(child->pid, &child->status, 0) < 0) {
        child->error = errno;
        return -1;
    }
    if (WIFEXITED(child->status) || WIFSIGNALED(child->status)) {
        child->state = ptrace_exited;
    } else if(WIFSTOPPED(child->status)) {
        int sig = WSTOPSIG(child->status);
        if (sig & 0x80) {
            child->state = (child->state == ptrace_at_syscall) ?
                ptrace_after_syscall : ptrace_at_syscall;
        } else {
            if (sig == SIGTRAP && (((child->status >> 8) & PTRACE_EVENT_FORK) == PTRACE_EVENT_FORK))
                ptrace_command(child, PTRACE_GETEVENTMSG, 0, &child->forked_pid);
            if (child->state != ptrace_at_syscall)
                child->state = ptrace_stopped;
            if (sig != SIGSTOP && sig != SIGTRAP && sig != SIGCHLD && sig != SIGHUP && sig != SIGCONT) {
                child->error = EAGAIN;
                return -1;
            }
        }
    } else {
        child->error = EINVAL;
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
            err = ptrace_command(child, PTRACE_SYSCALL, 0, 0);
            break;
        case ptrace_running:
            return ptrace_command(child, PTRACE_CONT, 0, 0);
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
        if(ptrace_wait(child) < 0)
            return -1;
    }
    return 0;
}


static void reset_user_struct(struct user *user) {
    user->regs.reg_ip -= 2;
    user->regs.reg_ax = user->regs.orig_ax;
}

int ptrace_save_regs(struct ptrace_child *child) {
    if (ptrace_advance_to_state(child, ptrace_at_syscall) < 0)
        return -1;
    if (ptrace_command(child, PTRACE_GETREGS, 0, &child->user) < 0)
        return -1;
    reset_user_struct(&child->user);
    return 0;
}

int ptrace_restore_regs(struct ptrace_child *child) {
    return ptrace_command(child, PTRACE_SETREGS, 0, &child->user);
}

unsigned long ptrace_remote_syscall(struct ptrace_child *child,
                                    unsigned long sysno,
                                    unsigned long p0, unsigned long p1,
                                    unsigned long p2, unsigned long p3,
                                    unsigned long p4, unsigned long p5) {
    unsigned long rv;
    if (ptrace_advance_to_state(child, ptrace_at_syscall) < 0)
        return -1;

#define setreg(r, v) do {                                               \
        if (ptrace_command(child, PTRACE_POKEUSER,                      \
                           offsetof(struct user, regs.r),               \
                           (v)) < 0)                                    \
            return -1;                                                  \
    } while(0)

    setreg(orig_ax, sysno);
    setreg(syscall_arg0, p0);
    setreg(syscall_arg1, p1);
    setreg(syscall_arg2, p2);
    setreg(syscall_arg3, p3);
    setreg(syscall_arg4, p4);
    setreg(syscall_arg5, p5);

    if (ptrace_advance_to_state(child, ptrace_after_syscall) < 0)
        return -1;

    rv = ptrace_command(child, PTRACE_PEEKUSER, offsetof(struct user, regs.reg_ax));
    if (child->error)
        return -1;

    setreg(reg_ax, child->user.regs.orig_ax);
    setreg(reg_ip, child->user.regs.reg_ip);

    #undef setreg

    return rv;
}

int ptrace_memcpy_to_child(struct ptrace_child *child, child_addr_t dst, const void *src, size_t n) {
    unsigned long scratch;

    while (n >= sizeof(unsigned long)) {
        if (ptrace_command(child, PTRACE_POKEDATA, dst, *((unsigned long*)src)) < 0)
            return -1;
        dst += sizeof(unsigned long);
        src += sizeof(unsigned long);
        n -= sizeof(unsigned long);
    }

    if (n) {
        scratch = ptrace_command(child, PTRACE_PEEKDATA, dst);
        if (child->error)
            return -1;
        memcpy(&scratch, src, n);
        if (ptrace_command(child, PTRACE_POKEDATA, dst, scratch) < 0)
            return -1;
    }

    return 0;
}

int ptrace_memcpy_from_child(struct ptrace_child *child, void *dst, child_addr_t src, size_t n) {
    unsigned long scratch;

    while (n) {
         scratch = ptrace_command(child, PTRACE_PEEKDATA, src);
        if (child->error) return -1;
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

static long __ptrace_command(struct ptrace_child *child, enum __ptrace_request req,
                             void *addr, void *data) {
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

    printf("mmap = %lx\n", ptrace_remote_syscall(&child, mmap_syscall, 0,
                                                 4096, PROT_READ|PROT_WRITE,
                                                 MAP_ANONYMOUS|MAP_PRIVATE, 0, 0));

    reset_user_struct(&child.user);
    assert(!ptrace_restore_regs(&child));
    assert(!ptrace_detach_child(&child));

    return 0;
}
#endif
