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

#ifdef __amd64__
#include "arch/amd64.h"
#else
#include "arch/i386.h"
#endif

#ifndef mmap_syscall
#define mmap_syscall __NR_mmap
#endif

#define offsetof(a, b) __builtin_offsetof(a,b)

void attach_child(pid_t pid) {
    int status;

    if (ptrace(PTRACE_ATTACH, pid) < 0) {
        perror("Unable to attach");
        exit(1);
    }

    if (waitpid(pid, NULL, 0) < 0) {
        perror("Waiting on child");
        exit(1);
    }

    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        if (waitpid(pid, &status, 0) < 0) {
            perror("Waiting on child");
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            break;
    }
}

unsigned long remote_syscall(pid_t pid, unsigned long sysno,
                             unsigned long p0, unsigned long p1,
                             unsigned long p2, unsigned long p3,
                             unsigned long p4, unsigned long p5) {
    int status;

#define setreg(r, v) do {                                               \
        if (ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, regs.r), \
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

    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, &status, 0);
    assert(WIFSTOPPED(status));

    return ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, regs.reg_ax));
}

void reset_user_struct(struct user *user) {
    user->regs.reg_ip -= 2;
    user->regs.reg_ax = user->regs.orig_ax;
}

int main(int argc, char **argv) {
    pid_t pid;
    struct user regs;

    if (argc < 2) {
        printf("Usage: %s pid\n", argv[0]);
        return 1;
    }
    pid = atoi(argv[1]);

    attach_child(pid);

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
        perror("getregs");
        return 1;
    }

    printf("mmap = %lx\n", remote_syscall(pid, mmap_syscall, 0,
                                          4096, PROT_READ|PROT_WRITE,
                                          MAP_ANONYMOUS|MAP_PRIVATE, 0, 0));

    reset_user_struct(&regs);

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
        perror("setregs");
        return 1;
    }

    if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
        perror("Unable to detach");
        return 1;
    }

    return 0;
}
