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

#ifndef PLATFORM_H
#define PLATFORM_H

#include "linux/linux.h"
#include "freebsd/freebsd.h"
#include "../ptrace.h"

struct fd_array {
    int *fds;
    int n;
    int allocated;
};
int fd_array_push(struct fd_array *fda, int fd);

#define do_syscall(child, name, a0, a1, a2, a3, a4, a5) \
    ptrace_remote_syscall((child), ptrace_syscall_numbers((child))->nr_##name, \
                          a0, a1, a2, a3, a4, a5)

#define TASK_COMM_LENGTH 16
struct proc_stat {
    pid_t pid;
    char comm[TASK_COMM_LENGTH+1];
    char state;
    pid_t ppid, sid, pgid;
    dev_t ctty;
};

struct steal_pty_state {
    struct proc_stat target_stat;

    pid_t emulator_pid;
    struct fd_array master_fds;

    char tmpdir[PATH_MAX];
    union {
        struct sockaddr addr;
        struct sockaddr_un addr_un;
    };
    int sockfd;

    struct ptrace_child child;
    child_addr_t child_scratch;
    int child_fd;

    int ptyfd;
};

void check_ptrace_scope(void);
int check_pgroup(pid_t target);
int check_proc_stopped(pid_t pid, int fd);
int *get_child_tty_fds(struct ptrace_child *child, int statfd, int *count);
int get_terminal_state(struct steal_pty_state *steal, pid_t target);
int find_master_fd(struct steal_pty_state *steal);
int get_pt();
int get_process_tty_termios(pid_t pid, struct termios *tio);
void move_process_group(struct ptrace_child *child, pid_t from, pid_t to);
void copy_user(struct ptrace_child *d, struct ptrace_child *s);

#endif
