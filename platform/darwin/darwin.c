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

#include "darwin.h"
#include "../platform.h"
#include "../../reptyr.h"
#include "../../ptrace.h"

void check_ptrace_scope(void) {
    error("macOS support is partial: targets must be debug-attachable, attach is arm64-only, and -T/control-tty handoff is not implemented yet.");
}

int check_pgroup(pid_t target) {
    (void)target;
    return 0;
}

int check_proc_stopped(pid_t pid, int fd) {
    (void)pid;
    (void)fd;
    return 1;
}

int *get_child_tty_fds(struct ptrace_child *child, int statfd, int *count) {
    (void)child;
    (void)statfd;
    *count = 0;
    return NULL;
}

int get_terminal_state(struct steal_pty_state *steal, pid_t target) {
    (void)steal;
    (void)target;
    return ENOTSUP;
}

int find_master_fd(struct steal_pty_state *steal) {
    (void)steal;
    return ENOTSUP;
}

int get_pt(void) {
    return posix_openpt(O_RDWR | O_NOCTTY);
}

int get_process_tty_termios(pid_t pid, struct termios *tio) {
    (void)pid;
    (void)tio;
    return ENOTSUP;
}

void move_process_group(struct ptrace_child *child, pid_t from, pid_t to) {
    (void)child;
    (void)from;
    (void)to;
}

void copy_user(struct ptrace_child *d, struct ptrace_child *s) {
    (void)d;
    (void)s;
}

#endif
