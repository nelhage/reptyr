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

#ifdef __FreeBSD__

#include "freebsd.h"
#include "../platform.h"
#include "../../reptyr.h"
#include "../../ptrace.h"

void check_ptrace_scope(void) {
}

int check_pgroup(pid_t target) {
    struct procstat *procstat;
    struct kinfo_proc *kp;
    pid_t pg;
    unsigned int cnt;

    pg = getpgid(target);

    procstat = procstat_open_sysctl();
    kp = procstat_getprocs(procstat, KERN_PROC_PGRP, pg, &cnt);
    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);

    if (cnt > 1) {
        error("Process %d shares a process group with %d other processes. Unable to attach.\n", target, cnt - 1);
        return EINVAL;
    }

    return 0;
}

int check_proc_stopped(pid_t pid, int fd) {
    struct procstat *procstat;
    struct kinfo_proc *kp;
    int state;
    unsigned int cnt;

    procstat = procstat_open_sysctl();
    kp = procstat_getprocs(procstat, KERN_PROC_PID, pid, &cnt);

    if (cnt > 0)
        state = kp->ki_stat;

    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);

    if (cnt < 1)
        return 1;


    if (state == SSTOP)
        return 1;

    return 0;
}

struct filestat_list* get_procfiles(pid_t pid, struct kinfo_proc **kp, struct procstat **procstat, unsigned int *cnt) {
    int mflg = 0; // include mmapped files
    (*procstat) = procstat_open_sysctl();
    (*kp) = procstat_getprocs(*procstat, KERN_PROC_PID, pid, cnt);
    if ((*kp) == NULL || *cnt < 1)
        return NULL;

    return procstat_getfiles(*procstat, *kp, mflg);
}

int *get_child_tty_fds(struct ptrace_child *child, int statfd, int *count) {
    struct filestat *fst;
    struct filestat_list *head;
    struct procstat *procstat;
    struct kinfo_proc *kp;
    unsigned int cnt;
    struct fd_array fds = {};
    struct vnstat vn;
    int er;
    char errbuf[_POSIX2_LINE_MAX];

    head = get_procfiles(child->pid, &kp, &procstat, &cnt);

    STAILQ_FOREACH(fst, head, next) {
        if (fst->fs_type == PS_FST_TYPE_VNODE) {
            er = procstat_get_vnode_info(procstat, fst, &vn, errbuf);
            if (er != 0) {
                error("%s", errbuf);
                goto out;
            }

            if (vn.vn_dev == kp->ki_tdev && fst->fs_fd >= 0) {
                if (fd_array_push(&fds, fst->fs_fd) != 0) {
                    error("Unable to allocate memory for fd array.");
                    goto out;
                }
            }
        }
    }

out:
    procstat_freefiles(procstat, head);
    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);
    *count = fds.n;
    debug("Found %d tty fds in child %d.", fds.n, child->pid);
    return fds.fds;
}

// Find the PID of the terminal emulator for `target's terminal.
//
// We assume that the terminal emulator is the parent of the session
// leader. This is true in most cases, although in principle you can
// construct situations where it is false. We should fail safe later
// on if this turns out to be wrong, however.
int find_terminal_emulator(struct steal_pty_state *steal) {
    struct procstat *procstat;
    struct kinfo_proc *kp;
    unsigned int cnt;

    procstat = procstat_open_sysctl();
    kp = procstat_getprocs(procstat, KERN_PROC_PID, steal->target_stat.sid, &cnt);

    if (kp && cnt > 0)
        steal->emulator_pid = kp->ki_ppid;

    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);

    return 0;
}

int get_terminal_state(struct steal_pty_state *steal, pid_t target) {
    struct procstat *procstat;
    struct kinfo_proc *kp;
    unsigned int cnt;
    int err = 0;

    procstat = procstat_open_sysctl();
    kp = procstat_getprocs(procstat, KERN_PROC_PID, target, &cnt);
    if (kp == NULL || cnt < 1)
        goto done;

    if (kp->ki_tdev == NODEV) {
        error("Child is not connected to a pseudo-TTY. Unable to steal TTY.");
        err = EINVAL;
        goto done;
    }

    if ((err = find_terminal_emulator(steal)))
        return err;

done:
    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);
    return err;
}

int find_master_fd(struct steal_pty_state *steal) {
    error("How do I find master in FreeBSD? FIXME.");
    return EINVAL;
}

int get_pt() {
    return posix_openpt(O_RDWR | O_NOCTTY);
}

int get_process_tty_termios(pid_t pid, struct termios *tio) {
    int err = EINVAL;
    struct kinfo_proc *kp;
    unsigned int cnt;
    struct filestat_list *head;
    struct filestat *fst;
    struct procstat *procstat;
    int fd = -1;

    head = get_procfiles(pid, &kp, &procstat, &cnt);

    STAILQ_FOREACH(fst, head, next) {
        if (fst->fs_type == PS_FST_TYPE_VNODE) {
            if (fst->fs_path) {
                fd = open(fst->fs_path, O_RDONLY);
                if (fd >= 0 && isatty(fd)) {
                    if (tcgetattr(fd, tio) < 0) {
                        err = -assert_nonzero(errno);
                    }
                    else {
                        close(fd);
                        err = 0;
                        goto done;
                    }
                }
                close(fd);
            }
        }
    }

done:
    procstat_freefiles(procstat, head);
    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);
    return err;
}

void move_process_group(struct ptrace_child *child, pid_t from, pid_t to) {
    struct procstat *procstat;
    struct kinfo_proc *kp;
    unsigned int cnt;
    int i;
    int err;

    procstat = procstat_open_sysctl();
    kp = procstat_getprocs(procstat, KERN_PROC_PGRP, from, &cnt);

    for (i = 0; i < cnt; i++) {
        debug("Change pgid for pid %d to %d", kp[i].ki_pid, to);
        err = do_syscall(child, setpgid, kp[i].ki_pid, to, 0, 0, 0, 0);
        if (err < 0)
            error(" failed: %s", strerror(-err));
    }
    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);
}

void copy_user(struct ptrace_child *d, struct ptrace_child *s) {
    memcpy(&d->regs, &s->regs, sizeof(s->regs));
}

#endif
