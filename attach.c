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
#include <sys/types.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "ptrace.h"
#include "reptyr.h"

#define TASK_COMM_LENGTH 16
struct proc_stat {
    pid_t pid;
    char comm[TASK_COMM_LENGTH+1];
    char state;
    pid_t ppid, sid, pgid;
    dev_t ctty;
};

#define do_syscall(child, name, a0, a1, a2, a3, a4, a5) \
    ptrace_remote_syscall((child), ptrace_syscall_numbers((child))->nr_##name, \
                          a0, a1, a2, a3, a4, a5)

int parse_proc_stat(int statfd, struct proc_stat *out) {
    char buf[1024];
    int n;
    unsigned dev;
    lseek(statfd, 0, SEEK_SET);
    if (read(statfd, buf, sizeof buf) < 0)
        return errno;
    n = sscanf(buf, "%d (%16[^)]) %c %d %d %d %u",
               &out->pid, out->comm,
               &out->state, &out->ppid, &out->sid,
               &out->pgid, &dev);
    if (n == EOF)
        return errno;
    if (n != 7) {
        return EINVAL;
    }
    out->ctty = dev;
    return 0;
}

static void do_unmap(struct ptrace_child *child, child_addr_t addr, unsigned long len) {
    if (addr == (unsigned long)-1)
        return;
    do_syscall(child, munmap, addr, len, 0, 0, 0, 0);
}

int *get_child_tty_fds(struct ptrace_child *child, int statfd, int *count) {
    struct proc_stat child_status;
    struct stat tty_st, st;
    char buf[PATH_MAX];
    int n = 0, allocated = 0;
    int *fds = NULL;
    DIR *dir;
    struct dirent *d;
    int *tmp = NULL;

    debug("Looking up fds for tty in child.");
    if ((child->error = parse_proc_stat(statfd, &child_status)))
        return NULL;

    debug("Resolved child tty: %x", (unsigned)child_status.ctty);

    if (stat("/dev/tty", &tty_st) < 0) {
        child->error = errno;
        error("Unable to stat /dev/tty");
        return NULL;
    }

    snprintf(buf, sizeof buf, "/proc/%d/fd/", child->pid);
    if ((dir = opendir(buf)) == NULL)
        return NULL;
    while ((d = readdir(dir)) != NULL) {
        if (d->d_name[0] == '.') continue;
        snprintf(buf, sizeof buf, "/proc/%d/fd/%s", child->pid, d->d_name);
        if (stat(buf, &st) < 0)
            continue;

        if (st.st_rdev == child_status.ctty
            || st.st_rdev == tty_st.st_rdev) {
            if (n == allocated) {
                allocated = allocated ? 2 * allocated : 2;
                tmp = realloc(fds, allocated * sizeof *tmp);
                if (tmp == NULL) {
                  child->error = errno;
                  error("Unable to allocate memory for fd array.");
                  free(fds);
                  fds = NULL;
                  goto out;
                }
                fds = tmp;
            }
            debug("Found an alias for the tty: %s", d->d_name);
            fds[n++] = atoi(d->d_name);
        }
    }
 out:
    *count = n;
    closedir(dir);
    return fds;
}

void move_process_group(struct ptrace_child *child, pid_t from, pid_t to) {
    DIR *dir;
    struct dirent *d;
    pid_t pid;
    char *p;
    int err;

    if ((dir = opendir("/proc/")) == NULL)
        return;

    while ((d = readdir(dir)) != NULL) {
        if (d->d_name[0] == '.') continue;
        pid = strtol(d->d_name, &p, 10);
        if (*p) continue;
        if (getpgid(pid) == from) {
            debug("Change pgid for pid %d", pid);
            err = do_syscall(child, setpgid, pid, to, 0, 0, 0, 0);
            if (err < 0)
                error(" failed: %s", strerror(-err));
        }
    }
    closedir(dir);
}

int do_setsid(struct ptrace_child *child) {
    int err = 0;
    struct ptrace_child dummy;

    err = do_syscall(child, fork, 0, 0, 0, 0, 0, 0);
    if (err < 0)
        return err;

    debug("Forked a child: %ld", child->forked_pid);

    err = ptrace_finish_attach(&dummy, child->forked_pid);
    if (err < 0)
        goto out_kill;

    dummy.state = ptrace_after_syscall;
    memcpy(&dummy.user, &child->user, sizeof child->user);
    if (ptrace_restore_regs(&dummy)) {
        err = dummy.error;
        goto out_kill;
    }

    err = do_syscall(&dummy, setpgid, 0, 0, 0, 0, 0, 0);
    if (err < 0) {
        error("Failed to setpgid: %s", strerror(-err));
        goto out_kill;
    }

    move_process_group(child, child->pid, dummy.pid);

    err = do_syscall(child, setsid, 0, 0, 0, 0, 0, 0);
    if (err < 0) {
        error("Failed to setsid: %s", strerror(-err));
        move_process_group(child, dummy.pid, child->pid);
        goto out_kill;
    }

    debug("Did setsid()");

 out_kill:
    kill(dummy.pid, SIGKILL);
    ptrace_detach_child(&dummy);
    ptrace_wait(&dummy);
    do_syscall(child, wait4, dummy.pid, 0, WNOHANG, 0, 0, 0);
    return err;
}

int ignore_hup(struct ptrace_child *child, unsigned long scratch_page) {
    int err;
    if (ptrace_syscall_numbers(child)->nr_signal != -1) {
        err = do_syscall(child, signal, SIGHUP, (unsigned long)SIG_IGN, 0, 0, 0, 0);
    } else {
        struct sigaction act = {
            .sa_handler = SIG_IGN,
        };
        err = ptrace_memcpy_to_child(child, scratch_page,
                                     &act, sizeof act);
        if (err < 0)
            return err;
        err = do_syscall(child, rt_sigaction,
                         SIGHUP, scratch_page,
                         0, 8, 0, 0);
    }
    return err;
}

/*
 * Wait for the specific pid to enter state 'T', or stopped. We have to pull the
 * /proc file rather than attaching with ptrace() and doing a wait() because
 * half the point of this exercise is for the process's real parent (the shell)
 * to see the TSTP.
 *
 * In case the process is masking or ignoring SIGTSTP, we time out after a
 * second and continue with the attach -- it'll still work mostly right, you
 * just won't get the old shell back.
 */
void wait_for_stop(pid_t pid, int fd) {
    struct timeval start, now;
    struct timespec sleep;
    struct proc_stat st;

    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        if ((now.tv_sec > start.tv_sec && now.tv_usec > start.tv_usec)
            || (now.tv_sec - start.tv_sec > 1)) {
            error("Timed out waiting for child stop.");
            break;
        }
        /*
         * If anything goes wrong reading or parsing the stat node, just give
         * up.
         */
        if (parse_proc_stat(fd, &st))
            break;
        if (st.state == 'T')
            break;

        sleep.tv_sec  = 0;
        sleep.tv_nsec = 10000000;
        nanosleep(&sleep, NULL);
    }
}

int copy_tty_state(pid_t pid, const char *pty) {
    char buf[PATH_MAX];
    int fd, err = 0;
    struct termios tio;
    int i;

    for (i = 0; i < 3; i++) {
        err = 0;
        snprintf(buf, sizeof buf, "/proc/%d/fd/%d", pid, i);

        if ((fd = open(buf, O_RDONLY)) < 0) {
            err = -fd;
            continue;
        }

        if (!isatty(fd)) {
            err = ENOTTY;
            goto retry;
        }

        if (tcgetattr(fd, &tio) < 0) {
            err = -errno;
        }
    retry:
        close(fd);
    }

    if (err)
        return err;

    if ((fd = open(pty, O_RDONLY)) < 0)
        return -errno;

    if (tcsetattr(fd, TCSANOW, &tio) < 0)
        err = errno;
    close(fd);
    return -err;
}

int attach_child(pid_t pid, const char *pty, int force_stdio) {
    struct ptrace_child child;
    unsigned long scratch_page = -1;
    int *child_tty_fds = NULL, n_fds, child_fd, statfd;
    int i;
    int err = 0;
    long page_size = sysconf(_SC_PAGE_SIZE);
    char stat_path[PATH_MAX];
    long mmap_syscall;

    if ((err = copy_tty_state(pid, pty))) {
        if (err == ENOTTY && !force_stdio) {
            error("Target is not connected to a terminal.\n"
                  "    Use -s to force attaching anyways.");
            return err;
        }
    }

    snprintf(stat_path, sizeof stat_path, "/proc/%d/stat", pid);
    statfd = open(stat_path, O_RDONLY);
    if (statfd < 0) {
        error("Unable to open %s: %s", stat_path, strerror(errno));
        return -statfd;
    }

    kill(pid, SIGTSTP);
    wait_for_stop(pid, statfd);

    if (ptrace_attach_child(&child, pid)) {
        err = child.error;
        goto out_cont;
    }

    if (ptrace_advance_to_state(&child, ptrace_at_syscall)) {
        err = child.error;
        goto out_detach;
    }
    if (ptrace_save_regs(&child)) {
        err = child.error;
        goto out_detach;
    }

    mmap_syscall = ptrace_syscall_numbers(&child)->nr_mmap2;
    if (mmap_syscall == -1)
        mmap_syscall = ptrace_syscall_numbers(&child)->nr_mmap;
    scratch_page = ptrace_remote_syscall(&child, mmap_syscall, 0,
                                         page_size, PROT_READ|PROT_WRITE,
                                         MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);

    if (scratch_page > (unsigned long)-1000) {
        err = -(signed long)scratch_page;
        goto out_unmap;
    }

    debug("Allocated scratch page: %lx", scratch_page);

    if (force_stdio) {
        child_tty_fds = malloc(3 * sizeof(int));
        if (!child_tty_fds) {
            err = ENOMEM;
            goto out_unmap;
        }
        n_fds = 3;
        child_tty_fds[0] = 0;
        child_tty_fds[1] = 1;
        child_tty_fds[2] = 2;
    } else {
        child_tty_fds = get_child_tty_fds(&child, statfd, &n_fds);
        if (!child_tty_fds) {
            err = child.error;
            goto out_unmap;
        }
    }

    if (ptrace_memcpy_to_child(&child, scratch_page, pty, strlen(pty)+1)) {
        err = child.error;
        error("Unable to memcpy the pty path to child.");
        goto out_free_fds;
    }

    child_fd = do_syscall(&child, open,
                          scratch_page, O_RDWR|O_NOCTTY,
                          0, 0, 0, 0);
    if (child_fd < 0) {
        err = child_fd;
        error("Unable to open the tty in the child.");
        goto out_free_fds;
    }

    debug("Opened the new tty in the child: %d", child_fd);

    err = ignore_hup(&child, scratch_page);
    if (err < 0)
        goto out_close;

    err = do_syscall(&child, getsid, 0, 0, 0, 0, 0, 0);
    if (err != child.pid) {
        debug("Target is not a session leader, attempting to setsid.");
        err = do_setsid(&child);
    } else {
        do_syscall(&child, ioctl, child_tty_fds[0], TIOCNOTTY, 0, 0, 0, 0);
    }
    if (err < 0)
        goto out_close;

    err = do_syscall(&child, ioctl, child_fd, TIOCSCTTY, 0, 0, 0, 0);
    if (err < 0) {
        error("Unable to set controlling terminal.");
        goto out_close;
    }

    debug("Set the controlling tty");

    for (i = 0; i < n_fds; i++)
        do_syscall(&child, dup2, child_fd, child_tty_fds[i], 0, 0, 0, 0);


    err = 0;

 out_close:
    do_syscall(&child, close, child_fd, 0, 0, 0, 0, 0);
 out_free_fds:
    free(child_tty_fds);

 out_unmap:
    do_unmap(&child, scratch_page, page_size);

    ptrace_restore_regs(&child);
 out_detach:
    ptrace_detach_child(&child);

    if (err == 0) {
        kill(child.pid, SIGSTOP);
        wait_for_stop(child.pid, statfd);
    }
    kill(child.pid, SIGWINCH);
 out_cont:
    kill(child.pid, SIGCONT);
    close(statfd);

    return err < 0 ? -err : err;
}
