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

#include "ptrace.h"
#include "reptyr.h"

static void do_unmap(struct ptrace_child *child, child_addr_t addr, int pages) {
    if (addr == (unsigned long)-1)
        return;
    ptrace_remote_syscall(child, __NR_munmap, addr, pages, 0, 0, 0, 0);
}

int *get_child_tty_fds(struct ptrace_child *child, int *count) {
    char buf[PATH_MAX];
    char child_tty[PATH_MAX];
    int n = 0, allocated = 0;
    int *fds = NULL;
    DIR *dir;
    ssize_t len;
    struct dirent *d;

    debug("Looking up fds for tty in child.");
    snprintf(buf, sizeof buf, "/proc/%d/fd/0", child->pid);
    len = readlink(buf, child_tty, PATH_MAX);
    if(len < 0)
        return NULL;

    child_tty[len] = 0;
    debug("Resolved child tty: %s", child_tty);

    snprintf(buf, sizeof buf, "/proc/%d/fd/", child->pid);
    if ((dir = opendir(buf)) == NULL)
        return NULL;
    while ((d = readdir(dir)) != NULL) {
        if (d->d_name[0] == '.') continue;
        snprintf(buf, sizeof buf, "/proc/%d/fd/%s", child->pid, d->d_name);
        len = readlink(buf, buf, PATH_MAX);
        if (len < 0)
            continue;
        buf[len] = 0;
        if (strcmp(buf, child_tty) == 0
            || strcmp(buf, "/dev/tty") == 0) {
            if (n == allocated) {
                allocated = allocated ? 2 * allocated : 2;
                fds = realloc(fds, sizeof(int) * allocated);
                if (!fds)
                    goto out;
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

void move_process_group(struct ptrace_child *from, pid_t to) {
    DIR *dir;
    struct dirent *d;
    pid_t pid;
    char *p;
    int err;

    if ((dir = opendir("/proc/")) == NULL)
        return;

    while ((d = readdir(dir)) != NULL) {
        if(d->d_name[0] == '.') continue;
        pid = strtol(d->d_name, &p, 10);
        if (*p) continue;
        if (getpgid(pid) == from->pid) {
            debug("Change pgid for pid %d", pid);
            err = ptrace_remote_syscall(from, __NR_setpgid,
                                        pid, to,
                                        0, 0, 0, 0);
            if (err < 0)
                error(" failed: %s", strerror(-err));
        }
    }
    closedir(dir);
}

int attach_child(pid_t pid, const char *pty) {
    struct ptrace_child child;
    unsigned long scratch_page = -1;
    int *child_tty_fds = NULL, n_fds, child_fd;
    int i;
    int err = 0;
    struct ptrace_child dummy;


    if (ptrace_attach_child(&child, pid))
        return child.error;

    if (ptrace_advance_to_state(&child, ptrace_at_syscall)) {
        err = child.error;
        goto out_detach;
    }
    if (ptrace_save_regs(&child)) {
        err = child.error;
        goto out_detach;
    }

    scratch_page = ptrace_remote_syscall(&child, mmap_syscall, 0,
                                         PAGE_SIZE, PROT_READ|PROT_WRITE,
                                         MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);

    if (scratch_page > (unsigned long)-1000) {
        err = -(signed long)scratch_page;
        goto out_unmap;
    }

    debug("Allocated scratch page: %lx", scratch_page);

    child_tty_fds = get_child_tty_fds(&child, &n_fds);
    if (!child_tty_fds) {
        err = child.error;
        goto out_unmap;
    }

    if (ptrace_memcpy_to_child(&child, scratch_page, pty, strlen(pty)+1)) {
        err = child.error;
        goto out_free_fds;
    }

    child_fd = ptrace_remote_syscall(&child, __NR_open,
                                     scratch_page, O_RDWR|O_NOCTTY,
                                     0, 0, 0, 0);
    if (child_fd < 0) {
        err = child_fd;
        goto out_free_fds;
    }

    debug("Opened the new tty in the child: %d", child_fd);

    err = ptrace_remote_syscall(&child, __NR_ioctl,
                                child_tty_fds[0], TCGETS, scratch_page,
                                0, 0, 0);
    debug("TCGETS(%d): %d", child_tty_fds[0], err);
    if(err < 0)
        goto out_close;
    err = ptrace_remote_syscall(&child, __NR_ioctl,
                                child_fd, TCSETS, scratch_page,
                                0, 0, 0);
    debug("TCSETS: %d", err);
    if (err < 0)
        goto out_close;

    debug("Copied terminal settings");

    err = ptrace_remote_syscall(&child, __NR_fork,
                                 0, 0, 0, 0, 0, 0);
    if (err < 0)
        goto out_close;

    debug("Forked a child: %d", child.forked_pid);

    err = ptrace_finish_attach(&dummy, child.forked_pid);
    if (err < 0)
        goto out_kill;

    dummy.state = ptrace_after_syscall;
    memcpy(&dummy.user, &child.user, sizeof child.user);
    if (ptrace_restore_regs(&dummy)) {
        err = dummy.error;
        goto out_kill;
    }

    err = ptrace_remote_syscall(&dummy, __NR_setpgid,
                                0, 0, 0, 0, 0, 0);
    if (err < 0) {
        error("Failed to setpgid: %s", strerror(-err));
        goto out_kill;
    }

    move_process_group(&child, dummy.pid);

    err = ptrace_remote_syscall(&child, __NR_setsid,
                                0, 0, 0, 0, 0, 0);
    if (err < 0) {
        error("Failed to setsid: %s", strerror(-err));
        goto out_kill;
    }

    debug("Did setsid()");

    err = ptrace_remote_syscall(&child, __NR_ioctl,
                                child_fd, TIOCSCTTY,
                                0, 0, 0, 0);
    if (err < 0)
        goto out_kill;

    debug("Set the controlling tty");

    for (i = 0; i < n_fds; i++)
        ptrace_remote_syscall(&child, __NR_dup2,
                              child_fd, child_tty_fds[i],
                              0, 0, 0, 0);

#ifdef __NR_signal
    ptrace_remote_syscall(&child, __NR_signal,
                          SIGHUP, (unsigned long)SIG_IGN,
                          0, 0, 0, 0);
#else
    {
        struct sigaction act = {
            .sa_handler = SIG_IGN,
        };
        err = ptrace_memcpy_to_child(&child, scratch_page,
                                     &act, sizeof act);
        if (err < 0)
            goto out_kill;
        err = ptrace_remote_syscall(&child, __NR_rt_sigaction,
                                    SIGHUP, scratch_page,
                                    0, 8, 0, 0);
        if (err < 0)
            goto out_kill;
        
    }
#endif

    err = 0;

 out_kill:
    kill(dummy.pid, SIGKILL);
    ptrace_wait(&dummy);
    ptrace_remote_syscall(&child, __NR_waitid,
                          P_PID, dummy.pid, 0, WNOHANG,
                          0, 0);

 out_close:
    ptrace_remote_syscall(&child, __NR_close, child_fd,
                          0, 0, 0, 0, 0);
 out_free_fds:
    free(child_tty_fds);

 out_unmap:
    do_unmap(&child, scratch_page, 1);

    ptrace_restore_regs(&child);
 out_detach:
    ptrace_detach_child(&child);

    if (err == 0)
        kill(child.pid, SIGWINCH);

    return err < 0 ? -err : err;
}
