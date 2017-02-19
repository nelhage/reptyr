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
#include <stdint.h>
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
#include <sys/socket.h>
#include <sys/un.h>

#include "ptrace.h"
#include "reptyr.h"
#include "reallocarray.h"
#include "platform/platform.h"

int fd_array_push(struct fd_array *fda, int fd) {
    int *tmp;

    if (fda->n == fda->allocated) {
        fda->allocated = fda->allocated ? 2 * fda->allocated : 2;
        tmp = xreallocarray(fda->fds, fda->allocated, sizeof *tmp);
        if (tmp == NULL) {
            free(fda->fds);
            fda->fds = NULL;
            fda->allocated = 0;
            return -1;
        }
        fda->fds = tmp;
    }
    fda->fds[fda->n++] = fd;
    return 0;
}

static void do_unmap(struct ptrace_child *child, child_addr_t addr, unsigned long len) {
    if (addr == (child_addr_t) - 1)
        return;
    do_syscall(child, munmap, (unsigned long)addr, len, 0, 0, 0, 0);
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
    copy_user(&dummy, child);
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
    //ptrace_wait(&dummy);
    do_syscall(child, wait4, dummy.pid, 0, WNOHANG, 0, 0, 0);
    return err;
}

int ignore_hup(struct ptrace_child *child, child_addr_t scratch_page) {
    int err;

    struct sigaction act = {
        .sa_handler = SIG_IGN,
    };
    err = ptrace_memcpy_to_child(child, scratch_page,
                                 &act, sizeof act);
    if (err < 0)
        return err;
    err = do_syscall(child, rt_sigaction,
                     SIGHUP, (unsigned long)scratch_page,
                     0, 8, 0, 0);

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
        if (check_proc_stopped(pid, fd))
            break;

        sleep.tv_sec  = 0;
        sleep.tv_nsec = 10000000;
        nanosleep(&sleep, NULL);
    }
}

int copy_tty_state(pid_t pid, const char *pty) {
    int fd, err = EINVAL;
    struct termios tio;

    err = get_process_tty_termios(pid, &tio);

    if (err)
        return err;

    if ((fd = open(pty, O_RDONLY)) < 0)
        return -assert_nonzero(errno);

    if (tcsetattr(fd, TCSANOW, &tio) < 0)
        err = assert_nonzero(errno);
    close(fd);
    return -err;
}

int mmap_scratch(struct ptrace_child *child, child_addr_t *addr) {
    long mmap_syscall;
    child_addr_t scratch_page;

    mmap_syscall = ptrace_syscall_numbers(child)->nr_mmap2;
    if (mmap_syscall == -1)
        mmap_syscall = ptrace_syscall_numbers(child)->nr_mmap;
    scratch_page = ptrace_remote_syscall(child, mmap_syscall, 0,
                                         sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE,
                                         MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    //MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if (scratch_page > (unsigned long) - 1000) {
        return -(signed long)scratch_page;
    }

    *addr = scratch_page;
    debug("Allocated scratch page: %lx", scratch_page);

    return 0;
}

int grab_pid(pid_t pid, struct ptrace_child *child, child_addr_t *scratch) {
    int err;

    if (ptrace_attach_child(child, pid)) {
        err = child->error;
        goto out;
    }
    if (ptrace_advance_to_state(child, ptrace_at_syscall)) {
        err = child->error;
        goto out;
    }
    if (ptrace_save_regs(child)) {
        err = child->error;
        goto out;
    }

    if ((err = mmap_scratch(child, scratch)))
        goto out_restore_regs;

    return 0;

out_restore_regs:
    ptrace_restore_regs(child);

out:
    ptrace_detach_child(child);

    return err;
}

int preflight_check(pid_t pid) {
    struct ptrace_child child;
    debug("Making sure we have permission to attach...");
    if (ptrace_attach_child(&child, pid)) {
        return child.error;
    }
    ptrace_detach_child(&child);
    return 0;
}

int attach_child(pid_t pid, const char *pty, int force_stdio) {
    struct ptrace_child child;
    child_addr_t scratch_page = -1;
    int *child_tty_fds = NULL, n_fds, child_fd, statfd = -1;
    int i;
    int err = 0;
    long page_size = sysconf(_SC_PAGE_SIZE);
#ifdef __linux__
    char stat_path[PATH_MAX];
#endif

    if ((err = check_pgroup(pid))) {
        return err;
    }

    if ((err = preflight_check(pid))) {
        return err;
    }

    debug("Using tty: %s", pty);

    if ((err = copy_tty_state(pid, pty))) {
        if (err == ENOTTY && !force_stdio) {
            error("Target is not connected to a terminal.\n"
                  "    Use -s to force attaching anyways.");
            return err;
        }
    }

#ifdef __linux__
    snprintf(stat_path, sizeof stat_path, "/proc/%d/stat", pid);
    statfd = open(stat_path, O_RDONLY);
    if (statfd < 0) {
        error("Unable to open %s: %s", stat_path, strerror(errno));
        return -statfd;
    }
#endif

    kill(pid, SIGTSTP);
    wait_for_stop(pid, statfd);

    if ((err = grab_pid(pid, &child, &scratch_page))) {
        goto out_cont;
    }

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

    if (ptrace_memcpy_to_child(&child, scratch_page, pty, strlen(pty) + 1)) {
        err = child.error;
        error("Unable to memcpy the pty path to child.");
        goto out_free_fds;
    }

    child_fd = do_syscall(&child, open,
                          scratch_page, O_RDWR | O_NOCTTY,
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

    err = do_syscall(&child, ioctl, child_fd, TIOCSCTTY, 1, 0, 0, 0);
    if (err != 0) { /* Seems to be returning >0 for error */
        error("Unable to set controlling terminal: %s", strerror(err));
        goto out_close;
    }

    debug("Set the controlling tty");

    for (i = 0; i < n_fds; i++) {
        err = do_syscall(&child, dup2, child_fd, child_tty_fds[i], 0, 0, 0, 0);
        if (err < 0)
            error("Problem moving child fd number %d to new tty: %s", child_tty_fds[i], strerror(errno));
    }


    err = 0;

out_close:
    do_syscall(&child, close, child_fd, 0, 0, 0, 0, 0);
out_free_fds:
    free(child_tty_fds);

out_unmap:
    do_unmap(&child, scratch_page, page_size);

    ptrace_restore_regs(&child);
    ptrace_detach_child(&child);

    if (err == 0) {
        kill(child.pid, SIGSTOP);
        wait_for_stop(child.pid, statfd);
    }
    kill(child.pid, SIGWINCH);
out_cont:
    kill(child.pid, SIGCONT);
#ifdef __linux__
    close(statfd);
#endif

    return err < 0 ? -err : err;
}

int setup_steal_socket(struct steal_pty_state *steal) {
    strcpy(steal->tmpdir, "/tmp/reptyr.XXXXXX");
    if (mkdtemp(steal->tmpdir) == NULL)
        return errno;

    steal->addr_un.sun_family = AF_UNIX;
    if (snprintf(steal->addr_un.sun_path, sizeof(steal->addr_un.sun_path),
                 "%s/reptyr.sock", steal->tmpdir) >= sizeof(steal->addr_un.sun_path)) {
        error("tmpdir path too long!");
        return ENAMETOOLONG;
    }

    if ((steal->sockfd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
        return errno;

    if (bind(steal->sockfd, &steal->addr, sizeof(steal->addr_un)) < 0)
        return errno;

    if (chown(steal->addr_un.sun_path, steal->emulator_uid, -1) < 0)
        debug("chown %s: %s", steal->addr_un.sun_path, strerror(errno));
    if (chown(steal->tmpdir, steal->emulator_uid, -1) < 0)
        debug("chown %s: %s", steal->tmpdir, strerror(errno));

    return 0;
}

int setup_steal_socket_child(struct steal_pty_state *steal) {
    int err;
    err = do_socketcall(&steal->child,
                        steal->child_scratch + sysconf(_SC_PAGE_SIZE)/2,
                        socket, AF_UNIX, SOCK_DGRAM, 0, 0, 0);
    if (err < 0)
        return -err;
    steal->child_fd = err;
    debug("Opened fd %d in the child.", steal->child_fd);
    err = ptrace_memcpy_to_child(&steal->child, steal->child_scratch,
                                 &steal->addr_un, sizeof(steal->addr_un));
    if (err < 0)
        return steal->child.error;
    err = do_socketcall(&steal->child,
                        steal->child_scratch + sysconf(_SC_PAGE_SIZE)/2,
                        connect, steal->child_fd, steal->child_scratch,
                        sizeof(steal->addr_un), 0, 0);
    if (err < 0)
        return -err;
    debug("Connected to the shared socket.");
    return 0;
}

int steal_child_pty(struct steal_pty_state *steal) {
    struct {
        struct msghdr msg;
        unsigned char buf[CMSG_SPACE(sizeof(int))];
    } buf = {};
    struct cmsghdr *cm;
    int err;

    buf.msg.msg_control = buf.buf;
    buf.msg.msg_controllen = CMSG_SPACE(sizeof(int));
    cm = CMSG_FIRSTHDR(&buf.msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type  = SCM_RIGHTS;
    cm->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &steal->master_fds.fds[0], sizeof(int));
    buf.msg.msg_controllen = cm->cmsg_len;

    // Relocate for the child
    buf.msg.msg_control = (void*)(steal->child_scratch +
                                  ((uint8_t*)buf.msg.msg_control - (uint8_t*)&buf));

    if (ptrace_memcpy_to_child(&steal->child,
                               steal->child_scratch,
                               &buf, sizeof(buf))) {
        return steal->child.error;
    }

    steal->child.error = 0;
    err = do_socketcall(&steal->child,
                        steal->child_scratch + sysconf(_SC_PAGE_SIZE)/2,
                        sendmsg,
                        steal->child_fd,
                        steal->child_scratch,
                        MSG_DONTWAIT, 0, 0);
    if (err < 0) {
        return steal->child.error ? steal->child.error : -err;
    }

    debug("Sent the pty fd, going to receive it.");

    buf.msg.msg_control = buf.buf;
    buf.msg.msg_controllen = CMSG_SPACE(sizeof(int));

    err = recvmsg(steal->sockfd, &buf.msg, MSG_DONTWAIT);
    if (err < 0) {
        error("Error receiving message.");
        return errno;
    }

    debug("Got a message: %d bytes, %ld control",
          err, (long)buf.msg.msg_controllen);

    if (buf.msg.msg_controllen < CMSG_LEN(sizeof(int))) {
        error("No fd received?");
        return EINVAL;
    }

    memcpy(&steal->ptyfd, CMSG_DATA(cm), sizeof(steal->ptyfd));

    debug("Got tty fd: %d", steal->ptyfd);

    return 0;
}

// Attach to the session leader of the stolen session, and block
// SIGHUP so that if and when the terminal emulator tries to HUP it,
// it doesn't die.
int steal_block_hup(struct steal_pty_state *steal) {
    struct ptrace_child leader;
    child_addr_t scratch = 0;
    int err = 0;

    if ((err = grab_pid(steal->target_stat.sid, &leader, &scratch)))
        return err;

    err = ignore_hup(&leader, scratch);

    ptrace_restore_regs(&leader);
    ptrace_detach_child(&leader);

    return err;
}

int steal_cleanup_child(struct steal_pty_state *steal) {
    if (ptrace_memcpy_to_child(&steal->child,
                               steal->child_scratch,
                               "/dev/null", sizeof("/dev/null"))) {
        return steal->child.error;
    }

    int nullfd = do_syscall(&steal->child, open, steal->child_scratch, O_RDWR, 0, 0, 0, 0);
    if (nullfd < 0) {
        return steal->child.error;
    }

    int i;
    for (i = 0; i < steal->master_fds.n; ++i) {
        do_syscall(&steal->child, dup2, nullfd, steal->master_fds.fds[i], 0, 0, 0, 0);
    }

    do_syscall(&steal->child, close, nullfd, 0, 0, 0, 0, 0);
    do_syscall(&steal->child, close, steal->child_fd, 0, 0, 0, 0, 0);

    steal->child_fd = 0;

    ptrace_restore_regs(&steal->child);

    ptrace_detach_child(&steal->child);
    ptrace_wait(&steal->child);
    return 0;
}

int steal_pty(pid_t pid, int *pty) {
    int err = 0;
    struct steal_pty_state steal = {};
    long page_size = sysconf(_SC_PAGE_SIZE);

    if ((err = preflight_check(pid)))
        goto out;

    if ((err = get_terminal_state(&steal, pid)))
        goto out;

    if ((err = setup_steal_socket(&steal)))
        goto out;

    debug("Listening on socket: %s", steal.addr_un.sun_path);

    if ((err = grab_pid(steal.emulator_pid, &steal.child, &steal.child_scratch)))
        goto out;

    debug("Attached to terminal emulator (pid %d)",
          (int)steal.emulator_pid);

    if ((err = find_master_fd(&steal))) {
        error("Unable to find the fd for the pty!");
        goto out;
    }

    if ((err = setup_steal_socket_child(&steal)))
        goto out;

    if ((err = steal_child_pty(&steal)))
        goto out;

    if ((err = steal_block_hup(&steal)))
        goto out;

    if ((err = steal_cleanup_child(&steal)))
        goto out;

    goto out_no_child;

out:
    if (steal.ptyfd) {
        close(steal.ptyfd);
        steal.ptyfd = 0;
    }

    if (steal.child_fd > 0)
        do_syscall(&steal.child, close, steal.child_fd, 0, 0, 0, 0, 0);

    if (steal.child_scratch > 0)
        do_unmap(&steal.child, steal.child_scratch, page_size);

    if (steal.child.state != ptrace_detached) {
        ptrace_restore_regs(&steal.child);
        ptrace_detach_child(&steal.child);
    }

out_no_child:

    if (steal.sockfd > 0) {
        close(steal.sockfd);
        unlink(steal.addr_un.sun_path);
    }

    if (steal.tmpdir[0]) {
        rmdir(steal.tmpdir);
    }

    if (steal.ptyfd)
        *pty = steal.ptyfd;

    free(steal.master_fds.fds);

    return err;
}
