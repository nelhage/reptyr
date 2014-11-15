#ifdef __linux__

#include "linux.h"
#include "../platform.h"

int parse_proc_stat(int statfd, struct proc_stat *out) {
    char buf[1024];
    int n;
    unsigned dev;
    lseek(statfd, 0, SEEK_SET);
    if (read(statfd, buf, sizeof buf) < 0)
        return assert_nonzero(errno);
    n = sscanf(buf, "%d (%16[^)]) %c %d %d %d %u",
               &out->pid, out->comm,
               &out->state, &out->ppid, &out->pgid,
               &out->sid, &dev);
    if (n == EOF)
        return assert_nonzero(errno);
    if (n != 7) {
        return EINVAL;
    }
    out->ctty = dev;
    return 0;
}

int read_proc_stat(pid_t pid, struct proc_stat *out) {
    char stat_path[PATH_MAX];
    int statfd;
    int err;

    snprintf(stat_path, sizeof stat_path, "/proc/%d/stat", pid);
    statfd = open(stat_path, O_RDONLY);
    if (statfd < 0) {
        error("Unable to open %s: %s", stat_path, strerror(errno));
        return -statfd;
    }

    err = parse_proc_stat(statfd, out);
    close(statfd);
    return err;
}

// Find the PID of the terminal emulator for `target's terminal.
//
// We assume that the terminal emulator is the parent of the session
// leader. This is true in most cases, although in principle you can
// construct situations where it is false. We should fail safe later
// on if this turns out to be wrong, however.
int find_terminal_emulator(struct steal_pty_state *steal) {
    debug("session leader of pid %d = %d",
          (int)steal->target_stat.pid,
          (int)steal->target_stat.sid);
    struct proc_stat leader_st;
    int err;
    if ((err = read_proc_stat(steal->target_stat.sid, &leader_st)))
        return err;
    debug("found terminal emulator process: %d", (int) leader_st.ppid);
    steal->emulator_pid = leader_st.ppid;
    return 0;
}

void check_ptrace_scope(void) {
    int fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        int n;
        n = read(fd, buf, sizeof buf);
        close(fd);
        if (n > 0) {
            if (!atoi(buf)) {
                return;
            }
        }
    } else if (errno == ENOENT)
        return;
    fprintf(stderr, "The kernel denied permission while attaching. If your uid matches\n");
    fprintf(stderr, "the target's, check the value of /proc/sys/kernel/yama/ptrace_scope.\n");
    fprintf(stderr, "For more information, see /etc/sysctl.d/10-ptrace.conf\n");
}

int check_pgroup(pid_t target) {
    pid_t pg;
    DIR *dir;
    struct dirent *d;
    pid_t pid;
    char *p;
    int err = 0;
    struct proc_stat pid_stat;

    debug("Checking for problematic process group members...");

    pg = getpgid(target);
    if (pg < 0) {
        error("Unable to get pgid for pid %d", (int)target);
        return errno;
    }

    if ((dir = opendir("/proc/")) == NULL)
        return assert_nonzero(errno);

    while ((d = readdir(dir)) != NULL) {
        if (d->d_name[0] == '.') continue;
        pid = strtol(d->d_name, &p, 10);
        if (*p) continue;
        if (pid == target) continue;
        if (getpgid(pid) == pg) {
            /*
             * We are actually being somewhat overly-conservative here
             * -- if pid is a child of target, and has not yet called
             * execve(), reptyr's setpgid() strategy may suffice. That
             * is a fairly rare case, and annoying to check for, so
             * for now let's just bail out.
             */
            if ((err = read_proc_stat(pid, &pid_stat))) {
                memcpy(pid_stat.comm, "???", 4);
            }
            error("Process %d (%.*s) shares %d's process group. Unable to attach.\n"
                  "(This most commonly means that %d has suprocesses).",
                  (int)pid, TASK_COMM_LENGTH, pid_stat.comm, (int)target, (int)target);
            err = EINVAL;
            goto out;
        }
    }
 out:
    closedir(dir);
    return err;
}

int check_proc_stopped(pid_t pid, int fd){
    struct proc_stat st;

	if (parse_proc_stat(fd, &st))
		return 1;

	if (st.state == 'T')
		return 1;

	return 0;
}

int *get_child_tty_fds(struct ptrace_child *child, int statfd, int *count) {
    struct proc_stat child_status;
    struct stat tty_st, console_st, st;
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
        child->error = assert_nonzero(errno);
        error("Unable to stat /dev/tty");
        return NULL;
    }

    if (stat("/dev/console", &console_st) < 0) {
        child->error = errno;
        error("Unable to stat /dev/console");
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
            || st.st_rdev == tty_st.st_rdev
            || st.st_rdev == console_st.st_rdev) {
            if (n == allocated) {
                allocated = allocated ? 2 * allocated : 2;
                tmp = xreallocarray(fds, allocated, sizeof *tmp);
                if (tmp == NULL) {
                  child->error = assert_nonzero(errno);
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

int get_terminal_state(struct steal_pty_state *steal, pid_t target) {
    int err;

    if ((err = read_proc_stat(target, &steal->target_stat)))
        return err;

    if (major(steal->target_stat.ctty) != UNIX98_PTY_SLAVE_MAJOR) {
        error("Child is not connected to a pseudo-TTY. Unable to steal TTY.");
        return EINVAL;
    }

    if ((err = find_terminal_emulator(steal)))
        return err;

    return 0;
}

// ptmx(4) and Linux Documentation/devices.txt document
// /dev/ptmx has having major 5 and minor 2. I can't find any
// constants in headers after a brief glance that I should be
// using here.
#define PTMX_DEVICE (makedev(5, 2))

// Find the fd in the terminal emulator process that corresponds to
// the master side of the target's pty. Store the result in
// steal->master_fd.
int find_master_fd(struct steal_pty_state *steal) {
    DIR *dir;
    struct dirent *d;
    struct stat st;
    int err;
    char buf[PATH_MAX];

    snprintf(buf, sizeof buf, "/proc/%d/fd/", steal->child.pid);
    if ((dir = opendir(buf)) == NULL)
        return errno;
    while ((d = readdir(dir)) != NULL) {
        if (d->d_name[0] == '.') continue;
        snprintf(buf, sizeof buf, "/proc/%d/fd/%s", steal->child.pid, d->d_name);
        if (stat(buf, &st) < 0)
            continue;

        debug("Checking fd: %s: st_dev=%x", d->d_name, (int)st.st_rdev);

        if (st.st_rdev != PTMX_DEVICE)
            continue;

        debug("found a ptmx fd: %s", d->d_name);
        err = do_syscall(&steal->child, ioctl,
                         atoi(d->d_name),
                         TIOCGPTN,
                         steal->child_scratch,
                         0, 0, 0);
        if (err < 0) {
            debug(" error doing TIOCGPTN: %s", strerror(-err));
            continue;
        }
        int ptn;
        err = ptrace_memcpy_from_child(&steal->child, &ptn,
                                       steal->child_scratch, sizeof(ptn));
        if (err < 0) {
            debug(" error getting ptn: %s", strerror(steal->child.error));
            continue;
        }
        if (ptn == (int)minor(steal->target_stat.ctty)) {
            debug("found the master fd: %d", atoi(d->d_name));
            steal->master_fd = atoi(d->d_name);
            return 0;
        }
    }

    return ESRCH;
}

/* Homebrew posix_openpt() */
int get_pt(){
	return open("/dev/ptmx", O_RDWR|O_NOCTTY);
}

int get_process_tty_termios(pid_t pid, struct termios *tio){
    int i;
	int err=EINVAL;

    for (i = 0; i < 3 && err; i++) {
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

        if (tcgetattr(fd, tio) < 0) {
            err = -assert_nonzero(errno);
        }
    retry:
        close(fd);
    }

	return err;
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

void copy_user(struct ptrace_child *d, struct ptrace_child *s){
	memcpy(&d->user,&s->user,sizeof(s->user));
}

#endif
