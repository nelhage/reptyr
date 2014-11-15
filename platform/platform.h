#ifndef PLATFORM_H
#define PLATFORM_H

#include "linux/linux.h"
#include "freebsd/freebsd.h"
#include "../ptrace.h"

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
    int master_fd;

    char tmpdir[PATH_MAX];
    union {
        struct sockaddr addr;
        struct sockaddr_un addr_un;
    };
    int sockfd;

    struct ptrace_child child;
    unsigned long child_scratch;
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
