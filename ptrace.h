#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

enum child_state {
    ptrace_detached = 0,
    ptrace_at_syscall,
    ptrace_after_syscall,
    ptrace_running,
    ptrace_stopped,
    ptrace_exited
};

struct ptrace_child {
    pid_t pid;
    enum child_state state;
    int status;
    int error;
    unsigned long forked_pid;
    struct user user;
    unsigned long saved_syscall;
};

typedef unsigned long child_addr_t;

int ptrace_wait(struct ptrace_child *child);
int ptrace_attach_child(struct ptrace_child *child, pid_t pid);
int ptrace_finish_attach(struct ptrace_child *child, pid_t pid);
int ptrace_detach_child(struct ptrace_child *child);
int ptrace_wait(struct ptrace_child *child);
int ptrace_advance_to_state(struct ptrace_child *child,
                            enum child_state desired);
int ptrace_save_regs(struct ptrace_child *child);
int ptrace_restore_regs(struct ptrace_child *child);
unsigned long ptrace_remote_syscall(struct ptrace_child *child,
                                    unsigned long sysno,
                                    unsigned long p0, unsigned long p1,
                                    unsigned long p2, unsigned long p3,
                                    unsigned long p4, unsigned long p5);

int ptrace_memcpy_to_child(struct ptrace_child *, child_addr_t, const void*, size_t);
int ptrace_memcpy_from_child(struct ptrace_child *, void*, child_addr_t, size_t);
