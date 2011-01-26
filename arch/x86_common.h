static inline void arch_fixup_regs(struct user *user) {
    user->regs.reg_ip -= 2;
    user->regs.reg_ax = user->regs.orig_ax;
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    return ptrace_command(child, PTRACE_POKEUSER,
                          offsetof(struct user, regs.orig_ax),
                          sysno);
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    child->saved_syscall = child->user.regs.orig_ax;
    return 0;
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return 0;
}
