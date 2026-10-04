static struct ptrace_personality arch_personality[1] = {
    {
        offsetof(struct user_regs_struct, regs[4]),
        offsetof(struct user_regs_struct, regs[4]),
        offsetof(struct user_regs_struct, regs[5]),
        offsetof(struct user_regs_struct, regs[6]),
        offsetof(struct user_regs_struct, regs[7]),
        offsetof(struct user_regs_struct, regs[8]),
        offsetof(struct user_regs_struct, regs[9]),
        offsetof(struct user_regs_struct, csr_era),
    }
};

static inline void arch_fixup_regs(struct ptrace_child *child) {
    child->regs.csr_era -= 4;
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    struct user_regs_struct regs;
    struct iovec reg_iovec = {
        .iov_base = &regs,
        .iov_len = sizeof(regs)
    };
    if (ptrace_command(child, PTRACE_GETREGSET, NT_PRSTATUS, &reg_iovec) < 0)
        return -1;

    regs.regs[11] = sysno;
    return ptrace_command(child, PTRACE_SETREGSET, NT_PRSTATUS, &reg_iovec);
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    struct user_regs_struct regs;
    struct iovec reg_iovec = {
        .iov_base = &regs,
        .iov_len = sizeof(regs)
    };
    if (ptrace_command(child, PTRACE_GETREGSET, NT_PRSTATUS, &reg_iovec) < 0)
        return -1;

    child->saved_syscall = regs.regs[11];
    return 0;
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return arch_set_syscall(child, child->saved_syscall);
}
