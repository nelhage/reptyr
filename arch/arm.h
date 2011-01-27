#define reg_ip ARM_pc

#define syscall_rv   uregs[0]
#define syscall_arg0 uregs[0]
#define syscall_arg1 uregs[1]
#define syscall_arg2 uregs[2]
#define syscall_arg3 uregs[3]
#define syscall_arg4 uregs[4]
#define syscall_arg5 uregs[5]

static inline void arch_fixup_regs(struct user *user) {
    user->regs.reg_ip -= 4;
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    return ptrace_command(child, PTRACE_SET_SYSCALL, 0, sysno);
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    unsigned long swi;
    swi = ptrace_command(child, PTRACE_PEEKTEXT, child->user.regs.reg_ip);
    if (child->error)
        return -1;
    if (swi == 0xef000000)
        child->saved_syscall = child->user.regs.uregs[7];
    else
        child->saved_syscall = (swi & 0x000fffff);
    return 0;
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return arch_set_syscall(child, child->saved_syscall);
}
