static inline void arch_fixup_ip(struct user *user) {
    user->regs.reg_ip -= 2;
}
