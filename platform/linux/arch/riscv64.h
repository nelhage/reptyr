/*
 * Copyright (C) 2021 by Ast-x64
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
static struct ptrace_personality arch_personality[1] = {
    {
        offsetof(struct user_regs_struct, a0),
        offsetof(struct user_regs_struct, a0),
        offsetof(struct user_regs_struct, a1),
        offsetof(struct user_regs_struct, a2),
        offsetof(struct user_regs_struct, a3),
        offsetof(struct user_regs_struct, a4),
        offsetof(struct user_regs_struct, a5),
        offsetof(struct user_regs_struct, pc),
    }
};

static inline void arch_fixup_regs(struct ptrace_child *child) {
    child->regs.pc -= 4;
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    unsigned long x_reg[18];
    struct iovec reg_iovec = {
        .iov_base = x_reg,
        .iov_len = sizeof(x_reg)
    };
    if (ptrace_command(child, PTRACE_GETREGSET, NT_PRSTATUS, &reg_iovec) < 0)
        return -1;

    x_reg[17] = sysno;
    return ptrace_command(child, PTRACE_SETREGSET, NT_PRSTATUS, &reg_iovec);
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    unsigned long x_reg[18];
    struct iovec reg_iovec = {
        .iov_base = x_reg,
        .iov_len = sizeof(x_reg)
    };
    if (ptrace_command(child, PTRACE_GETREGSET, NT_PRSTATUS, &reg_iovec) < 0)
        return -1;

    child->saved_syscall = x_reg[17];
    return 0;
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return arch_set_syscall(child, child->saved_syscall);
}
