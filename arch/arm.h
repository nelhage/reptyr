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
