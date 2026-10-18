/*
 * Copyright (c) 2026, Piotr Kubaj. All rights reserved.
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

/*
 * FreeBSD/powerpc64 (ELFv1 and ELFv2, either endianness): the system call
 * number goes in r0, the arguments in r3-r10 and the result comes back in
 * r3, so all six arguments reptyr passes fit in registers.
 */
static struct ptrace_personality arch_personality[1] = {
    {
        offsetof(struct reg, fixreg[3]),
        offsetof(struct reg, fixreg[3]),
        offsetof(struct reg, fixreg[4]),
        offsetof(struct reg, fixreg[5]),
        offsetof(struct reg, fixreg[6]),
        offsetof(struct reg, fixreg[7]),
        offsetof(struct reg, fixreg[8]),
        offsetof(struct reg, pc),
        offsetof(struct reg, fixreg[1]),
    }
};

#define ptr(regs, off) ((unsigned long*)((void*)(regs)+(off)))

static inline void arch_fixup_regs(struct ptrace_child *child, struct reg *regs) {
    /* SRR0 already points past the 4-byte sc instruction. */
    regs->pc -= 4;
}

static inline void arch_set_register(struct ptrace_child *child, unsigned long oft, unsigned long val)
{
    struct reg regs;

    (void)ptrace_command(child, PT_GETREGS, &regs);
    *ptr(&regs, oft) = val;
    (void)ptrace_command(child, PT_SETREGS, &regs);
}

static inline void arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    arch_set_register(child, offsetof(struct reg, fixreg[0]), sysno);
}

#undef ptr
