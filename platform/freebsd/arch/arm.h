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

#include <machine/armreg.h>

static struct ptrace_personality arch_personality[1] = {
    {
        offsetof(struct reg, r[0]),
        offsetof(struct reg, r[0]),
        offsetof(struct reg, r[1]),
        offsetof(struct reg, r[2]),
        offsetof(struct reg, r[3]),
        ~0UL,	/* Spill to stack */
        ~0UL,	/* Spill to stack */
        offsetof(struct reg, r_pc),
        offsetof(struct reg, r_sp),
    }
};

#define ptr(regs, off) ((unsigned long*)((void*)(regs)+(off)))

static inline void arch_fixup_regs(struct ptrace_child *child) {
    if ((child->regs.r_cpsr & PSR_T) != 0)
        child->regs.r_pc -= THUMB_INSN_SIZE;
    else
        child->regs.r_pc -= INSN_SIZE;
}

static inline void arch_set_register(struct ptrace_child *child, unsigned long oft, unsigned long val)
{
    struct reg regs;

    (void)ptrace_command(child, PT_GETREGS, &regs);
    *ptr(&regs, oft) = val;
    (void)ptrace_command(child, PT_SETREGS, &regs);
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    arch_set_register(child, offsetof(struct reg, r[7]), sysno);
    return 0;
}

#undef ptr
