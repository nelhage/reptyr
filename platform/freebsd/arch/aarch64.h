/*
 * Copyright (C) 2011 by Nelson Elhage
 * Copyright (C) 2023 Kyle Evans <kevans@FreeBSD.org>
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
        offsetof(struct reg, x[0]),
        offsetof(struct reg, x[0]),
        offsetof(struct reg, x[1]),
        offsetof(struct reg, x[2]),
        offsetof(struct reg, x[3]),
        offsetof(struct reg, x[4]),
        offsetof(struct reg, x[5]),
        offsetof(struct reg, elr),
    }
};

#define ptr(regs, off) ((unsigned long*)((void*)(regs)+(off)))

static inline void arch_fixup_regs(struct ptrace_child *child) {
    child->regs.elr -= 4;
}

static inline void arch_set_register(struct ptrace_child *child, unsigned long oft, unsigned long val)
{
    struct reg regs;

    (void)ptrace_command(child, PT_GETREGS, &regs);
    *ptr(&regs, oft) = val;
    (void)ptrace_command(child, PT_SETREGS, &regs);
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    child->saved_syscall = child->regs.x[0];
    return 0;
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    arch_set_register(child, offsetof(struct reg, x[8]), sysno);
    return 0;
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return 0;
}

#undef ptr
