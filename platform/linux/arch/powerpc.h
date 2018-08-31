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

static struct ptrace_personality arch_personality[1] = {
    {
        offsetof(struct user, regs.gpr[3]),
        offsetof(struct user, regs.gpr[3]),
        offsetof(struct user, regs.gpr[4]),
        offsetof(struct user, regs.gpr[5]),
        offsetof(struct user, regs.gpr[6]),
        offsetof(struct user, regs.gpr[7]),
        offsetof(struct user, regs.gpr[8]),
        offsetof(struct user, regs.nip),
    }
};

static const unsigned long r0off = offsetof(struct user, regs.gpr[0]);
#define ptr(user, off) ((unsigned long*)((void*)(user)+(off)))

static inline void arch_fixup_regs(struct ptrace_child *child) {
    child->user.regs.nip -= 4;
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    return ptrace_command(child, PTRACE_POKEUSER, r0off, sysno);
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    child->saved_syscall = *ptr(&child->user, r0off);
    return 0;
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return arch_set_syscall(child, child->saved_syscall);
}
