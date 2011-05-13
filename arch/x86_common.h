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

struct x86_personality {
    size_t orig_ax;
    size_t ax;
};

struct x86_personality x86_personality[];

static inline struct x86_personality *x86_pers(struct ptrace_child *child) {
    return &x86_personality[child->personality];
}

static inline void arch_fixup_regs(struct ptrace_child *child) {
    struct x86_personality *x86pers = x86_pers(child);
    struct ptrace_personality *pers = personality(child);
    struct user *user = &child->user;
#define ptr(user, off) ((unsigned long*)((void*)(user)+(off)))
    *ptr(user, pers->reg_ip) -= 2;
    *ptr(user, x86pers->ax) = *ptr(user, x86pers->orig_ax);
}

static inline int arch_set_syscall(struct ptrace_child *child,
                                   unsigned long sysno) {
    return ptrace_command(child, PTRACE_POKEUSER,
                          x86_pers(child)->orig_ax,
                          sysno);
}

static inline int arch_save_syscall(struct ptrace_child *child) {
    child->saved_syscall = *ptr(&child->user, x86_pers(child)->orig_ax);
    return 0;
}

static inline int arch_restore_syscall(struct ptrace_child *child) {
    return 0;
}

#undef ptr
