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

#include "x86_common.h"

#define ARCH_HAVE_MULTIPLE_PERSONALITIES

static struct ptrace_personality arch_personality[2] = {
    {
        offsetof(struct reg, r_rax),
        offsetof(struct reg, r_rdi),
        offsetof(struct reg, r_rsi),
        offsetof(struct reg, r_rdx),
        offsetof(struct reg, r_rcx),
        //offsetof(struct reg, r_r10),
        offsetof(struct reg, r_r8),
        offsetof(struct reg, r_r9),
        offsetof(struct reg, r_rip),
    },
    {
        offsetof(struct reg, r_rax),
        offsetof(struct reg, r_rbx),
        offsetof(struct reg, r_rcx),
        offsetof(struct reg, r_rdx),
        offsetof(struct reg, r_rsi),
        offsetof(struct reg, r_rdi),
        offsetof(struct reg, r_rbp),
        offsetof(struct reg, r_rip),
    },
};

struct x86_personality x86_personality[2] = {
    {
        offsetof(struct reg, r_rax),
    },
    {
        offsetof(struct reg, r_rax),
    },
};

struct syscall_numbers arch_syscall_numbers[2] = {
#include "default-syscalls.h"
    {
    }
};

int arch_get_personality(struct ptrace_child *child) {
    unsigned long cs;

	cs = arch_get_register(child,offsetof(struct reg, r_cs));
    if (child->error)
        return -1;
    if (cs == 0x23)
        child->personality = 1;
    return 0;
}
