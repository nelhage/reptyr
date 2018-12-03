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

static struct ptrace_personality arch_personality[1] = {
    {
        offsetof(struct user_regs_struct, eax),
        offsetof(struct user_regs_struct, ebx),
        offsetof(struct user_regs_struct, ecx),
        offsetof(struct user_regs_struct, edx),
        offsetof(struct user_regs_struct, esi),
        offsetof(struct user_regs_struct, edi),
        offsetof(struct user_regs_struct, ebp),
        offsetof(struct user_regs_struct, eip),
    }
};

struct x86_personality x86_personality[1] = {
    {
        offsetof(struct user_regs_struct, orig_eax),
        offsetof(struct user_regs_struct, eax),
    }
};
