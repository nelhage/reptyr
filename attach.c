#include <sys/types.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <stdio.h>

#include "ptrace.h"

extern void debug(const char *msg, ...);

static void do_unmap(struct ptrace_child *child, unsigned long addr, int pages) {
    if (addr == (unsigned long)-1)
        return;
    ptrace_remote_syscall(child, __NR_munmap, addr, pages, 0, 0, 0, 0);
}

extern char child_stub_begin[], child_stub_end[];

int attach_child(pid_t pid, const char *pty) {
    struct ptrace_child child;
    unsigned long arg_page = -1,
        stack_page = -1,
        code_map   = -1;
    int code_pages = 1;

    if (ptrace_attach_child(&child, pid)) {
        perror("attach");
        return -1;
    }
    if (ptrace_advance_to_state(&child, ptrace_at_syscall))
        goto out_detach;
    if (ptrace_save_regs(&child))
        goto out_detach;

    arg_page = ptrace_remote_syscall(&child, mmap_syscall, 0,
                                     PAGE_SIZE, PROT_READ|PROT_WRITE,
                                     MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);

    debug("Allocated argument page: %lx", arg_page);

    stack_page = ptrace_remote_syscall(&child, mmap_syscall, 0,
                                     PAGE_SIZE, PROT_READ|PROT_WRITE,
                                     MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    debug("Allocated stack page: %lx", stack_page);

    code_map = ptrace_remote_syscall(&child, mmap_syscall, 0,
                                     code_pages * PAGE_SIZE,
                                     PROT_READ|PROT_WRITE,
                                     MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    debug("Allocated code buffer: %lx", code_map);

    if (arg_page == (unsigned long)-1
        || stack_page == (unsigned long)-1
        || code_map   == (unsigned long)-1)
        goto out_unmap;

    if (ptrace_memcpy_to_child(&child, arg_page, pty, strlen(pty) + 1))
        goto out_unmap;
    if (ptrace_memcpy_to_child(&child, code_map, child_stub_begin,
                               child_stub_end - child_stub_begin + 1))
        goto out_unmap;

 out_unmap:
    do_unmap(&child, arg_page, 1);
    do_unmap(&child, stack_page, 1);
    do_unmap(&child, code_map, code_pages);

    ptrace_restore_regs(&child);
 out_detach:
    ptrace_detach_child(&child);

    return -1;
}
