#define orig_ax orig_rax
#define reg_ax  rax
#define reg_ip  rip

#define syscall_rv   rax
#define syscall_arg0 rdi
#define syscall_arg1 rsi
#define syscall_arg2 rdx
#define syscall_arg3 r10
#define syscall_arg4 r8
#define syscall_arg5 r9

#include "x86_common.h"
