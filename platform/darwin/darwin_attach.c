/*
 * Copyright (C) 2026 by reptyr contributors
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

#ifdef __APPLE__

#include "darwin.h"
#include "../platform.h"
#include "../../reptyr.h"

#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <sys/proc_info.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#ifndef NODEV
#define NODEV ((dev_t)-1)
#endif

#define DARWIN_PAYLOAD_TIMEOUT_MS 2000
#define DARWIN_MAX_REDIRECT_FDS 64

#if defined(__arm64__)
static uint32_t movz64(unsigned reg, uint16_t imm, unsigned shift) {
    return 0xd2800000u | ((shift / 16) << 21) | ((uint32_t)imm << 5) | reg;
}

static uint32_t movk64(unsigned reg, uint16_t imm, unsigned shift) {
    return 0xf2800000u | ((shift / 16) << 21) | ((uint32_t)imm << 5) | reg;
}

static uint32_t movz32(unsigned reg, uint16_t imm, unsigned shift) {
    return 0x52800000u | ((shift / 16) << 21) | ((uint32_t)imm << 5) | reg;
}

static size_t emit_mov64(uint32_t *out, unsigned reg, uint64_t value) {
    out[0] = movz64(reg, (uint16_t)(value & 0xffff), 0);
    out[1] = movk64(reg, (uint16_t)((value >> 16) & 0xffff), 16);
    out[2] = movk64(reg, (uint16_t)((value >> 32) & 0xffff), 32);
    out[3] = movk64(reg, (uint16_t)((value >> 48) & 0xffff), 48);
    return 4;
}
#endif

struct remote_result {
    uint64_t result;
    uint32_t done;
    uint32_t step;
};

#if defined(__arm64__)

static int task_for_pid_errno(pid_t pid, task_t *task) {
    kern_return_t kr = task_for_pid(mach_task_self(), pid, task);
    if (kr == KERN_SUCCESS)
        return 0;
    error("task_for_pid(%d) failed: %s (%d). On macOS, the target usually needs get-task-allow entitlement or Developer Mode/debug permission.",
          pid, mach_error_string(kr), kr);
    return EPERM;
}

static void deallocate_thread_list(thread_act_array_t threads, mach_msg_type_number_t thread_count) {
    mach_msg_type_number_t i;

    if (!threads)
        return;
    for (i = 0; i < thread_count; i++) {
        if (threads[i] != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(thread_t));
}

static int read_target_ctty(pid_t pid, dev_t *ctty) {
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };

    if (sysctl(mib, 4, &kp, &len, NULL, 0) < 0) {
        error("sysctl(KERN_PROC_PID, %d) failed: %s", pid, strerror(errno));
        return assert_nonzero(errno);
    }
    if (len == 0)
        return ESRCH;

    *ctty = kp.kp_eproc.e_tdev;
    return 0;
}

static int darwin_find_tty_fds(pid_t pid, int **out_fds, int *out_count) {
    struct fd_array tty_fds = {};
    struct proc_fdinfo *fds = NULL;
    int buffer_size;
    int actual_size;
    int fd_count;
    int attempts;
    dev_t ctty;
    int err;
    int i;

    *out_fds = NULL;
    *out_count = 0;

    err = read_target_ctty(pid, &ctty);
    if (err)
        return err;
    if (ctty == NODEV) {
        error("Target is not connected to a terminal.\n"
              "    Use -s to force attaching anyways.");
        return ENOTTY;
    }

    for (attempts = 0; attempts < 3; attempts++) {
        buffer_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (buffer_size <= 0) {
            error("proc_pidinfo(PROC_PIDLISTFDS, %d) failed: %s", pid, strerror(errno));
            return assert_nonzero(errno);
        }

        buffer_size += 8 * (int)PROC_PIDLISTFD_SIZE;
        free(fds);
        fds = malloc((size_t)buffer_size);
        if (!fds)
            return ENOMEM;

        actual_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, buffer_size);
        if (actual_size <= 0) {
            err = assert_nonzero(errno);
            error("proc_pidinfo(PROC_PIDLISTFDS, %d) failed: %s", pid, strerror(errno));
            goto out;
        }
        if (actual_size < buffer_size)
            break;
    }

    fd_count = actual_size / (int)sizeof(fds[0]);
    debug("Looking up fds for Darwin controlling tty %llu in child %d.",
          (unsigned long long)ctty, pid);

    for (i = 0; i < fd_count; i++) {
        struct vnode_fdinfowithpath vnode_info;
        dev_t rdev;
        int got;

        if (fds[i].proc_fd < 0 || fds[i].proc_fdtype != PROX_FDTYPE_VNODE)
            continue;

        got = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO,
                             &vnode_info, sizeof(vnode_info));
        if (got != sizeof(vnode_info)) {
            debug("Skipping fd %d: PROC_PIDFDVNODEPATHINFO failed: %s",
                  fds[i].proc_fd, strerror(errno));
            continue;
        }

        if (vnode_info.pvip.vip_vi.vi_type != VCHR)
            continue;

        rdev = vnode_info.pvip.vip_vi.vi_stat.vst_rdev;
        if (rdev != ctty)
            continue;

        debug("Found an alias for the tty: fd %d (%s)",
              fds[i].proc_fd, vnode_info.pvip.vip_path);
        if (fd_array_push(&tty_fds, fds[i].proc_fd) != 0) {
            err = ENOMEM;
            error("Unable to allocate memory for fd array.");
            goto out;
        }
    }

    if (tty_fds.n == 0) {
        error("Target has a controlling terminal, but no open fd aliases were found.\n"
              "    Use -s to force attaching stdio fds 0-2.");
        err = ENOTTY;
        goto out;
    }

    *out_fds = tty_fds.fds;
    *out_count = tty_fds.n;
    tty_fds.fds = NULL;
    err = 0;

out:
    free(tty_fds.fds);
    free(fds);
    return err;
}

#define ARM64_COND_EQ 0u
#define ARM64_COND_CS 2u
#define DARWIN_PAYLOAD_STEP_OPEN 1u
#define DARWIN_PAYLOAD_STEP_DUP2_BASE 100u
#define DARWIN_PAYLOAD_STEP_CLOSE 200u

static void patch_cond_branch(uint32_t *insns, size_t branch_at, size_t target, unsigned cond) {
    int64_t offset = (int64_t)target - (int64_t)branch_at;
    insns[branch_at] = 0x54000000u | (((uint32_t)offset & 0x7ffffu) << 5) | (cond & 0xfu);
}

static size_t emit_syscall_error_branch(uint32_t *insns, size_t *n, unsigned step) {
    size_t branch_at;

    insns[(*n)++] = movz32(21, (uint16_t)step, 0); /* mov w21, step */
    insns[(*n)++] = 0xd4001001u; /* svc #0x80 */
    branch_at = (*n)++;
    return branch_at;
}

static void emit_success_report(uint32_t *insns, size_t *n, mach_vm_address_t result_addr) {
    *n += emit_mov64(&insns[*n], 1, result_addr);
    *n += emit_mov64(&insns[*n], 0, 0);          /* result = 0 */
    insns[(*n)++] = 0xf9000020u;                 /* str x0, [x1] */
    insns[(*n)++] = movz32(2, 1, 0);             /* done = success */
    insns[(*n)++] = 0xb9000822u;                 /* str w2, [x1, #8] */
    insns[(*n)++] = movz32(2, 0, 0);             /* step = 0 */
    insns[(*n)++] = 0xb9000c22u;                 /* str w2, [x1, #12] */
    insns[(*n)++] = 0xd503205fu;                 /* wfe */
    insns[(*n)++] = 0x17ffffffu;                 /* b .-4 */
}

static void emit_error_report(uint32_t *insns, size_t *n, mach_vm_address_t result_addr) {
    *n += emit_mov64(&insns[*n], 1, result_addr);
    insns[(*n)++] = 0xf9000020u;                 /* str x0, [x1] */
    insns[(*n)++] = movz32(2, 2, 0);             /* done = error */
    insns[(*n)++] = 0xb9000822u;                 /* str w2, [x1, #8] */
    insns[(*n)++] = 0xb9000c35u;                 /* str w21, [x1, #12] */
    insns[(*n)++] = 0xd503205fu;                 /* wfe */
    insns[(*n)++] = 0x17ffffffu;                 /* b .-4 */
}
static int darwin_redirect_fds(task_t task, const char *pty, const int *target_fds, int target_fd_count) {
    mach_vm_address_t remote_pty = 0;
    mach_vm_size_t remote_pty_size = strlen(pty) + 1;
    mach_vm_address_t result_addr = 0;
    mach_vm_size_t result_size = 4096;
    mach_vm_address_t code = 0;
    mach_vm_size_t code_size = 8192;
    mach_vm_address_t stack = 0;
    mach_vm_size_t stack_size = 64 * 1024;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    char *suspended = NULL;
    thread_act_t thread = MACH_PORT_NULL;
    kern_return_t kr;
    struct remote_result result = {0};
    uint32_t insns[64 + DARWIN_MAX_REDIRECT_FDS * 18];
    size_t error_branches[2 + DARWIN_MAX_REDIRECT_FDS];
    size_t skip_close_branches[DARWIN_MAX_REDIRECT_FDS];
    size_t n = 0;
    size_t error_label;
    arm_thread_state64_t saved_state;
    arm_thread_state64_t state;
    mach_msg_type_number_t state_count;
    int err = 0;
    int thread_running_payload = 0;
    int state_saved = 0;
    int can_deallocate_payload = 1;
    int i;

    if (target_fd_count <= 0)
        return EINVAL;
    if (target_fd_count > DARWIN_MAX_REDIRECT_FDS) {
        error("Refusing to redirect %d fds; built-in safety cap is %d.",
              target_fd_count, DARWIN_MAX_REDIRECT_FDS);
        return E2BIG;
    }

    kr = mach_vm_allocate(task, &remote_pty, remote_pty_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        error("mach_vm_allocate(pty) failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }
    kr = mach_vm_write(task, remote_pty, (vm_offset_t)pty, (mach_msg_type_number_t)remote_pty_size);
    if (kr != KERN_SUCCESS) {
        error("mach_vm_write(pty) failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }

    kr = mach_vm_allocate(task, &result_addr, result_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        error("mach_vm_allocate(result) failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }
    kr = mach_vm_write(task, result_addr, (vm_offset_t)&result, sizeof(result));
    if (kr != KERN_SUCCESS) {
        error("mach_vm_write(result) failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }

    /* fd = open(remote_pty, O_RDWR | O_NOCTTY); */
    n += emit_mov64(&insns[n], 0, remote_pty);
    n += emit_mov64(&insns[n], 1, O_RDWR | O_NOCTTY);
    n += emit_mov64(&insns[n], 16, SYS_open);
    error_branches[0] = emit_syscall_error_branch(insns, &n, DARWIN_PAYLOAD_STEP_OPEN);
    insns[n++] = 0xaa0003f4u; /* mov x20, x0 */

    for (i = 0; i < target_fd_count; i++) {
        /* dup2(x20, target_fds[i]); */
        insns[n++] = 0xaa1403e0u; /* mov x0, x20 */
        n += emit_mov64(&insns[n], 1, (uint64_t)target_fds[i]);
        n += emit_mov64(&insns[n], 16, SYS_dup2);
        error_branches[1 + i] = emit_syscall_error_branch(insns, &n, DARWIN_PAYLOAD_STEP_DUP2_BASE + (unsigned)i);
    }

    for (i = 0; i < target_fd_count; i++) {
        /* If open() reused a closed target fd, closing x20 would undo the redirect. */
        n += emit_mov64(&insns[n], 21, (uint64_t)target_fds[i]);
        insns[n++] = 0xeb15029fu; /* cmp x20, x21 */
        skip_close_branches[i] = n++;
    }

    /* close(x20); */
    insns[n++] = 0xaa1403e0u; /* mov x0, x20 */
    n += emit_mov64(&insns[n], 16, SYS_close);
    error_branches[1 + target_fd_count] = emit_syscall_error_branch(insns, &n, DARWIN_PAYLOAD_STEP_CLOSE);

    for (i = 0; i < target_fd_count; i++)
        patch_cond_branch(insns, skip_close_branches[i], n, ARM64_COND_EQ);

    emit_success_report(insns, &n, result_addr);
    error_label = n;
    emit_error_report(insns, &n, result_addr);

    for (i = 0; i < target_fd_count + 2; i++)
        patch_cond_branch(insns, error_branches[i], error_label, ARM64_COND_CS);

    kr = mach_vm_allocate(task, &code, code_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        error("mach_vm_allocate(code) failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }
    kr = mach_vm_write(task, code, (vm_offset_t)insns, (mach_msg_type_number_t)(n * sizeof(insns[0])));
    if (kr != KERN_SUCCESS) {
        error("mach_vm_write(code) failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }
    kr = mach_vm_protect(task, code, code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        error("mach_vm_protect(code RX) failed: %s (%d)", mach_error_string(kr), kr);
        err = EACCES;
        goto out;
    }

    kr = mach_vm_allocate(task, &stack, stack_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        error("mach_vm_allocate(stack) failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }

    kr = task_threads(task, &threads, &thread_count);
    if (kr != KERN_SUCCESS || thread_count == 0) {
        error("task_threads failed: %s (%d), count=%u", mach_error_string(kr), kr, thread_count);
        err = EIO;
        goto out;
    }

    suspended = calloc(thread_count, sizeof(*suspended));
    if (!suspended) {
        err = ENOMEM;
        goto out;
    }

    for (i = 0; i < (int)thread_count; i++) {
        kr = thread_suspend(threads[i]);
        if (kr != KERN_SUCCESS) {
            error("thread_suspend failed: %s (%d)", mach_error_string(kr), kr);
            err = EIO;
            goto out;
        }
        suspended[i] = 1;
    }
    thread = threads[0];
    thread_abort(thread);

    state_count = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&saved_state, &state_count);
    if (kr != KERN_SUCCESS) {
        error("thread_get_state failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }
    state_saved = 1;

    memset(&state, 0, sizeof(state));
    state.__pc = code;
    state.__sp = (stack + stack_size - 16) & ~((mach_vm_address_t)0xf);
    kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        error("thread_set_state failed: %s (%d)", mach_error_string(kr), kr);
        err = EACCES;
        goto out;
    }

    kr = thread_resume(thread);
    if (kr != KERN_SUCCESS) {
        error("thread_resume failed: %s (%d)", mach_error_string(kr), kr);
        err = EIO;
        goto out;
    }
    suspended[0] = 0;
    thread_running_payload = 1;

    for (i = 0; i < DARWIN_PAYLOAD_TIMEOUT_MS / 10; i++) {
        mach_vm_size_t out_size = 0;
        kr = mach_vm_read_overwrite(task, result_addr, sizeof(result), (mach_vm_address_t)&result, &out_size);
        if (kr != KERN_SUCCESS) {
            error("mach_vm_read_overwrite(result) failed: %s (%d)", mach_error_string(kr), kr);
            err = EIO;
            goto out;
        }
        if (result.done == 1) {
            debug("Darwin fd redirect payload completed");
            err = 0;
            goto out;
        }
        if (result.done == 2) {
            err = result.result > 0 && result.result < 4096 ? (int)result.result : EIO;
            error("Darwin fd redirect payload syscall step %u failed: %s",
                  result.step, strerror(err));
            goto out;
        }
        usleep(10000);
    }

    error("Darwin fd redirect payload timed out");
    err = ETIMEDOUT;

out:
    if (thread != MACH_PORT_NULL && thread_running_payload) {
        kr = thread_suspend(thread);
        if (kr == KERN_SUCCESS) {
            thread_running_payload = 0;
            if (state_saved)
                thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&saved_state, ARM_THREAD_STATE64_COUNT);
            thread_abort(thread);
            thread_resume(thread);
        } else {
            error("thread_suspend during cleanup failed: %s (%d)", mach_error_string(kr), kr);
            can_deallocate_payload = 0;
        }
    } else if (thread != MACH_PORT_NULL && state_saved) {
        thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&saved_state, ARM_THREAD_STATE64_COUNT);
        thread_abort(thread);
    }

    if (suspended) {
        for (i = 0; i < (int)thread_count; i++) {
            if (suspended[i])
                thread_resume(threads[i]);
        }
    }

    if (remote_pty && can_deallocate_payload)
        mach_vm_deallocate(task, remote_pty, remote_pty_size);
    if (result_addr && can_deallocate_payload)
        mach_vm_deallocate(task, result_addr, result_size);
    if (code && can_deallocate_payload)
        mach_vm_deallocate(task, code, code_size);
    if (stack && can_deallocate_payload)
        mach_vm_deallocate(task, stack, stack_size);
    free(suspended);
    deallocate_thread_list(threads, thread_count);
    return err;
}

#endif

int darwin_attach_child(pid_t pid, const char *pty, int force_stdio) {
#if !defined(__arm64__)
    (void)pid;
    (void)pty;
    (void)force_stdio;
    error("macOS attach is currently implemented only for arm64 targets.");
    return ENOTSUP;
#else
    task_t task = MACH_PORT_NULL;
    int stdio_fds[] = {0, 1, 2};
    int *target_fds = NULL;
    int target_fd_count = 0;
    int err;

    if (force_stdio) {
        target_fds = stdio_fds;
        target_fd_count = 3;
    } else {
        err = darwin_find_tty_fds(pid, &target_fds, &target_fd_count);
        if (err)
            return err;
    }

    err = task_for_pid_errno(pid, &task);
    if (err)
        goto out;

    debug("Using tty: %s", pty);
    err = darwin_redirect_fds(task, pty, target_fds, target_fd_count);
    if (err)
        goto out;

    kill(pid, SIGWINCH);

out:
    if (task != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), task);
    if (!force_stdio)
        free(target_fds);
    return err;
#endif
}

#endif
