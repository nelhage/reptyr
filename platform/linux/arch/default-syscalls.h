#define SC(name) .nr_##name = __NR_##name

{
#ifdef __NR_mmap2
    .nr_mmap = -1,
    SC(mmap2),
#else
    SC(mmap),
    .nr_mmap2 = -1,
#endif
    SC(munmap),
    SC(getsid),
    SC(setsid),
    SC(setpgid),
#ifdef __NR_fork
    SC(fork),
    .nr_clone = -1,
#else
    .nr_fork = -1,
    SC(clone),
#endif
    SC(wait4),
#ifdef __NR_signal
    SC(signal),
#else
     .nr_signal = -1,
#endif
    SC(rt_sigaction),
    SC(openat),
    SC(close),
    SC(ioctl),
#ifdef __NR_dup2
    SC(dup2),
    .nr_dup3 = -1,
#else
    .nr_dup2 = -1,
    SC(dup3),
#endif
#ifdef __NR_socket
    SC(socket),
    SC(connect),
    SC(sendmsg),
#else
    SC(socketcall),
#endif
},

#undef SC
