#define SC(name) .nr_##name = SYS_##name

{
#ifdef SYS_mmap2
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
    SC(fork),
    .nr_clone = -1,
    SC(wait4),
#ifdef SYS_signal
    SC(signal),
#else
     .nr_signal = -1,
#endif
    .nr_rt_sigaction = SYS_sigaction,
    SC(openat),
    SC(close),
    SC(ioctl),
    SC(dup2),
    .nr_dup3 = -1,
#ifdef SYS_socketcall
    SC(socketcall),
#else
    SC(socket),
    SC(connect),
    SC(sendmsg),
#endif
},

#undef SC
