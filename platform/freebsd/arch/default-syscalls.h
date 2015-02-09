#define SC(name) .nr_##name = SYS_##name

{
#ifdef SYS_mmap
    SC(mmap),
#else
    .nr_mmap = -1,
#endif
#ifdef SYS_mmap2
    SC(mmap2),
#else
    .nr_mmap2 = -1,
#endif
    SC(munmap),
    SC(getsid),
    SC(setsid),
    SC(setpgid),
    SC(fork),
    SC(wait4),
#ifdef SYS_signal
    SC(signal),
#else
     .nr_signal = -1,
#endif
    .nr_rt_sigaction = SYS_sigaction,
    SC(open),
    SC(close),
    SC(ioctl),
    SC(dup2),
#ifdef SYS_socketcall
    SC(socketcall),
#else
    SC(socket),
    SC(connect),
    SC(sendmsg),
#endif
},

#undef SC
