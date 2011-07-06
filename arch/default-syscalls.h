#define SC(name) .nr_##name = __NR_##name

{
#ifdef __NR_mmap
    SC(mmap),
#else
    .nr_mmap = -1,
#endif
#ifdef __NR_mmap2
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
#ifdef __NR_signal
    SC(signal),
#else
     .nr_signal = -1,
#endif
    SC(rt_sigaction),
    SC(open),
    SC(close),
    SC(ioctl),
    SC(dup2),
},

#undef SC
