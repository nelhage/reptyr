#define _GNU_SOURCE

#include <sys/syscall.h>
#define _FCNTL_H
#include <bits/fcntl.h>



static inline unsigned long __syscall(unsigned long sysno,
                                      unsigned long p0, unsigned long p1,
                                      unsigned long p2, unsigned long p3,
                                      unsigned long p4, unsigned long p5) {
    unsigned long rv;
#ifdef __amd64__
    register unsigned long _p3 asm("r10") = p3;
    register unsigned long _p4 asm("r8")  = p4;
    register unsigned long _p5 asm("r9")  = p5;
    asm("syscall" : "=a" (rv) : "a" (sysno),
        "rdi" (p0), "rsi" (p1), "rdx" (p2), "r"   (_p3), "r"  (_p4), "r"   (_p5)
        : "memory", "cc");
#else
    register unsigned long _p0 asm("ebx") = p0;
    register unsigned long _p1 asm("ecx") = p1;
    register unsigned long _p2 asm("edx") = p2;
    register unsigned long _p3 asm("esi") = p3;
    register unsigned long _p4 asm("edi") = p4;
    register unsigned long _p5 asm("ebp") = p5;
    asm("int $0x80" : "=a" (rv) : "a" (sysno),
        "r" (_p0), "r" (_p1), "r" (_p2), "r" (_p3), "r" (_p4), "r" (_p5)
        : "memory", "cc");
#endif
    return rv;
}

#define syscall1(name, t0, p0) \
    unsigned long name(t0 p0) {                                 \
        return __syscall(__NR_##name,                           \
                         (unsigned long)p0,                     \
                         0, 0, 0, 0, 0);                        \
    }

#define syscall2(name, t0, p0, t1, p1)                          \
    unsigned long name(t0 p0, t1 p1) {                          \
        return __syscall(__NR_##name,                           \
                         (unsigned long)p0,                     \
                         (unsigned long)p1,                     \
                         0, 0, 0, 0);                           \
    }

#define syscall3(name, t0, p0, t1, p1, t2, p2)                  \
    unsigned long name(t0 p0, t1 p1, t2 p2) {                   \
        return __syscall(__NR_##name,                           \
                         (unsigned long)p0,                     \
                         (unsigned long)p1,                     \
                         (unsigned long)p2,                     \
                         0, 0, 0);                              \
    }

#define syscall4(name, t0, p0, t1, p1, t2, p2, t3, p3)          \
    unsigned long name(t0 p0, t1 p1, t2 p2, t3 p3) {            \
        return __syscall(__NR_##name,                           \
                         (unsigned long)p0,                     \
                         (unsigned long)p1,                     \
                         (unsigned long)p2,                     \
                         (unsigned long)p3,                     \
                         0, 0);                                 \
    }

#define syscall5(name, t0, p0, t1, p1, t2, p2, t3, p3, t4, p4)  \
    unsigned long name(t0 p0, t1 p1, t2 p2, t3 p3, t4 p4) {     \
        return __syscall(__NR_##name,                           \
                         (unsigned long)p0,                     \
                         (unsigned long)p1,                     \
                         (unsigned long)p2,                     \
                         (unsigned long)p3,                     \
                         (unsigned long)p4,                     \
                         0);                                    \
    }

#define syscall6(name, t0, p0, t1, p1, t2, p2, t3, p3, t4, p4,  \
                 t5, p5)                                        \
    unsigned long name(t0 p0, t1 p1, t2 p2, t3 p3, t4 p4,       \
                       t5 p5) {                                 \
        return __syscall(__NR_##name,                           \
                         (unsigned long)p0,                     \
                         (unsigned long)p1,                     \
                         (unsigned long)p2,                     \
                         (unsigned long)p3,                     \
                         (unsigned long)p4,                     \
                         (unsigned long)p5);                    \
    }

syscall1(close, int, fd);
syscall2(open, const char*, path, int, mode);

void stub_entry() {
}

void _start(void) __attribute__((alias("stub_entry")));
