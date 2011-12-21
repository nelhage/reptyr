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
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <termios.h>
#include <signal.h>

#include "reptyr.h"

#ifndef __linux__
#error reptyr is currently Linux-only.
#endif

static int verbose = 0;

void _debug(const char *pfx, const char *msg, va_list ap) {

    if (pfx)
        fprintf(stderr, "%s", pfx);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
}

void die(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    _debug("[!] ", msg, ap);
    va_end(ap);

    exit(1);
}

void debug(const char *msg, ...) {

    va_list ap;

    if (!verbose)
        return;

    va_start(ap, msg);
    _debug("[+] ", msg, ap);
    va_end(ap);
}

void error(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    _debug("[-] ", msg, ap);
    va_end(ap);
}

void setup_raw(struct termios *save) {
    struct termios set;
    if (tcgetattr(0, save) < 0)
        die("Unable to read terminal attributes: %m");
    set = *save;
    cfmakeraw(&set);
    if (tcsetattr(0, TCSANOW, &set) < 0)
        die("Unable to set terminal attributes: %m");
}

void resize_pty(int pty) {
    struct winsize sz;
    if (ioctl(0, TIOCGWINSZ, &sz) < 0)
        return;
    ioctl(pty, TIOCSWINSZ, &sz);
}

int writeall(int fd, const void *buf, ssize_t count) {
    ssize_t rv;
    while (count > 0) {
        rv = write(fd, buf, count);
        if (rv < 0)
            return rv;
        count -= rv;
        buf += rv;
    }
    return 0;
}

int winch_happened = 0;

void do_winch(int signal) {
    winch_happened = 1;
}

void do_proxy(int pty) {
    char buf[4096];
    ssize_t count;
    fd_set set;
    while (1) {
        if (winch_happened) {
            resize_pty(pty);
            /* FIXME: racy against a second resize */
            winch_happened = 0;
        }
        FD_ZERO(&set);
        FD_SET(0, &set);
        FD_SET(pty, &set);
        if (select(pty+1, &set, NULL, NULL, NULL) < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "select: %m");
            return;
        }
        if (FD_ISSET(0, &set)) {
            count = read(0, buf, sizeof buf);
            if (count < 0)
                return;
            writeall(pty, buf, count);
        }
        if (FD_ISSET(pty, &set)) {
            count = read(pty, buf, sizeof buf);
            if (count < 0)
                return;
            writeall(1, buf, count);
        }
    }
}

void usage(char *me) {
    fprintf(stderr, "Usage: %s [-s] PID\n", me);
    fprintf(stderr, "       %s -l\n", me);
    fprintf(stderr, "  -l    Create a new pty pair and print the name of the slave.\n");
    fprintf(stderr, "  -s    Attach fds 0-2 on the target, even if it is not attached to a tty.\n");
    fprintf(stderr, "  -h    Print this help message and exit.\n");
    fprintf(stderr, "  -v    Print the version number and exit.\n");
    fprintf(stderr, "  -V    Print verbose debug output.\n");
}

void check_yama_ptrace_scope(void) {
    int fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        int n;
        n = read(fd, buf, sizeof buf);
        close(fd);
        if (n > 0) {
            if (!atoi(buf)) {
                return;
            }
        }
    } else if (errno == ENOENT)
        return;
    fprintf(stderr, "The kernel denied permission while attaching. If your uid matches\n");
    fprintf(stderr, "the target's, check the value of /proc/sys/kernel/yama/ptrace_scope.\n");
    fprintf(stderr, "For more information, see /etc/sysctl.d/10-ptrace.conf\n");
}

int main(int argc, char **argv) {
    struct termios saved_termios;
    struct sigaction act;
    int pty;
    int arg = 1;
    int do_attach = 1;
    int force_stdio = 0;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    if (argv[arg][0] == '-') {
        switch(argv[arg][1]) {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'l':
            do_attach = 0;
            break;
        case 's':
            arg++;
            force_stdio = 1;
            break;
        case 'v':
            printf("This is reptyr version %s.\n", REPTYR_VERSION);
            printf(" by Nelson Elhage <nelhage@nelhage.com>\n");
            printf("http://github.com/nelhage/reptyr/\n");
            return 0;
        case 'V':
            arg++;
            verbose = 1;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (do_attach && arg >= argc) {
        fprintf(stderr, "%s: No pid specified to attach\n", argv[0]);
        usage(argv[0]);
        return 1;
    }

    if ((pty = open("/dev/ptmx", O_RDWR|O_NOCTTY)) < 0)
        die("Unable to open /dev/ptmx: %m");
    if (unlockpt(pty) < 0)
        die("Unable to unlockpt: %m");
    if (grantpt(pty) < 0)
        die("Unable to grantpt: %m");

    if (do_attach) {
        pid_t child = atoi(argv[arg]);
        int err;
        if ((err = attach_child(child, ptsname(pty), force_stdio))) {
            fprintf(stderr, "Unable to attach to pid %d: %s\n", child, strerror(err));
            if (err == EPERM) {
                check_yama_ptrace_scope();
            }
            return 1;
        }
    } else {
        printf("Opened a new pty: %s\n", ptsname(pty));
    }

    setup_raw(&saved_termios);
    resize_pty(pty);
    memset(&act, 0, sizeof act);
    act.sa_handler = do_winch;
    act.sa_flags   = 0;
    sigaction(SIGWINCH, &act, NULL);
    do_proxy(pty);
    tcsetattr(0, TCSANOW, &saved_termios);

    return 0;
}
