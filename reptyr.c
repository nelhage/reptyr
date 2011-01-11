#define _XOPEN_SOURCE 500
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

void die(const char *msg, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, msg);
    vsnprintf(buf, sizeof buf, msg, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", buf);
    exit(1);
}

void setup_raw(struct termios *save) {
    struct termios set;
    if (tcgetattr(0, save) < 0)
        die("Unable to read terminal attributes: %m");
    set = *save;
    set.c_iflag = 0;
    set.c_oflag = 0;
    set.c_cflag = 0;
    set.c_lflag = 0;
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

int main(int argc, char **argv) {
    struct termios saved_termios;
    struct sigaction act;
    int pty;

    if ((pty = open("/dev/ptmx", O_RDWR|O_NOCTTY)) < 0)
        die("Unable to open /dev/ptmx: %m");
    if (unlockpt(pty) < 0)
        die("Unable to unlockpt: %m");
    if (grantpt(pty) < 0)
        die("Unable to unlockpt: %m");
    printf("Opened a new pty: %s\n", ptsname(pty));

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
