#include <stdio.h>

#ifdef __linux__
#include <sys/prctl.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER
#endif

#ifndef PR_SET_PTRACER_ANY
# define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif
#endif

int main(int argc, char **argv) {
    char *line = NULL;
    size_t cap = 0;

#ifdef __linux__
    int err = prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    if (err != 0) {
        fprintf(stderr, "Unable to PR_SET_PTRACER: %m\n");
    }
#endif

    while (getline(&line, &cap, stdin) != -1) {
        printf("ECHO: %s", line);
    }

    return 0;
}
