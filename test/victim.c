#include <stdio.h>
#include <sys/prctl.h>

int main(int argc, char **argv) {
    char *line = NULL;
    size_t cap = 0;

#ifdef PR_SET_PTRACER
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
#endif

    while(getline(&line, &cap, stdin) != -1) {
        printf("ECHO: %s", line);
    }

    return 0;
}
